require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const argon2 = require('argon2');
const { rateLimit } = require('express-rate-limit');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const requiredEnv = ['DATABASE_URL', 'SESSION_SECRET', 'APP_ORIGIN'];
if (isProd) {
  const missing = requiredEnv.filter(k => !process.env[k]);
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  if ((process.env.SESSION_SECRET || '').length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10, idleTimeoutMillis: 30000 });
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: isProd ? [] : null } } }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

const sessionStore = new PgSession({ pool, createTableIfMissing: true, tableName: 'web_sessions' });
app.use(session({
  name: 'bzc.sid', store: sessionStore,
  secret: process.env.SESSION_SECRET || 'local-development-only-change-this-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'strict', maxAge: 1000 * 60 * 60 * 8 }
}));

// Same-origin protection for browser state changes. Set APP_ORIGIN to the exact deployed URL.
app.use('/api', (req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    const expectedOrigin = process.env.APP_ORIGIN === 'AUTO_RENDER_ORIGIN' && process.env.RENDER_EXTERNAL_HOSTNAME
      ? `https://${process.env.RENDER_EXTERNAL_HOSTNAME}` : process.env.APP_ORIGIN;
    if (!origin || (expectedOrigin && origin !== expectedOrigin)) {
      return res.status(403).json({ error: 'Request origin not allowed.' });
    }
  }
  next();
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
const generalLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', generalLimiter);
app.use(['/api/register','/api/login','/api/admin/bootstrap'], authLimiter);

const networks = ['TRC20','ERC20','BEP20','Polygon','Arbitrum','Optimism','Solana','Avalanche'];
const emailSchema = z.string().trim().email().max(254).transform(v => v.toLowerCase());
const passwordSchema = z.string().min(12).max(128);
const registerSchema = z.object({ fullName: z.string().trim().min(2).max(80), email: emailSchema, password: passwordSchema });
const loginSchema = z.object({ email: emailSchema, password: z.string().min(1).max(128) });
const depositSchema = z.object({ planSlug: z.enum(['starter','growth','advanced']), network: z.enum(networks), amount: z.coerce.number().finite().positive().max(100000000), txHash: z.string().trim().max(180).optional().default('') });
const reviewSchema = z.object({ status: z.enum(['under_review','confirmed','rejected']), txHash: z.string().trim().max(180).optional(), reviewNote: z.string().trim().max(500).optional() });
const addressSchema = z.object({ publicAddress: z.string().trim().min(20).max(180).nullable(), enabled: z.boolean() });

function asyncRoute(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }
function requireAuth(req,res,next) { if (!req.session.user) return res.status(401).json({ error: 'Please log in.' }); next(); }
function requireAdmin(req,res,next) { if (!req.session.user) return res.status(401).json({ error: 'Please log in.' }); if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' }); next(); }
async function audit(req, action, targetType, targetId, metadata = {}) {
  await pool.query('INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,metadata,ip_address) VALUES($1,$2,$3,$4,$5,$6)', [req.session.user?.id || null, action, targetType, targetId || null, JSON.stringify(metadata), req.ip || null]);
}
function publicUser(u) { return { id: u.id, fullName: u.full_name, email: u.email, role: u.role, selectedPlanSlug: u.selected_plan_slug || null, createdAt: u.created_at }; }

app.get('/api/health', asyncRoute(async (_req,res) => { await pool.query('SELECT 1'); res.json({ ok: true, service: 'bzc-api' }); }));
app.get('/api/me', (req,res) => res.json({ user: req.session.user || null }));
app.get('/api/plans', asyncRoute(async (_req,res) => {
  const { rows } = await pool.query('SELECT slug,name,min_usdt,max_usdt,description FROM investment_plans WHERE active=TRUE ORDER BY min_usdt');
  res.json({ plans: rows.map(p => ({ slug:p.slug, name:p.name, minUsdt:Number(p.min_usdt), maxUsdt:p.max_usdt===null?null:Number(p.max_usdt), description:p.description })) });
}));
app.get('/api/deposit-addresses', asyncRoute(async (_req,res) => {
  const { rows } = await pool.query('SELECT network,display_name,public_address FROM network_addresses WHERE enabled=TRUE AND public_address IS NOT NULL ORDER BY display_name');
  res.json({ addresses: rows });
}));

app.post('/api/register', asyncRoute(async (req,res) => {
  const parsed = registerSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Enter a name, valid email, and password of at least 12 characters.' });
  const { fullName,email,password } = parsed.data;
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  let result;
  try { result = await pool.query('INSERT INTO users(full_name,email,password_hash) VALUES($1,$2,$3) RETURNING id,full_name,email,role,created_at', [fullName,email,passwordHash]); }
  catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Unable to create account with these details. Try logging in.' }); throw e; }
  await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
  req.session.user = publicUser(result.rows[0]);
  await audit(req,'user.register','user',result.rows[0].id);
  res.status(201).json({ user:req.session.user });
}));
app.post('/api/login', asyncRoute(async (req,res) => {
  const parsed = loginSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email and password.' });
  const { rows } = await pool.query('SELECT u.*,p.slug AS selected_plan_slug FROM users u LEFT JOIN investment_plans p ON p.id=u.selected_plan_id WHERE u.email=$1', [parsed.data.email]);
  const u = rows[0];
  if (!u || !(await argon2.verify(u.password_hash, parsed.data.password).catch(()=>false))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
  req.session.user = publicUser(u);
  await audit(req,'user.login','user',u.id);
  res.json({ user:req.session.user });
}));
app.post('/api/logout', requireAuth, asyncRoute(async (req,res) => { await audit(req,'user.logout','user',req.session.user.id); req.session.destroy(err=>{ if(err) return res.status(500).json({error:'Could not log out.'}); res.clearCookie('bzc.sid',{httpOnly:true,secure:isProd,sameSite:'strict'}); res.json({ok:true}); }); }));
app.post('/api/plan/select', requireAuth, asyncRoute(async (req,res) => {
  const slug = z.enum(['starter','growth','advanced']).safeParse(req.body?.planSlug); if(!slug.success) return res.status(400).json({error:'Choose a valid plan.'});
  const result = await pool.query('UPDATE users SET selected_plan_id=(SELECT id FROM investment_plans WHERE slug=$1 AND active=TRUE),updated_at=NOW() WHERE id=$2 RETURNING id', [slug.data,req.session.user.id]);
  if (!result.rowCount) return res.status(400).json({error:'Plan is not available.'});
  req.session.user.selectedPlanSlug=slug.data; await audit(req,'plan.selected','user',req.session.user.id,{planSlug:slug.data}); res.json({selectedPlanSlug:slug.data});
}));
app.get('/api/dashboard', requireAuth, asyncRoute(async (req,res) => {
  const { rows: users } = await pool.query('SELECT u.id,u.full_name,u.email,u.role,u.created_at,p.slug AS selected_plan_slug FROM users u LEFT JOIN investment_plans p ON p.id=u.selected_plan_id WHERE u.id=$1',[req.session.user.id]);
  const { rows: deposits } = await pool.query('SELECT d.reference,d.amount_usdt,d.network,d.tx_hash,d.status,d.review_note,d.created_at,d.updated_at,p.name AS plan_name FROM deposit_requests d JOIN investment_plans p ON p.id=d.plan_id WHERE d.user_id=$1 ORDER BY d.created_at DESC LIMIT 100',[req.session.user.id]);
  const { rows: totals } = await pool.query("SELECT COALESCE(SUM(amount_usdt),0) AS confirmed_deposits FROM deposit_requests WHERE user_id=$1 AND status='confirmed'",[req.session.user.id]);
  res.json({ user:publicUser(users[0]), confirmedDepositsUsdt:Number(totals[0].confirmed_deposits), deposits:deposits.map(d=>({...d,amountUsdt:Number(d.amount_usdt)})) });
}));
app.post('/api/deposits', requireAuth, asyncRoute(async (req,res) => {
  const parsed = depositSchema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Check plan, network, amount and transaction hash.'});
  const {planSlug,network,amount,txHash}=parsed.data;
  const { rows: plans } = await pool.query('SELECT id,min_usdt,max_usdt FROM investment_plans WHERE slug=$1 AND active=TRUE',[planSlug]);
  if(!plans[0] || amount < Number(plans[0].min_usdt) || (plans[0].max_usdt !== null && amount > Number(plans[0].max_usdt))) return res.status(400).json({error:'Amount does not fit the selected plan limits.'});
  const { rows: addr } = await pool.query('SELECT 1 FROM network_addresses WHERE network=$1 AND enabled=TRUE AND public_address IS NOT NULL',[network]);
  if(!addr.length) return res.status(400).json({error:'Deposits are not enabled for this network yet. Do not send funds.'});
  const reference='BZC-'+require('crypto').randomBytes(6).toString('hex').toUpperCase();
  try {
    const { rows } = await pool.query('INSERT INTO deposit_requests(reference,user_id,plan_id,network,amount_usdt,tx_hash) VALUES($1,$2,$3,$4,$5,$6) RETURNING reference,amount_usdt,network,tx_hash,status,created_at',[reference,req.session.user.id,plans[0].id,network,amount,txHash||null]);
    await pool.query('UPDATE users SET selected_plan_id=$1,updated_at=NOW() WHERE id=$2',[plans[0].id,req.session.user.id]);
    await audit(req,'deposit.request_created','deposit',reference,{network,amountUsdt:amount,planSlug});
    res.status(201).json({deposit:rows[0],notice:'Request recorded only. This does not prove a blockchain transfer or guarantee a credit.'});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'This transaction hash has already been submitted for this network.'}); throw e; }
}));

app.get('/api/admin/summary', requireAdmin, asyncRoute(async (_req,res) => {
  const { rows } = await pool.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status='pending')::int AS pending, COUNT(*) FILTER (WHERE status='under_review')::int AS under_review, COUNT(*) FILTER (WHERE status='confirmed')::int AS confirmed, COUNT(*) FILTER (WHERE status='rejected')::int AS rejected FROM deposit_requests");
  const { rows: users } = await pool.query('SELECT COUNT(*)::int AS total_users FROM users'); res.json({...rows[0],totalUsers:users[0].total_users});
}));
app.get('/api/admin/deposits', requireAdmin, asyncRoute(async (_req,res) => {
  const { rows } = await pool.query('SELECT d.reference,d.user_id,u.full_name,u.email,d.amount_usdt,d.network,d.tx_hash,d.status,d.review_note,d.created_at,d.updated_at,p.name AS plan_name FROM deposit_requests d JOIN users u ON u.id=d.user_id JOIN investment_plans p ON p.id=d.plan_id ORDER BY d.created_at DESC LIMIT 500');
  res.json({deposits:rows.map(d=>({...d,amountUsdt:Number(d.amount_usdt)}))});
}));
app.patch('/api/admin/deposits/:reference', requireAdmin, asyncRoute(async (req,res) => {
  const parsed=reviewSchema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Invalid review action.'});
  const {status,txHash,reviewNote}=parsed.data;
  if(status==='confirmed' && !(txHash||'').trim()) return res.status(400).json({error:'A transaction hash is required before marking a deposit confirmed.'});
  const { rows: current } = await pool.query('SELECT * FROM deposit_requests WHERE reference=$1',[req.params.reference]); if(!current[0]) return res.status(404).json({error:'Deposit request not found.'});
  if(status==='confirmed' && !txHash && !current[0].tx_hash) return res.status(400).json({error:'A transaction hash is required before confirmation.'});
  try {
    const { rows } = await pool.query('UPDATE deposit_requests SET status=$1,tx_hash=COALESCE(NULLIF($2,\'\'),tx_hash),review_note=$3,reviewed_by=$4,reviewed_at=NOW(),updated_at=NOW() WHERE reference=$5 RETURNING reference,status,tx_hash,review_note,updated_at',[status,txHash||'',reviewNote||null,req.session.user.id,req.params.reference]);
    await audit(req,'deposit.reviewed','deposit',req.params.reference,{status,hasTxHash:Boolean(txHash||current[0].tx_hash),note:reviewNote||''}); res.json({deposit:rows[0],notice:status==='confirmed'?'Admin marked this request confirmed. Verify transaction, token contract, network, destination and confirmations independently before doing so.':'Deposit request updated.'});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'That transaction hash is already associated with another request on this network.'}); throw e; }
}));
app.get('/api/admin/networks', requireAdmin, asyncRoute(async (_req,res) => { const {rows}=await pool.query('SELECT network,display_name,public_address,enabled,updated_at FROM network_addresses ORDER BY display_name'); res.json({networks:rows}); }));
app.put('/api/admin/networks/:network', requireAdmin, asyncRoute(async (req,res) => {
  if(!networks.includes(req.params.network)) return res.status(404).json({error:'Unsupported network.'});
  const parsed=addressSchema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Enter a public address and enabled state.'});
  if(parsed.data.enabled && !parsed.data.publicAddress) return res.status(400).json({error:'An address is required to enable deposits.'});
  const {rows}=await pool.query('UPDATE network_addresses SET public_address=$1,enabled=$2,updated_by=$3,updated_at=NOW() WHERE network=$4 RETURNING network,display_name,public_address,enabled,updated_at',[parsed.data.publicAddress,parsed.data.enabled,req.session.user.id,req.params.network]);
  await audit(req,'network.address_updated','network',req.params.network,{enabled:parsed.data.enabled}); res.json({network:rows[0],notice:'Address saved. Independently verify ownership, network, token support and custody/security before enabling real deposits.'});
}));
app.post('/api/admin/bootstrap', asyncRoute(async (req,res) => {
  const token = req.get('x-admin-bootstrap-token');
  if(!process.env.ADMIN_BOOTSTRAP_TOKEN || !token || token !== process.env.ADMIN_BOOTSTRAP_TOKEN) return res.status(403).json({error:'Bootstrap token rejected.'});
  const { rows: admins } = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if(admins.length) return res.status(409).json({error:'An admin already exists. Disable/remove ADMIN_BOOTSTRAP_TOKEN after initial setup.'});
  if(!req.session.user) return res.status(401).json({error:'Register a normal account first, then log in before bootstrapping admin.'});
  const {rows}=await pool.query("UPDATE users SET role='admin',updated_at=NOW() WHERE id=$1 RETURNING id,full_name,email,role,created_at",[req.session.user.id]);
  req.session.user={...publicUser(rows[0])}; await audit(req,'admin.bootstrap','user',rows[0].id); res.json({user:req.session.user,notice:'Admin role assigned. Remove ADMIN_BOOTSTRAP_TOKEN from deployment environment immediately.'});
}));

// Serve a minimal API-connected interface. The older visual prototype is kept separately for reference.
app.use(express.static(path.join(__dirname,'public'), { index: 'index.html', dotfiles:'deny', etag:true, maxAge:isProd?'1h':0 }));
app.use((req,res,next)=>{ if(req.path.startsWith('/api/')) return res.status(404).json({error:'API route not found.'}); next(); });
app.use((err,req,res,_next)=>{ console.error('Request failed:',err.message); res.status(500).json({error:'Unexpected server error.'}); });

async function start(){
  if (process.env.DATABASE_URL && fs.existsSync(path.join(__dirname,'db','schema.sql'))) {
    const schema=fs.readFileSync(path.join(__dirname,'db','schema.sql'),'utf8');
    await pool.query(schema);
  }
  const port=Number(process.env.PORT||3000); app.listen(port,()=>console.log(`BZC server listening on ${port}`));
}
start().catch(err=>{console.error('Startup failed:',err);process.exit(1)});
