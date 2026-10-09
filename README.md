# BZC production backend starter

This project replaces browser-local demo storage with a Node.js/Express API and PostgreSQL. It includes server-side registration/login (Argon2id password hashes), HTTP-only sessions stored in PostgreSQL, user dashboard endpoints, plan selection, USDT deposit request tracking, network-address configuration, admin review endpoints, rate limiting, origin checks, audit logs, Docker support, and a small API-connected interface.

## Important boundaries

- This is a deployment-ready **starter**, not a security-audited or legally cleared financial product.
- No private keys are stored, no transactions are initiated, and there is no automatic blockchain confirmation or withdrawal system.
- An admin's `confirmed` status is a manual database status, not proof from the blockchain. Independently verify network, token contract, destination, amount, confirmations and duplicate transaction hashes before using it.
- All receiving addresses are disabled and empty by default. The previously supplied address `TY9zt3vTvkYTK3yGc3RZYgAvdbLwRzFfac` is displayed as unverified information only; it is not configured as a deposit destination.
- The Starter/Growth/Advanced plan tiers (10 / 100 / 500 USDT minimums) only categorize requests. No APY, profit or return is promised.
- Before accepting real funds, obtain qualified legal/security review, determine licensing and KYC/AML obligations, add independent chain monitoring and reconciliation, secure wallet custody, backups/monitoring, admin MFA, incident response, accurate terms/privacy disclosures and penetration testing.

## Run locally

1. Install Node.js 20+ and PostgreSQL 14+.
2. Copy `.env.example` to `.env` and set `DATABASE_URL`, `APP_ORIGIN=http://localhost:3000`, `SESSION_SECRET` (32+ random characters), and `ADMIN_BOOTSTRAP_TOKEN` (a separate random secret).
3. Run `npm install`.
4. Run `npm start`. The server applies `db/schema.sql` at startup and serves the UI at `http://localhost:3000`.

For local development, PostgreSQL can use a local connection string. Production database connections should use TLS and restricted credentials. Do not commit `.env` or share secret values in chat.

## First admin setup

1. Register a normal user account through the website and log in.
2. Set `ADMIN_BOOTSTRAP_TOKEN` in the deployment environment before first-admin setup.
3. While logged in, open Admin dashboard, enter the same token, and select **Bootstrap this account as admin**. The endpoint refuses if an admin already exists.
4. Immediately remove `ADMIN_BOOTSTRAP_TOKEN` from the hosting environment and redeploy/restart. Admin MFA is not implemented in this starter; add it before handling real funds.

## Deployment outline (Render + managed PostgreSQL)

A `render.yaml` Blueprint is included to make initial testing easier. It uses free-tier resources, which may sleep or have persistence/availability limits and are **not appropriate for real customer funds**. Select an always-on web service and a persistent managed database plan before any production financial use.

1. Put this folder in a private Git repository you control; do not commit `.env`.
2. Create a managed PostgreSQL database in your hosting provider and copy its internal connection string into the app's `DATABASE_URL` environment variable. Ensure the host supports TLS.
3. Create a Node web service from the repository, build command `npm install`, start command `npm start`, and set Node 20+.
4. Set `NODE_ENV=production`, `APP_ORIGIN` to the exact HTTPS service URL (no trailing slash), `SESSION_SECRET` to a strong random secret, and `ADMIN_BOOTSTRAP_TOKEN` to another unique random secret. The included Render Blueprint uses `AUTO_RENDER_ORIGIN` to validate the generated Render domain; for a custom domain, set `APP_ORIGIN` to that exact HTTPS origin. Set `TRUST_PROXY=true` when running behind a trusted single reverse proxy.
5. Deploy. Visit `/api/health`; it should return `{"ok":true,"service":"bzc-api"}`. Test registration/login and admin bootstrap using non-customer test data.
6. Configure a custom domain and HTTPS, verify the exact `APP_ORIGIN`, test backups/restore and monitoring, and conduct a security review before inviting users.

Hosting providers and their account requirements change. No hosting account was accessed and this project has not been deployed publicly by this build step. A live deployment requires access to an account you control and real environment variables. Never send hosting passwords, database passwords, wallet seed phrases or private keys in chat.

## API routes

- `GET /api/health`, `GET /api/me`, `GET /api/plans`, `GET /api/deposit-addresses`
- `POST /api/register`, `POST /api/login`, `POST /api/logout`
- `POST /api/plan/select`, `GET /api/dashboard`, `POST /api/deposits`
- Admin only: `GET /api/admin/summary`, `GET /api/admin/deposits`, `PATCH /api/admin/deposits/:reference`, `GET /api/admin/networks`, `PUT /api/admin/networks/:network`, one-time `POST /api/admin/bootstrap`

Mutating browser requests must have the exact `Origin` matching `APP_ORIGIN`. Session cookies are HTTP-only, same-site strict, and secure in production.
