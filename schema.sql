CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name VARCHAR(80) NOT NULL,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(16) NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  selected_plan_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS investment_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug VARCHAR(32) NOT NULL UNIQUE,
  name VARCHAR(80) NOT NULL,
  min_usdt NUMERIC(18,6) NOT NULL CHECK (min_usdt > 0),
  max_usdt NUMERIC(18,6),
  description TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (max_usdt IS NULL OR max_usdt >= min_usdt)
);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_selected_plan_id_fkey;
ALTER TABLE users ADD CONSTRAINT users_selected_plan_id_fkey FOREIGN KEY (selected_plan_id) REFERENCES investment_plans(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS network_addresses (
  network VARCHAR(24) PRIMARY KEY,
  display_name VARCHAR(80) NOT NULL,
  public_address VARCHAR(180),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_by UUID REFERENCES users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deposit_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reference VARCHAR(32) NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES users(id),
  plan_id UUID NOT NULL REFERENCES investment_plans(id),
  network VARCHAR(24) NOT NULL REFERENCES network_addresses(network),
  amount_usdt NUMERIC(18,6) NOT NULL CHECK (amount_usdt > 0),
  tx_hash VARCHAR(180),
  status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','under_review','confirmed','rejected')),
  review_note VARCHAR(500),
  reviewed_by UUID REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS deposit_tx_hash_unique_per_network
  ON deposit_requests(network, tx_hash) WHERE tx_hash IS NOT NULL AND tx_hash <> '';
CREATE INDEX IF NOT EXISTS deposit_requests_user_created_idx ON deposit_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS deposit_requests_status_created_idx ON deposit_requests(status, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id UUID REFERENCES users(id),
  action VARCHAR(80) NOT NULL,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(80),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO investment_plans(slug,name,min_usdt,max_usdt,description)
VALUES
 ('starter','Starter',10,99.999999,'Illustrative entry tier. No return is promised.'),
 ('growth','Growth',100,499.999999,'Illustrative middle tier. No return is promised.'),
 ('advanced','Advanced',500,NULL,'Illustrative higher tier. No return is promised.')
ON CONFLICT(slug) DO NOTHING;

INSERT INTO network_addresses(network,display_name,public_address,enabled) VALUES
 ('TRC20','TRON (TRC20)',NULL,FALSE),
 ('ERC20','Ethereum (ERC20)',NULL,FALSE),
 ('BEP20','BNB Smart Chain (BEP20)',NULL,FALSE),
 ('Polygon','Polygon PoS',NULL,FALSE),
 ('Arbitrum','Arbitrum One',NULL,FALSE),
 ('Optimism','Optimism',NULL,FALSE),
 ('Solana','Solana',NULL,FALSE),
 ('Avalanche','Avalanche C-Chain',NULL,FALSE)
ON CONFLICT(network) DO NOTHING;
