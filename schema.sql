CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS wallets (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asset TEXT NOT NULL,
  network TEXT NOT NULL,
  deposit_address TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, asset, network),
  UNIQUE(deposit_address, network)
);
CREATE TABLE IF NOT EXISTS deposits (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wallet_id BIGINT REFERENCES wallets(id),
  asset TEXT NOT NULL,
  network TEXT NOT NULL,
  amount NUMERIC(30,12) NOT NULL CHECK(amount > 0),
  tx_hash TEXT NOT NULL,
  confirmations INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','rejected')),
  provider_event_id TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confirmed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ledger_entries (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asset TEXT NOT NULL,
  amount NUMERIC(30,12) NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal','arbitrage_profit','arbitrage_loss','adjustment')),
  reference_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(type, reference_id)
);
CREATE INDEX IF NOT EXISTS deposits_user_idx ON deposits(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ledger_user_idx ON ledger_entries(user_id, asset, created_at DESC);
