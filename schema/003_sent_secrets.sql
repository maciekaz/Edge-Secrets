-- Sender-side ledger for secrets. Applied to the `secret-db` D1 database.
--
--   npx wrangler d1 execute secret-db --remote --file schema/003_sent_secrets.sql
--
-- Holds no secret material: no verifier, ciphertext, passphrase or fragment.
--
-- `owner_hash` is HMAC-SHA256(PEPPER, 'owner:' || <CF Access subject>), never
-- the address, so a dump cannot be joined against the Access user directory and
-- an e-mail change does not orphan anything.
--
-- Timestamps are epoch SECONDS, matching KV metadata and the binding tables.
-- Note that `files.expires_at` uses milliseconds; do not copy that convention.

CREATE TABLE IF NOT EXISTS sent_secrets (
  -- Matches the KV key. Safe to show its owner: without the passphrase, which
  -- lives only in the URL fragment, an identifier decrypts nothing.
  secret_id       TEXT PRIMARY KEY,
  owner_hash      TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  -- Mirrors the secret's own expiry.
  expires_at      INTEGER NOT NULL,
  -- Later than expires_at, so "nobody ever opened this" outlives the secret.
  purge_at        INTEGER NOT NULL,
  bind_mode       TEXT,
  -- 'pending' | 'opened' | 'revoked' | 'forgotten' | 'burned'. A lapsed row
  -- still reads 'pending'; the API reports it as expired from the clock.
  status          TEXT NOT NULL DEFAULT 'pending',
  first_opened_at INTEGER,
  last_opened_at  INTEGER,
  open_count      INTEGER NOT NULL DEFAULT 0,
  -- Three wrong passphrases destroy the secret, so non-zero is worth surfacing.
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  revoked_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sent_secrets_owner
  ON sent_secrets(owner_hash, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sent_secrets_purge
  ON sent_secrets(purge_at);
