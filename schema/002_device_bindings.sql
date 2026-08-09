-- Device-bound secrets (opt-in). Applied to the `secret-db` D1 database.
--
--   npx wrangler d1 execute secret-db --remote --file schema/002_device_bindings.sql
--
-- Why D1 and not KV: claiming a secret has to be atomic. KV has no
-- compare-and-swap and is eventually consistent, so two simultaneous first
-- reads would both observe an unclaimed secret and both bind. The UPDATE ...
-- WHERE bound_hash IS NULL below is what makes exactly one of them win.
--
-- Timestamps here are epoch SECONDS, matching the KV metadata `expiresAt`.
-- Note that `files.expires_at` uses milliseconds; do not copy that convention.

CREATE TABLE IF NOT EXISTS secret_bindings (
  -- Matches the KV key of the secret this binding guards.
  secret_id      TEXT PRIMARY KEY,
  -- What the sender asked for: 'device' | 'webauthn'. Pinned at creation.
  mode           TEXT NOT NULL,
  -- Whether the sender allowed degrading to a cookie-only binding when the
  -- first reader's browser cannot produce a key at all.
  allow_fallback INTEGER NOT NULL DEFAULT 0,
  -- What the first reader actually proved: 'ecdsa' | 'webauthn' | 'cookie'.
  -- NULL until claimed. Once set it is never renegotiated, which is what stops
  -- a later client from asking to be let in with a weaker factor.
  bound_factor   TEXT,
  -- SHA-256 (base64url) of the cookie token. NULL means still unclaimed.
  bound_hash     TEXT,
  -- P-256 public key, SPKI base64url. NULL for cookie-only bindings.
  pubkey         TEXT,
  -- WebAuthn credential id, replayed to the client in allowCredentials.
  cred_id        TEXT,
  -- WebAuthn signature counter. Stays 0 on authenticators that do not keep one.
  sign_count     INTEGER NOT NULL DEFAULT 0,
  bound_at       INTEGER,
  -- Mirrors the secret's own expiry so the cron can drop the row.
  expires_at     INTEGER NOT NULL,
  read_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_secret_bindings_expires
  ON secret_bindings(expires_at);

-- Single-use challenges. Issued when the server asks a client to prove
-- possession, then consumed by an atomic DELETE, so a captured challenge
-- cannot be replayed even inside its short TTL.
CREATE TABLE IF NOT EXISTS bind_nonces (
  nonce      TEXT PRIMARY KEY,
  secret_id  TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bind_nonces_expires
  ON bind_nonces(expires_at);
