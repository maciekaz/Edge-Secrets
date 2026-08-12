-- File sharing metadata. Applied to the `secret-db` D1 database.
--
--   npx wrangler d1 execute secret-db --remote --file schema/001_files.sql
--
-- Timestamps here are epoch MILLISECONDS. The later migrations use seconds;
-- do not copy this convention into them.

CREATE TABLE IF NOT EXISTS files (
  id              TEXT PRIMARY KEY,
  filename        TEXT NOT NULL,
  size            INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  -- 'pending' until the multipart upload completes, then 'ready', then
  -- 'downloaded' once the download limit is spent.
  status          TEXT NOT NULL DEFAULT 'pending',
  -- SHA-256(password | password_salt | PEPPER). NULL when no password is set.
  password_hash   TEXT,
  -- 16 random bytes per row, so identical passwords never share a digest.
  password_salt   TEXT,
  max_downloads   INTEGER NOT NULL DEFAULT 1,
  download_count  INTEGER NOT NULL DEFAULT 0,
  -- Three wrong passwords destroy the file. Incremented atomically.
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  -- End-to-end encrypted uploads. The Argon2id verifier replaces the password
  -- hash entirely; the server holds no key material for these rows.
  encrypted       INTEGER DEFAULT 0,
  verifier        TEXT,
  algo_version    TEXT
);
