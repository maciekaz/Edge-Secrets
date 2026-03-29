# Edge Secrets

Secure, one-time sharing of passwords, files and links - built on Cloudflare Workers.

## Features

| Feature | Details |
|---|---|
| **Text secrets** | Zero-knowledge credential sharing - AES-256-GCM, passphrase in URL hash, burn-on-read |
| **File sharing** | Up to 5 GB via R2, optional password, download limit, server-enforced TTL |
| **URL shortener** | Short links with TTL and click limit, SSRF-safe |
| **Appearance editor** | Accent colour, background colour, brand name, tagline, logo - all globally persistent |
| **Dark / light mode** | System-detected per client, manually overridable |
| **QR codes** | Server-rendered SVG QR on every output link - scan directly from desktop |
| **CF Access** | All write/admin endpoints protected by Cloudflare Access + RS256 JWT verification |
| **Internationalisation** | 8 languages, auto-detected per user, flag picker in the UI |
| **REST API** | Versioned `/api/v1/` - admin zone (`/api/v1/admin/*`) protected by CF Access, public zone (`/api/v1/public/*`) open; full docs in [docs/api.md](docs/api.md) |

> **$0 to run.** The entire stack - Workers, KV, D1, R2, and Cloudflare Access (up to 50 users) - runs on Cloudflare's free tier. No credit card required, no infrastructure to manage. You only start paying if you exceed the free-tier request limits, which for a self-hosted internal tool is unlikely.

---

## Internationalisation (i18n)

All UI text is managed in `src/i18n.ts` - a self-contained module with no external dependencies.

### Supported languages

| Code | Language |
|------|----------|
| `en` | English (default) |
| `pl` | Polski |
| `de` | Deutsch |
| `fr` | Français |
| `es` | Español |
| `uk` | Українська |
| `pt` | Português |
| `zh` | 中文 (Simplified) |

### Language resolution - per user, not global

Each user's language is resolved independently on every request. Priority order:

1. **Cookie `lang`** - set when the user picks a language via the flag picker (stored for 1 year, `SameSite=Lax`). This is the highest priority and persists across sessions.
2. **`Accept-Language` header** - automatic browser locale, parsed and matched against supported codes.
3. **Default: English** - used when neither source yields a supported code.

Changing the language via the picker only affects the requesting user's browser - it has no effect on other users.

### Flag picker

A small flag button appears in the top-left corner of every page (next to the dark/light mode toggle). Clicking it opens a dropdown with all supported languages. Selecting one sets the `lang` cookie and reloads the page.

### How to add your own language

1. Open `src/i18n.ts`.
2. Add the new code to the `LangCode` union type:
   ```ts
   export type LangCode = 'en' | 'pl' | 'de' | 'fr' | 'es' | 'uk' | 'pt' | 'zh' | 'xx'
   ```
3. Add a full `Translations` object under the new key in the `I18N` record (~95 keys).
4. Add an entry to `LANG_OPTIONS` in the same file:
   ```ts
   { code: 'xx', flag: '🇽🇽', name: 'Language name' }
   ```
5. Deploy - no other files need to change.
---

## How It Works

### Text Secrets (passwords, credentials)

Encryption happens **entirely in the browser**. The server never sees plaintext data or the encryption key.

```mermaid
sequenceDiagram
    participant S as Sender
    participant Server
    participant R as Recipient

    S->>S: encrypt(content, passphrase) → ciphertext
    S->>Server: store ciphertext + verifier hash
    S-->>R: /receive/{id}#passphrase

    Note over Server,R: passphrase is in the URL hash - browsers never send it to the server

    R->>Server: retrieve (verifier hash only)
    Server->>Server: verify → delete (burn on read)
    Server-->>R: ciphertext only

    R->>R: decrypt(ciphertext, passphrase from URL hash)
```

**What the server knows:** encrypted bytes + a password verification hash.
**What the server never knows:** the content, the encryption key, or the passphrase itself.

#### Cryptography Details

| Element | Algorithm | Parameters |
|---|---|---|
| Key derivation | PBKDF2 | SHA-256, 100,000 iterations |
| Encryption | AES-GCM | 256-bit, random IV (12 B) |
| Password verifier | PBKDF2 | SHA-256, 50,000 iterations, salt `id + "_v"` |
| Link entropy (with passphrase) | 20-char key, 58-char alphabet | ~118 bits |

---

### Files

Files are **not client-side encrypted** - they go directly to R2. Protection is enforced through:

```mermaid
flowchart LR
    U([Uploader]) -->|file + password + TTL + limit| W[Worker]
    W -->|binary| R2[(R2)]
    W -->|metadata + SHA-256 password hash| D1[(D1)]
    W -->|share link| U

    R([Recipient]) -->|GET /share/id| W
    W -->|check password · TTL · download limit| W
    W -->|file stream| R
    W -.->|burn when limit reached| R2
```

- Optional password (`SHA-256(password + PEPPER)` - verified server-side)
- Download limit (1×, 5×, or unlimited)
- Server-enforced TTL - maximum 7 days regardless of what the client sends
- Automatic deletion on expiry (hourly cron)
- Lockout after 3 failed password attempts → file deleted immediately

#### Global Pepper

File passwords are hashed as `SHA-256(password + PEPPER)`, where `PEPPER` is a global secret stored as a Cloudflare Secret (not in code, not in the repo). Even if the D1 database leaks, the password hashes are useless without the pepper.

```mermaid
flowchart LR
    P[User password] --> H[SHA-256]
    K[PEPPER\nCloudflare Secret] --> H
    H --> DB[(Hash stored in D1)]
```

The Worker refuses to start if `PEPPER` is not set (`bindings guard`).

---

## Security

| Measure | Description |
|---|---|
| **Burn-on-read** | Secret deleted from KV on first successful retrieval |
| **Rate limiting** | Max 3 attempts; permanent deletion on lockout (secrets & files) |
| **Global Pepper** | File password hashes include a server-side secret; D1 leak doesn't compromise passwords |
| **Server-side TTL cap** | Backend enforces maximum lifetime; client cannot exceed it |
| **CF Access + JWT verification** | Protected endpoints guarded at two layers: Cloudflare Access policy + in-Worker RS256 JWT verification against JWKS endpoint (cached 1 h) |
| **Security headers** | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **RFC 5987 filenames** | Safe percent-encoded `Content-Disposition` filenames (no header injection) |
| **No content logging** | Errors return generic messages - no `e.message` leakage |
| **Bindings guard** | Worker returns 500 on startup if any required binding is missing (DB, BUCKET, KV, PEPPER, CF_TEAM_DOMAIN, CF_AUD) |
| **Turnstile** | Optional Cloudflare Turnstile (managed challenge) on secret retrieval and file downloads - blocks bots and brute-force before any KV/D1/R2 access; token bound to visitor IP via `remoteip`; failed challenge never increments the attempt counter. See [docs/turnstile.md](docs/turnstile.md). |

---

## Architecture

```mermaid
flowchart TD
    Browser -->|protected routes\n/gen\n/api/v1/admin/*| CFA[Cloudflare Access\nJWT RS256 verification]
    Browser -->|public routes\n/receive/:id, /share/:id\n/api/v1/public/*\n/ui/config, /ui/logo| Worker

    CFA -->|verified request| Worker[Cloudflare Worker\nHono / TypeScript]

    Worker --> KV[(KV Store\nEncrypted text secrets)]
    Worker --> D1[(D1 Database\nFile metadata)]
    Worker --> R2[(R2 Bucket\nFile binaries)]
```

| Resource | Usage |
|---|---|
| **KV** (`SECRETS_STORE`) | Encrypted text secrets + verifier, short links, global UI config (accent, bg, brand, tagline) |
| **D1** (`DB`) | File metadata (name, size, TTL, download count, password hash) |
| **R2** (`BUCKET`) | Raw file data (multipart upload up to 5 GB) + logo image |

---

## Stack

- **Runtime:** Cloudflare Workers
- **Framework:** [Hono](https://hono.dev) v4
- **Language:** TypeScript (strict)
- **Deploy tool:** Wrangler v4
- **QR codes:** [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) - server-side SVG rendering

---

## API Endpoints

API endpoints are grouped under `/api/v1/` in two zones. Cloudflare Access needs only **two rules**: `/gen` and `/api/v1/admin/*`.

### Admin Zone - `/api/v1/admin/` (🔒 CF Access)

| Method | Path | Description |
|---|---|---|
| `GET` | `/gen` | Secret & upload creation panel |
| `POST` | `/api/v1/admin/secrets` | Save encrypted secret to KV |
| `GET` | `/api/v1/admin/stats` | Storage statistics + file list |
| `POST` | `/api/v1/admin/files/init` | Initiate multipart upload |
| `PUT` | `/api/v1/admin/files/part` | Upload file part |
| `POST` | `/api/v1/admin/files/complete` | Finalize upload |
| `POST` | `/api/v1/admin/links` | Create short link (TTL + click limit) |
| `POST` | `/api/v1/admin/ui/config` | Update global UI settings |
| `POST` | `/api/v1/admin/ui/turnstile` | Update Turnstile settings |
| `POST` | `/api/v1/admin/ui/logo` | Upload logo (PNG/SVG/WebP, max 256 KB) |
| `DELETE` | `/api/v1/admin/ui/logo` | Remove logo |

### Public Zone - `/api/v1/public/` (No auth)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/public/secrets/:id/retrieve` | Retrieve and burn secret |
| `DELETE` | `/api/v1/public/files/:id` | Delete file (uploader self-service) |

### Public UI Routes (No auth)

| Method | Path | Description |
|---|---|---|
| `GET` | `/receive/:id` | Secret retrieval page |
| `GET` | `/share/:id` | File download / Turnstile gate |
| `GET` | `/s/:id` | Redirect to target URL |
| `GET` | `/ui/config` | Read global UI settings (accent, bg, brand, tagline) |
| `GET` | `/ui/logo` | Serve logo image from R2 |
| `GET` | `/ui/qr` | Generate QR code SVG for a given URL (`?d=encodedUrl`) |

> Full request/response documentation: [docs/api.md](docs/api.md)
>
> `/api/v1/public/files/:id` (DELETE) is intentionally outside CF Access - used by the uploader to self-revoke a link.
> `/ui/config` and `/ui/logo` (GET) are outside `/api/v1/` so CF Access policies don't block public clients.

---

## Deploy

### 1. Clone and install

```bash
git clone https://github.com/maciekaz/edge-secrets
cd edge-secrets
npm install
```

### 2. Configure `wrangler.toml`

Copy the example config and fill in your values:

```bash
cp wrangler.example.toml wrangler.toml
```

`wrangler.toml` is git-ignored - your account ID and resource IDs stay local.

#### Create Cloudflare resources

```bash
# KV namespace
npx wrangler kv namespace create SECRETS_STORE
# → copy the returned id into wrangler.toml

# D1 database
npx wrangler d1 create secret-db
# → copy the returned database_id into wrangler.toml

# R2 bucket is auto-provisioned on first deploy
```

#### Initialize D1 schema

```bash
npx wrangler d1 execute secret-db --remote --command \
  "CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    password_hash TEXT,
    max_downloads INTEGER NOT NULL DEFAULT 1,
    download_count INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0
  );"
```

### 3. Set Cloudflare Secrets

None of these go into the repo or `wrangler.toml`. The Worker won't start without all three.

```bash
# 1. Global pepper for file password hashes (generate a random one)
echo "$(openssl rand -base64 32)" | npx wrangler secret put PEPPER

# 2. Cloudflare Access team domain
npx wrangler secret put CF_TEAM_DOMAIN
# → e.g. yourteam.cloudflareaccess.com

# 3. Application Audience (AUD) tag
# Found at: CF Zero Trust → Access → Applications → (app) → Overview → AUD Tag
npx wrangler secret put CF_AUD
```

> Make sure you have a CF Zero Trust **Access Policy** configured for only **two paths**: `/gen` and `/api/v1/admin/*`. Do **not** include `/ui/config`, `/ui/logo`, `/ui/qr`, `/s/`, or `/api/v1/public/*` - these must remain public.

### 4. Deploy

```bash
npx wrangler deploy
```

---

### Local Development

Create a `.dev.vars` file (git-ignored):

```ini
PEPPER=local-pepper-for-testing-only
CF_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CF_AUD=your-aud-tag
```

> In local dev, requests don't go through CF Access - protected endpoints require a JWT passed manually via the `Cf-Access-Jwt-Assertion` header.

```bash
npx wrangler dev
# → http://localhost:8787
```
