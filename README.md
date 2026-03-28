# Edge Secrets

Secure, one-time sharing of passwords and files — built on Cloudflare Workers.

---

## How It Works

### Text Secrets (passwords, credentials)

Encryption happens **entirely in the browser**. The server never sees plaintext data or the encryption key.

```mermaid
sequenceDiagram
    participant S as Sender (Browser)
    participant W as Worker
    participant KV as KV Store
    participant R as Recipient (Browser)

    Note over S: Enter content + passphrase
    S->>S: id = randomUUID()
    S->>S: key = PBKDF2(passphrase, id, 100k iter) → AES-256-GCM key
    S->>S: verifier = PBKDF2(passphrase, id+"_v", 50k iter)
    S->>S: {iv, encryptedData} = AES-GCM.encrypt(content, key)

    S->>W: POST /api/store {id, encryptedData, verifier, ttl}
    W->>KV: put(id, encryptedData, {verifier, attempts:0}, ttl≤7d)
    W-->>S: {success: true}

    S-->>R: /receive/{id}#{passphrase}  ← shared out-of-band

    Note over R: passphrase extracted from URL hash (never sent to server)
    R->>R: verifierCandidate = PBKDF2(passphrase, id+"_v", 50k iter)
    R->>W: POST /api/retrieve/{id} {verifierCandidate}
    W->>KV: getWithMetadata(id)
    KV-->>W: {encryptedData, metadata: {verifier, attempts}}
    W->>W: safeCompare(verifier, verifierCandidate)

    alt wrong passphrase
        W->>KV: put(id, ..., {attempts: attempts+1})
        W-->>R: 403 RETRY_N (or 410 TERMINATED after 3 attempts + delete)
    else correct passphrase
        W->>KV: delete(id)  ← burn on read
        W-->>R: {encryptedData}
        R->>R: key = PBKDF2(passphrase, id, 100k iter)
        R->>R: content = AES-GCM.decrypt(encryptedData, key)
        Note over R: Display → auto-wipe after 5 min
    end
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

Files are **not client-side encrypted** — they go directly to R2. Protection is enforced through:

**Upload (3-step multipart):**

```mermaid
sequenceDiagram
    participant U as Uploader (Browser)
    participant W as Worker
    participant D1 as D1 (metadata)
    participant R2 as R2 (binary)

    U->>W: POST /api/upload/init {filename, size, password, ttl, limit}
    W->>W: safeTtl = min(ttl, 7 days)
    W->>W: password_hash = SHA-256(password + PEPPER)
    W->>D1: INSERT files (id, filename, size, expires_at, password_hash, max_downloads, status="pending")
    W->>R2: createMultipartUpload(id) → uploadId
    W-->>U: {key, uploadId, fileId}

    loop each 50 MB chunk · up to 4 parallel
        U->>W: PUT /api/upload/part?key&id&num + binary chunk
        W->>R2: uploadPart(num, chunk) → partInfo
        W-->>U: partInfo
    end

    U->>W: POST /api/upload/complete {key, uploadId, parts, fileId}
    W->>R2: completeMultipartUpload(parts)
    W->>D1: UPDATE files SET status="ready"
    W-->>U: {ok: true}

    Note over U: Share link: /share/{fileId} or /share/{fileId}?pwd=password
```

**Download:**

```mermaid
sequenceDiagram
    participant R as Recipient
    participant W as Worker
    participant D1 as D1
    participant R2 as R2

    R->>W: GET /share/{id}[?pwd=password]
    W->>D1: SELECT * FROM files WHERE id=?
    D1-->>W: FileRecord

    alt expired or status="downloaded"
        W-->>R: 410 LINK_EXPIRED
    else password set, no ?pwd param
        W-->>R: 200 Password entry page
    else wrong password
        W->>D1: UPDATE failed_attempts++
        alt failed_attempts >= 3
            W->>D1: DELETE file record
            W->>R2: delete(id)
            W-->>R: 410 FILE_DELETED
        else
            W-->>R: 403 INVALID_PASSWORD (remaining attempts)
        end
    else correct password (or no password)
        W->>D1: UPDATE download_count++
        alt download_count >= max_downloads
            W->>D1: UPDATE status="downloaded"
            W-)R2: delete(id)  [async, waitUntil]
        end
        W->>R2: get(id) → stream
        W-->>R: file stream (Content-Disposition: attachment)
    end
```

- Optional password (`SHA-256(password + PEPPER)` — verified server-side)
- Download limit (1×, 5×, or unlimited)
- Server-enforced TTL — maximum 7 days regardless of what the client sends
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
| **No content logging** | Errors return generic messages — no `e.message` leakage |
| **Bindings guard** | Worker returns 500 on startup if any required binding is missing (DB, BUCKET, KV, PEPPER, CF_TEAM_DOMAIN, CF_AUD) |

---

## Architecture

```mermaid
flowchart TD
    Browser -->|protected routes\n/gen, /api/store\n/api/stats, /api/upload/*| CFA[Cloudflare Access\nJWT RS256 verification]
    Browser -->|public routes\n/receive/:id, /share/:id\n/api/retrieve/:id| Worker

    CFA -->|verified request| Worker[Cloudflare Worker\nHono / TypeScript]

    Worker --> KV[(KV Store\nEncrypted text secrets)]
    Worker --> D1[(D1 Database\nFile metadata)]
    Worker --> R2[(R2 Bucket\nFile binaries)]
```

| Resource | Usage |
|---|---|
| **KV** (`SECRETS_STORE`) | Encrypted text secrets + verifier, TTL 1–72 h |
| **D1** (`DB`) | File metadata (name, size, TTL, download count, password hash) |
| **R2** (`BUCKET`) | Raw file data, multipart upload up to 5 GB |

---

## Stack

- **Runtime:** Cloudflare Workers
- **Framework:** [Hono](https://hono.dev) v4
- **Language:** TypeScript (strict)
- **Deploy tool:** Wrangler v4

---

## API Endpoints

| Method | Path | Description | Access |
|---|---|---|---|
| `GET` | `/gen` | Secret & upload creation panel | 🔒 CF Access |
| `POST` | `/api/store` | Save encrypted secret to KV | 🔒 CF Access |
| `POST` | `/api/retrieve/:id` | Retrieve and burn secret | Public |
| `GET` | `/receive/:id` | Secret retrieval page | Public |
| `GET` | `/api/stats` | Storage statistics | 🔒 CF Access |
| `POST` | `/api/upload/init` | Initiate multipart upload | 🔒 CF Access |
| `PUT` | `/api/upload/part` | Upload file part | 🔒 CF Access |
| `POST` | `/api/upload/complete` | Finalize upload | 🔒 CF Access |
| `GET` | `/share/:id` | Download file | Public |
| `DELETE` | `/api/del/:id` | Delete file | Public* |

> *`/api/del` is intentionally outside CF Access.

---

## Deploy

```bash
npm install
npx wrangler deploy
```

### Required `wrangler.toml` Bindings

```toml
[[kv_namespaces]]
binding = "SECRETS_STORE"
id = "<KV_NAMESPACE_ID>"

[[d1_databases]]
binding = "DB"
database_name = "<D1_DATABASE_NAME>"
database_id = "<D1_DATABASE_ID>"

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "<R2_BUCKET_NAME>"
```

### Required Cloudflare Secrets

None of these go into the repo or `wrangler.toml`. The Worker won't start without all three.

```bash
# 1. Global pepper for file password hashes
openssl rand -base64 32
npx wrangler secret put PEPPER

# 2. Cloudflare Access team domain
npx wrangler secret put CF_TEAM_DOMAIN
# → e.g. yourteam.cloudflareaccess.com

# 3. Application Audience (AUD) tag
# Found at: CF Zero Trust → Access → Applications → (app) → Overview → AUD Tag
npx wrangler secret put CF_AUD
```

> **Note:** `CF_AUD` is unique per CF Access application. Without it, JWT verification always returns 401. Make sure you also have an **Access Policy** configured in CF Zero Trust for the protected paths (`/gen`, `/api/store`, `/api/stats`, `/api/upload`).

### Local Development

Create a `.dev.vars` file (git-ignored):

```ini
PEPPER=local-pepper-for-testing-only
CF_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CF_AUD=your-aud-tag
```

> In local dev, requests don't go through CF Access — protected endpoints require a JWT passed manually via the `Cf-Access-Jwt-Assertion` header.

```bash
npx wrangler dev
# → http://localhost:8787
```
