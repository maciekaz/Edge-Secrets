# Edge Secrets - API Reference

All API endpoints live under `/api/v1/`. They are split into two zones:

| Zone | Prefix | Access |
|------|--------|--------|
| **Admin** | `/api/v1/admin/` | Protected by Cloudflare Access + RS256 JWT verification |
| **Public** | `/api/v1/public/` | No authentication required |

Cloudflare Access requires only **two rules** to protect the entire application:
- `/gen` - the creation panel
- `/api/v1/admin/*` - all write/admin API operations

> Public UI routes (`/receive/:id`, `/share/:id`, `/s/:id`, `/ui/config`, `/ui/logo`, `/ui/qr`) and public API routes (`/api/v1/public/*`) must remain outside the Access policy.

---

## Admin Zone - `/api/v1/admin/`

All requests in this zone must carry a valid Cloudflare Access JWT in either:
- `Cf-Access-Jwt-Assertion` header, or
- `CF_Authorization` cookie

### Secrets

#### `POST /api/v1/admin/secrets`
Store an encrypted secret in KV.

**Request body (JSON):**
```json
{
  "id": "string",
  "encryptedData": "string",
  "verifier": "string",
  "ttl": 86400,
  "algoVersion": "argon2id-v1"
}
```

- `algoVersion` is optional. Only `argon2id-v1` is accepted today; any other value (or an absent field) is coerced server-side to the current algo, so a tampered client cannot silently pin a secret to a weaker scheme.
- The server additionally records `attempts: 0` and `expiresAt` (absolute epoch seconds) in KV metadata. `expiresAt` is used by the retrieve endpoint to preserve the original TTL across failed verifier attempts (see below).

**Response `200`:**
```json
{ "success": true }
```

#### Programmatic usage (Node.js / browser)

The server stores only ciphertext — **all encryption must happen client-side** before calling this endpoint. The passphrase never leaves the caller; it is embedded in the share URL fragment (`#passphrase`) which browsers never send to the server.

Key derivation uses **Argon2id** (m=19 MiB, t=2, p=1, 32-byte output). Both the AES-GCM encryption key and the server-side verifier are derived from the same passphrase with different salts (`id` and `id + "_v"` respectively). `hash-wasm` is the reference implementation the server ships; any Argon2id library with the same parameters will produce identical output.

```js
import { argon2id } from 'hash-wasm'

const BASE_URL = 'https://secret.example.com'
const JWT     = 'eyJ...'   // Cf-Access-Jwt-Assertion from your CF Access service token

const ARGON2_PARAMS = { parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32 }

async function deriveBytes(passphrase, saltStr) {
  const enc = new TextEncoder()
  return argon2id({
    password: enc.encode(passphrase),
    salt:     enc.encode(saltStr),
    outputType: 'binary',
    ...ARGON2_PARAMS,
  })
}

async function pushSecret(plaintext, passphrase, ttlSeconds = 86400) {
  const enc = new TextEncoder()
  const id  = crypto.randomUUID()

  // Encryption key — Argon2id over (passphrase, id)
  const keyBytes = await deriveBytes(passphrase, id)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  const encryptedData = JSON.stringify({
    iv: btoa(String.fromCharCode(...iv)),
    d:  btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  })

  // Verifier — Argon2id over (passphrase, id + "_v")
  const vBytes   = await deriveBytes(passphrase, id + '_v')
  const verifier = btoa(String.fromCharCode(...vBytes))

  await fetch(`${BASE_URL}/api/v1/admin/secrets`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Cf-Access-Jwt-Assertion': JWT },
    body:    JSON.stringify({ id, encryptedData, verifier, ttl: ttlSeconds, algoVersion: 'argon2id-v1' }),
  })

  return `${BASE_URL}/receive/${id}#${passphrase}`
}
```

To retrieve programmatically (e.g. in automation), derive the same verifier from the passphrase and call `POST /api/v1/public/secrets/:id/retrieve`, then decrypt locally with the same key derivation in reverse.

---

### Files (Multipart Upload)

#### `POST /api/v1/admin/files/init`
Initiate a multipart upload. Two modes, selected by the `encrypted` flag:

- **Normal (server-visible) upload** — the client sends plaintext bytes; the server assigns the `id`, hashes the optional password with a fresh per-file salt, and stores the blob as-is.
- **End-to-end encrypted upload** — the client generates its own UUIDv4 `id`, derives an Argon2id verifier, encrypts the file locally, and uploads the ciphertext. The server stores only the verifier + ciphertext; no password hash, no key material.

**Request body (JSON) — normal:**
```json
{
  "filename": "archive.zip",
  "size": 104857600,
  "password": "optional-password",
  "ttl": 172800000,
  "limit": 1
}
```

**Request body (JSON) — E2EE:**
```json
{
  "id": "client-generated-uuid-v4",
  "filename": "secret.pdf",
  "size": 157286412,
  "encrypted": true,
  "verifier": "base64-argon2id-32B",
  "algoVersion": "argon2id-v1",
  "ttl": 172800000,
  "limit": 1
}
```

For E2EE the server validates `id` against a UUIDv4 regex, rejects collisions (`409`), and enforces that `verifier` length is in `[32, 128]` and `algoVersion === 'argon2id-v1'`. The server coerces any tampered/unknown values to safe defaults — a caller cannot pin a secret to an unsupported scheme.

**Response `200`:**
```json
{ "key": "uuid", "uploadId": "r2-upload-id", "fileId": "uuid" }
```

**Response `400`** — `size` missing, non-numeric, non-finite, or ≤ 0:
```json
{ "error": "INVALID_SIZE" }
```

**Response `413`** — single file exceeds the configured per-file cap (`ui:max_upload_bytes`, default 9 GiB):
```json
{ "error": "UPLOAD_LIMIT" }
```

**Response `413`** — E2EE upload exceeds the hard 150 MiB cap:
```json
{ "error": "E2EE_UPLOAD_LIMIT" }
```

**Response `507`** — would exceed the total-storage cap (`ui:max_storage_bytes`, default 9.5 GiB):
```json
{ "error": "STORAGE_LIMIT" }
```

**Response `409`** — E2EE path only: the client-provided `id` collides with an existing row:
```json
{ "error": "ID collision" }
```

Both caps are admin-controlled via `POST /api/v1/admin/ui/limits` (see below). The server is authoritative — the client's own pre-flight check on `file.size` is UX-only.

---

#### `PUT /api/v1/admin/files/part`
Upload a single part of an ongoing multipart upload.

**Query parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `key` | string | R2 object key (`fileId`) |
| `id` | string | R2 multipart `uploadId` |
| `num` | integer | Part number (1-based) |

**Request body:** raw binary chunk

**Response `200`:** R2 `UploadedPart` object (etag + part number)

---

#### `POST /api/v1/admin/files/complete`
Finalize a multipart upload and mark the file as `ready` in D1. After R2 stitches the parts, the server compares the resulting object's actual size against the value declared at `/files/init` — on mismatch the object and DB row are both deleted. Without this gate a caller could declare `size: 1` at init (slipping past per-file and total-storage caps) and then push arbitrary amounts through `/files/part`.

**Request body (JSON):**
```json
{
  "key": "uuid",
  "uploadId": "r2-upload-id",
  "parts": [{ "partNumber": 1, "etag": "..." }],
  "fileId": "uuid"
}
```

**Response `200`:**
```json
{ "ok": true }
```

**Response `400`** — actual R2 object size differs from the declared size:
```json
{ "error": "SIZE_MISMATCH" }
```

---

### Stats

#### `GET /api/v1/admin/stats`
Return storage usage, current limits, and list of active files.

- `limit` — effective total-storage cap (bytes). Reads `ui:max_storage_bytes` from KV, falls back to the built-in default (9.5 GiB) when unset.
- `maxUpload` — effective per-file cap (bytes). Reads `ui:max_upload_bytes` from KV, falls back to 9 GiB.

**Response `200`:**
```json
{
  "used": 10485760,
  "limit": 10200547328,
  "maxUpload": 9663676416,
  "files": [
    {
      "id": "uuid",
      "filename": "report.pdf",
      "size": 10485760,
      "created_at": 1700000000000,
      "expires_at": 1700172800000,
      "status": "ready",
      "password_hash": null,
      "max_downloads": 1,
      "download_count": 0,
      "failed_attempts": 0
    }
  ]
}
```

---

### Links (URL Shortener)

#### `POST /api/v1/admin/links`
Create a short link with optional TTL and click limit.

**Request body (JSON):**
```json
{
  "url": "https://example.com/long-path",
  "ttl": 86400,
  "maxClicks": 10
}
```

- `ttl`: seconds; `-1` = no expiry; clamped to `[3600, 604800]`
- `maxClicks`: `-1` = unlimited; clamped to `[1, 10000]`

**Response `200`:**
```json
{ "id": "aBcDeFg", "shortUrl": "https://secret.example.com/s/aBcDeFg" }
```

---

### UI Configuration

#### `POST /api/v1/admin/ui/config`
Update global appearance settings.

**Request body (JSON):**
```json
{
  "accent": "#818cf8",
  "bg": "#000000",
  "brand": "My Company",
  "tagline": "Secure sharing"
}
```

All fields are optional. `brand` and `tagline` accept `null` to clear them.
- `accent` / `bg`: must match `#RRGGBB`
- `brand`: max 32 chars
- `tagline`: max 60 chars

**Response `200`:**
```json
{ "ok": true }
```

---

#### `POST /api/v1/admin/ui/turnstile`
Configure Cloudflare Turnstile protection. The three per-feature toggles are independent — `files` and `filesE2ee` especially, so an admin can force a challenge on client-encrypted downloads while leaving automation flows on plain files untouched (or vice versa).

**Request body (JSON):**
```json
{
  "siteKey": "0x4AAAAAAA...",
  "creds": true,
  "files": false,
  "filesE2ee": true
}
```

All fields are optional. Set `siteKey` to `null` to remove it. KV keys written: `ui:turnstile_site_key`, `ui:turnstile_creds`, `ui:turnstile_files`, `ui:turnstile_files_e2ee`.

**Response `200`:**
```json
{ "ok": true }
```

---

#### `POST /api/v1/admin/ui/limits`
Update the storage caps used by `/api/v1/admin/files/init` and surfaced on `/api/v1/admin/stats` + `/ui/config`. Values are provided in GB (binary: 1 GB = 1024³ bytes) and stored in KV as exact byte counts.

**Request body (JSON):**
```json
{
  "maxStorageGb": 9.5,
  "maxUploadGb": 9
}
```

**Validation:**
- Both fields are required, must be finite positive numbers.
- Each is capped at **50 GB** server-side — a deliberate safety rail against a typo silently opening a large R2 bill. Raise this in code if you genuinely need more.
- `maxUploadGb` must not exceed `maxStorageGb`.
- The admin UI additionally gates anything above the 10 GiB Cloudflare R2 free tier behind an `OKAY` typed-confirmation modal (uppercase, English, identical across all locales).

**Response `200`:**
```json
{ "ok": true }
```

**Response `400`** — one of the validation rules above failed:
```json
{ "error": "Value too large (max 50 GB)" }
```

---

#### `POST /api/v1/admin/ui/logo`
Upload the brand logo. Body is the raw image binary.

**Headers:**
- `Content-Type`: `image/png` | `image/svg+xml` | `image/jpeg` | `image/webp`

**Constraints:** max 256 KB

**Response `200`:**
```json
{ "ok": true }
```

---

#### `DELETE /api/v1/admin/ui/logo`
Remove the brand logo from R2.

**Response `200`:**
```json
{ "ok": true }
```

---

## Public Zone - `/api/v1/public/`

No authentication required. Turnstile may apply depending on KV settings.

### Secrets

#### `POST /api/v1/public/secrets/:id/retrieve`
Retrieve and burn an encrypted secret. Verifier is checked before returning ciphertext.

**Path parameter:** `id` - secret ID

**Request body (JSON):**
```json
{
  "verifierCandidate": "string",
  "cfTurnstileToken": "optional-token"
}
```

**Response `200`:**
```json
{ "encryptedData": "base64-json-blob" }
```

**Response `403`** — wrong verifier (attempts remaining). The secret's original expiration is preserved across failed attempts — a bad guess increments `attempts` in KV metadata but does **not** slide the TTL forward.
```json
{ "error": "RETRY_2" }
```

**Response `403`** — Turnstile challenge failed:
```json
{ "error": "CHALLENGE_FAILED" }
```

**Response `410`** — secret deleted. Either the 3-attempt limit was hit, or a bad attempt arrived with < 60 s of TTL remaining (KV's minimum `expirationTtl`) and the server chose to burn the record rather than extend it.
```json
{ "error": "TERMINATED" }
```

**Response `404`** — secret not found or expired:
```json
{ "error": "Link wygasł, lub klucz jest nieprawidłowy" }
```

---

### Files

#### `POST /api/v1/public/files/:id/retrieve-ciphertext`
Retrieve the ciphertext of an end-to-end-encrypted file. The server verifies the Argon2id verifier (same pattern as the secrets retrieve endpoint), decrements the download counter (burn on limit), and streams the R2 object body as `application/octet-stream`. The caller strips the 12-byte IV prefix from the response and decrypts locally — the server never sees the key or the plaintext.

**Path parameter:** `id` — file ID (UUIDv4, set by the client at `/files/init`)

**Request body (JSON):**
```json
{
  "verifierCandidate": "base64-argon2id-32B",
  "cfTurnstileToken": "optional-token"
}
```

**Response `200`:** raw ciphertext stream (`Content-Type: application/octet-stream`). First 12 bytes are the AES-GCM IV, rest is the encrypted payload + 16-byte auth tag.

**Response `403`** — wrong verifier. The file's `failed_attempts` counter is bumped atomically with `UPDATE … RETURNING` so parallel attempts cannot race past the cap:
```json
{ "error": "RETRY_2" }
```

**Response `403`** — Turnstile challenge failed (only if `ui:turnstile_files_e2ee` is enabled — this is a separate toggle from the normal-files Turnstile, so admins can force a challenge on E2EE without breaking automation on non-encrypted uploads):
```json
{ "error": "CHALLENGE_FAILED" }
```

**Response `404`** — no such file, or the row exists but is not E2EE (`encrypted != 1`):
```json
{ "error": "NOT_FOUND" }
```

**Response `410`** — either the 3-attempt cap was reached (burn), or the file was already expired / downloaded:
```json
{ "error": "TERMINATED" }
```
or
```json
{ "error": "EXPIRED" }
```

---

#### `DELETE /api/v1/public/files/:id`
Delete a file from R2 and D1. Intentionally outside CF Access - used by the uploader immediately after generating a link if they choose to revoke it.

**Path parameter:** `id` - file ID (UUID)

**Response `200`:**
```json
{ "ok": true }
```

---

## Public UI Routes (not under `/api/`)

These routes are HTML pages or static assets and must remain outside CF Access:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/receive/:id` | Secret retrieval page |
| `GET` | `/share/:id` | File download / Turnstile gate |
| `POST` | `/share/:id` | File download form submission (Turnstile + password) |
| `GET` | `/s/:id` | Short-link redirect |
| `GET` | `/ui/config` | Global UI settings — accent, bg, brand, tagline, all three Turnstile flags (`turnstileCreds` / `turnstileFiles` / `turnstileFilesE2ee`), current storage caps (`maxStorageGb`, `maxUploadGb`, `freeTierGb`), and the fixed E2EE cap (`e2eeMaxUploadMb`) |
| `GET` | `/ui/logo` | Brand logo from R2 |
| `GET` | `/ui/qr` | Server-rendered SVG QR code (`?d=encodedUrl`) |
| `GET` | `/ui/argon2.v1.js` | Bundled hash-wasm Argon2id module. `immutable` cached; same-origin delivery so no external CDN enters the CSP. Bump the version suffix (`v1` → `v2`) when swapping implementations |
| `GET` | `/ui/app.v1.js` | Main client application bundle — **the only executable script on any page**. Contains the JSON-island reader, crypto helpers (`derive`, upload / decrypt pipelines), all form handlers, and the global event delegator that dispatches `data-click` / `data-change` / `data-input` / `data-submit` attributes to named actions. Served with `Cache-Control: public, max-age=60` so deploys propagate within a minute. Bump the version suffix if a breaking change requires immediate cache invalidation |

---

## Error format

All JSON errors follow:
```json
{ "error": "MACHINE_READABLE_CODE_OR_MESSAGE" }
```

HTTP status codes used:
| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (missing/invalid params, `INVALID_SIZE`) |
| 401 | Unauthorized (missing or invalid CF Access JWT) |
| 403 | Forbidden (wrong verifier, Turnstile failed) |
| 404 | Not found |
| 410 | Gone (expired, burned, or `TERMINATED`) |
| 409 | Conflict (client-provided UUID already exists — E2EE `/files/init`) |
| 413 | Payload too large (`UPLOAD_LIMIT` — non-E2EE file exceeds per-file cap; `E2EE_UPLOAD_LIMIT` — E2EE file exceeds the 150 MiB ceiling) |
| 507 | Insufficient storage (`STORAGE_LIMIT` — total cap exceeded) |
