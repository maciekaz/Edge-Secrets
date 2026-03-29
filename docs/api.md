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
  "ttl": 86400
}
```

**Response `200`:**
```json
{ "success": true }
```

#### Programmatic usage (Node.js / Web Crypto)

The server stores only ciphertext - **all encryption must happen client-side** before calling this endpoint. The passphrase never leaves the caller; it is embedded in the share URL fragment (`#passphrase`) which browsers never send to the server.

```js
const BASE_URL = 'https://secret.example.com'
const JWT     = 'eyJ...'   // Cf-Access-Jwt-Assertion from your CF Access service token

async function pushSecret(plaintext, passphrase, ttlSeconds = 86400) {
  const enc  = new TextEncoder()
  const id   = crypto.randomUUID()

  // Derive encryption key - PBKDF2 / SHA-256 / 100k iterations
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(id + '_k'), iterations: 100_000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  )

  // Encrypt
  const iv         = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  const encryptedData = JSON.stringify({
    iv: btoa(String.fromCharCode(...iv)),
    d:  btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  })

  // Derive verifier - separate PBKDF2 / 50k iterations / salt = id + "_v"
  const vBase    = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits'])
  const vBits    = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(id + '_v'), iterations: 50_000, hash: 'SHA-256' },
    vBase, 256
  )
  const verifier = btoa(String.fromCharCode(...new Uint8Array(vBits)))

  // Store
  await fetch(`${BASE_URL}/api/v1/admin/secrets`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Cf-Access-Jwt-Assertion': JWT },
    body:    JSON.stringify({ id, encryptedData, verifier, ttl: ttlSeconds }),
  })

  // Share link - passphrase in fragment, never sent to server
  return `${BASE_URL}/receive/${id}#${passphrase}`
}
```

To retrieve programmatically (e.g. in automation), derive the same verifier from the passphrase and call `POST /api/v1/public/secrets/:id/retrieve`, then decrypt locally with the same key derivation in reverse.

---

### Files (Multipart Upload)

#### `POST /api/v1/admin/files/init`
Initiate a multipart upload. Returns the R2 `uploadId` and `key`.

**Request body (JSON):**
```json
{
  "filename": "archive.zip",
  "size": 104857600,
  "password": "optional-password",
  "ttl": 172800000,
  "limit": 1
}
```

**Response `200`:**
```json
{ "key": "uuid", "uploadId": "r2-upload-id", "fileId": "uuid" }
```

**Response `507`** - storage limit exceeded:
```json
{ "error": "STORAGE_LIMIT" }
```

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
Finalize a multipart upload and mark the file as `ready` in D1.

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

---

### Stats

#### `GET /api/v1/admin/stats`
Return storage usage and list of active files.

**Response `200`:**
```json
{
  "used": 10485760,
  "limit": 9663676416,
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
Configure Cloudflare Turnstile protection.

**Request body (JSON):**
```json
{
  "siteKey": "0x4AAAAAAA...",
  "creds": true,
  "files": false
}
```

All fields are optional. Set `siteKey` to `null` to remove it.

**Response `200`:**
```json
{ "ok": true }
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

**Response `403`** - wrong verifier (attempts remaining):
```json
{ "error": "RETRY_2" }
```

**Response `403`** - Turnstile challenge failed:
```json
{ "error": "CHALLENGE_FAILED" }
```

**Response `410`** - max attempts exceeded, secret deleted:
```json
{ "error": "TERMINATED" }
```

**Response `404`** - secret not found or expired:
```json
{ "error": "Link wygasł, lub klucz jest nieprawidłowy" }
```

---

### Files

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
| `GET` | `/ui/config` | Global UI settings (JSON) |
| `GET` | `/ui/logo` | Brand logo from R2 |
| `GET` | `/ui/qr` | Server-rendered SVG QR code (`?d=encodedUrl`) |

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
| 400 | Bad request (missing/invalid params) |
| 401 | Unauthorized (missing or invalid CF Access JWT) |
| 403 | Forbidden (wrong verifier, Turnstile failed) |
| 404 | Not found |
| 410 | Gone (expired or burned) |
| 507 | Insufficient storage |
