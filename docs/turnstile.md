# Turnstile — Bot & Brute-Force Protection

Cloudflare Turnstile adds an invisible (managed) security challenge to protect secret retrieval and file downloads from bots and brute-force attacks. It can be enabled independently for each receiver type from the `/gen` settings panel.

---

## Where the challenge appears

| Route | With Turnstile enabled |
|---|---|
| `/receive/:id` | Challenge widget appears **at the button** (DECRYPT / OPEN MESSAGE). Button stays disabled until challenge passes. After passing, it either enables the button (manual mode) or auto-decrypts (auto mode with hash in URL). |
| `/share/:id` | Challenge gate page shown for **all downloads** — both password-protected and public files (Option B). |

---

## Option B — files without a password

When Turnstile is enabled for files (`ui:turnstile_files = "1"`), every file download goes through a challenge gate regardless of whether the file has a password or not.

```
GET /share/:id
  └─ Turnstile active → gate page (challenge + optional password field)
       └─ User passes challenge → form POSTs to /share/:id
            └─ Server verifies token → check password (if any) → stream file
```

Files without a password but with Turnstile active:
- Show gate page with Turnstile widget only (no password field)
- After challenge passes → form auto-submits → file downloads immediately

Files with a password and Turnstile active:
- Show gate page with Turnstile widget + password field
- Challenge must pass first (button disabled until then)
- After challenge + correct password → file downloads

---

## Setup

### 1. Create a Turnstile site on Cloudflare

1. Go to **Cloudflare Dashboard → Turnstile**
2. Create a new site — choose **Managed** challenge type
3. Add your domain (e.g. `secret.sentrivo.pl`)
4. Copy the **Site Key** (public) and **Secret Key** (server-side)

### 2. Store the secret key as a Cloudflare Secret

The secret key must never appear in code or `wrangler.toml`:

```bash
npx wrangler secret put TURNSTILE_SECRET
# Paste your Turnstile secret key when prompted
```

### 3. Configure site key and toggles from the panel

Open `/gen` → click the ⚙ settings icon → scroll to the **TURNSTILE** section:

| Field | Description |
|---|---|
| **Site Key** | Your public Turnstile site key (e.g. `0x4AAAAAAA...`) |
| **Protect secret retrieval** | Enable challenge on `/receive/:id` |
| **Protect file downloads** | Enable challenge on `/share/:id` (Option B for all files) |

Click **SAVE** in the Turnstile section.

The site key is stored in KV (`ui:turnstile_site_key`) and embedded in HTML — it is public by design. The secret key stays in Cloudflare Secrets and is never exposed to clients.

---

## How the server verifies tokens

Every token is verified against `https://challenges.cloudflare.com/turnstile/v1/siteverify` **before** any KV, D1, or R2 access. A failed challenge returns `403` — the brute-force attempt counter in KV/D1 is never incremented.

```
POST /api/retrieve/:id
  body: { verifierCandidate, cfTurnstileToken }
  → verifyTurnstile(token, TURNSTILE_SECRET)  ← server-side, before KV read
  → verifier check → burn on read

POST /share/:id
  form: { cf-turnstile-response, pwd? }
  → verifyTurnstile(token, TURNSTILE_SECRET)  ← before D1/R2 access
  → password check → stream file
```

---

## Safety notes

- If `TURNSTILE_SECRET` is not set as a Cloudflare Secret, Turnstile is treated as **disabled** even if the KV toggle is `"1"`. This prevents lockout during initial setup.
- Tokens are **one-time use**. A wrong password after a valid challenge redirects to `GET /share/:id` for a fresh challenge.
- The challenge appears **at the action button**, not on a separate page for secrets — the password field remains visible so users can prepare before solving the challenge.

---

## Local development

In local dev (`wrangler dev`), add `TURNSTILE_SECRET` to `.dev.vars`:

```ini
TURNSTILE_SECRET=your-turnstile-secret-key
```

For testing without a real challenge, use Cloudflare's test keys:
- Site key: `1x00000000000000000000AA` (always passes)
- Secret key: `1x0000000000000000000000000000000AA` (always succeeds in siteverify)
