# Edge Secrets

Secure, one-time sharing of passwords, files and links - built on Cloudflare Workers.
<img width="1280" height="684" alt="image" src="https://github.com/user-attachments/assets/a39e4cf2-01ba-4a8c-9f36-42dada1c6c9f" />

## Quick deployment

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/maciekaz/edge-secrets)

(Read instructions at the end of this page!)

## Features

| Feature | Details |
|---|---|
| **Text secrets** | Zero-knowledge credential sharing - AES-256-GCM, Argon2id key derivation, passphrase in URL hash, burn-on-read |
| **File sharing** | R2-backed, per-file and total caps admin-configurable in Appearance (defaults 9 GB / 9.5 GB, hard ceiling 50 GB), optional password, download limit, server-enforced TTL |
| **E2EE file sharing** | Opt-in client-side AES-GCM + Argon2id for files up to 150 MiB. Server stores ciphertext only; passphrase travels in the URL fragment (or out-of-band) and never hits the server |
| **Device-bound secrets** | Opt-in per secret. The link keeps working after the first read, but only from the browser or security key that opened it first. Lifetime configurable up to 30 days |
| **Password generator standards** | Pick the standard the target system actually demands: NIST SP 800-63B, a memorable passphrase from the EFF Long or BIP-39 wordlist, legacy corporate character-class rules, or a 256/512-bit Base64 API key. Entropy is stated for each |
| **Sent-secret ledger** | Each sender sees the secrets they created, whether anyone opened them, and how many times. Scoped to the signed-in CF Access identity, so senders never see each other's entries |
| **Revocation** | A sender can destroy any secret they created, at any time, from the panel. A recipient of a device-bound secret can destroy it early from the retrieval page |
| **URL shortener** | Short links with TTL and click limit, SSRF-safe, unbiased ID generation |
| **Appearance editor** | Accent colour, background colour, brand name, tagline, logo, storage limits - all globally persistent |
| **Dark / light mode** | System-detected per client, manually overridable |
| **Drag-and-drop** | Full-screen dim overlay on the files tab; drops a file straight into the upload form |
| **QR codes** | SVG QR on every output link - scan directly from desktop. Rendered in the browser, so the link never has to be handed to the Worker to be drawn |
| **Hold-to-reveal** | The decrypted secret is masked by default on the retrieval screen. It is shown only while the reveal button is held, and copying to the clipboard works without revealing anything |
| **CF Access** | All write/admin endpoints protected by Cloudflare Access + RS256 JWT verification |
| **Internationalisation** | 9 languages, auto-detected per user, flag picker in the UI |
| **REST API** | Versioned `/api/v1/` - admin zone (`/api/v1/admin/*`) protected by CF Access, public zone (`/api/v1/public/*`) open; full docs in [docs/api.md](docs/api.md) |

> **$0 to run.** The entire stack - Workers, KV, D1, R2, and Cloudflare Access (up to 50 users) - runs on Cloudflare's free tier. No credit card required, no infrastructure to manage. You only start paying if you exceed the free-tier request limits, which for a self-hosted internal tool is unlikely.

---

## Why Secrets on Edge?

Running a secrets tool on Cloudflare Workers is not just a cost decision - it changes what the tool can actually do.

**Globally fast, always.** Workers run in 300+ locations worldwide. Whether your recipient is in Warsaw, Singapore, or San Escobar, the secret is served from the nearest edge node - no single-region latency, no cold starts, no load balancers to manage.

**No servers, no attack surface.** There is no VM to patch, no open SSH port, no container to harden. The entire runtime is ephemeral and managed by Cloudflare. Your only security responsibility is the application code itself.

**Native CI/CD integration.** Because everything is behind a versioned REST API (`/api/v1/`), injecting secrets into pipelines is trivial. A GitHub Actions step, a GitLab CI job, or a shell script can push a one-time credential to a recipient without any human in the loop - authenticated via a Cloudflare Access service token, burned on first read which can be used also by machine.

**Scales to zero, scales to bursts.** Idle periods cost nothing. Traffic spikes are absorbed automatically by Cloudflare's infrastructure - no autoscaling groups, no capacity planning.

**Edge-native storage.** KV, D1, and R2 are co-located with the Worker. Secret retrieval, file streaming, and metadata lookups all happen without leaving the Cloudflare network.

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
| `cs` | Čeština |


### How to add your own language

1. Open `src/i18n.ts`.
2. Add the new code to the `LangCode` union type:
   ```ts
   export type LangCode = 'en' | 'pl' | 'de' | 'fr' | 'es' | 'uk' | 'pt' | 'zh' | 'cs' | 'xx' 
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
| Key derivation | Argon2id | m=19 MiB, t=2, p=1, 32-byte output |
| Encryption | AES-GCM | 256-bit, random IV (12 B) |
| Password verifier | Argon2id | Same params, salt `id + "_v"` |
| Link entropy (with passphrase) | 20-char key, 58-char alphabet | ~118 bits |

**Why Argon2id:** PBKDF2 is GPU-friendly - a single RTX 4090 can try ~100-200 guesses/s against each stored verifier. Argon2id is memory-hard (19 MiB per hash), which forces attackers to trade GPU parallelism for memory bandwidth and drops the same attack to ~1-10 guesses/s per GPU. It won the 2015 Password Hashing Competition and is the OWASP and NIST default for new systems.

**Delivery:** the Argon2id WebAssembly implementation ([hash-wasm](https://www.npmjs.com/package/hash-wasm)) is bundled into the Worker and served at `/ui/argon2.v1.js` - same-origin only, `immutable` cached. No external CDN. The Worker itself never runs Argon2id: key derivation stays client-side, so the ~300-500 ms (desktop) / ~2-3 s (mobile) cost is the browser's, not the Worker's CPU budget.

**Versioned verifier:** each stored secret carries an `algoVersion` field in its KV metadata. This lets a future `argon2id-v2` (stronger params) roll out without breaking in-flight secrets - the client derives with whatever algo the server says the record was written with.

---

#### Device-bound secrets (opt-in)

By default a secret is destroyed the moment it is read. Some secrets need to stay
reachable for longer without turning the link into a permanent liability. Setting
an access mode at creation keeps the link usable, but ties it to whoever opened it
first.

| Mode | What it binds to | When to use it |
|---|---|---|
| One-time read | nothing (default) | Anything that only needs to be seen once |
| Browser | non-extractable ECDSA key in IndexedDB | The recipient will re-open the link over days |
| Security key | WebAuthn authenticator | The recipient is known to have a hardware key |

```mermaid
sequenceDiagram
    participant R as Recipient
    participant Server

    R->>Server: retrieve (verifier hash only)
    Server-->>R: 401 enrol, one-time challenge
    Note over R: warning shown, then key generated or authenticator registered
    R->>Server: challenge + public key
    Server->>Server: atomic claim in D1, factor pinned
    Server-->>R: ciphertext + __Host- cookie

    Note over R,Server: later reads

    R->>Server: retrieve
    Server-->>R: 401 prove, one-time challenge
    R->>Server: signature over the challenge
    Server->>Server: cookie hash + signature + pinned factor
    Server-->>R: ciphertext
```

Both factors are required on every later read. The cookie is deliberately not
enough on its own: an infostealer that copies the cookie jar off disk defeats
`HttpOnly` entirely, so the resistance lives in the signing key, which no browser
API can export.

Binding state lives in D1 rather than KV because claiming a secret has to be
atomic, and KV has no compare-and-swap. `UPDATE ... WHERE bound_hash IS NULL`
means exactly one of two simultaneous first readers wins.

**Trade-offs worth knowing before you enable it:**

- Access is tied to a browser profile, not a device. A different browser on the
  same machine, or a private window, will not get in.
- Clearing cookies or site data is irreversible. There is no recovery path, by
  design: if the passphrase could restore access, anyone holding the link could
  restore it too.
- The ciphertext stays in KV for the secret's whole lifetime rather than being
  destroyed on first read. The extended lifetime is only safe because of the
  binding, so unbound secrets keep the 7-day cap.
- Synced passkeys (iCloud Keychain, Google Password Manager) are refused in
  security-key mode. Only device-bound credentials can bind.
- If the sender allows it, a browser that can produce no key at all falls back to
  a cookie-only binding. That decision is made once by the first reader and then
  pinned; no later client can request it.

#### Password generator standards

The generator next to the secret field offers the format the receiving system
actually requires, rather than one compromise shape for every case:

| Standard | Output | Entropy |
|---|---|---|
| NIST SP 800-63B | 20 characters, no forced symbol classes | 117 bits |
| Memorable, EFF Long Wordlist | 6 words joined by hyphens | 77 bits |
| Memorable, BIP-39 English | 12 words joined by hyphens | 132 bits |
| Legacy corporate | exactly 12 characters, one of each class, symbol from `!@#$%^&*` | 64 bits |
| API key | 32 or 64 random bytes, Base64 | 256 / 512 bits |

The stated entropy is a floor, never a flattering upper bound. For the legacy
mode in particular, counting all twelve characters as freely chosen would
overstate it by roughly nine bits, because four are drawn from small
class-specific alphabets; the shuffle that hides their positions is not credited
either, since its permutations overlap.

The passphrase modes use published wordlists rather than anything home-grown:

| List | Words | Bits/word | Source |
|---|---|---|---|
| EFF Long Wordlist | 7776 | 12.925 | [eff.org](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt) |
| BIP-39 English | 2048 | 11 | [bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) |

BIP-39 ships byte-identical to the standard, `sha256
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. The EFF file
is published as `<dice code>\t<word>` per line; only the second column is kept,
since selection comes from the CSPRNG rather than from five dice and the codes
would cost 18 KB on the wire for data the generator never reads. Reproduce with
`cut -f2` over the published file (`sha256
addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`).

Note that four EFF entries contain a hyphen themselves (`t-shirt`, `yo-yo`,
`drop-down`, `felt-tip`), so a six-word phrase can show more than five
separators. This is cosmetic: entropy is one of 7776 per word either way.

The BIP-39 mode draws twelve words, the seed-phrase convention the list is known
for. These are twelve uniform draws and therefore 132 bits, not a valid BIP-39
seed phrase, where the tail carries a checksum and the entropy is 128 bits.
Nothing produced here is meant to be restored into a wallet.

Every mode draws from `crypto.getRandomValues` in the browser, never
`Math.random`. The server is never told what was generated, which is the same
property the rest of the design rests on. Selection is unbiased in both cases:
BIP-39 is exactly 2^11 entries, and EFF is not a power of two, so draws outside
the largest whole multiple of 7776 are rejected and redrawn rather than folded
in with a modulo.

Each list is bundled into the Worker as a string constant, so serving it costs
no storage read, and each has its own immutable, year-cached URL fetched only
when someone selects that standard. Picking one never downloads the other, and a
recipient opening `/receive/:id` downloads neither. On the wire that is 24 KB for
EFF and 6 KB for BIP-39, once per browser per year.

#### Sent-secret ledger and revocation

A sender needs two things a burn-on-read link cannot give them: whether the
secret was ever collected, and a way to pull it back if it was sent to the wrong
person. Both live in a section directly below the generator on the secrets tab. Its
header always shows how many secrets the account has and which account that is,
so the disclosure itself carries the summary; expanding reveals the list. The
open state is remembered between visits.

The list shows what the signed-in sender created, newest first: the identifier,
when it was made, whether it has been opened and how often, and how many wrong
passphrases were tried against it. Anything still live carries a Revoke button
that destroys the secret, its binding and any outstanding challenges. Creating a
secret refreshes the list, so a link and its ledger entry appear together.

```mermaid
flowchart LR
    A[Create secret] --> B[pending]
    B -->|recipient reads it| C[opened]
    B -->|TTL elapses| D[expired]
    B -->|3 wrong passphrases| E[burned]
    B -->|sender revokes| F[revoked]
    C -->|sender revokes| F
    C -->|recipient destroys| G[forgotten]
```

Ownership is derived from the Cloudflare Access JWT. The ledger stores
`HMAC-SHA256(PEPPER, 'owner:' || subject)` and never the address itself, so a
leaked copy of the table cannot be joined against the Access user directory, and
changing an e-mail does not orphan what that person already sent. Scoping is
enforced in the `WHERE` clause of every query rather than applied to results
afterwards, and reusing another sender's identifier is refused outright.

Zero-knowledge is unaffected. The ledger holds identifiers, timestamps and a
status; never the verifier, the ciphertext, the passphrase or the URL fragment.
Knowing an identifier is enough to build the link and nothing more, because the
passphrase never leaves the fragment.

Recipients get the mirror image of this on the retrieval page: a device-bound
secret that survives its first read shows a destroy control, so the recipient can
end access as soon as they are done rather than waiting out the window. It sits
below a divider, after the reveal and copy actions, and is red at rest rather
than only on hover, because it is irreversible and should never be mistaken for
one of the primary controls. It takes two clicks. Being
able to destroy requires being able to read, so the request has to clear the same
gates a read does, the binding cookie plus a signature over a fresh challenge. An
identifier alone will not do it, which is the difference between an emergency
control and a denial-of-service hole.

Two caveats worth stating plainly:

- Revocation destroys the secret immediately, but KV is eventually consistent.
  Reaching every Cloudflare edge location can take up to about a minute.
- Secrets created before this feature, or created by a service token rather than
  a user, carry no owner and therefore appear on nobody's list.

---

### Files

Files have two independent modes, chosen per-upload via a toggle on `/gen` → Files:

| Mode | When to use | Trust model |
|---|---|---|
| **Normal** (default) | Automation, large files up to 50 GB, cases where server-visible content is acceptable | Server has access to the plaintext blob; password (if set) gates retrieval via `SHA-256(pwd + salt + PEPPER)` |
| **End-to-end encrypted** | Sensitive content that must never touch the server in cleartext; max 150 MiB | Client encrypts with AES-GCM before upload; server stores ciphertext and an Argon2id verifier; no key material ever reaches the server |

#### Normal (server-visible) flow

```mermaid
sequenceDiagram
    participant U as Uploader
    participant W as Worker
    participant R2 as R2
    participant D1 as D1
    participant R as Recipient

    U->>W: file + password + TTL + limit
    W->>R2: store binary
    W->>D1: metadata + salted SHA-256 hash
    W-->>U: share link

    R->>W: GET /share/:id + password
    W->>W: verify salted hash · check TTL + download limit
    W-->>R: file stream
    W-->>R2: burn when download limit reached
```

- Optional password hashed as `SHA-256(password + per-file salt + PEPPER)` with constant-time comparison — each row gets its own 16-byte random salt so identical passwords across files never collide, and timing cannot leak how close a guess was
- Download limit (1×, 5×, or unlimited)
- Server-enforced TTL - maximum 7 days regardless of what the client sends
- Automatic deletion on expiry (hourly cron)
- Lockout after 3 failed password attempts → file deleted immediately. The counter increments atomically (`UPDATE … RETURNING`) so parallel guesses cannot race past the 3-try cap
- Per-file and total storage caps admin-configurable (defaults 9 GB / 9.5 GB, hard ceiling 50 GB per value) — any value above the 10 GiB Cloudflare R2 free tier requires typing `OKAY` to confirm in the Appearance panel
- After multipart upload completes the server re-reads the R2 object's actual size and rejects the upload if it does not match the size declared at init — blocks a declare-1-byte-upload-200-MB cap bypass

#### Global Pepper

File passwords are hashed as `SHA-256(password + PEPPER)`, where `PEPPER` is a global secret stored as a Cloudflare Secret (not in code, not in the repo). Even if the D1 database leaks, the password hashes are useless without the pepper.

```mermaid
flowchart LR
    P[User password] --> H[SHA-256]
    S[Per-file salt<br/>16 random bytes] --> H
    K[PEPPER<br/>Cloudflare Secret] --> H
    H --> DB[(Hash stored in D1)]
```

The Worker refuses to start if `PEPPER` is not set (`bindings guard`).

#### End-to-end encrypted flow (opt-in)

When the uploader flips the **End-to-End Encryption** toggle on the files tab, the file never leaves the browser unencrypted:

```mermaid
sequenceDiagram
    participant U as Uploader (browser)
    participant W as Worker
    participant R2 as R2
    participant D1 as D1
    participant R as Recipient (browser)

    U->>U: derive Argon2id key + verifier from passphrase
    U->>U: AES-GCM encrypt (IV prepended to ciphertext)
    U->>W: ciphertext + verifier + algoVersion
    W->>R2: store ciphertext blob
    W->>D1: metadata + verifier + algoVersion
    W-->>U: share link (passphrase in URL fragment)

    R->>W: POST verifier candidate (+ Turnstile token)
    W->>W: compare verifier · check limit
    W-->>R: ciphertext stream
    R->>R: AES-GCM decrypt, trigger download
```

| Element | Algorithm | Parameters |
|---|---|---|
| Key derivation | Argon2id | m=19 MiB, t=2, p=1, 32-byte output |
| Salt | File UUID (for AES key) / UUID + `"_v"` (for verifier) | 36 bytes |
| Encryption | AES-GCM | 256-bit, random 12-byte IV prepended to the ciphertext blob |
| Verifier | Argon2id output, 32 bytes | Stored base64 in D1, checked via `safeCompare` |

**Constraints and trade-offs:**

- **150 MiB hard cap** on E2EE uploads. AES-GCM in the browser is one-shot (no streaming), so the full plaintext + ciphertext must coexist in RAM — ~300 MB peak for a 150 MB file, which is the ceiling we can rely on for mid-range mobile.
- **Passphrase is irrecoverable.** Losing it means the file is permanently unreadable. The server has no way to help — it never sees the passphrase or the key.
- **Independent Turnstile toggle.** `ui:turnstile_files_e2ee` in KV can force a challenge on E2EE downloads without touching the normal-files toggle, which is often left off to keep automation working.
- **Server trust minimised.** The server stores only the ciphertext, the Argon2id verifier, and the `algoVersion`. A full D1 + R2 leak produces no plaintext.

---

## Security

| Measure | Description |
|---|---|
| **Burn-on-read** | Secret deleted from KV on first successful retrieval |
| **Rate limiting** | Max 3 attempts; permanent deletion on lockout (secrets & files). File counter increments atomically (`UPDATE … RETURNING`) so parallel requests cannot race past the cap |
| **TTL preservation** | Failed verifier attempts bump the counter but preserve the secret's original expiration — an attacker cannot keep a short-TTL record alive indefinitely by stopping before the 3rd attempt. Secrets with <60 s remaining are burned instead of refreshed |
| **Upload size verification** | After multipart complete, the server compares the actual R2 object size against the value declared at init and drops the upload on mismatch. Blocks a declared-small / uploaded-large cap bypass |
| **Per-file password salt** | File passwords hashed with a per-row random 16-byte salt (`SHA-256(pwd | salt | PEPPER)`), constant-time compared — identical passwords across different files never produce the same digest |
| **Client-encrypted files (E2EE)** | Opt-in per upload. AES-GCM + Argon2id client-side, server never sees plaintext or key material. Independent Turnstile toggle (`ui:turnstile_files_e2ee`) so a managed challenge can be forced on E2EE downloads without breaking automation on the normal flow |
| **Device binding (opt-in)** | Two factors, both required: a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`) and a signature from a key the client cannot export. The cookie alone is deliberately insufficient, because an infostealer that copies the cookie jar off disk defeats `HttpOnly` entirely |
| **Non-extractable device key** | ECDSA P-256 generated with `extractable: false` and stored in IndexedDB. No browser API can export its bytes, so neither injected script nor extension can exfiltrate it. One keypair per secret, so the server never receives an identifier linking a recipient's secrets |
| **Hardware binding (WebAuthn)** | Alternative factor for high-assurance secrets. Backup-eligible (synced) credentials are rejected on the signed assertion, since a credential present on every device the user owns cannot bind a secret to one of them |
| **Pinned binding factor** | Whatever the first reader proves possession of is frozen in D1 and enforced verbatim on every later read. A later client can never negotiate a weaker factor, which is what makes the compatibility fallback safe |
| **Single-use challenges** | Proof-of-possession challenges are consumed by an atomic `DELETE`, so a captured challenge cannot be replayed inside its TTL |
| **Binding checked before the attempt counter** | An unbound client is refused before its verifier is compared, so a stranger holding the link cannot burn someone else's secret with wrong guesses |
| **Per-sender isolation** | The sent-secret ledger is scoped by an owner hash inside the `WHERE` clause of every query, so no arrangement of parameters returns another sender's rows. Revoking an identifier that belongs to someone else answers 404 rather than 403, so the ledger cannot be probed for which identifiers exist |
| **Pseudonymous ownership** | Ownership is recorded as `HMAC-SHA256(PEPPER, 'owner:' || CF Access subject)`. No e-mail or subject is stored, so a D1 leak cannot be correlated with the Access user directory |
| **Recipient-side destruction gated on proof** | Destroying a bound secret early requires the binding cookie and a signature over a single-use challenge, the same gate a read must clear. A wrong passphrase on this path charges the same attempt counter, so it is not an unmetered oracle |
| **Identifier collision refused** | Creating a secret under an identifier another sender already owns is rejected atomically by the insert's conflict clause, so neither the ciphertext nor the right to revoke can be taken over |
| **Ledger holds no secret material** | Identifiers, timestamps and status only. No verifier, ciphertext, passphrase or URL fragment, and no recipient IP or user agent |
| **Client-side QR rendering** | QR codes are generated in the browser from a lazily loaded encoder. Nothing about a link, least of all the fragment that carries the passphrase, is sent anywhere in order to draw it |
| **Masked by default on reveal** | The decrypted secret renders masked; it is legible only while the reveal control is held, and the copy button reads it without ever unmasking. Limits shoulder-surfing and accidental exposure on shared screens |
| **Stated entropy is a floor** | Every generator reports the lower bound of its search space, never a flattering figure. Class-constrained modes are counted as constrained, and shuffles are not credited |
| **Generators use the CSPRNG only** | `crypto.getRandomValues` throughout, never `Math.random`. Selection is unbiased by rejection sampling wherever the alphabet or wordlist does not divide the random range evenly |
| **Global Pepper** | File password hashes include a server-side secret; D1 leak doesn't compromise passwords |
| **Server-side TTL cap** | Backend enforces maximum lifetime; client cannot exceed it |
| **CF Access + JWT verification** | Protected endpoints guarded at two layers: Cloudflare Access policy + in-Worker RS256 JWT verification against JWKS endpoint (cached 1 h) |
| **Security headers** | HSTS (1-year, preloadable), X-Frame-Options `DENY`, X-Content-Type-Options `nosniff`, Referrer-Policy `no-referrer`, Cross-Origin-Opener-Policy `same-origin`, Cross-Origin-Resource-Policy `same-origin`, explicit Permissions-Policy denying every permission-gated API we don't use |
| **Content-Security-Policy (strict)** | No `'unsafe-inline'` on `script-src`, no `'unsafe-eval'`, no external script origins beyond Cloudflare Turnstile. All page JS is delivered from `/ui/app.v1.js` (same-origin, bundled). Per-page data (i18n, page context) ships in `<script type="application/json">` data islands that the browser stores but never executes. Event handlers use `data-action` attributes dispatched by a single delegating listener — no `onclick=` attributes anywhere. A stored XSS (even one that slipped past escapeHtml) cannot execute because inline script is categorically forbidden |
| **RFC 5987 filenames** | Safe percent-encoded `Content-Disposition` filenames (no header injection) |
| **No content logging** | Errors return generic messages - no `e.message` leakage |
| **Bindings guard** | Worker returns 500 on startup if any required binding is missing (DB, BUCKET, KV, PEPPER, CF_TEAM_DOMAIN, CF_AUD) |
| **Turnstile** | Optional Cloudflare Turnstile (managed challenge) on secret retrieval and file downloads - blocks bots and brute-force before any KV/D1/R2 access; token bound to visitor IP via `remoteip`; failed challenge never increments the attempt counter. See [docs/turnstile.md](docs/turnstile.md). |

### Audited

Every release goes through the layered toolchain below before it is cut. Findings from each stage are triaged and either fixed in the same commit, documented as accepted risk, or suppressed with a reasoned `.snyk` / inline ignore. The live site is re-audited on every push to `master`.

| Layer | Tool | What it catches | How it's run |
|---|---|---|---|
| **Dependency vulnerabilities** | [Snyk Open Source (SCA)](https://snyk.io/product/open-source-security-management/) | Known CVEs in `hono`, `hash-wasm`, `wrangler`, `qrcode-generator` and their transitive deps | `snyk_sca_scan` on every commit |
| **Static code analysis** | [Snyk Code](https://snyk.io/product/snyk-code/) + [Semgrep](https://semgrep.dev) with `p/typescript`, `p/javascript`, `p/owasp-top-ten`, `p/security-audit`, `p/xss`, `p/command-injection` rulesets | SAST — insecure patterns, taint analysis, OWASP Top 10 classes | `semgrep scan` locally before each deploy |
| **Architectural & threat-model review** | [Anthropic Claude Opus 4.7](https://www.anthropic.com/) | Cross-cutting design flaws a rule-based scanner does not see — trust-boundary breaches, endpoint scope / auth gaps, race conditions, protocol misuse between crypto primitives, key / salt reuse, UX flows that silently bypass a control. Used strictly as a reviewer of structure, not as an orchestrator of other tools | Pre-release code walk-through against the full `src/index.ts`, scoped brief to zero-trust invariants and the E2EE boundary |
| **Secret scanning** | [Gitleaks](https://github.com/gitleaks/gitleaks) | Credentials, tokens and keys committed anywhere in the history, not just the working tree | `gitleaks detect` over the full commit history before each release |
| **Dynamic scanning (DAST)** | [OWASP ZAP](https://www.zaproxy.org), full scan (spider + AJAX spider + active scan) plus a second OpenAPI-seeded API scan covering every public JSON endpoint | Active scan: reflected / persistent / DOM XSS, SQL injection, command injection, path traversal, open redirect, CSRF, insecure cookies, CSP / header audit, SRI, HTTP method manipulation | Run against a local `wrangler dev` deployment, so active/injection probes never touch production data |
| **Template-based DAST** | [Nuclei](https://github.com/projectdiscovery/nuclei) with the public template set | Known CVEs, exposed files, misconfigurations, default credentials, HTTP header / TLS issues, CSP audit, sensitive-data exposure | `nuclei -list <public-endpoints> -severity critical,high,medium,low -exclude-tags dns,tech,intrusive` against production |
| **CSP audit** | [Google CSP Evaluator](https://csp-evaluator.withgoogle.com) logic reproduced in `scripts/csp-check.sh` | Missing hardening directives, `'unsafe-inline'`, wildcards, unsafe sources | Part of `npm test`; fails the suite on any new anti-pattern |
| **Header & invariant suite** | Custom smoke + KV / D1 invariant scripts (`scripts/smoke.sh`, `scripts/kv-invariants.sh`, `scripts/d1-invariants.sh`) | Security-header regression, CF Access gating, stored-state shape (algoVersion, failed_attempts bounds, expiresAt canary for TTL preservation) | Part of `npm test`; run against live production |

Every layer above was re-run for this release: static analysis and secret scanning across the
source and the full commit history, both dynamic passes against a local `wrangler dev` deployment
so that active and injection probes never touch production data, and the template scan against the
production edge. Everything raised is triaged before the release is cut, then either fixed
in the same release or recorded as an accepted trade-off of the design choices above.

Audit artefacts are kept outside the repo. Reach out if you want the reports for a specific release.

---

## Architecture

```mermaid
flowchart TD
    Browser -->|"protected routes<br/>/gen · /api/v1/admin/*"| CFA["Cloudflare Access<br/>JWT RS256 verification"]
    Browser -->|"public routes<br/>/receive/:id · /share/:id<br/>/api/v1/public/* · /ui/*"| Worker

    CFA -->|verified request| Worker["Cloudflare Worker<br/>Hono / TypeScript"]

    Worker --> KV[("KV Store<br/>Encrypted text secrets")]
    Worker --> D1[("D1 Database<br/>File metadata")]
    Worker --> R2[("R2 Bucket<br/>File binaries")]
```

| Resource | Usage |
|---|---|
| **KV** (`SECRETS_STORE`) | Encrypted text secrets + verifier + `algoVersion` + `expiresAt`, short links, global UI config (accent, bg, brand, tagline, storage caps, Turnstile flags) |
| **D1** (`DB`) | File metadata (name, size, TTL, download count, password hash) |
| **R2** (`BUCKET`) | Raw file data (multipart upload, per-file cap admin-configurable up to 50 GB) + logo image |

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

### Admin Zone - `/api/v1/admin/` (CF Access)

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
| `POST` | `/api/v1/admin/ui/limits` | Update storage / per-file upload caps (GB) |
| `POST` | `/api/v1/admin/ui/logo` | Upload logo (PNG/SVG/WebP, max 256 KB) |
| `DELETE` | `/api/v1/admin/ui/logo` | Remove logo |

### Public Zone - `/api/v1/public/` (No auth)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/public/secrets/:id/retrieve` | Retrieve secret. Burns it on read, or runs the binding handshake for device-bound secrets |
| `POST` | `/api/v1/public/files/:id/retrieve-ciphertext` | Verify Argon2id verifier and stream the ciphertext for an E2EE file (client decrypts) |
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
| `GET` | `/ui/argon2.v1.js` | Serve bundled hash-wasm Argon2id module (immutable, long-cached) |
| `GET` | `/ui/app.v1.js` | Serve the main client application bundle (short-cached; the file that used to live inline in every page) |

> Full request/response documentation: [docs/api.md](docs/api.md)
>
> `/api/v1/public/files/:id` (DELETE) is intentionally outside CF Access - used by the uploader to self-revoke a link.
> `/ui/config` and `/ui/logo` (GET) are outside `/api/v1/` so CF Access policies don't block public clients.

---
## Quick deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/maciekaz/edge-secrets)

Deploy with one click, then complete the required post-deploy setup below.

### Post-deploy required steps

1. Create/bind Cloudflare resources:
   - KV namespace: `SECRETS_STORE`
   - D1 database: `DB`
   - R2 bucket: `BUCKET`

2. Initialize D1 schema (table: `files`).

3. Set required Worker secrets:
   - `PEPPER`
   - `CF_TEAM_DOMAIN`
   - `CF_AUD`
   - Optional: `TURNSTILE_SECRET`

4. Configure Cloudflare Access policies for:
   - `/gen`
   - `/api/v1/admin/*`

5. Keep these routes public (no Access policy):
   - `/api/v1/public/*`
   - `/ui/config`
   - `/ui/logo`
   - `/ui/qr`
   - `/s/*`

6. Deploy and verify:
   - Open `/gen` (protected)
   - Open `/receive/:id` and `/share/:id` (public)
  
   
## Another way of deployment

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

None of these go into the repo or `wrangler.toml`. The Worker won't start without the first three.

```bash
# 1. Global pepper for file password hashes (generate a random one)
echo "$(openssl rand -base64 32)" | npx wrangler secret put PEPPER

# 2. Cloudflare Access team domain
npx wrangler secret put CF_TEAM_DOMAIN
# → e.g. yourteam.cloudflareaccess.com

# 3. Application Audience (AUD) tag
# Found at: CF Zero Trust → Access → Applications → (app) → Overview → AUD Tag
npx wrangler secret put CF_AUD

# 4. Turnstile secret key (optional - only if you want bot protection)
# Found at: Cloudflare Dashboard → Turnstile → your site → Secret Key
npx wrangler secret put TURNSTILE_SECRET
```

> If `TURNSTILE_SECRET` is not set, Turnstile is silently disabled even if the KV toggles are on - no lockout, no errors.

> Make sure you have a CF Zero Trust **Access Policy** configured for only **two paths**: `/gen` and `/api/v1/admin/*`. Do **not** include `/ui/config`, `/ui/logo`, `/ui/qr`, `/s/`, or `/api/v1/public/*` - these must remain public.

### 4. Deploy

```bash
npx wrangler deploy
```

> **Cron trigger** - the hourly cleanup job (`0 * * * *`) is already defined in `wrangler.toml` and is deployed automatically with the command above. No manual setup needed. It deletes expired files from R2 and D1 every hour. You can verify it was registered under **Workers & Pages → your worker → Triggers** in the Cloudflare dashboard.

---

### Local Development

Create a `.dev.vars` file (git-ignored):

```ini
PEPPER=local-pepper-for-testing-only
CF_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CF_AUD=your-aud-tag

# Optional - use Cloudflare's always-pass test key for local Turnstile testing
TURNSTILE_SECRET=1x0000000000000000000000000000000AA
```

> In local dev, requests don't go through CF Access - protected endpoints require a JWT passed manually via the `Cf-Access-Jwt-Assertion` header.

```bash
npx wrangler dev
# → http://localhost:8787
```

#### Tests

```bash
npm test          # lint + Worker integration tests + smoke / KV / D1 / CSP suites
npm run test:unit # Worker integration tests only

# browser tests need the KV namespace id from your wrangler.toml, so that the
# fixtures can be seeded into local storage
KV_NAMESPACE_ID=<your-kv-namespace-id> npm run test:e2e
```

`npm run test:unit` runs the real Worker inside workerd with simulated KV, D1 and
R2, so the binding state machine is exercised through the actual request
pipeline. `npm run test:e2e` drives Chromium against a local `wrangler dev` and
uses CDP virtual authenticators for the WebAuthn paths, including the
backup-eligibility flags, so no physical security key is needed.

Two things about the Playwright setup are easy to get wrong and are pinned in
`playwright.config.mts`: the dev server must be reached over `localhost` rather
than `127.0.0.1`, because WebAuthn refuses an IP address as an RP ID, and
`--local-upstream` must carry the port, otherwise wrangler rewrites the request
URL to the route in `wrangler.toml` and the origin check correctly rejects the
browser's assertion.

The D1 tables used by device binding and by the sent-secret ledger are created
from `schema/`, and must be applied before deploying a version that offers those
features:

```bash
npx wrangler d1 execute secret-db --local  --file schema/002_device_bindings.sql
npx wrangler d1 execute secret-db --remote --file schema/002_device_bindings.sql
npx wrangler d1 execute secret-db --local  --file schema/003_sent_secrets.sql
npx wrangler d1 execute secret-db --remote --file schema/003_sent_secrets.sql
```
