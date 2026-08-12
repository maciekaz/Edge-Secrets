# Security

[← Documentation index](README.md)

This page describes what Edge Secrets protects, what it deliberately does not,
and how each release is checked before it ships.

---

## Threat model in one table

| Attacker | What they get | Why |
|---|---|---|
| Someone reading the database and object storage | Ciphertext, verifiers, timestamps | Text secrets and E2EE files are encrypted in the browser; no key material is stored |
| Someone who intercepts a link in transit | Everything, if they open it first | The passphrase travels in the URL fragment, so the link *is* the credential. Burn-on-read means the intended recipient finds it already gone |
| Someone who guesses an identifier | Nothing | Without the fragment there is no key, and three wrong attempts destroy the record |
| An operator of the Worker | Ciphertext only, for text secrets and E2EE files | The server is never told the passphrase. Normal file uploads are the exception and are server-visible by design |
| Another signed-in sender | Nothing of yours | Ledger scoping is in the `WHERE` clause of every query, not applied to results afterwards |

The single most important consequence: **a link that reaches the wrong inbox is
a disclosed secret.** Everything else in this document exists to limit the blast
radius of that one event — burn-on-read, the three-attempt cap, device binding,
and sender-side revocation.

---

## Cryptography

### Text secrets

| Element | Algorithm | Parameters |
|---|---|---|
| Key derivation | Argon2id | m = 19 MiB, t = 2, p = 1, 32-byte output |
| Encryption | AES-GCM | 256-bit key, random 12-byte IV |
| Password verifier | Argon2id | Same parameters, salt `id + "_v"` |
| Link entropy | 20 characters from a 58-character alphabet | 117 bits |

The Argon2id parameters are the OWASP baseline configuration, and Argon2id is
what NIST SP 800-63B names for memory-hard derivation. The salt is the secret's
UUIDv4: 122 bits of randomness, marginally under the 128 bits NIST SP 800-132
recommends, which is acceptable here because a salt's job is uniqueness rather
than unpredictability and the identifier is unique by construction. Deriving the
key and the verifier from the same passphrase is made safe by domain separation
— `<id>` for the key, `<id>_v` for the verifier — so the value the server stores
cannot be used to decrypt anything.

**Why Argon2id and not PBKDF2.** PBKDF2 parallelises almost perfectly across GPU
cores, so guessing rates scale with the hardware an attacker is willing to rent.
Argon2id at 19 MiB per hash makes each guess buy memory bandwidth instead, which
does not scale the same way. Combined with a 117-bit link, offline guessing is
not the interesting attack on this system — obtaining the link is.

**Where it runs.** Never on the Worker. Key derivation is client-side, so the
300–500 ms desktop cost (2–3 s on mobile) is the browser's, not the Worker's CPU
budget. The WebAssembly build ([hash-wasm](https://www.npmjs.com/package/hash-wasm))
is bundled and served from `/ui/argon2.v1.js` — same origin, no external CDN in
the CSP.

**Forward compatibility.** Each stored secret carries an `algoVersion`. A future
`argon2id-v2` with stronger parameters can roll out without breaking secrets
already in flight, because the client derives with whatever the server says the
record was written with.

### Files

E2EE uploads use the same primitives as text secrets, with the file UUID as the
salt. Normal uploads are different and the difference matters: their optional
password is hashed as `SHA-256(password | per-file salt | PEPPER)`. That is a
fast hash, chosen because these downloads are an automation path where an
Argon2id round-trip per request is not acceptable. It is an accepted trade-off,
not an oversight — a normal-mode file is server-visible anyway, so its password
gates retrieval rather than protecting confidentiality against the server. Use
E2EE mode when the content itself must stay unreadable.

---

## Controls

### Destruction and rate limiting

| Measure | Description |
|---|---|
| **Burn-on-read** | Secret deleted from KV on first successful retrieval |
| **Attempt cap** | Three wrong attempts, then permanent deletion, for both secrets and files. The file counter increments atomically (`UPDATE … RETURNING`) so parallel guesses cannot race past the cap |
| **TTL preservation** | A failed attempt bumps the counter but keeps the original expiry, so an attacker cannot keep a short-lived record alive by stopping at two. Secrets with under 60 s left are burned rather than refreshed |
| **Server-side TTL cap** | The backend enforces the maximum lifetime; a client cannot ask for longer |
| **Sender revocation** | Any secret the signed-in sender created can be destroyed from the panel, together with its binding and outstanding challenges |
| **Recipient destruction** | A device-bound secret can be ended early by its holder, gated on the same proof a read requires |

### Device binding (opt-in)

| Measure | Description |
|---|---|
| **Two factors, both required** | A `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`) *and* a signature from a key the client cannot export. The cookie alone is deliberately insufficient: an infostealer that copies the cookie jar off disk defeats `HttpOnly` entirely |
| **Non-extractable key** | ECDSA P-256 generated with `extractable: false`, held in IndexedDB. No browser API can export its bytes, so neither injected script nor an extension can exfiltrate it. One keypair per secret, so the server never receives an identifier linking a recipient's secrets |
| **Hardware binding** | WebAuthn as an alternative factor. Backup-eligible (synced) credentials are rejected on the assertion — a credential present on every device its owner has cannot bind a secret to one of them |
| **Pinned factor** | Whatever the first reader proved is frozen in D1 and enforced verbatim afterwards. No later client can negotiate something weaker, which is what makes the compatibility fallback safe |
| **Single-use challenges** | Consumed by an atomic `DELETE`, so a captured challenge cannot be replayed inside its TTL |
| **Binding checked before the counter** | An unbound client is refused before its verifier is compared, so a stranger holding the link cannot burn someone else's secret with wrong guesses |
| **Atomic claim** | `UPDATE … WHERE bound_hash IS NULL` in D1 rather than KV, because exactly one of two simultaneous first readers must win and KV has no compare-and-swap |

### Sender isolation

| Measure | Description |
|---|---|
| **Per-sender scoping** | The ledger is filtered by owner hash inside the `WHERE` clause of every query, so no arrangement of parameters returns another sender's rows |
| **Pseudonymous ownership** | Recorded as `HMAC-SHA256(PEPPER, 'owner:' ‖ CF Access subject)`. No address or subject is stored, so a database leak cannot be joined against the Access user directory |
| **404, not 403** | Revoking an identifier owned by someone else answers 404, so the ledger cannot be probed for which identifiers exist |
| **Collision refused** | Creating a secret under an identifier another sender owns is rejected by the insert's conflict clause, so neither the ciphertext nor the right to revoke can be taken over |
| **No secret material stored** | Identifiers, timestamps and status only. No verifier, ciphertext, passphrase or fragment, and no recipient IP or user agent |

### Client and transport

| Measure | Description |
|---|---|
| **Content-Security-Policy** | No `'unsafe-inline'` on `script-src`, no `'unsafe-eval'`, no external script origin beyond Turnstile. All page JS comes from `/ui/app.v1.js`; per-page data ships in `<script type="application/json">` islands the browser stores but never executes; handlers are `data-action` attributes dispatched by one delegating listener, so there is no `onclick=` anywhere. A stored XSS that slipped past escaping still could not execute |
| **Security headers** | HSTS (1 year, preloadable), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and a Permissions-Policy denying every gated API the app does not use |
| **Client-side QR rendering** | Codes are drawn in the browser by a lazily loaded encoder, so nothing about a link — least of all the fragment carrying the passphrase — is sent anywhere to render it |
| **Masked on reveal** | The decrypted secret renders masked and is legible only while the reveal control is held. Copy works without unmasking. Limits shoulder-surfing on shared screens |
| **RFC 5987 filenames** | Percent-encoded `Content-Disposition`, so a filename cannot inject a header |
| **No content logging** | Errors return generic messages; no exception text reaches the client |
| **CSPRNG only** | `crypto.getRandomValues` throughout, never `Math.random`. Rejection sampling wherever the alphabet or wordlist does not divide the random range evenly |
| **Stated entropy is a floor** | Every generator reports a lower bound, never a flattering figure. Class-constrained modes are counted as constrained and shuffles are not credited |

### Server and access

| Measure | Description |
|---|---|
| **CF Access + JWT verification** | Two layers: the Cloudflare Access policy, and in-Worker RS256 verification against the JWKS endpoint (cached 1 h) |
| **Bindings guard** | The Worker returns 500 on startup if any of `DB`, `BUCKET`, `SECRETS_STORE`, `PEPPER`, `CF_TEAM_DOMAIN` or `CF_AUD` is missing, rather than running degraded |
| **Global pepper** | File password hashes include a server-side secret held as a Cloudflare Secret. A database leak alone does not expose them |
| **Upload size verification** | After a multipart upload completes, the actual R2 object size is compared against the value declared at init and the upload is dropped on mismatch, blocking a declare-small / upload-large cap bypass |
| **Turnstile** | Optional managed challenge on secret retrieval and file downloads, before any storage access. The token is bound to the visitor IP, and a failed challenge never increments the attempt counter. See [turnstile.md](turnstile.md) |

---

## Accepted trade-offs

Stated plainly, because a security page that lists only strengths is not much
use.

- **The link is the credential.** Anyone who obtains it before the recipient
  gets the secret. Use device binding when a link will live longer than a few
  minutes.
- **No recovery.** A lost passphrase, or cleared site data on a bound secret,
  means the content is gone. If a recovery path existed, whoever held the link
  could use it too.
- **Normal-mode file passwords use a fast hash.** See above; use E2EE mode when
  that matters.
- **The secret verifier is not peppered.** It cannot be: the client has to be
  able to compute it, and a client-known pepper is not a pepper. Adding one
  would mean sending the passphrase to the server, which is the property the
  whole design exists to avoid.
- **Revocation is not instantaneous everywhere.** KV is eventually consistent;
  reaching every edge location can take up to about a minute.
- **Secrets created before the ledger existed, or created by a service token,
  have no owner** and therefore appear on nobody's list and cannot be revoked
  from the panel.
- **150 MiB cap on E2EE uploads.** Browser AES-GCM is one-shot, so plaintext and
  ciphertext must coexist in memory — around 300 MB peak, which is the ceiling
  mid-range mobile can be relied on for.

---

## How releases are audited

Every release goes through the layers below before it is cut. Findings are
triaged and either fixed in the same commit, recorded as an accepted risk above,
or suppressed with a reasoned `.snyk` or inline ignore.

| Layer | Tool | What it catches |
|---|---|---|
| **Dependencies** | Snyk Open Source | Known CVEs in `hono`, `hash-wasm`, `wrangler`, `qrcode-generator` and their transitive dependencies |
| **Static analysis** | Snyk Code and Semgrep (`p/typescript`, `p/javascript`, `p/owasp-top-ten`, `p/security-audit`, `p/xss`, `p/command-injection`) | Insecure patterns, taint analysis, OWASP Top 10 classes |
| **Architectural review** | Manual walk-through against the full `src/index.ts`, scoped to the zero-trust invariants and the E2EE boundary | Cross-cutting design flaws a rule-based scanner does not see: trust-boundary breaches, auth scope gaps, race conditions, key or salt reuse, UI flows that quietly bypass a control |
| **Secret scanning** | Gitleaks over the full commit history, not just the working tree | Credentials, tokens and keys committed anywhere |
| **Dynamic scanning** | OWASP ZAP full scan (spider, AJAX spider, active scan) plus an OpenAPI-seeded API scan, run against a local `wrangler dev` | Reflected, stored and DOM XSS, SQL and command injection, path traversal, open redirect, CSRF, cookie flags, header and CSP audit, HTTP method manipulation |
| **Template scanning** | Nuclei with the public template set | Known CVEs, exposed files, misconfigurations, default credentials, TLS and header issues |
| **CSP audit** | Google CSP Evaluator logic reproduced in `scripts/csp-check.sh` | Missing directives, `'unsafe-inline'`, wildcards, unsafe sources. Fails the suite on any new anti-pattern |
| **Invariant suite** | `scripts/smoke.sh`, `kv-invariants.sh`, `d1-invariants.sh` | Security-header regressions, Access gating, stored-state shape — `algoVersion`, `failed_attempts` bounds, an `expiresAt` canary for TTL preservation |

Injection and active probes run against a local deployment so they never touch
production data. Audit artefacts are kept outside the repository; ask if you
want the reports for a specific release.

---

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) in the repository root.
