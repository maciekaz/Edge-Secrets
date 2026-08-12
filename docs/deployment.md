# Deployment

[← Documentation index](README.md)

Edge Secrets runs entirely on Cloudflare. There is no server to provision, and
every component it uses has a free tier generous enough for an internal tool.

Two routes are described below. **Manual deploy** is the recommended one: it is
about ten minutes of copy-paste and leaves you with a working install. The
**Deploy button** is faster to start but leaves more to do afterwards, because
the button cannot create your KV namespace, your database or your Access policy.

---

## What you need first

| Requirement | Why | Cost |
|---|---|---|
| A Cloudflare account | Runs the Worker and all storage | Free |
| A domain on Cloudflare | Workers need a route; `workers.dev` is disabled in the shipped config | Free (the domain itself is not) |
| Cloudflare Zero Trust enabled | Protects the creation panel | Free up to 50 users |
| Node.js 18 or newer | Runs Wrangler | Free |

Turnstile is optional and can be added at any point later.

---

## Manual deploy

### 1. Clone and install

```bash
git clone https://github.com/maciekaz/edge-secrets
cd edge-secrets
npm install
```

### 2. Create the config file

```bash
cp wrangler.example.toml wrangler.toml
```

`wrangler.toml` is git-ignored, so your account ID and resource IDs never leave
your machine. Open it and set:

- `account_id` — Cloudflare dashboard, right-hand sidebar of any zone
- `routes` — the hostname you want the app on, e.g.
  `{ pattern = "secrets.example.com", custom_domain = true, zone_name = "example.com" }`

Leave the `[[rules]]` blocks alone. They bundle the Argon2id module, the two
wordlists and the QR encoder into the Worker so that no browser ever fetches
them from a third-party CDN.

### 3. Create the storage

```bash
npx wrangler kv namespace create SECRETS_STORE
```

Copy the returned `id` into the `[[kv_namespaces]]` block of `wrangler.toml`.

```bash
npx wrangler d1 create secret-db
```

Copy the returned `database_id` into the `[[d1_databases]]` block.

The R2 bucket is provisioned automatically on the first deploy — nothing to do.

### 4. Apply the database schema

All three migrations are required. Run them in order, against both the local
simulator and the remote database:

```bash
npx wrangler d1 execute secret-db --local  --file schema/001_files.sql
npx wrangler d1 execute secret-db --remote --file schema/001_files.sql
npx wrangler d1 execute secret-db --local  --file schema/002_device_bindings.sql
npx wrangler d1 execute secret-db --remote --file schema/002_device_bindings.sql
npx wrangler d1 execute secret-db --local  --file schema/003_sent_secrets.sql
npx wrangler d1 execute secret-db --remote --file schema/003_sent_secrets.sql
```

Each file is written with `CREATE TABLE IF NOT EXISTS`, so re-running one is
harmless.

| Migration | Creates | Needed for |
|---|---|---|
| `001_files.sql` | `files` | File sharing, both normal and E2EE |
| `002_device_bindings.sql` | `secret_bindings`, `bind_nonces` | Device-bound secrets |
| `003_sent_secrets.sql` | `sent_secrets` | The sent-secret ledger and revocation |

Skipping one does not degrade gracefully — the feature it backs will return
errors, because the Worker expects the table to be there.

### 5. Set the Worker secrets

None of these belong in the repo or in `wrangler.toml`. **The Worker refuses to
serve any request until the first three are set**, which is deliberate: a
missing pepper would otherwise mean silently weaker password hashes.

```bash
echo "$(openssl rand -base64 32)" | npx wrangler secret put PEPPER
```

```bash
npx wrangler secret put CF_TEAM_DOMAIN
```

Your Zero Trust team domain, e.g. `yourteam.cloudflareaccess.com`. Find it under
**Zero Trust → Settings → Custom Pages**, or in the URL of your Zero Trust
dashboard.

```bash
npx wrangler secret put CF_AUD
```

The Application Audience tag of the Access application you are about to create
in step 7. Come back for this one after that step if you are following in order.
Find it under **Zero Trust → Access → Applications → (your app) → Overview**.

```bash
npx wrangler secret put TURNSTILE_SECRET
```

Optional. Only if you want bot protection — see [turnstile.md](turnstile.md).
If it is unset, Turnstile stays off even when the panel toggles are on. No
lockout, no errors.

> Never rotate `PEPPER` on a live install. Every stored file password hash is
> derived from it, so changing it makes existing password-protected files
> permanently unopenable. Text secrets are unaffected, because their keys never
> touch the server.

### 6. Deploy

```bash
npx wrangler deploy
```

The hourly cleanup cron (`0 * * * *`) is declared in `wrangler.toml` and ships
with this command. Confirm it registered under **Workers & Pages → your worker →
Settings → Trigger Events**.

### 7. Protect the panel with Cloudflare Access

This is the step that actually makes the install private. Until you do it,
anyone who finds the hostname can create secrets and upload files.

In **Zero Trust → Access → Applications**, add a self-hosted application
covering your hostname, and give it exactly **two** paths:

| Path | What it is |
|---|---|
| `/gen` | The creation panel |
| `/api/v1/admin/*` | Every write and admin API call |

Then attach a policy — typically *Allow · Emails ending in `@yourcompany.com`*,
or a named list of addresses.

**Everything else must stay public.** Adding an Access policy to any of these
breaks recipients, who by design have no account:

```
/receive/:id      the secret retrieval page
/share/:id        the file download page
/s/:id            short links
/api/v1/public/*  retrieval, early destruction, E2EE ciphertext
/ui/*             config, logo, and the bundled JS and wordlists
```

The two-rule split is the whole authorisation model, so it is worth a second
look before you move on.

If you deferred `CF_AUD` in step 5, set it now and redeploy.

### 8. Verify

```bash
curl -sI https://your.domain.com/gen | head -1
```

Expect a redirect to a Cloudflare Access login, not a `200`.

Then open the panel in a browser, create a test secret, and open the resulting
link in a private window. You should see the retrieval page without being asked
to log in, and the secret should be masked until you hold the reveal button.

Signed in on the panel, the **Sent secrets** section under the generator should
now list that secret and show your own e-mail address in its header.

---

## Deploy button

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/maciekaz/edge-secrets)

The button forks the repository and deploys the Worker. It cannot create your
storage, apply the schema, set your secrets or configure Access, so after it
finishes you still need to work through **steps 3 to 7 above** against the
deployed Worker. If you would rather not switch between the dashboard and the
CLI halfway through, take the manual route from the start.

---

## Local development

Create a `.dev.vars` file (git-ignored):

```ini
PEPPER=local-pepper-for-testing-only
CF_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CF_AUD=your-aud-tag

# Cloudflare's always-pass test key, for exercising the Turnstile paths locally
TURNSTILE_SECRET=1x0000000000000000000000000000000AA
```

```bash
npx wrangler dev
```

The app comes up on `http://localhost:8787`. Local requests do not pass through
Cloudflare Access, but the in-Worker JWT check still runs, so `/gen` and every
`/api/v1/admin/*` call expect a valid token in the `Cf-Access-Jwt-Assertion`
header. Public routes — `/receive/:id`, `/share/:id`, `/s/:id`, `/ui/*` — work
straight away, which is enough to develop against most of the app.

Testing and the rest of the developer workflow are covered in
[development.md](development.md).

---

## Upgrading an existing install

1. Read the release notes for migrations. Any release that adds one says so at
   the top.
2. Apply new `schema/*.sql` files with `--remote` before deploying, not after.
   The Worker tolerates a table it does not yet use; it does not tolerate a
   missing one.
3. `npx wrangler deploy`.

A deployed version can take a few minutes to reach every edge location. If the
old bundle answers for a while after a successful deploy, that is propagation,
not a failed deploy.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every request returns 500 | One of `PEPPER`, `CF_TEAM_DOMAIN`, `CF_AUD`, or a binding is missing. The bindings guard fails closed on purpose |
| Panel loads but uploads fail with a database error | `schema/001_files.sql` was not applied, or was applied from an older README that omitted the `password_salt`, `encrypted`, `verifier` and `algo_version` columns |
| Sent-secret list is empty though you just created one | `schema/003_sent_secrets.sql` not applied — or the secret was created by a service token, which has no personal ledger |
| Device binding fails on first read | `schema/002_device_bindings.sql` not applied |
| Recipients are asked to log in | An Access policy is matching more than `/gen` and `/api/v1/admin/*` |
| Admin calls return 401 with a valid login | `CF_AUD` does not match the AUD tag of the Access application actually in front of the route |
| Revoked secret still opens somewhere | KV is eventually consistent. Reaching every edge can take up to about a minute |
