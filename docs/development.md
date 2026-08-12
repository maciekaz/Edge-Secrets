# Development

[← Documentation index](README.md)

Setting up a local environment is covered in
[deployment.md](deployment.md#local-development). This page is about working on
the code once it runs.

---

## Layout

```
src/
  index.ts             the entire Worker: routes, crypto, HTML, client bundle
  i18n.ts              every UI string, in 9 languages
  eff-wordlist.txt     EFF Long Wordlist, 7776 words
  bip39-wordlist.txt   BIP-39 English, 2048 words, byte-identical to the standard
  qrcode-vendor.js     vendored qrcode-generator dist, served to the browser
schema/                D1 migrations, applied in numeric order
test/                  Worker integration tests (vitest + workerd)
test/e2e/              browser tests (Playwright)
docs/                  this documentation
```

`src/index.ts` is one large file on purpose. The Worker is deployed as a single
bundle, the routes share a lot of small helpers, and keeping the request pipeline
readable end to end has been worth more than splitting it up.

The client-side script is a template literal inside that file, served at
`/ui/app.v1.js`. Two things about it bite:

- A backslash escape meant for the *browser* has to be doubled in the
  TypeScript source. A bare `\n` becomes a real newline in the emitted bundle
  and breaks it at parse time.
- Nothing there may rely on inline event handlers. The CSP forbids inline
  script categorically, so handlers are `data-action` attributes dispatched by a
  single delegating listener.

---

## Tests

```bash
npm test
```

runs, in order: type check, Worker integration tests, then the smoke, KV, D1 and
CSP suites.

```bash
npm run lint       # tsc --noEmit
npm run test:unit  # Worker integration tests only

# browser tests need the KV namespace id from your wrangler.toml, so that
# fixtures can be seeded into local storage
KV_NAMESPACE_ID=<your-kv-namespace-id> npm run test:e2e
```

`test:unit` runs the real Worker inside workerd with simulated KV, D1 and R2, so
the request pipeline — middleware, bindings guard, Turnstile gate, binding state
machine — is exercised rather than a stubbed re-implementation of it. Outbound
requests are served by an auxiliary worker, so a test never reaches the network;
the only outbound call the Worker makes is for the Access JWKS, and the test
suite mints a throwaway keypair for it rather than committing a fixture.

`test:e2e` drives Chromium against a local `wrangler dev`, using CDP virtual
authenticators for the WebAuthn paths — including the backup-eligibility flags —
so no physical security key is needed.

Two things in `playwright.config.mts` are easy to get wrong and are pinned there
deliberately: the dev server must be reached over `localhost` rather than
`127.0.0.1`, because WebAuthn refuses an IP address as an RP ID; and
`--local-upstream` must carry the port, or wrangler rewrites the request URL to
the route from `wrangler.toml` and the origin check correctly rejects the
browser's assertion.

> **`scripts/` is git-ignored**, so a fresh clone cannot run the smoke, KV, D1
> and CSP suites — `npm test` will fail at the first of them. Use
> `npm run lint && npm run test:unit` when working from a clone. These scripts
> run against live infrastructure and were kept out of the repository for that
> reason.

---

## Adding a language

All UI text lives in `src/i18n.ts`, a self-contained module with no
dependencies. Currently shipped:

`en` English (default) · `pl` Polski · `de` Deutsch · `fr` Français ·
`es` Español · `uk` Українська · `pt` Português · `zh` 中文 (Simplified) ·
`cs` Čeština

To add one:

1. Add the code to the `LangCode` union.
2. Add a full `Translations` object under that key in the `I18N` record.
3. Add an entry to `LANG_OPTIONS`:
   ```ts
   { code: 'xx', flag: '🇽🇽', name: 'Language name' }
   ```
4. Deploy. No other file changes.

The type checker will tell you about every key you missed, so start with
`npm run lint`.

---

## Adding a migration

Number the file after the highest existing one, write it with
`CREATE TABLE IF NOT EXISTS`, and apply it with `--remote` **before** deploying
code that depends on it. The Worker tolerates a table it does not yet use; it
does not tolerate a missing one.

Watch the units. `files.expires_at` is in milliseconds; every later table uses
seconds, matching KV's `expiresAt`.

---

## Before opening a pull request

- `npm run lint && npm run test:unit` must pass.
- New endpoints belong in [api.md](api.md), and anything with a security
  consequence in [security.md](security.md) — including trade-offs, which are
  documented rather than omitted.
- Keep the routes grouped as they are in `src/index.ts`: public pages, `/ui/*`
  assets, admin UI config, the shortener, secrets, then files.
- Nothing that would introduce `'unsafe-inline'`, an external script origin, or
  a `Math.random` call in any path that touches key material.
