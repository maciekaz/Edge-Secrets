import { readFileSync } from 'node:fs'
import { defineConfig } from 'vitest/config'
import { cloudflareTest } from '@cloudflare/vitest-pool-workers'

// Read from wrangler.toml rather than hard-coded: that file is gitignored, and
// the auxiliary worker below has to share the Worker's KV to serve the JWKS.
const KV_NAMESPACE_ID = (() => {
  const m = readFileSync('./wrangler.toml', 'utf8').match(/binding\s*=\s*"SECRETS_STORE"[\s\S]*?id\s*=\s*"([^"]+)"/)
  if (!m) throw new Error('SECRETS_STORE namespace id not found in wrangler.toml')
  return m[1]
})()

// Runs the real Worker inside workerd with simulated KV / D1 / R2, so the tests
// exercise the actual request pipeline (middleware, bindings guard, Turnstile
// gate) rather than a stubbed re-implementation of it.
export default defineConfig({
  test: {
    // test/e2e is Playwright's; it drives a browser and cannot run in workerd.
    exclude: ['node_modules/**', 'test/e2e/**'],
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      // Each test file gets its own KV/D1/R2 view, so a secret bound in one
      // test cannot leak into another and change its outcome.
      isolatedStorage: true,
      miniflare: {
        bindings: {
          PEPPER: 'test-pepper-not-production',
          CF_TEAM_DOMAIN: 'test.cloudflareaccess.com',
          CF_AUD: 'test-audience',
        },
        // Every outbound request from the Worker lands here instead of the
        // network. The only one it makes is for the CF Access JWKS, which the
        // test publishes under `test:jwks` after generating a throwaway
        // keypair. Keeping the key in KV rather than committing a fixture
        // means no private key material ever enters the repository.
        outboundService: 'access-jwks-stub',
        workers: [
          {
            name: 'access-jwks-stub',
            modules: true,
            script: `export default {
              async fetch(request, env) {
                if (new URL(request.url).pathname === '/cdn-cgi/access/certs') {
                  const jwks = await env.STORE.get('test:jwks')
                  if (jwks) {
                    return new Response(jwks, { headers: { 'Content-Type': 'application/json' } })
                  }
                }
                return new Response('outbound blocked in tests', { status: 502 })
              },
            }`,
            kvNamespaces: { STORE: KV_NAMESPACE_ID },
          },
        ],
      },
    }),
  ],
})
