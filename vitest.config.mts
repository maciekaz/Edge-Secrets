import { defineConfig } from 'vitest/config'
import { cloudflareTest } from '@cloudflare/vitest-pool-workers'

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
      },
    }),
  ],
})
