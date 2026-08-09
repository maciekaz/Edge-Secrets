import { defineConfig } from '@playwright/test'

// Drives a real Chromium against a local `wrangler dev`. The WebAuthn cases use
// Chrome DevTools Protocol virtual authenticators, which is the only way to
// exercise registration and assertion, including the backup-eligibility flags
// that decide whether a credential is device-bound, without physical hardware.
export default defineConfig({
  testDir: './test/e2e',
  testMatch: /.*\.spec\.mts/,
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  use: {
    baseURL: 'http://localhost:8787',
    // Argon2id in the browser takes a moment on every unlock.
    actionTimeout: 30_000,
  },
  webServer: {
    // Two things matter here and both are easy to get wrong:
    //   * the host must be `localhost`, not 127.0.0.1. WebAuthn refuses an IP
    //     address as an RP ID, so the whole flow silently fails on one.
    //   * --local-upstream must carry the port, otherwise wrangler rewrites the
    //     request URL to the route in wrangler.toml (secrets.example.com) and the
    //     Worker's origin check correctly rejects the browser's assertion.
    command:
      'npx wrangler dev src/index.ts --port 8787 --ip 127.0.0.1 --local-upstream localhost:8787',
    url: 'http://localhost:8787/ui/config',
    reuseExistingServer: true,
    timeout: 120_000,
  },
})
