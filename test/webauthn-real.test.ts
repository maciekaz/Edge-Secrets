import { SELF, env } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import { applySchema, b64u } from './helpers'
import fixture from './fixtures-webauthn.json'

// A genuine assertion captured from a Chrome CDP virtual authenticator. Synthetic
// signatures can accidentally agree with a buggy verifier; this one cannot.
const ORIGIN = 'http://localhost:8787'
const ID = 'real-webauthn'
const VERIFIER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const TOKEN = 'test-cookie-token'

beforeEach(applySchema)

describe('real authenticator assertion', () => {
  it('is accepted by the Worker', async () => {
    const hash = b64u(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(TOKEN)))
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    await env.SECRETS_STORE.put(ID, 'CIPHERTEXT', {
      expirationTtl: 3600,
      metadata: { verifier: VERIFIER, attempts: 0, algoVersion: 'argon2id-v1', expiresAt, bindMode: 'webauthn' },
    })
    await env.DB.prepare(
      "INSERT OR REPLACE INTO secret_bindings (secret_id,mode,allow_fallback,bound_factor,bound_hash,pubkey,cred_id,sign_count,bound_at,expires_at,read_count) VALUES (?,'webauthn',0,'webauthn',?,?,'x',0,1,?,1)"
    ).bind(ID, hash, fixture.pubkey, expiresAt).run()
    await env.DB.prepare('INSERT INTO bind_nonces (nonce,secret_id,expires_at) VALUES (?,?,?)')
      .bind(fixture.nonce, ID, expiresAt).run()

    const res = await SELF.fetch(`${ORIGIN}/api/v1/public/secrets/${ID}/retrieve`, {
      method: 'POST',
      headers: { Cookie: `__Host-es_${ID}=${TOKEN}` },
      body: JSON.stringify({
        verifierCandidate: VERIFIER,
        bindNonce: fixture.nonce,
        bindAssertion: fixture.assertion,
      }),
    })
    expect(await res.json()).toMatchObject({ encryptedData: 'CIPHERTEXT' })
    expect(res.status).toBe(200)
  })
})
