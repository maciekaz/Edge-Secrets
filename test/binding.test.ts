import { SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  ORIGIN,
  applySchema,
  b64u,
  cookieFrom,
  getAttempts,
  getBinding,
  makeAuthenticator,
  makeDeviceKey,
  seedSecret,
  setCookieAttrs,
} from './helpers'

const VERIFIER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const WRONG = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='

function retrieve(id: string, body: Record<string, unknown>, cookie?: string) {
  return SELF.fetch(`${ORIGIN}/api/v1/public/secrets/${id}/retrieve`, {
    method: 'POST',
    headers: cookie ? { Cookie: cookie } : {},
    body: JSON.stringify(body),
  })
}

/** Drives the enrol handshake to completion and returns the binding cookie. */
async function bind(
  id: string,
  extra: Record<string, unknown>
): Promise<{ res: Response; cookie: string | null }> {
  const first = await retrieve(id, { verifierCandidate: VERIFIER })
  const { challenge } = (await first.json()) as { challenge: string }
  const res = await retrieve(id, { verifierCandidate: VERIFIER, bindNonce: challenge, ...extra })
  return { res, cookie: cookieFrom(res, id) }
}

beforeEach(applySchema)

describe('classic burn-on-read (unchanged path)', () => {
  it('returns the ciphertext once and destroys it', async () => {
    await seedSecret({ id: 'plain-1', verifier: VERIFIER })

    const ok = await retrieve('plain-1', { verifierCandidate: VERIFIER })
    expect(ok.status).toBe(200)
    expect((await ok.json() as any).encryptedData).toBe('CIPHERTEXT')

    const again = await retrieve('plain-1', { verifierCandidate: VERIFIER })
    expect(again.status).toBe(404)
  })

  it('never sets a binding cookie', async () => {
    await seedSecret({ id: 'plain-2', verifier: VERIFIER })
    const res = await retrieve('plain-2', { verifierCandidate: VERIFIER })
    expect(res.headers.get('Set-Cookie')).toBeNull()
  })

  it('counts wrong keys and burns at the limit', async () => {
    await seedSecret({ id: 'plain-3', verifier: VERIFIER })
    expect((await retrieve('plain-3', { verifierCandidate: WRONG })).status).toBe(403)
    expect(await getAttempts('plain-3')).toBe(1)
    await retrieve('plain-3', { verifierCandidate: WRONG })
    const third = await retrieve('plain-3', { verifierCandidate: WRONG })
    expect(third.status).toBe(410)
    expect((await retrieve('plain-3', { verifierCandidate: VERIFIER })).status).toBe(404)
  })
})

describe('device binding: enrolment', () => {
  it('asks for enrolment only after the key checks out', async () => {
    await seedSecret({ id: 'dev-1', verifier: VERIFIER, bindMode: 'device' })

    const wrong = await retrieve('dev-1', { verifierCandidate: WRONG })
    expect(wrong.status).toBe(403)
    expect((await wrong.json() as any).error).toMatch(/^RETRY_/)

    const right = await retrieve('dev-1', { verifierCandidate: VERIFIER })
    expect(right.status).toBe(401)
    expect((await right.json() as any).error).toBe('BIND_ENROLL')
  })

  it('binds the first reader and hands back a __Host- cookie', async () => {
    await seedSecret({ id: 'dev-2', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    const { res, cookie } = await bind('dev-2', { bindPubKey: key.spki })

    expect(res.status).toBe(200)
    expect((await res.json() as any).bound).toBe('ecdsa')
    expect(cookie).toBeTruthy()

    const attrs = setCookieAttrs(res)
    expect(attrs).toContain('__Host-es_dev-2=')
    expect(attrs).toMatch(/Secure/i)
    expect(attrs).toMatch(/HttpOnly/i)
    expect(attrs).toMatch(/SameSite=Strict/i)
    expect(attrs).toMatch(/Path=\//i)
    expect(attrs).not.toMatch(/Domain=/i)

    const row = await getBinding('dev-2')
    expect(row?.bound_factor).toBe('ecdsa')
    expect(row?.pubkey).toBe(key.spki)
    expect(row?.read_count).toBe(1)
  })

  it('does not burn the ciphertext on a bound read', async () => {
    await seedSecret({ id: 'dev-3', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    await bind('dev-3', { bindPubKey: key.spki })
    const { value } = await import('cloudflare:test').then(async (m) =>
      m.env.SECRETS_STORE.getWithMetadata('dev-3')
    )
    expect(value).toBe('CIPHERTEXT')
  })

  it('only one of two simultaneous first readers wins', async () => {
    await seedSecret({ id: 'dev-race', verifier: VERIFIER, bindMode: 'device' })
    const a = await makeDeviceKey()
    const b = await makeDeviceKey()

    const n1 = (await (await retrieve('dev-race', { verifierCandidate: VERIFIER })).json()) as any
    const n2 = (await (await retrieve('dev-race', { verifierCandidate: VERIFIER })).json()) as any

    const [r1, r2] = await Promise.all([
      retrieve('dev-race', { verifierCandidate: VERIFIER, bindNonce: n1.challenge, bindPubKey: a.spki }),
      retrieve('dev-race', { verifierCandidate: VERIFIER, bindNonce: n2.challenge, bindPubKey: b.spki }),
    ])

    const codes = [r1.status, r2.status].sort()
    expect(codes).toEqual([200, 403])
    const row = await getBinding('dev-race')
    expect([a.spki, b.spki]).toContain(row?.pubkey)
  })
})

describe('device binding: later reads', () => {
  it('lets the bound browser back in with a signature', async () => {
    await seedSecret({ id: 'dev-4', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    const { cookie } = await bind('dev-4', { bindPubKey: key.spki })

    const challenged = await retrieve('dev-4', { verifierCandidate: VERIFIER }, cookie!)
    expect(challenged.status).toBe(401)
    const { challenge, factor } = (await challenged.json()) as any
    expect(factor).toBe('ecdsa')

    const proven = await retrieve(
      'dev-4',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: await key.sign(challenge) },
      cookie!
    )
    expect(proven.status).toBe(200)
    expect((await proven.json() as any).encryptedData).toBe('CIPHERTEXT')
  })

  it('refuses a stranger who has the link and the right key', async () => {
    await seedSecret({ id: 'dev-5', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    await bind('dev-5', { bindPubKey: key.spki })

    const res = await retrieve('dev-5', { verifierCandidate: VERIFIER })
    expect(res.status).toBe(403)
    expect((await res.json() as any).error).toBe('BOUND_TO_OTHER_DEVICE')
  })

  it('refuses the cookie alone, without a signature', async () => {
    await seedSecret({ id: 'dev-6', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    const { cookie } = await bind('dev-6', { bindPubKey: key.spki })

    const challenged = await retrieve('dev-6', { verifierCandidate: VERIFIER }, cookie!)
    const { challenge } = (await challenged.json()) as any
    const forged = await retrieve(
      'dev-6',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: b64u(new Uint8Array(64)) },
      cookie!
    )
    expect(forged.status).toBe(403)
  })

  it('rejects a replayed challenge', async () => {
    await seedSecret({ id: 'dev-7', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    const { cookie } = await bind('dev-7', { bindPubKey: key.spki })

    const { challenge } = (await (
      await retrieve('dev-7', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any
    const sig = await key.sign(challenge)

    const first = await retrieve(
      'dev-7',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: sig },
      cookie!
    )
    expect(first.status).toBe(200)

    const replay = await retrieve(
      'dev-7',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: sig },
      cookie!
    )
    expect(replay.status).toBe(403)
    expect((await replay.json() as any).error).toBe('BIND_CHALLENGE_INVALID')
  })

  // The ordering guarantee: an unbound client must be turned away before the
  // attempt counter is touched, or anyone with the link could burn the secret.
  it('never lets a stranger touch the attempt counter', async () => {
    await seedSecret({ id: 'dev-8', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    await bind('dev-8', { bindPubKey: key.spki })
    expect(await getAttempts('dev-8')).toBe(0)

    for (let i = 0; i < 5; i++) {
      const res = await retrieve('dev-8', { verifierCandidate: WRONG })
      expect(res.status).toBe(403)
      expect((await res.json() as any).error).toBe('BOUND_TO_OTHER_DEVICE')
    }

    expect(await getAttempts('dev-8')).toBe(0)
    const still = await retrieve('dev-8', { verifierCandidate: VERIFIER }, undefined)
    expect(still.status).toBe(403)
  })
})

describe('compatibility fallback', () => {
  it('degrades to cookie-only when the sender allowed it', async () => {
    await seedSecret({ id: 'fb-1', verifier: VERIFIER, bindMode: 'device', allowFallback: true })
    const { res, cookie } = await bind('fb-1', { bindFactor: 'none' })
    expect(res.status).toBe(200)
    expect((await res.json() as any).bound).toBe('cookie')

    const row = await getBinding('fb-1')
    expect(row?.bound_factor).toBe('cookie')
    expect(row?.pubkey).toBeNull()

    // The cookie alone is sufficient because that is what was pinned, and only
    // the first reader could pin it.
    const again = await retrieve('fb-1', { verifierCandidate: VERIFIER }, cookie!)
    expect(again.status).toBe(200)
  })

  it('locks out instead when the sender refused the fallback', async () => {
    await seedSecret({ id: 'fb-2', verifier: VERIFIER, bindMode: 'device', allowFallback: false })
    const { res } = await bind('fb-2', { bindFactor: 'none' })
    expect(res.status).toBe(400)
    expect((await res.json() as any).error).toBe('BIND_UNSUPPORTED')
    expect((await getBinding('fb-2'))?.bound_factor).toBeNull()
  })

  // A later client must not be able to ask for the weaker factor.
  it('does not let a stranger claim cookie-only on a key-bound secret', async () => {
    await seedSecret({ id: 'fb-3', verifier: VERIFIER, bindMode: 'device', allowFallback: true })
    const key = await makeDeviceKey()
    const { cookie } = await bind('fb-3', { bindPubKey: key.spki })
    expect((await getBinding('fb-3'))?.bound_factor).toBe('ecdsa')

    const res = await retrieve('fb-3', { verifierCandidate: VERIFIER, bindFactor: 'none' }, cookie!)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toBe('BIND_CHALLENGE')
  })
})

describe('webauthn binding', () => {
  const RP = 'secret.test'

  it('rejects a syncable passkey at enrolment', async () => {
    await seedSecret({ id: 'wa-1', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const { res } = await bind('wa-1', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04 | 0x08)), // BE=1
    })
    expect(res.status).toBe(400)
    expect((await res.json() as any).error).toBe('BIND_SYNCED_PASSKEY')
    expect((await getBinding('wa-1'))?.bound_factor).toBeNull()
  })

  it('accepts a device-bound credential and verifies later assertions', async () => {
    await seedSecret({ id: 'wa-2', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const { res, cookie } = await bind('wa-2', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04)),
    })
    expect(res.status).toBe(200)
    expect((await getBinding('wa-2'))?.bound_factor).toBe('webauthn')

    const { challenge, credId } = (await (
      await retrieve('wa-2', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any
    expect(credId).toBe(auth.credId)

    const proven = await retrieve(
      'wa-2',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindAssertion: await auth.assert(challenge, ORIGIN) },
      cookie!
    )
    expect(proven.status).toBe(200)
  })

  it('rejects an assertion from a forged origin', async () => {
    await seedSecret({ id: 'wa-3', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const { cookie } = await bind('wa-3', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04)),
    })
    const { challenge } = (await (
      await retrieve('wa-3', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any

    const res = await retrieve(
      'wa-3',
      {
        verifierCandidate: VERIFIER,
        bindNonce: challenge,
        bindAssertion: await auth.assert(challenge, 'https://evil.example.com'),
      },
      cookie!
    )
    expect(res.status).toBe(403)
  })

  it('rejects an assertion whose credential became syncable', async () => {
    await seedSecret({ id: 'wa-4', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const { cookie } = await bind('wa-4', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04)),
    })
    const { challenge } = (await (
      await retrieve('wa-4', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any

    const res = await retrieve(
      'wa-4',
      {
        verifierCandidate: VERIFIER,
        bindNonce: challenge,
        bindAssertion: await auth.assert(challenge, ORIGIN, 0x01 | 0x04 | 0x08),
      },
      cookie!
    )
    expect(res.status).toBe(403)
  })

  it('rejects an assertion without user verification', async () => {
    await seedSecret({ id: 'wa-5', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const { cookie } = await bind('wa-5', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04)),
    })
    const { challenge } = (await (
      await retrieve('wa-5', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any

    const res = await retrieve(
      'wa-5',
      {
        verifierCandidate: VERIFIER,
        bindNonce: challenge,
        bindAssertion: await auth.assert(challenge, ORIGIN, 0x01), // UP only, no UV
      },
      cookie!
    )
    expect(res.status).toBe(403)
  })

  // Mode is pinned at creation; the two factors are never interchangeable.
  it('does not accept a raw ECDSA proof on a webauthn secret', async () => {
    await seedSecret({ id: 'wa-6', verifier: VERIFIER, bindMode: 'webauthn' })
    const auth = await makeAuthenticator(RP)
    const key = await makeDeviceKey()
    const { cookie } = await bind('wa-6', {
      bindPubKey: auth.spki,
      bindCredId: auth.credId,
      bindAuthData: b64u(auth.authData(0x01 | 0x04)),
    })
    const { challenge } = (await (
      await retrieve('wa-6', { verifierCandidate: VERIFIER }, cookie!)
    ).json()) as any

    const res = await retrieve(
      'wa-6',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: await key.sign(challenge) },
      cookie!
    )
    expect(res.status).toBe(403)
  })

  it('falls back to cookie-only when webauthn produced nothing and the sender allowed it', async () => {
    await seedSecret({ id: 'wa-7', verifier: VERIFIER, bindMode: 'webauthn', allowFallback: true })
    const { res } = await bind('wa-7', { bindFactor: 'none' })
    expect(res.status).toBe(200)
    expect((await getBinding('wa-7'))?.bound_factor).toBe('cookie')
  })
})

describe('fail-closed behaviour', () => {
  it('refuses a bound secret whose binding row vanished', async () => {
    await seedSecret({ id: 'fc-1', verifier: VERIFIER, bindMode: 'device' })
    const key = await makeDeviceKey()
    const { cookie } = await bind('fc-1', { bindPubKey: key.spki })

    const { env } = await import('cloudflare:test')
    await env.DB.prepare('DELETE FROM secret_bindings WHERE secret_id=?').bind('fc-1').run()

    const res = await retrieve('fc-1', { verifierCandidate: VERIFIER }, cookie!)
    expect(res.status).toBe(403)
    expect((await res.json() as any).error).toBe('BIND_STATE_MISSING')
  })

  it('stops serving once the read ceiling is reached', async () => {
    await seedSecret({ id: 'fc-2', verifier: VERIFIER, bindMode: 'device', allowFallback: true })
    const { cookie } = await bind('fc-2', { bindFactor: 'none' })

    const { env } = await import('cloudflare:test')
    await env.DB.prepare('UPDATE secret_bindings SET read_count=100 WHERE secret_id=?')
      .bind('fc-2')
      .run()

    const res = await retrieve('fc-2', { verifierCandidate: VERIFIER }, cookie!)
    expect(res.status).toBe(429)
    expect((await res.json() as any).error).toBe('BIND_READ_LIMIT')
  })
})
