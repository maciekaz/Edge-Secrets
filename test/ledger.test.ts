import { SELF, env } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  ORIGIN,
  applySchema,
  cookieFrom,
  makeAccessIssuer,
  makeDeviceKey,
  seedSecret,
  setCookieAttrs,
} from './helpers'

const VERIFIER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const WRONG = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='

const ALICE = 'alice-subject-uuid'
const BOB = 'bob-subject-uuid'

let issuer: Awaited<ReturnType<typeof makeAccessIssuer>>

// isolatedStorage rolls KV back between tests, so the JWKS the outbound stub
// serves has to be republished each time. D1 rows are not rolled back, so the
// ledger is emptied here too: these tests assert on list contents, and a row
// surviving from an earlier case would order ahead of the one under test.
beforeEach(async () => {
  await applySchema()
  await env.DB.exec('DELETE FROM sent_secrets')
  await env.DB.exec('DELETE FROM secret_bindings')
  await env.DB.exec('DELETE FROM bind_nonces')
  issuer ??= await makeAccessIssuer(env.CF_TEAM_DOMAIN, env.CF_AUD)
  await env.SECRETS_STORE.put('test:jwks', issuer.certs)
})

async function asUser(sub: string, path: string, init: RequestInit = {}) {
  const token = await issuer.token({ sub, email: `${sub}@example.test` })
  return SELF.fetch(`${ORIGIN}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), 'Cf-Access-Jwt-Assertion': token },
  })
}

async function create(sub: string, id: string, extra: Record<string, unknown> = {}) {
  return asUser(sub, '/api/v1/admin/secrets', {
    method: 'POST',
    body: JSON.stringify({ id, encryptedData: 'CIPHERTEXT', verifier: VERIFIER, ttl: 3600, ...extra }),
  })
}

async function list(sub: string) {
  const res = await asUser(sub, '/api/v1/admin/secrets')
  return (await res.json()) as { secrets: Array<Record<string, unknown>> }
}

function retrieve(id: string, body: Record<string, unknown>, cookie?: string) {
  return SELF.fetch(`${ORIGIN}/api/v1/public/secrets/${id}/retrieve`, {
    method: 'POST',
    headers: cookie ? { Cookie: cookie } : {},
    body: JSON.stringify(body),
  })
}

function forget(id: string, body: Record<string, unknown>, cookie?: string) {
  return SELF.fetch(`${ORIGIN}/api/v1/public/secrets/${id}/forget`, {
    method: 'POST',
    headers: cookie ? { Cookie: cookie } : {},
    body: JSON.stringify(body),
  })
}

/** Drives a bound secret through enrolment and returns its binding cookie. */
async function bind(id: string) {
  const key = await makeDeviceKey()
  const first = await retrieve(id, { verifierCandidate: VERIFIER })
  const { challenge } = (await first.json()) as { challenge: string }
  const res = await retrieve(id, {
    verifierCandidate: VERIFIER,
    bindNonce: challenge,
    bindPubKey: key.spki,
  })
  return { key, cookie: cookieFrom(res, id), res }
}

describe('access identity', () => {
  it('rejects an unauthenticated caller', async () => {
    const res = await SELF.fetch(`${ORIGIN}/api/v1/admin/secrets`)
    expect(res.status).toBe(401)
  })

  it('rejects an expired token', async () => {
    const token = await issuer.token({ sub: ALICE, exp: Math.floor(Date.now() / 1000) - 10 })
    const res = await SELF.fetch(`${ORIGIN}/api/v1/admin/secrets`, {
      headers: { 'Cf-Access-Jwt-Assertion': token },
    })
    expect(res.status).toBe(401)
  })

  it('rejects a token signed by the wrong key', async () => {
    const other = await makeAccessIssuer(env.CF_TEAM_DOMAIN, env.CF_AUD)
    const res = await SELF.fetch(`${ORIGIN}/api/v1/admin/secrets`, {
      headers: { 'Cf-Access-Jwt-Assertion': await other.token({ sub: ALICE }) },
    })
    expect(res.status).toBe(401)
  })
})

describe('sender panel markup', () => {
  it('renders the list inline on the secrets tab, wired to the endpoint', async () => {
    const res = await asUser(ALICE, '/gen?t=cred')
    const html = await res.text()
    expect(res.status).toBe(200)
    expect(html).toContain('class="sent-section"')
    expect(html).toContain('id="histBody"')
    expect(html).toContain('id="sentWho"')
    // Visible on load rather than hidden behind a control the reader has to
    // discover first.
    expect(html).not.toContain('hist-panel')

    // The loader lives in the shared bundle, not inline, so the wiring is only
    // real if the bundle actually ships it.
    const js = await (await SELF.fetch(`${ORIGIN}/ui/app.v1.js`)).text()
    expect(js).toContain('/api/v1/admin/secrets')
    expect(js).toContain('loadSent')
  })

  it('leaves the files and links tabs untouched', async () => {
    for (const tab of ['file', 'link']) {
      const html = await (await asUser(ALICE, `/gen?t=${tab}`)).text()
      expect(html).not.toContain('class="sent-section"')
    }
  })

  it('ships the disclosure wiring and a themed scroll area', async () => {
    const html = await (await asUser(ALICE, '/gen?t=cred')).text()
    expect(html).toContain('data-click="toggleSent"')
    expect(html).toContain('aria-expanded="false"')
    expect(html).toContain('aria-controls="sentBody"')

    // The reported bug was the browser painting its own light scrollbar on a
    // dark page, which only a declared color-scheme prevents everywhere.
    expect(html).toContain('color-scheme: dark')
    expect(html).toContain('color-scheme:light')
    expect(html).toContain('.hist-list::-webkit-scrollbar')
  })

  it('names the signed-in account on the list response', async () => {
    const res = await asUser(ALICE, '/api/v1/admin/secrets')
    expect((await res.json() as any).email).toBe(`${ALICE}@example.test`)
  })

  it('offers the destroy control only on a bound receive page', async () => {
    await seedSecret({ id: 'ui-1', verifier: VERIFIER, bindMode: 'device' })
    await seedSecret({ id: 'ui-2', verifier: VERIFIER })

    const bound = await (await SELF.fetch(`${ORIGIN}/receive/ui-1`)).text()
    const plain = await (await SELF.fetch(`${ORIGIN}/receive/ui-2`)).text()
    expect(bound).toContain('id="btnForget"')
    // The destructive control sits after the primary actions, not before them.
    expect(bound.indexOf('id="btnReveal"')).toBeLessThan(bound.indexOf('id="btnForget"'))
    // Present but inert on a one-time secret: the client only reveals the row
    // when the server reports a binding, and the endpoint refuses it anyway.
    expect(plain).toContain('id="forgetRow" class="forget-row hidden"')
  })
})

describe('sender ledger', () => {
  it('lists what the sender created', async () => {
    expect((await create(ALICE, 'led-1')).status).toBe(200)
    const { secrets } = await list(ALICE)
    expect(secrets).toHaveLength(1)
    expect(secrets[0]).toMatchObject({ secret_id: 'led-1', status: 'pending', open_count: 0 })
  })

  it('never shows one sender the secrets of another', async () => {
    await create(ALICE, 'led-2')
    await create(BOB, 'led-3')

    const alice = await list(ALICE)
    const bob = await list(BOB)
    expect(alice.secrets.map((s) => s.secret_id)).toEqual(['led-2'])
    expect(bob.secrets.map((s) => s.secret_id)).toEqual(['led-3'])
  })

  it('refuses to let one sender reuse another sender identifier', async () => {
    await create(ALICE, 'clash-1')
    const res = await create(BOB, 'clash-1', { encryptedData: 'BOB-CIPHERTEXT' })

    expect(res.status).toBe(409)
    // Neither the ciphertext nor the right to revoke may change hands.
    expect(await env.SECRETS_STORE.get('clash-1')).toBe('CIPHERTEXT')
    expect((await list(BOB)).secrets).toHaveLength(0)
    expect((await list(ALICE)).secrets.map((s) => s.secret_id)).toEqual(['clash-1'])
  })

  it('lets a sender reuse an identifier of their own', async () => {
    await create(ALICE, 'clash-2')
    await retrieve('clash-2', { verifierCandidate: VERIFIER })
    expect((await create(ALICE, 'clash-2')).status).toBe(200)

    // Reissuing resets the history rather than carrying the old read forward.
    const { secrets } = await list(ALICE)
    expect(secrets[0]).toMatchObject({ status: 'pending', open_count: 0 })
  })

  it('stores no plaintext identity, only a keyed hash', async () => {
    await create(ALICE, 'led-4')
    const row = await env.DB.prepare('SELECT owner_hash FROM sent_secrets WHERE secret_id=?')
      .bind('led-4')
      .first<{ owner_hash: string }>()
    expect(row?.owner_hash).toBeTruthy()
    expect(row?.owner_hash).not.toContain(ALICE)
    expect(row?.owner_hash).not.toContain('@example.test')
  })

  it('keeps no verifier or ciphertext in the ledger', async () => {
    await create(ALICE, 'led-5')
    const row = await env.DB.prepare('SELECT * FROM sent_secrets WHERE secret_id=?')
      .bind('led-5')
      .first<Record<string, unknown>>()
    expect(JSON.stringify(row)).not.toContain(VERIFIER)
    expect(JSON.stringify(row)).not.toContain('CIPHERTEXT')
  })

  it('reports a lapsed secret as expired without rewriting the row', async () => {
    await create(ALICE, 'led-6')
    const past = Math.floor(Date.now() / 1000) - 10
    await env.DB.prepare('UPDATE sent_secrets SET expires_at=? WHERE secret_id=?')
      .bind(past, 'led-6')
      .run()

    const { secrets } = await list(ALICE)
    expect(secrets[0]!.status).toBe('expired')
    const stored = await env.DB.prepare('SELECT status FROM sent_secrets WHERE secret_id=?')
      .bind('led-6')
      .first<{ status: string }>()
    expect(stored?.status).toBe('pending')
  })
})

describe('ledger status tracking', () => {
  it('marks a one-time secret opened when it is read', async () => {
    await create(ALICE, 'trk-1')
    expect((await retrieve('trk-1', { verifierCandidate: VERIFIER })).status).toBe(200)

    const { secrets } = await list(ALICE)
    expect(secrets[0]).toMatchObject({ secret_id: 'trk-1', status: 'opened', open_count: 1 })
    expect(secrets[0]!.first_opened_at).toBeTruthy()
  })

  it('counts wrong keys and reports the burn', async () => {
    await create(ALICE, 'trk-2')
    await retrieve('trk-2', { verifierCandidate: WRONG })
    let { secrets } = await list(ALICE)
    expect(secrets[0]).toMatchObject({ status: 'pending', failed_attempts: 1 })

    await retrieve('trk-2', { verifierCandidate: WRONG })
    expect((await retrieve('trk-2', { verifierCandidate: WRONG })).status).toBe(410)
    ;({ secrets } = await list(ALICE))
    expect(secrets[0]).toMatchObject({ status: 'burned', failed_attempts: 3 })
  })

  it('counts every read of a bound secret', async () => {
    await create(ALICE, 'trk-3', { bindMode: 'device' })
    const { key, cookie } = await bind('trk-3')

    const challenged = await retrieve('trk-3', { verifierCandidate: VERIFIER }, cookie!)
    const { challenge } = (await challenged.json()) as { challenge: string }
    await retrieve(
      'trk-3',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: await key.sign(challenge) },
      cookie!
    )

    const { secrets } = await list(ALICE)
    expect(secrets[0]).toMatchObject({ status: 'opened', open_count: 2 })
  })

  it('does not let a late read undo a revocation', async () => {
    await create(ALICE, 'trk-4', { bindMode: 'device' })
    await bind('trk-4')
    await asUser(ALICE, '/api/v1/admin/secrets/trk-4', { method: 'DELETE' })

    // Simulates a read landing after the revoke: the ledger update must not
    // walk the terminal status back to 'opened'.
    await env.DB.prepare('UPDATE sent_secrets SET open_count=open_count+1 WHERE secret_id=?')
      .bind('trk-4')
      .run()
    const { secrets } = await list(ALICE)
    expect(secrets[0]!.status).toBe('revoked')
  })
})

describe('revocation by the sender', () => {
  it('destroys the secret and its binding', async () => {
    await create(ALICE, 'rev-1', { bindMode: 'device' })
    const { cookie } = await bind('rev-1')

    const res = await asUser(ALICE, '/api/v1/admin/secrets/rev-1', { method: 'DELETE' })
    expect(res.status).toBe(200)

    expect(await env.SECRETS_STORE.get('rev-1')).toBeNull()
    const binding = await env.DB.prepare('SELECT * FROM secret_bindings WHERE secret_id=?')
      .bind('rev-1')
      .first()
    expect(binding).toBeNull()

    // The bound reader's cookie is now worthless.
    expect((await retrieve('rev-1', { verifierCandidate: VERIFIER }, cookie!)).status).toBe(404)

    const { secrets } = await list(ALICE)
    expect(secrets[0]).toMatchObject({ status: 'revoked' })
    expect(secrets[0]!.revoked_at).toBeTruthy()
  })

  it('refuses to revoke a secret belonging to someone else', async () => {
    await create(ALICE, 'rev-2')
    const res = await asUser(BOB, '/api/v1/admin/secrets/rev-2', { method: 'DELETE' })
    // 404 rather than 403: a distinct code would confirm the id exists.
    expect(res.status).toBe(404)
    expect(await env.SECRETS_STORE.get('rev-2')).toBe('CIPHERTEXT')
  })

  it('reports 404 for an id nobody created', async () => {
    const res = await asUser(ALICE, '/api/v1/admin/secrets/does-not-exist', { method: 'DELETE' })
    expect(res.status).toBe(404)
  })

  it('is idempotent', async () => {
    await create(ALICE, 'rev-3')
    const first = await asUser(ALICE, '/api/v1/admin/secrets/rev-3', { method: 'DELETE' })
    const second = await asUser(ALICE, '/api/v1/admin/secrets/rev-3', { method: 'DELETE' })
    expect(first.status).toBe(200)
    expect(second.status).toBe(200)
  })

  it('rejects an unauthenticated revoke', async () => {
    await create(ALICE, 'rev-4')
    const res = await SELF.fetch(`${ORIGIN}/api/v1/admin/secrets/rev-4`, { method: 'DELETE' })
    expect(res.status).toBe(401)
    expect(await env.SECRETS_STORE.get('rev-4')).toBe('CIPHERTEXT')
  })
})

describe('destruction by the recipient', () => {
  it('refuses a caller with the passphrase but no binding', async () => {
    await seedSecret({ id: 'fgt-1', verifier: VERIFIER, bindMode: 'device' })
    await bind('fgt-1')

    const res = await forget('fgt-1', { verifierCandidate: VERIFIER })
    expect(res.status).toBe(403)
    expect(await env.SECRETS_STORE.get('fgt-1')).toBe('CIPHERTEXT')
  })

  it('refuses the cookie without a signature', async () => {
    await seedSecret({ id: 'fgt-2', verifier: VERIFIER, bindMode: 'device' })
    const { cookie } = await bind('fgt-2')

    const challenged = await forget('fgt-2', { verifierCandidate: VERIFIER }, cookie!)
    expect(challenged.status).toBe(401)
    expect((await challenged.json() as any).error).toBe('BIND_CHALLENGE')
    expect(await env.SECRETS_STORE.get('fgt-2')).toBe('CIPHERTEXT')
  })

  it('destroys the secret for the bound client', async () => {
    await create(ALICE, 'fgt-3', { bindMode: 'device' })
    const { key, cookie } = await bind('fgt-3')

    const challenged = await forget('fgt-3', { verifierCandidate: VERIFIER }, cookie!)
    const { challenge } = (await challenged.json()) as { challenge: string }
    const res = await forget(
      'fgt-3',
      { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: await key.sign(challenge) },
      cookie!
    )

    expect(res.status).toBe(200)
    expect(await env.SECRETS_STORE.get('fgt-3')).toBeNull()
    expect(setCookieAttrs(res)).toMatch(/__Host-es_fgt-3=/)

    const { secrets } = await list(ALICE)
    expect(secrets[0]!.status).toBe('forgotten')
  })

  it('still charges a wrong passphrase to the attempt counter', async () => {
    await seedSecret({ id: 'fgt-4', verifier: VERIFIER, bindMode: 'device' })
    const { key, cookie } = await bind('fgt-4')

    const challenged = await forget('fgt-4', { verifierCandidate: WRONG }, cookie!)
    const { challenge } = (await challenged.json()) as { challenge: string }
    const res = await forget(
      'fgt-4',
      { verifierCandidate: WRONG, bindNonce: challenge, bindSignature: await key.sign(challenge) },
      cookie!
    )

    expect(res.status).toBe(403)
    expect((await res.json() as any).error).toMatch(/^RETRY_/)
    const { metadata } = await env.SECRETS_STORE.getWithMetadata<{ attempts: number }>('fgt-4')
    expect(metadata?.attempts).toBe(1)
  })

  it('does not apply to a one-time secret', async () => {
    await seedSecret({ id: 'fgt-5', verifier: VERIFIER })
    const res = await forget('fgt-5', { verifierCandidate: VERIFIER })
    expect(res.status).toBe(400)
    expect((await res.json() as any).error).toBe('FORGET_NOT_APPLICABLE')
    expect(await env.SECRETS_STORE.get('fgt-5')).toBe('CIPHERTEXT')
  })

  it('reports 404 for an unknown id without revealing anything else', async () => {
    const res = await forget('no-such-secret', { verifierCandidate: VERIFIER })
    expect(res.status).toBe(404)
  })

  it('cannot be replayed with a consumed challenge', async () => {
    await seedSecret({ id: 'fgt-6', verifier: VERIFIER, bindMode: 'device' })
    const { key, cookie } = await bind('fgt-6')

    const challenged = await forget('fgt-6', { verifierCandidate: VERIFIER }, cookie!)
    const { challenge } = (await challenged.json()) as { challenge: string }
    const sig = await key.sign(challenge)
    const body = { verifierCandidate: VERIFIER, bindNonce: challenge, bindSignature: sig }

    expect((await forget('fgt-6', body, cookie!)).status).toBe(200)
    expect((await forget('fgt-6', body, cookie!)).status).toBe(404)
  })
})
