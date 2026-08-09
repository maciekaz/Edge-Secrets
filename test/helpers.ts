import { env } from 'cloudflare:test'

export const ORIGIN = 'https://secret.test'

/** The binding tables are created by schema/002_device_bindings.sql in prod. */
export async function applySchema() {
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS secret_bindings (secret_id TEXT PRIMARY KEY, mode TEXT NOT NULL, allow_fallback INTEGER NOT NULL DEFAULT 0, bound_factor TEXT, bound_hash TEXT, pubkey TEXT, cred_id TEXT, sign_count INTEGER NOT NULL DEFAULT 0, bound_at INTEGER, expires_at INTEGER NOT NULL, read_count INTEGER NOT NULL DEFAULT 0)'
  )
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS bind_nonces (nonce TEXT PRIMARY KEY, secret_id TEXT NOT NULL, expires_at INTEGER NOT NULL)'
  )
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS sent_secrets (secret_id TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, purge_at INTEGER NOT NULL, bind_mode TEXT, status TEXT NOT NULL DEFAULT \'pending\', first_opened_at INTEGER, last_opened_at INTEGER, open_count INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER)'
  )
}

/**
 * Mints CF Access JWTs and serves the matching JWKS, so the admin endpoints can
 * be exercised as a specific signed-in user. Without this the ownership checks
 * could only be asserted at the SQL level, never through the real middleware.
 */
export async function makeAccessIssuer(teamDomain: string, aud: string) {
  const kid = 'test-key-1'
  const kp = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair
  const { key_ops: _ops, ext: _ext, ...jwk } = (await crypto.subtle.exportKey(
    'jwk',
    kp.publicKey
  )) as JsonWebKey
  const certs = JSON.stringify({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] })

  const b64uStr = (s: string) => b64u(new TextEncoder().encode(s))

  return {
    certs,
    async token(claims: { sub?: string; email?: string; common_name?: string; exp?: number } = {}) {
      const header = b64uStr(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }))
      const payload = b64uStr(
        JSON.stringify({
          aud,
          iss: `https://${teamDomain}`,
          exp: claims.exp ?? Math.floor(Date.now() / 1000) + 3600,
          ...claims,
        })
      )
      const sig = await crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        kp.privateKey,
        new TextEncoder().encode(`${header}.${payload}`)
      )
      return `${header}.${payload}.${b64u(sig)}`
    },
  }
}

export function b64u(buf: ArrayBuffer | Uint8Array): string {
  const b = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64uDec(s: string): Uint8Array {
  const t = s.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0))
}

/**
 * Seeds a secret straight into KV, mirroring what POST /api/v1/admin/secrets
 * writes. Going around the admin endpoint keeps these tests focused on the
 * retrieve state machine and avoids needing a CF Access token for every case.
 */
export async function seedSecret(opts: {
  id: string
  verifier: string
  bindMode?: 'device' | 'webauthn'
  allowFallback?: boolean
  ttl?: number
  value?: string
}) {
  const ttl = opts.ttl ?? 3600
  const expiresAt = Math.floor(Date.now() / 1000) + ttl
  const meta: Record<string, unknown> = {
    verifier: opts.verifier,
    attempts: 0,
    algoVersion: 'argon2id-v1',
    expiresAt,
  }
  if (opts.bindMode) meta.bindMode = opts.bindMode
  await env.SECRETS_STORE.put(opts.id, opts.value ?? 'CIPHERTEXT', {
    expirationTtl: ttl,
    metadata: meta,
  })
  if (opts.bindMode) {
    await env.DB.prepare(
      'INSERT OR REPLACE INTO secret_bindings (secret_id,mode,allow_fallback,bound_factor,bound_hash,pubkey,cred_id,sign_count,bound_at,expires_at,read_count) VALUES (?,?,?,NULL,NULL,NULL,NULL,0,NULL,?,0)'
    )
      .bind(opts.id, opts.bindMode, opts.allowFallback ? 1 : 0, expiresAt)
      .run()
  }
  return { expiresAt }
}

export async function getAttempts(id: string): Promise<number | undefined> {
  const { metadata } = await env.SECRETS_STORE.getWithMetadata<{ attempts: number }>(id)
  return metadata?.attempts
}

export async function getBinding(id: string) {
  return env.DB.prepare('SELECT * FROM secret_bindings WHERE secret_id=?').bind(id).first<{
    mode: string
    allow_fallback: number
    bound_factor: string | null
    bound_hash: string | null
    pubkey: string | null
    cred_id: string | null
    sign_count: number
    read_count: number
  }>()
}

/** Pulls the binding cookie out of a Set-Cookie header. */
export function cookieFrom(res: Response, id: string): string | null {
  const raw = res.headers.get('Set-Cookie')
  if (!raw) return null
  const m = raw.match(new RegExp(`__Host-es_${id}=([^;]+)`))
  return m ? `__Host-es_${id}=${m[1]}` : null
}

export function setCookieAttrs(res: Response): string {
  return res.headers.get('Set-Cookie') ?? ''
}

/** A P-256 keypair standing in for the browser's non-extractable device key. */
export async function makeDeviceKey() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const spki = b64u(await crypto.subtle.exportKey('spki', kp.publicKey))
  return {
    spki,
    sign: async (challenge: string) =>
      b64u(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          kp.privateKey,
          new TextEncoder().encode(challenge)
        )
      ),
  }
}

/** WebCrypto signs P1363; a real authenticator emits ASN.1 DER. */
export function toDer(sig: Uint8Array): Uint8Array {
  const enc = (x: Uint8Array): number[] => {
    let i = 0
    while (i < x.length - 1 && x[i] === 0) i++
    let v = x.slice(i)
    if (v[0]! & 0x80) v = new Uint8Array([0, ...v])
    return [0x02, v.length, ...v]
  }
  const r = enc(sig.slice(0, 32))
  const s = enc(sig.slice(32))
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s])
}

/** Synthetic WebAuthn authenticator with controllable BE/BS flags. */
export async function makeAuthenticator(rpId: string) {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const spki = b64u(await crypto.subtle.exportKey('spki', kp.publicKey))
  const rpHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
  )

  const authData = (flags: number, counter = 0) => {
    const a = new Uint8Array(37)
    a.set(rpHash, 0)
    a[32] = flags
    a[33] = (counter >>> 24) & 255
    a[34] = (counter >>> 16) & 255
    a[35] = (counter >>> 8) & 255
    a[36] = counter & 255
    return a
  }

  return {
    spki,
    credId: b64u(new TextEncoder().encode('test-credential-id')),
    authData,
    /** flags default to UP|UV with BE=0, i.e. a device-bound credential. */
    assert: async (challenge: string, origin: string, flags = 0x01 | 0x04, counter = 0) => {
      const cd = new TextEncoder().encode(
        JSON.stringify({ type: 'webauthn.get', challenge, origin })
      )
      const ad = authData(flags, counter)
      const cdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', cd))
      const signed = new Uint8Array([...ad, ...cdHash])
      const raw = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signed)
      )
      return {
        clientDataJSON: b64u(cd),
        authenticatorData: b64u(ad),
        signature: b64u(toDer(raw)),
      }
    },
  }
}
