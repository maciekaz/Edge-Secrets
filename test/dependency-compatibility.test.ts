import { SELF, env } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import FILE_SCHEMA from '../schema/001_files.sql?raw'
import { ORIGIN, applySchema, makeAccessIssuer } from './helpers'

let issuer: Awaited<ReturnType<typeof makeAccessIssuer>>

beforeEach(async () => {
  await applySchema()
  await env.DB.exec(FILE_SCHEMA.replace(/--[^\n]*/g, '').replace(/\s+/g, ' '))
  await env.DB.exec('DELETE FROM files')
  issuer ??= await makeAccessIssuer(env.CF_TEAM_DOMAIN, env.CF_AUD)
  await env.SECRETS_STORE.put('test:jwks', issuer.certs)
})

async function admin(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers)
  headers.set('Cf-Access-Jwt-Assertion', await issuer.token({ sub: 'upgrade-audit-user' }))
  return SELF.fetch(`${ORIGIN}${path}`, { ...init, headers, redirect: 'manual' })
}

async function upload(data: Uint8Array, options: Record<string, unknown> = {}) {
  const init = await admin('/api/v1/admin/files/init', {
    method: 'POST',
    body: JSON.stringify({ filename: 'upgrade-test.bin', size: data.length, limit: -1, ...options }),
  })
  expect(init.status).toBe(200)
  const file = await init.json() as { key: string; fileId: string; uploadId: string }
  const query = new URLSearchParams({ key: file.key, id: file.uploadId, num: '1' })
  const part = await admin(`/api/v1/admin/files/part?${query}`, { method: 'PUT', body: data })
  expect(part.status).toBe(200)
  const completion = await admin('/api/v1/admin/files/complete', {
    method: 'POST', body: JSON.stringify({ ...file, parts: [await part.json()] }),
  })
  expect(completion.status).toBe(200)
  expect(await completion.json()).toEqual({ ok: true })
  return file
}

describe('file, link and middleware compatibility', () => {
  it('preserves CORS preflight without granting access to protected endpoints', async () => {
    const preflight = await SELF.fetch(`${ORIGIN}/api/v1/admin/files/init`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://audit-client.example',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    })
    expect(preflight.status).toBe(204)
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe('*')
    expect(preflight.headers.get('Access-Control-Allow-Methods')).toContain('POST')
    expect(preflight.headers.get('Access-Control-Allow-Headers')?.toLowerCase()).toContain('content-type')
    await preflight.text()
    for (const [method, path] of [
      ['GET', '/api/v1/admin/stats'],
      ['POST', '/api/v1/admin/links'],
      ['POST', '/api/v1/admin/files/init'],
      ['DELETE', '/api/v1/admin/secrets/item%0Aencoded'],
    ]) {
      const blocked = await SELF.fetch(`${ORIGIN}${path}`, { method, redirect: 'manual' })
      expect(blocked.status, `${method} ${path}`).toBe(401)
      expect(await blocked.text()).toBe('Unauthorized')
    }
  })

  it('creates a limited URL and redirects once without contacting its destination', async () => {
    const destination = 'https://example.com/upgrade-check?q=1#fragment'
    const created = await admin('/api/v1/admin/links', {
      method: 'POST', body: JSON.stringify({ url: destination, ttl: 3600, maxClicks: 1 }),
    })
    expect(created.status).toBe(200)
    const link = await created.json() as { id: string; shortUrl: string }
    expect(link.shortUrl).toBe(`${ORIGIN}/s/${link.id}`)
    const redirect = await SELF.fetch(link.shortUrl, { redirect: 'manual' })
    expect(redirect.status).toBe(302)
    expect(redirect.headers.get('Location')).toBe(destination)
    expect(redirect.headers.get('Cache-Control')).toBe('no-store')
    await redirect.text()
    const spent = await SELF.fetch(link.shortUrl, { redirect: 'manual' })
    expect(spent.status).toBe(404)
    await spent.text()
  })

  it('uploads a password-protected file through multipart R2 and streams identical bytes', async () => {
    const data = new Uint8Array([0, 1, 2, 127, 128, 254, 255, 10, 13])
    const file = await upload(data, { password: 'upgrade-passphrase' })
    const denied = await SELF.fetch(`${ORIGIN}/share/${file.fileId}?pwd=wrong`, { redirect: 'manual' })
    expect(denied.status).toBe(403)
    await denied.text()
    const downloaded = await SELF.fetch(`${ORIGIN}/share/${file.fileId}?pwd=upgrade-passphrase`, { redirect: 'manual' })
    expect(downloaded.status).toBe(200)
    expect(downloaded.headers.get('Content-Disposition')).toContain('upgrade-test.bin')
    expect(downloaded.headers.get('Cache-Control')).toBe('no-store')
    expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(data)
    const stats = await admin('/api/v1/admin/stats')
    expect(stats.status).toBe(200)
    const inventory = await stats.json() as { used: number; files: Array<{ id: string; download_count: number }> }
    expect(inventory.used).toBe(data.length)
    expect(inventory.files.find((item) => item.id === file.fileId)?.download_count).toBe(1)
    const deleted = await SELF.fetch(`${ORIGIN}/api/v1/public/files/${file.fileId}`, { method: 'DELETE' })
    expect(deleted.status).toBe(200)
    await deleted.text()
    const absent = await SELF.fetch(`${ORIGIN}/share/${file.fileId}`, { redirect: 'manual' })
    expect(absent.status).toBe(404)
    await absent.text()
  })

  it('streams an encrypted file only after verifier acceptance and enforces its download limit', async () => {
    const data = new Uint8Array([11, 22, 33, 44, 55, 66])
    const verifier = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    const file = await upload(data, {
      id: crypto.randomUUID(), encrypted: true, verifier, algoVersion: 'argon2id-v1', limit: 1,
    })
    const path = `${ORIGIN}/api/v1/public/files/${file.fileId}/retrieve-ciphertext`
    const denied = await SELF.fetch(path, {
      method: 'POST', body: JSON.stringify({ verifierCandidate: 'wrong' }),
    })
    expect(denied.status).toBe(403)
    await denied.text()
    const accepted = await SELF.fetch(path, {
      method: 'POST', body: JSON.stringify({ verifierCandidate: verifier }),
    })
    expect(accepted.status).toBe(200)
    expect(accepted.headers.get('Content-Type')).toBe('application/octet-stream')
    expect(new Uint8Array(await accepted.arrayBuffer())).toEqual(data)
    const spent = await SELF.fetch(path, {
      method: 'POST', body: JSON.stringify({ verifierCandidate: verifier }),
    })
    expect(spent.status).toBe(410)
    expect(await spent.json()).toEqual({ error: 'EXPIRED' })
  })
})
