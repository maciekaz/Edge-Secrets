import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { cors } from 'hono/cors'
import { getCookie } from 'hono/cookie'
import qrcode from 'qrcode-generator'
import { getLang, renderLangPicker, LANG_PICKER_CSS, LANG_PICKER_JS, type Translations, type LangCode } from './i18n'

// ── Config ────────────────────────────────────────────────────────────────────

const CONFIG = {
  maxTtl: 604800,
  defaultTtl: 86400,
  maxAttempts: 3,
  maxStorage: 9 * 1024 * 1024 * 1024,
  visualTtl: 300,
} as const

// ── Types ─────────────────────────────────────────────────────────────────────

type Bindings = {
  DB: D1Database
  BUCKET: R2Bucket
  SECRETS_STORE: KVNamespace
  PEPPER: string
  CF_TEAM_DOMAIN: string
  CF_AUD: string
  TURNSTILE_SECRET?: string
}

type Lang = Translations

interface FileRecord {
  id: string
  filename: string
  size: number
  created_at: number
  expires_at: number
  status: string
  password_hash: string | null
  max_downloads: number
  download_count: number
  failed_attempts: number
}

interface SecretMetadata {
  verifier: string
  attempts: number
}

interface LinkMetadata {
  url: string
  maxClicks: number
  clicks: number
  createdAt: number
}

interface StoreBody {
  id: string
  encryptedData: string
  verifier: string
  ttl: string | number
}

interface UploadInitBody {
  filename: string
  size: number
  password?: string
  ttl?: number
  limit?: number | string
}

interface UploadCompleteBody {
  key: string
  uploadId: string
  parts: R2UploadedPart[]
  fileId: string
}

// ── Security headers for HTML responses ──────────────────────────────────────

const HTML_SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'text/html;charset=UTF-8',
  'Content-Security-Policy':
    "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'unsafe-inline' https://challenges.cloudflare.com; style-src 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; object-src 'none'; frame-ancestors 'none';",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(unsafe: unknown): unknown {
  if (typeof unsafe !== 'string') return unsafe
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function safeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let mismatch = 0
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return mismatch === 0
}

function generateShortId(length = 7): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join('')
}

function isValidRedirectUrl(raw: string): boolean {
  let u: URL
  try { u = new URL(raw) } catch { return false }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  const h = u.hostname.toLowerCase()
  // Block localhost, loopback, link-local, and RFC-1918 private ranges
  if (
    h === 'localhost' ||
    /^127\./.test(h) ||
    /^0\./.test(h) ||
    /^10\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^169\.254\./.test(h) ||
    h === '::1' ||
    /^fc00:/i.test(h) ||
    /^fd[0-9a-f]{2}:/i.test(h)
  ) return false
  return true
}

const hashPwd = async (p: string | null | undefined, pepper: string): Promise<string | null> => {
  if (!p) return null
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(p + pepper))
  return Array.from(new Uint8Array(buf))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('')
}

async function verifyTurnstile(token: string, secret: string): Promise<boolean> {
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v1/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret, response: token }),
    })
    if (!res.ok) return false
    const data = await res.json<{ success: boolean }>()
    return data.success === true
  } catch {
    return false
  }
}

// RFC 5987 percent-encoding for Content-Disposition filename — prevents header injection
function encodeFilename(filename: string): string {
  return `UTF-8''${encodeURIComponent(filename)}`
}

// ── CF Access JWT Verification ────────────────────────────────────────────────

interface JWK {
  kid: string
  kty: string
  alg: string
  use: string
  n: string
  e: string
}

// Module-level key cache — valid for the lifetime of the isolate (~few hours)
const _keyCache = new Map<string, CryptoKey>()
let _keysFetchedAt = 0
const KEYS_TTL_MS = 3_600_000 // 1 hour

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
}

async function refreshKeys(teamDomain: string): Promise<void> {
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`)
  if (!res.ok) throw new Error('Failed to fetch CF Access JWKS')
  const { keys } = (await res.json()) as { keys: JWK[] }
  _keyCache.clear()
  for (const jwk of keys) {
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    )
    _keyCache.set(jwk.kid, key)
  }
  _keysFetchedAt = Date.now()
}

async function verifyAccessJWT(token: string, teamDomain: string, aud: string): Promise<boolean> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return false
    const [headerB64, payloadB64, sigB64] = parts as [string, string, string]

    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64))) as { kid: string }

    // Refresh key cache if stale or kid not found
    if (Date.now() - _keysFetchedAt > KEYS_TTL_MS || !_keyCache.has(header.kid)) {
      await refreshKeys(teamDomain)
    }

    const key = _keyCache.get(header.kid)
    if (!key) return false

    const valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      b64urlDecode(sigB64),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`)
    )
    if (!valid) return false

    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64))) as {
      aud: string | string[]
      exp: number
      iss: string
    }

    // Verify expiry
    if (payload.exp < Math.floor(Date.now() / 1000)) return false

    // Verify audience matches this application
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
    if (!audiences.includes(aud)) return false

    return true
  } catch {
    return false
  }
}

const requireAccess: MiddlewareHandler<{ Bindings: Bindings }> = async (c, next) => {
  const token =
    c.req.header('Cf-Access-Jwt-Assertion') ??
    getCookie(c, 'CF_Authorization')

  if (!token) return c.text('Unauthorized', 401)

  const valid = await verifyAccessJWT(token, c.env.CF_TEAM_DOMAIN, c.env.CF_AUD)
  if (!valid) return c.text('Unauthorized', 401)

  return next()
}

// ── Hono App ──────────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Bindings }>()

// CORS middleware — handles OPTIONS preflight and injects headers on all routes
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
  })
)

// Bindings guard — fail fast if Cloudflare bindings are not attached
app.use('*', async (c, next) => {
  if (!c.env.DB || !c.env.BUCKET || !c.env.SECRETS_STORE || !c.env.PEPPER || !c.env.CF_TEAM_DOMAIN || !c.env.CF_AUD) {
    return c.text('System Error: Missing Bindings', 500)
  }
  return next()
})

// ── Routes ────────────────────────────────────────────────────────────────────

// CF Access JWT guard on all write/admin endpoints
app.use('/gen', requireAccess)
app.use('/api/store', requireAccess)
app.use('/api/stats', requireAccess)
app.use('/api/upload/*', requireAccess)
app.use('/api/shorten', requireAccess)

app.get('/', (c) => c.redirect('/gen', 302))

app.get('/gen', (c) => {
  const { t, code } = getLang(c.req.raw)
  return c.html(renderGen(c.req.query('t') ?? 'cred', t, code), 200, HTML_SECURITY_HEADERS)
})

app.get('/receive/:id', async (c) => {
  const { t, code } = getLang(c.req.raw)
  const [tsEnabled, tsSiteKey] = await Promise.all([
    c.env.SECRETS_STORE.get('ui:turnstile_creds'),
    c.env.SECRETS_STORE.get('ui:turnstile_site_key'),
  ])
  const turnstileActive = tsEnabled === '1' && !!tsSiteKey && !!c.env.TURNSTILE_SECRET
  return c.html(
    renderReceiveCred(c.req.param('id'), t, code, turnstileActive ? tsSiteKey! : null),
    200,
    HTML_SECURITY_HEADERS
  )
})

app.get('/share/:id', (c) => handleFileDownload(c))
app.post('/share/:id', (c) => handleFilePost(c))

// QR code generator — public, server-side SVG rendering
app.get('/ui/qr', (c) => {
  const raw = c.req.query('d') ?? ''
  if (!raw || raw.length > 2000) return c.text('', 400)

  let data: string
  try { data = decodeURIComponent(raw) } catch { return c.text('', 400) }

  try {
    const qr = qrcode(0, 'M')
    qr.addData(data, 'Byte')
    qr.make()
    const n = qr.getModuleCount()
    const pad = 4
    const cells: string[] = []
    for (let r = 0; r < n; r++)
      for (let col = 0; col < n; col++)
        if (qr.isDark(r, col))
          cells.push(`<rect x="${col + pad}" y="${r + pad}" width="1" height="1"/>`)

    const size = n + pad * 2
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="white"/><g fill="black">${cells.join('')}</g></svg>`
    return new Response(svg, {
      headers: {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=3600',
        'X-Content-Type-Options': 'nosniff',
      },
    })
  } catch {
    return c.text('QR generation failed — data too long', 400)
  }
})

// Global UI config — public read, protected write
app.get('/ui/config', async (c) => {
  const [accent, bg, brand, tagline, tsSiteKey, tsCreds, tsFiles] = await Promise.all([
    c.env.SECRETS_STORE.get('ui:accent'),
    c.env.SECRETS_STORE.get('ui:bg'),
    c.env.SECRETS_STORE.get('ui:brand'),
    c.env.SECRETS_STORE.get('ui:tagline'),
    c.env.SECRETS_STORE.get('ui:turnstile_site_key'),
    c.env.SECRETS_STORE.get('ui:turnstile_creds'),
    c.env.SECRETS_STORE.get('ui:turnstile_files'),
  ])
  return c.json({
    accent:  accent  ?? '#818cf8',
    bg:      bg      ?? '#000000',
    brand:   brand   ?? null,
    tagline: tagline ?? null,
    turnstileSiteKey: tsSiteKey ?? null,
    turnstileCreds:   tsCreds === '1',
    turnstileFiles:   tsFiles === '1',
  })
})

app.post('/api/ui/config', requireAccess, async (c) => {
  const body = await c.req.json<{ accent?: string; bg?: string; brand?: string | null; tagline?: string | null }>()
  const hexRe = /^#[0-9a-fA-F]{6}$/
  if ((body.accent && !hexRe.test(body.accent)) || (body.bg && !hexRe.test(body.bg))) {
    return c.json({ error: 'Invalid color value' }, 400)
  }
  if (body.brand !== undefined && body.brand !== null && body.brand.length > 32) {
    return c.json({ error: 'Brand name max 32 chars' }, 400)
  }
  if (body.tagline !== undefined && body.tagline !== null && body.tagline.length > 60) {
    return c.json({ error: 'Tagline max 60 chars' }, 400)
  }
  await Promise.all([
    body.accent  ? c.env.SECRETS_STORE.put('ui:accent', body.accent)   : Promise.resolve(),
    body.bg      ? c.env.SECRETS_STORE.put('ui:bg', body.bg)           : Promise.resolve(),
    body.brand   !== undefined ? (body.brand   ? c.env.SECRETS_STORE.put('ui:brand', body.brand)     : c.env.SECRETS_STORE.delete('ui:brand'))   : Promise.resolve(),
    body.tagline !== undefined ? (body.tagline ? c.env.SECRETS_STORE.put('ui:tagline', body.tagline) : c.env.SECRETS_STORE.delete('ui:tagline')) : Promise.resolve(),
  ])
  return c.json({ ok: true })
})

// Turnstile settings — site key (public) + per-feature toggles
app.post('/api/ui/turnstile', requireAccess, async (c) => {
  const body = await c.req.json<{ siteKey?: string | null; creds?: boolean; files?: boolean }>()
  if (body.siteKey !== undefined && body.siteKey !== null && typeof body.siteKey !== 'string') {
    return c.json({ error: 'Invalid siteKey' }, 400)
  }
  if (body.siteKey !== undefined && body.siteKey !== null && body.siteKey.length > 128) {
    return c.json({ error: 'Site key too long' }, 400)
  }
  await Promise.all([
    body.siteKey !== undefined
      ? (body.siteKey ? c.env.SECRETS_STORE.put('ui:turnstile_site_key', body.siteKey) : c.env.SECRETS_STORE.delete('ui:turnstile_site_key'))
      : Promise.resolve(),
    body.creds !== undefined
      ? c.env.SECRETS_STORE.put('ui:turnstile_creds', body.creds ? '1' : '0')
      : Promise.resolve(),
    body.files !== undefined
      ? c.env.SECRETS_STORE.put('ui:turnstile_files', body.files ? '1' : '0')
      : Promise.resolve(),
  ])
  return c.json({ ok: true })
})

// URL shortener — create link (protected), redirect (public)
app.post('/api/shorten', async (c) => {
  const body = await c.req.json<{ url?: string; ttl?: number; maxClicks?: number }>()

  if (!body.url || typeof body.url !== 'string') {
    return c.json({ error: 'URL required' }, 400)
  }
  if (!isValidRedirectUrl(body.url)) {
    return c.json({ error: 'Invalid or unsafe URL — must be http/https and not a private address' }, 400)
  }

  const ttlSec =
    body.ttl === -1 ? -1 : Math.min(Math.max(parseInt(String(body.ttl ?? 86400)), 3600), CONFIG.maxTtl)
  const maxClicks =
    body.maxClicks === -1 ? -1 : Math.min(Math.max(parseInt(String(body.maxClicks ?? -1)), 1), 10000)

  const id = generateShortId()
  const meta: LinkMetadata = {
    url: body.url,
    maxClicks,
    clicks: 0,
    createdAt: Date.now(),
  }

  await c.env.SECRETS_STORE.put(`link:${id}`, body.url, {
    ...(ttlSec > 0 ? { expirationTtl: ttlSec } : {}),
    metadata: meta satisfies LinkMetadata,
  })

  const origin = new URL(c.req.url).origin
  return c.json({ id, shortUrl: `${origin}/s/${id}` })
})

app.get('/s/:id', async (c) => {
  const id = c.req.param('id')
  if (!/^[a-zA-Z0-9]{5,12}$/.test(id)) return c.text('Not found', 404)

  const { value: url, metadata } =
    await c.env.SECRETS_STORE.getWithMetadata<LinkMetadata>(`link:${id}`)

  if (!url || !metadata) return c.text('Link not found or expired', 404)

  // Defense-in-depth: re-validate stored URL before redirecting
  if (!isValidRedirectUrl(url)) {
    await c.env.SECRETS_STORE.delete(`link:${id}`)
    return c.text('Invalid link target', 400)
  }

  // Click tracking — enforce limit if set
  if (metadata.maxClicks !== -1) {
    const newClicks = metadata.clicks + 1
    if (newClicks >= metadata.maxClicks) {
      await c.env.SECRETS_STORE.delete(`link:${id}`)
    } else {
      await c.env.SECRETS_STORE.put(`link:${id}`, url, {
        metadata: { ...metadata, clicks: newClicks } satisfies LinkMetadata,
      })
    }
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  })
})

// Logo — public read, protected upload/delete (stored in R2)
app.get('/ui/logo', async (c) => {
  const obj = await c.env.BUCKET.get('ui-logo')
  if (!obj) return c.text('', 404)
  const headers = new Headers()
  headers.set('Content-Type', obj.httpMetadata?.contentType ?? 'image/png')
  headers.set('Cache-Control', 'public, max-age=3600')
  return new Response(obj.body, { headers })
})

app.post('/api/ui/logo', requireAccess, async (c) => {
  const ct = c.req.header('Content-Type') ?? 'image/png'
  const allowed = ['image/png', 'image/svg+xml', 'image/jpeg', 'image/webp']
  if (!allowed.some((t) => ct.startsWith(t))) {
    return c.json({ error: 'Invalid image type — use PNG, SVG, JPEG, or WebP' }, 400)
  }
  const buf = await c.req.arrayBuffer()
  if (buf.byteLength > 262144) {
    return c.json({ error: 'Logo max 256 KB' }, 400)
  }
  await c.env.BUCKET.put('ui-logo', buf, { httpMetadata: { contentType: ct } })
  return c.json({ ok: true })
})

app.delete('/api/ui/logo', requireAccess, async (c) => {
  await c.env.BUCKET.delete('ui-logo')
  return c.json({ ok: true })
})

// Store encrypted secret in KV
app.post('/api/store', async (c) => {
  const body = await c.req.json<StoreBody>()
  await c.env.SECRETS_STORE.put(body.id, body.encryptedData, {
    expirationTtl: Math.min(
      parseInt(String(body.ttl)) || CONFIG.defaultTtl,
      CONFIG.maxTtl
    ),
    metadata: { verifier: body.verifier, attempts: 0 } satisfies SecretMetadata,
  })
  return c.json({ success: true })
})

// Retrieve encrypted secret from KV (verifier check + burn-on-read)
app.post('/api/retrieve/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json<{ verifierCandidate: string; cfTurnstileToken?: string }>()
  const { verifierCandidate } = body

  // Turnstile verification — runs before any KV access
  const tsEnabled = await c.env.SECRETS_STORE.get('ui:turnstile_creds')
  if (tsEnabled === '1' && c.env.TURNSTILE_SECRET) {
    const token = body.cfTurnstileToken ?? ''
    const valid = await verifyTurnstile(token, c.env.TURNSTILE_SECRET)
    if (!valid) return c.json({ error: 'CHALLENGE_FAILED' }, 403)
  }

  const { value, metadata } =
    await c.env.SECRETS_STORE.getWithMetadata<SecretMetadata>(id)
  if (!value || !metadata) {
    return c.json({ error: 'Link wygasł, lub klucz jest nieprawidłowy' }, 404)
  }
  if (!safeCompare(metadata.verifier, verifierCandidate)) {
    const attempts = (metadata.attempts ?? 0) + 1
    if (attempts >= CONFIG.maxAttempts) {
      await c.env.SECRETS_STORE.delete(id)
      return c.json({ error: 'TERMINATED' }, 410)
    }
    await c.env.SECRETS_STORE.put(id, value, {
      metadata: { ...metadata, attempts } satisfies SecretMetadata,
      expirationTtl: CONFIG.defaultTtl,
    })
    return c.json({ error: `RETRY_${CONFIG.maxAttempts - attempts}` }, 403)
  }
  await c.env.SECRETS_STORE.delete(id)
  return c.json({ encryptedData: value })
})

// Storage stats + file list
app.get('/api/stats', async (c) => {
  const s = await c.env.DB.prepare(
    'SELECT SUM(size) as used FROM files WHERE status!="downloaded"'
  ).first<{ used: number }>()
  const f = await c.env.DB.prepare(
    'SELECT * FROM files WHERE status!="downloaded" ORDER BY created_at DESC'
  ).all<FileRecord>()
  return c.json({ used: s?.used ?? 0, limit: CONFIG.maxStorage, files: f.results })
})

// Initiate multipart upload
app.post('/api/upload/init', async (c) => {
  const { filename, size, password, ttl, limit } = await c.req.json<UploadInitBody>()
  const s = await c.env.DB.prepare(
    'SELECT SUM(size) as t FROM files WHERE status!="downloaded"'
  ).first<{ t: number }>()
  if ((s?.t ?? 0) + size > CONFIG.maxStorage) {
    return c.json({ error: 'STORAGE_LIMIT' }, 507)
  }
  const safeTtl = Math.min(ttl ?? 172_800_000, CONFIG.maxTtl * 1000)
  const id = crypto.randomUUID()
  const mp = await c.env.BUCKET.createMultipartUpload(id)
  await c.env.DB.prepare(
    'INSERT INTO files (id,filename,size,created_at,expires_at,status,password_hash,max_downloads,download_count,failed_attempts) VALUES (?,?,?,?,?, "pending", ?, ?, 0, 0)'
  )
    .bind(
      id,
      filename,
      size,
      Date.now(),
      Date.now() + safeTtl,
      await hashPwd(password, c.env.PEPPER),
      parseInt(String(limit ?? 1))
    )
    .run()
  return c.json({ key: id, uploadId: mp.uploadId, fileId: id })
})

// Upload a single part of a multipart upload
app.put('/api/upload/part', async (c) => {
  const key = c.req.query('key')
  const uploadId = c.req.query('id')
  const num = c.req.query('num')
  if (!key || !uploadId || !num) {
    return c.json({ error: 'Missing query parameters: key, id, num' }, 400)
  }
  const body = c.req.raw.body
  if (!body) return c.json({ error: 'Empty request body' }, 400)
  const mp = c.env.BUCKET.resumeMultipartUpload(key, uploadId)
  const part = await mp.uploadPart(parseInt(num), body)
  return c.json(part)
})

// Finalize multipart upload
app.post('/api/upload/complete', async (c) => {
  const body = await c.req.json<UploadCompleteBody>()
  const mp = c.env.BUCKET.resumeMultipartUpload(body.key, body.uploadId)
  await mp.complete(body.parts)
  await c.env.DB.prepare('UPDATE files SET status="ready" WHERE id=?')
    .bind(body.fileId)
    .run()
  return c.json({ ok: true })
})

// Delete file from R2 + D1
app.delete('/api/del/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.BUCKET.delete(id)
  await c.env.DB.prepare('DELETE FROM files WHERE id=?').bind(id).run()
  return c.json({ ok: true })
})

// Default handlers
app.notFound((c) => c.text('NOT_FOUND', 404))

app.onError((err, c) => {
  console.error('[Worker Error]', err.message)
  return c.text('Internal Server Error', 500)
})

// ── File Download Handlers ────────────────────────────────────────────────────

async function handleFileDownload(c: Context<{ Bindings: Bindings }>): Promise<Response> {
  const id = c.req.param('id')
  if (!id) return c.text('BAD_REQUEST', 400)
  const env = c.env
  const { t: lang, code: langCode } = getLang(c.req.raw)

  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?')
    .bind(id)
    .first<FileRecord>()
  if (!f) return c.html('FILE_NOT_FOUND', 404, HTML_SECURITY_HEADERS)
  if (f.status === 'downloaded' || f.expires_at < Date.now()) {
    return c.html('LINK_EXPIRED', 410, HTML_SECURITY_HEADERS)
  }

  // Check Turnstile settings — if active, always show gate page (Option B)
  const [tsEnabled, tsSiteKey] = await Promise.all([
    env.SECRETS_STORE.get('ui:turnstile_files'),
    env.SECRETS_STORE.get('ui:turnstile_site_key'),
  ])
  const turnstileActive = tsEnabled === '1' && !!tsSiteKey && !!env.TURNSTILE_SECRET

  if (turnstileActive) {
    return c.html(
      renderFileTurnstileGate(id, f.filename, !!f.password_hash, lang, langCode, tsSiteKey!, false),
      200,
      HTML_SECURITY_HEADERS
    )
  }

  // Legacy path (no Turnstile): password check via query param
  if (f.password_hash) {
    const pwdParam = c.req.query('pwd')
    if (!pwdParam) {
      return c.html(renderReceiveFile(f.filename, lang, langCode), 200, HTML_SECURITY_HEADERS)
    }
    if ((await hashPwd(pwdParam, env.PEPPER)) !== f.password_hash) {
      const att = (f.failed_attempts ?? 0) + 1
      if (att >= CONFIG.maxAttempts) {
        c.executionCtx.waitUntil(env.BUCKET.delete(id))
        await env.DB.prepare('DELETE FROM files WHERE id=?').bind(id).run()
        return c.text('FILE_DELETED', 410)
      }
      await env.DB.prepare('UPDATE files SET failed_attempts=? WHERE id=?')
        .bind(att, id)
        .run()
      return c.text('INVALID_PASSWORD', 403)
    }
  }

  return serveFile(c, id, f)
}

async function handleFilePost(c: Context<{ Bindings: Bindings }>): Promise<Response> {
  const id = c.req.param('id')
  if (!id) return c.text('BAD_REQUEST', 400)
  const env = c.env
  const { t: lang, code: langCode } = getLang(c.req.raw)

  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?')
    .bind(id)
    .first<FileRecord>()
  if (!f) return c.html('FILE_NOT_FOUND', 404, HTML_SECURITY_HEADERS)
  if (f.status === 'downloaded' || f.expires_at < Date.now()) {
    return c.html('LINK_EXPIRED', 410, HTML_SECURITY_HEADERS)
  }

  const form = await c.req.formData()
  const tsToken = form.get('cf-turnstile-response') as string | null
  const pwdParam = form.get('pwd') as string | null

  // Verify Turnstile token
  const [tsEnabled, tsSiteKey] = await Promise.all([
    env.SECRETS_STORE.get('ui:turnstile_files'),
    env.SECRETS_STORE.get('ui:turnstile_site_key'),
  ])
  const turnstileActive = tsEnabled === '1' && !!tsSiteKey && !!env.TURNSTILE_SECRET

  if (turnstileActive) {
    const valid = await verifyTurnstile(tsToken ?? '', env.TURNSTILE_SECRET!)
    if (!valid) {
      // Redirect back to GET — fresh challenge
      return new Response(null, { status: 303, headers: { Location: `/share/${id}` } })
    }
  }

  // Password check
  if (f.password_hash) {
    if (!pwdParam) {
      return c.html(
        renderFileTurnstileGate(id, f.filename, true, lang, langCode, tsSiteKey ?? '', false),
        403,
        HTML_SECURITY_HEADERS
      )
    }
    if ((await hashPwd(pwdParam, env.PEPPER)) !== f.password_hash) {
      const att = (f.failed_attempts ?? 0) + 1
      if (att >= CONFIG.maxAttempts) {
        c.executionCtx.waitUntil(env.BUCKET.delete(id))
        await env.DB.prepare('DELETE FROM files WHERE id=?').bind(id).run()
        return c.text('FILE_DELETED', 410)
      }
      await env.DB.prepare('UPDATE files SET failed_attempts=? WHERE id=?')
        .bind(att, id)
        .run()
      // Re-render gate with error (fresh challenge needed)
      return new Response(null, { status: 303, headers: { Location: `/share/${id}?err=1` } })
    }
  }

  return serveFile(c, id, f)
}

async function serveFile(c: Context<{ Bindings: Bindings }>, id: string, f: FileRecord): Promise<Response> {
  const env = c.env
  const curDL = (f.download_count ?? 0) + 1
  const shouldBurn = f.max_downloads !== -1 && curDL >= f.max_downloads

  if (shouldBurn) {
    await env.DB.prepare('UPDATE files SET status="downloaded", download_count=? WHERE id=?')
      .bind(curDL, id)
      .run()
    c.executionCtx.waitUntil(env.BUCKET.delete(id))
  } else {
    await env.DB.prepare('UPDATE files SET download_count=? WHERE id=?')
      .bind(curDL, id)
      .run()
  }

  const obj = await env.BUCKET.get(id)
  if (!obj) return c.text('OBJECT_MISSING', 404)

  const headers = new Headers()
  obj.writeHttpMetadata(headers)
  // RFC 5987 encoding prevents header injection via malicious filenames
  headers.set('Content-Disposition', `attachment; filename*=${encodeFilename(f.filename)}`)
  headers.set('Cache-Control', 'no-store')
  headers.set('Access-Control-Allow-Origin', '*')
  return new Response(obj.body, { headers })
}

// ── Scheduled Handler (cron cleanup) ─────────────────────────────────────────

async function handleScheduled(_event: ScheduledEvent, env: Bindings): Promise<void> {
  if (!env.DB || !env.BUCKET) return
  const expired = await env.DB.prepare('SELECT id FROM files WHERE expires_at < ?')
    .bind(Date.now())
    .all<{ id: string }>()
  for (const f of expired.results) {
    await env.BUCKET.delete(f.id)
    await env.DB.prepare('DELETE FROM files WHERE id=?').bind(f.id).run()
  }
}

// ── Export ────────────────────────────────────────────────────────────────────

export default {
  fetch: app.fetch,
  scheduled: handleScheduled,
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML Templates
// ─────────────────────────────────────────────────────────────────────────────

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
:root {
  --accent: #818cf8;
  --accent-dim: rgba(129,140,248,0.07);
  --accent-glow: rgba(129,140,248,0.12);
  --bg: #000; --surface: #060609; --surface-2: #0c0c12; --surface-3: #111118;
  --border: rgba(255,255,255,0.04); --border-strong: rgba(255,255,255,0.08);
  --text: #e8e8f2; --text-muted: #4a4a64; --text-dim: #1e1e30;
  --success: #34d399; --danger: #f87171;
}
*{box-sizing:border-box;font-family:'Inter',sans-serif;margin:0}
body{background:var(--bg);display:flex;flex-direction:column;justify-content:center;align-items:center;min-height:100vh;padding:20px;color:var(--text);position:relative}
body::before{content:'';position:fixed;top:50%;left:50%;width:min(700px,90vw);height:min(700px,90vh);transform:translate(-50%,-50%);background:radial-gradient(circle,var(--accent-glow) 0%,transparent 65%);pointer-events:none;z-index:0;transition:background 0.4s}
.card{background:var(--surface);width:100%;max-width:640px;border:1px solid var(--border-strong);padding:40px;position:relative;z-index:1;animation:cardIn 0.45s cubic-bezier(0.16,1,0.3,1);box-shadow:0 0 120px -40px var(--accent-glow)}
.card::before{content:'';position:absolute;top:0;left:50%;right:50%;height:1px;background:var(--accent);animation:drawLine 0.6s 0.15s cubic-bezier(0.16,1,0.3,1) forwards}
.card::after{content:'';position:absolute;top:0;left:0;right:0;height:120px;background:linear-gradient(180deg,var(--accent-dim),transparent);pointer-events:none;opacity:0;animation:glowFade 0.8s 0.2s forwards}
@keyframes cardIn{from{opacity:0;transform:translateY(18px) scale(0.98)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes drawLine{to{left:0;right:0}}
@keyframes glowFade{to{opacity:1}}
.brand-header{text-align:center;margin-bottom:30px}
.brand-logo{font-size:0.82rem;font-weight:800;letter-spacing:0.22em;color:var(--accent);display:inline-block;position:relative}
.brand-logo::after{content:'';display:block;width:0;height:1px;background:var(--accent);margin:6px auto 0;animation:drawBrand 0.5s 0.4s cubic-bezier(0.16,1,0.3,1) forwards}
.brand-tagline{font-size:0.58rem;color:var(--text-muted);letter-spacing:0.14em;text-transform:uppercase;margin-top:6px}
.cfg-input{background:var(--surface-2);border:1px solid var(--border-strong);color:var(--text);padding:5px 8px;font-size:0.7rem;font-family:'Inter',sans-serif;outline:none;transition:border-color 0.2s;width:130px;border-radius:0}
.cfg-input:focus{border-color:var(--accent)}
@keyframes drawBrand{to{width:100%}}
.tabs{display:flex;background:var(--surface-2);border:1px solid var(--border);margin-bottom:26px;position:relative;overflow:hidden}
.tab{flex:1;text-align:center;padding:11px;font-weight:600;font-size:0.72rem;text-decoration:none;color:var(--text-muted);transition:color 0.2s,background 0.2s;border:none;letter-spacing:0.1em;text-transform:uppercase;position:relative;z-index:1}
.tab:hover{color:var(--text);background:rgba(255,255,255,0.02)}
.tab.active{color:var(--accent);background:var(--accent-dim)}
.tab.active::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:var(--accent)}
.label-row{display:flex;justify-content:space-between;align-items:center;font-weight:600;font-size:0.65rem;text-transform:uppercase;margin-bottom:8px;color:var(--text-muted);letter-spacing:0.12em}
.action-link{cursor:pointer;color:var(--accent);font-size:0.65rem;background:var(--accent-dim);padding:3px 10px;transition:all 0.2s;font-weight:600;letter-spacing:0.06em;border:1px solid transparent}
.action-link:hover{background:var(--accent);color:var(--bg)}
textarea,input,select{width:100%;border:1px solid var(--border-strong);padding:13px 15px;font-size:0.88rem;border-radius:0;margin-bottom:18px;outline:none;background:var(--surface-2);color:var(--text);transition:border-color 0.2s,box-shadow 0.2s;-webkit-appearance:none;appearance:none}
textarea:focus,input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-dim)}
textarea{min-height:120px;font-family:'Inter',monospace;resize:vertical}
.btn{width:100%;padding:15px;background:var(--accent);color:var(--bg);border:none;border-radius:0;font-weight:700;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.16em;cursor:pointer;display:flex;justify-content:center;align-items:center;gap:10px;position:relative;overflow:hidden;transition:box-shadow 0.2s}
.btn>*{pointer-events:none}
.btn::after{content:'';position:absolute;top:0;left:0;bottom:0;width:0;background:rgba(255,255,255,0.08);transition:width 0.3s cubic-bezier(0.16,1,0.3,1)}
.btn:hover::after{width:100%}
.btn:hover{box-shadow:0 0 30px -8px var(--accent-glow)}
.btn:active::after{background:rgba(0,0,0,0.12);width:100%}
.btn-del{padding:5px 12px;font-size:0.65rem;background:transparent;color:var(--danger);border:1px solid rgba(248,113,113,0.3);border-radius:0;cursor:pointer;font-weight:600;transition:all 0.2s;letter-spacing:0.06em;text-transform:uppercase}
.btn-del:hover{background:var(--danger);color:var(--bg);border-color:var(--danger)}
.res-box{border:1px solid var(--border-strong);padding:20px;background:var(--surface-2)}
.storage-info{display:flex;justify-content:space-between;font-size:0.7rem;font-weight:500;color:var(--text-muted);margin-bottom:6px;letter-spacing:0.04em}
.timer-wrap{background:var(--surface-2);border:1px solid var(--border);height:3px;overflow:hidden;margin-bottom:22px}
.timer-fill{height:100%;background:var(--accent);width:0%;transition:width 0.8s cubic-bezier(0.4,0,0.2,1)}
.drop-zone{border:1px dashed var(--border-strong);padding:36px 20px;text-align:center;cursor:pointer;background:var(--surface-2);margin-bottom:18px;transition:all 0.2s;position:relative}
.drop-zone>*{pointer-events:none}
.drop-zone:hover{border-color:var(--accent);background:var(--accent-dim);box-shadow:0 0 40px -12px var(--accent-glow)}
.input-group{display:flex;gap:6px;margin-bottom:18px}
.input-group input{margin-bottom:0;flex:1}
.btn-copy{background:var(--surface-2);color:var(--text-muted);border:1px solid var(--border-strong);border-radius:0;font-weight:600;padding:0 16px;cursor:pointer;min-width:80px;transition:all 0.2s;display:flex;align-items:center;justify-content:center;font-size:0.65rem;text-transform:uppercase;letter-spacing:0.08em}
.btn-copy>*{pointer-events:none}
.btn-copy:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.btn-qr{background:var(--surface-2);color:var(--text-muted);border:1px solid var(--border-strong);border-radius:0;font-weight:700;padding:0 11px;cursor:pointer;flex-shrink:0;transition:all 0.2s;display:flex;align-items:center;justify-content:center;font-size:0.62rem;letter-spacing:0.04em}
.btn-qr:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.qr-modal-img{width:200px;height:200px;display:block;margin:0 auto 14px;background:#fff;padding:8px;image-rendering:pixelated}
.overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);backdrop-filter:blur(12px);z-index:100;display:none;justify-content:center;align-items:center}
.modal{background:var(--surface);border:1px solid var(--border-strong);padding:32px;text-align:center;max-width:360px;width:90%;animation:cardIn 0.25s cubic-bezier(0.16,1,0.3,1);position:relative;box-shadow:0 0 80px -20px var(--accent-glow)}
.modal::before{content:'';position:absolute;top:0;left:50%;right:50%;height:1px;background:var(--accent);animation:drawLine 0.4s 0.1s cubic-bezier(0.16,1,0.3,1) forwards}
.modal h3{margin-top:0;color:var(--accent);font-size:0.8rem;text-transform:uppercase;letter-spacing:0.12em}
.modal p{color:var(--text-muted);font-size:0.85rem}
.modal-btn{margin-top:20px;width:100%;padding:12px;background:var(--accent);color:var(--bg);border:none;border-radius:0;font-weight:700;cursor:pointer;text-transform:uppercase;font-size:0.72rem;letter-spacing:0.12em;transition:opacity 0.15s}
.modal-btn:hover{opacity:0.85}
pre{background:var(--surface-2);color:var(--accent);padding:20px;white-space:pre-wrap;word-break:break-all;font-size:0.92rem;margin-bottom:22px;font-family:'Courier New',monospace;border:1px solid var(--border-strong);border-left:2px solid var(--accent)}
.hidden{display:none!important}
.spinner{width:14px;height:14px;border:2px solid rgba(0,0,0,0.2);border-top-color:var(--bg);border-radius:50%;animation:rot 0.6s linear infinite;display:none}
@keyframes rot{to{transform:rotate(360deg)}}
.meta-tag{font-size:0.6rem;background:var(--surface-2);border:1px solid var(--border);padding:2px 7px;color:var(--text-muted);margin-left:8px;font-weight:600;letter-spacing:0.05em}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:0.8rem}
td,th{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left;color:var(--text)}
th{color:var(--text-muted);font-size:0.62rem;text-transform:uppercase;letter-spacing:0.09em;font-weight:600}
footer{margin-top:28px;color:var(--text-dim);font-size:0.7rem;text-align:center;letter-spacing:0.06em}
.timer-text{position:absolute;width:100%;text-align:center;font-size:0.72rem;font-weight:600;color:var(--text-muted);letter-spacing:0.06em}
.cfg-toggle{position:fixed;top:18px;right:18px;z-index:10;width:32px;height:32px;display:flex;align-items:center;justify-content:center;color:var(--text-muted);cursor:pointer;transition:color 0.2s,transform 0.3s;border:1px solid var(--border);background:var(--surface)}
.cfg-toggle:hover{color:var(--accent);transform:rotate(45deg);border-color:var(--accent)}
.cfg-toggle svg{width:15px;height:15px}
.cfg-panel{position:fixed;top:56px;right:18px;z-index:10;background:var(--surface);border:1px solid var(--border-strong);padding:16px 20px;animation:cardIn 0.2s cubic-bezier(0.16,1,0.3,1);min-width:200px}
.cfg-panel::before{content:'';position:absolute;top:0;left:50%;right:50%;height:1px;background:var(--accent);animation:drawLine 0.3s cubic-bezier(0.16,1,0.3,1) forwards}
.cfg-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.cfg-label{font-size:0.62rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted)}
.cfg-color{-webkit-appearance:none;appearance:none;width:28px;height:28px;border:1px solid var(--border-strong);padding:0;cursor:pointer;background:none;transition:border-color 0.2s}
.cfg-color::-webkit-color-swatch-wrapper{padding:0}
.cfg-color::-webkit-color-swatch{border:none}
.cfg-color::-moz-color-swatch{border:none}
.cfg-color:hover{border-color:var(--accent)}
.cfg-swatch{width:6px;height:6px;background:var(--accent);transition:background 0.2s}
.cfg-divider{height:1px;background:var(--border);margin:12px 0}
.cfg-presets{display:flex;gap:7px;flex-wrap:wrap;margin-top:2px}
.cfg-preset,.cfg-preset-bg{width:20px;height:20px;border:1px solid transparent;cursor:pointer;transition:transform 0.15s,border-color 0.15s;flex-shrink:0}
.cfg-preset:hover,.cfg-preset-bg:hover{transform:scale(1.25);border-color:rgba(255,255,255,0.3)}
.cfg-preset.active,.cfg-preset-bg.active{border-color:#fff}
.cfg-section{margin-bottom:10px}
.cfg-section-label{font-size:0.58rem;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px}
.cfg-picker-row{display:flex;align-items:center;gap:8px;margin-top:8px}
.cfg-save{width:100%;padding:9px;background:var(--accent);color:var(--bg);border:none;font-weight:700;font-size:0.65rem;text-transform:uppercase;letter-spacing:0.14em;cursor:pointer;transition:opacity 0.2s,box-shadow 0.2s;margin-top:2px}
.cfg-save:hover:not(:disabled){opacity:0.85;box-shadow:0 0 20px -6px var(--accent-glow)}
.cfg-save:disabled{opacity:0.5;cursor:default}
.cfg-save.saved{background:var(--success)!important;color:#000}
.brand-logo-img{max-height:40px;max-width:200px;object-fit:contain;display:block;margin:0 auto 12px}
.cfg-upload{display:inline-flex;align-items:center;justify-content:center;padding:6px 14px;background:var(--surface-2);color:var(--text-muted);border:1px solid var(--border-strong);font-weight:600;font-size:0.6rem;text-transform:uppercase;letter-spacing:0.08em;cursor:pointer;transition:all 0.2s;flex:1;text-align:center}
.cfg-upload:hover{border-color:var(--accent);color:var(--accent)}
.cfg-upload-del:hover{border-color:var(--danger)!important;color:var(--danger)!important}
.cfg-logo-preview{max-height:32px;max-width:120px;object-fit:contain}
[data-theme="light"]{--bg:#eeeef5;--surface:#f8f8fc;--surface-2:#e4e4ee;--surface-3:#d8d8e8;--text:#14141e;--text-muted:rgba(20,20,30,0.45);--text-dim:rgba(20,20,30,0.22);--border:rgba(0,0,0,0.08);--border-strong:rgba(0,0,0,0.14)}
.theme-toggle{position:fixed;top:18px;left:18px;z-index:10;width:32px;height:32px;display:flex;align-items:center;justify-content:center;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text-muted);font-size:14px;transition:color 0.2s,border-color 0.2s}
.theme-toggle:hover{color:var(--accent);border-color:var(--accent)}
${LANG_PICKER_CSS}
.ts-toggle-row{display:flex;align-items:center;justify-content:space-between;margin-top:8px}
.ts-toggle{position:relative;width:36px;height:20px;flex-shrink:0}
.ts-toggle input{opacity:0;width:0;height:0;position:absolute}
.ts-track{position:absolute;inset:0;background:var(--border-strong);border-radius:20px;cursor:pointer;transition:background 0.2s}
.ts-toggle input:checked+.ts-track{background:var(--accent)}
.ts-thumb{position:absolute;top:3px;left:3px;width:14px;height:14px;background:#fff;border-radius:50%;transition:transform 0.2s;pointer-events:none}
.ts-toggle input:checked~.ts-thumb{transform:translateX(16px)}
.ts-verify-wrap{text-align:center;padding:20px 0 10px}
.ts-verify-label{font-size:0.65rem;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);margin-bottom:16px;display:block}`

const CLIENT_JS = `
<script>
const get = (id) => document.getElementById(id);
const modal = (t, m) => { get('mT').innerText = t; get('mMsg').innerText = m; get('ov').style.display = 'flex'; };
const setL = (btn, s) => { if (btn) { btn.disabled = s; const sp = btn.querySelector('.spinner'); if (sp) sp.style.display = s ? 'block' : 'none'; } };

var _customBg = '#000000';
function _applyBgVars(hex) {
    var r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
    var mix=function(rt){return 'rgb('+Math.round(r+(255-r)*rt)+','+Math.round(g+(255-g)*rt)+','+Math.round(b+(255-b)*rt)+')';};
    var s=document.documentElement.style;
    s.setProperty('--bg',hex);s.setProperty('--surface',mix(0.024));s.setProperty('--surface-2',mix(0.047));s.setProperty('--surface-3',mix(0.069));
}
function setAccent(hex) {
    var r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
    var s=document.documentElement.style;
    s.setProperty('--accent',hex);s.setProperty('--accent-dim','rgba('+r+','+g+','+b+',0.07)');s.setProperty('--accent-glow','rgba('+r+','+g+','+b+',0.12)');
    var sw=get('cfgSwatch');if(sw)sw.style.background=hex;
    var lbl=get('cfgAccentHex');if(lbl)lbl.textContent=hex;
    document.querySelectorAll('.cfg-preset').forEach(function(el){el.classList.toggle('active',el.getAttribute('onclick')==="pickPreset('"+hex+"')");});
}
function pickPreset(hex){setAccent(hex);var p=get('accentPicker');if(p)p.value=hex;}
function setBg(hex) {
    _customBg=hex;
    if(document.documentElement.getAttribute('data-theme')!=='light')_applyBgVars(hex);
    var sw=get('cfgBgSwatch');if(sw)sw.style.background=hex;
    var lbl=get('cfgBgHex');if(lbl)lbl.textContent=hex;
    document.querySelectorAll('.cfg-preset-bg').forEach(function(el){el.classList.toggle('active',el.getAttribute('onclick')==="pickBgPreset('"+hex+"')");});
}
function pickBgPreset(hex){setBg(hex);var p=get('bgPicker');if(p)p.value=hex;}
function applyTheme(t) {
    document.documentElement.setAttribute('data-theme',t);
    var btn=get('themeToggle');if(btn)btn.textContent=t==='dark'?'☀':'🌙';
    localStorage.setItem('es-theme',t);
    if(t==='light'){var s=document.documentElement.style;s.removeProperty('--bg');s.removeProperty('--surface');s.removeProperty('--surface-2');s.removeProperty('--surface-3');}
    else{_applyBgVars(_customBg);}
}
function toggleTheme(){var cur=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(cur==='dark'?'light':'dark');}
function _applyBranding(brand,tagline){
    var bn=get('brandName');if(bn&&brand)bn.textContent=brand;
    var bt=get('brandTagline');if(bt){bt.textContent=tagline||'';bt.style.display=tagline?'block':'none';}
}
function previewBrand(){
    var n=get('cfgBrandName'),t=get('cfgTagline');
    _applyBranding(n?n.value:'',t?t.value:'');
}
function saveConfig(){
    var accent=document.documentElement.style.getPropertyValue('--accent').trim()||'#818cf8';
    var bg=_customBg;
    var brand=(get('cfgBrandName')||{value:''}).value.trim();
    var tagline=(get('cfgTagline')||{value:''}).value.trim();
    var sk=(get('cfgTsSiteKey')||{value:''}).value.trim();
    var tsCreds=!!(get('cfgTsCreds')||{}).checked;
    var tsFiles=!!(get('cfgTsFiles')||{}).checked;
    var btn=get('cfgSave');if(btn){btn.disabled=true;btn.textContent='...';}
    Promise.all([
        fetch('/api/ui/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({accent:accent,bg:bg,brand:brand||null,tagline:tagline||null})}),
        fetch('/api/ui/turnstile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({siteKey:sk||null,creds:tsCreds,files:tsFiles})})
    ])
        .then(function(){if(btn){btn.textContent=window.L.js_saved;btn.classList.add('saved');setTimeout(function(){btn.textContent=window.L.js_save;btn.classList.remove('saved');btn.disabled=false;},2000);}})
        .catch(function(){if(btn){btn.textContent=window.L.js_error;btn.disabled=false;setTimeout(function(){btn.textContent=window.L.js_save;},2000);}});
}
function uploadLogo(){
    var input=get('logoInput');if(!input||!input.files.length)return;var file=input.files[0];
    if(file.size>262144){modal(window.L.js_error,window.L.js_logo_max);return;}
    fetch('/api/ui/logo',{method:'POST',headers:{'Content-Type':file.type},body:file})
        .then(function(r){if(!r.ok)throw r;return r.json();})
        .then(function(){
            var ts='?'+Date.now();
            var m=get('brandLogoImg');if(m){m.src='/ui/logo'+ts;m.style.display='block';}
            var pv=get('logoPreview');if(pv){pv.src='/ui/logo'+ts;pv.style.display='block';}
            var st=get('logoStatus');if(st)st.textContent=window.L.js_logo_active;
        })
        .catch(function(){modal(window.L.js_error,window.L.js_logo_fail);});
}
function removeLogo(){
    fetch('/api/ui/logo',{method:'DELETE'})
        .then(function(r){if(!r.ok)throw r;return r.json();})
        .then(function(){
            var m=get('brandLogoImg');if(m)m.style.display='none';
            var pv=get('logoPreview');if(pv)pv.style.display='none';
            var st=get('logoStatus');if(st)st.textContent=window.L.js_no_logo;
        })
        .catch(function(){});
}
async function shorten(){
    var urlEl=get('lurl');if(!urlEl)return;
    var url=urlEl.value.trim();
    if(!url){modal(window.L.js_error,window.L.js_enter_url);return;}
    var btn=get('btnLink');setL(btn,true);
    try{
        var r=await fetch('/api/shorten',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url,ttl:parseInt(get('lttl').value),maxClicks:parseInt(get('lclicks').value)})});
        var d=await r.json();
        if(!r.ok||d.error){modal(window.L.js_error,d.error||window.L.js_error_occurred);return;}
        get('shortLink').value=d.shortUrl;
        get('link-res').classList.remove('hidden');
    }catch(e){modal(window.L.js_error,window.L.js_shorten_fail);}
    finally{setL(btn,false);}
}
(function(){
    var savedTheme=localStorage.getItem('es-theme');
    var sysTheme=window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
    applyTheme(savedTheme||sysTheme);
    fetch('/ui/config').then(function(r){return r.json();}).then(function(cfg){
        if(cfg.accent){setAccent(cfg.accent);var p=get('accentPicker');if(p)p.value=cfg.accent;}
        if(cfg.bg){_customBg=cfg.bg;var p2=get('bgPicker');if(p2)p2.value=cfg.bg;var sw=get('cfgBgSwatch');if(sw)sw.style.background=cfg.bg;var lbl=get('cfgBgHex');if(lbl)lbl.textContent=cfg.bg;if(document.documentElement.getAttribute('data-theme')!=='light')_applyBgVars(cfg.bg);}
        _applyBranding(cfg.brand||'',cfg.tagline||'');
        var ni=get('cfgBrandName');if(ni&&cfg.brand)ni.value=cfg.brand;
        var ti=get('cfgTagline');if(ti&&cfg.tagline)ti.value=cfg.tagline;
        var tsk=get('cfgTsSiteKey');if(tsk&&cfg.turnstileSiteKey)tsk.value=cfg.turnstileSiteKey;
        var tc=get('cfgTsCreds');if(tc)tc.checked=!!cfg.turnstileCreds;
        var tf=get('cfgTsFiles');if(tf)tf.checked=!!cfg.turnstileFiles;
    }).catch(function(){});
    var bh=document.querySelector('.brand-header');
    if(bh){
        var li=document.createElement('img');li.id='brandLogoImg';li.className='brand-logo-img';
        li.src='/ui/logo';li.style.display='none';
        li.onload=function(){this.style.display='block';var st=get('logoStatus');if(st)st.textContent=window.L.js_logo_active;};
        li.onerror=function(){this.style.display='none';};
        bh.insertBefore(li,bh.firstChild);
    }
})();

function showQR(url){
    get('qrImg').src='/ui/qr?d='+encodeURIComponent(url);
    get('qrTxt').textContent=url;
    var qt=get('qrTitle');if(qt)qt.textContent=window.L.qr_title;
    var qc=get('qrCloseBtn');if(qc)qc.textContent=window.L.qr_close;
    get('qrOv').style.display='flex';
}
function escapeHtml(u) { return u.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }

async function copyBtn(btn, text) {
    try {
        await navigator.clipboard.writeText(text);
        const orig = btn.innerText;
        btn.innerText = window.L.js_copied;
        btn.style.background = 'var(--success)';
        btn.style.color = '#fff';
        setTimeout(() => { btn.innerText = orig; btn.style.background = ''; btn.style.color = ''; }, 1500);
    } catch (e) { modal('INFO', window.L.js_manual + text); }
}

function showFile() {
    const f = get('f').files[0];
    if (f) {
        const d = get('dtxt');
        d.innerHTML = '<span style="font-size:2.5rem">\u{1F4C4}</span><br><strong style="font-size:1.1rem; color:var(--text)">' + escapeHtml(f.name) + '</strong><br><span style="color:var(--text-muted); font-size:0.9rem; font-weight:500">' + (f.size / 1048576).toFixed(2) + ' MB</span>';
        d.parentNode.style.borderColor = 'var(--accent)';
        d.parentNode.style.backgroundColor = 'var(--accent-dim)';
    }
}

async function derive(p, s, t) {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey("raw", enc.encode(p), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
    if (t === 'v') {
        const b = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(s + "_v"), iterations: 50000, hash: "SHA-256" }, km, 256);
        return btoa(String.fromCharCode(...new Uint8Array(b)));
    }
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode(s), iterations: 100000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const genS = () => { const c = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789!?@"; let p = ""; const r = new Uint32Array(15); crypto.getRandomValues(r); for (let i = 0; i < 15; i++) p += c[r[i] % c.length]; if (get('body')) get('body').value = p; };
const genK = () => { const c = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789#%&"; let p = ""; const r = new Uint32Array(20); crypto.getRandomValues(r); for (let i = 0; i < 20; i++) p += c[r[i] % c.length]; if (get('pass')) get('pass').value = p; };

async function processStore() {
    const b = get('body').value, p = get('pass').value, ttl = get('ttl').value;
    if (!b || !p) return modal(window.L.js_error, window.L.js_enter_data);
    setL(get('btnGo'), 1);
    try {
        const id = crypto.randomUUID(), key = await derive(p, id, 'k'), iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(b)), vf = await derive(p, id, 'v');
        await fetch('/api/store', { method: 'POST', body: JSON.stringify({ id, verifier: vf, ttl, encryptedData: JSON.stringify({ iv: btoa(String.fromCharCode(...iv)), d: btoa(String.fromCharCode(...new Uint8Array(enc))) }) }) });
        get('v-create').classList.add('hidden'); get('v-result').classList.remove('hidden');
        const base = location.origin + '/receive/' + id;
        get('linkS').value = base; get('linkE').value = base + '#' + encodeURIComponent(p);
    } catch (e) { modal(window.L.js_error, window.L.js_server_error); } finally { setL(get('btnGo'), 0); }
}

const CHUNK = 50 * 1024 * 1024;
const CONCURRENCY = 4;

async function upl() {
    const f = get('f').files[0];
    if (!f) return modal(window.L.js_info, window.L.js_select_file);
    setL(get('btnF'), 1);
    const m = get('fmsg');
    m.innerText = window.L.js_initializing;
    try {
        const init = await (await fetch('/api/upload/init', { method: 'POST', body: JSON.stringify({ filename: f.name, size: f.size, password: get('fpwd').value, ttl: parseInt(get('fttl').value), limit: parseInt(get('flimit').value) }) })).json();
        if(init.error) throw new Error(init.error);

        const tot = Math.ceil(f.size / CHUNK);
        let completed = 0;
        const parts = new Array(tot);
        const queue = [];
        for (let i = 0; i < tot; i++) queue.push(i);

        const worker = async () => {
            while (queue.length > 0) {
                const i = queue.shift();
                const chunk = f.slice(i * CHUNK, Math.min((i + 1) * CHUNK, f.size));
                const res = await fetch('/api/upload/part?key=' + init.key + '&id=' + init.uploadId + '&num=' + (i + 1), { method: 'PUT', body: chunk });
                if(!res.ok) throw new Error('Part failed');
                const partData = await res.json();
                parts[i] = partData;
                completed++;
                m.innerText = window.L.js_uploading + Math.round((completed / tot) * 100) + '%';
            }
        };

        const threads = [];
        for(let t=0; t < CONCURRENCY; t++) threads.push(worker());
        await Promise.all(threads);

        await fetch('/api/upload/complete', { method: 'POST', body: JSON.stringify({ key: init.key, uploadId: init.uploadId, parts: parts, fileId: init.fileId }) });
        m.innerText = window.L.js_done;
        get('f-res').classList.remove('hidden');
        const base = location.origin + '/share/' + init.fileId;
        get('flinkS').value = base;
        if (get('fpwd').value) {
            get('f-auto-row').classList.remove('hidden');
            get('flinkE').value = base + '?pwd=' + encodeURIComponent(get('fpwd').value);
        }
        get('f').value = '';
        get('dtxt').innerHTML = window.L.js_click_select;
        get('dtxt').parentNode.style.backgroundColor = 'var(--surface-2)';
        get('dtxt').parentNode.style.borderColor = 'var(--border-strong)';
        loadS();
    } catch (e) { m.innerText = window.L.js_error_prefix + e.message; } finally { setL(get('btnF'), 0); }
}

async function loadS() {
    if (!get('tbl')) return;
    try {
        const r = await fetch('/api/stats');
        const d = await r.json();
        const p = (d.used / d.limit) * 100;
        get('bar').style.width = p + '%';
        if (p > 90) get('bar').style.background = 'var(--danger)';
        get('st_txt').innerText = window.L.js_used + (d.used / 1e9).toFixed(2) + ' GB / 9.00 GB';
        get('tbl').innerHTML = d.files.map(f => {
            const lim = f.max_downloads === -1 ? '\u221e' : f.max_downloads;
            return '<tr><td>' + escapeHtml(f.filename) + '</td><td>' + (f.size / 1e6).toFixed(1) + 'MB</td><td style="color:var(--text-muted)">' + window.L.js_downloads + f.download_count + '/' + lim + '</td><td style="text-align:right"><button class="btn-del" onclick="del(\\'' + f.id + '\\')">' + window.L.js_btn_delete + '</button></td></tr>';
        }).join('');
    } catch (e) { }
}

async function del(id) {
    if (confirm(window.L.js_confirm_delete)) {
        await fetch('/api/del/' + id, { method: 'DELETE' });
        loadS();
    }
}

async function start(p, bid) {
    if (!p) return modal(window.L.js_error, window.L.js_nopass);
    setL(get(bid), 1);
    try {
        const id = location.pathname.split('/').pop();
        const vf = await derive(p, id, 'v');
        const payload = { verifierCandidate: vf };
        if (_tsToken) payload.cfTurnstileToken = _tsToken;
        const res = await fetch('/api/retrieve/' + id, { method: 'POST', body: JSON.stringify(payload) });
        const json = await res.json();
        if (!res.ok) throw new Error(json.error);
        const d = JSON.parse(json.encryptedData);
        const key = await derive(p, id, 'k');
        const iv = new Uint8Array(atob(d.iv).split("").map(c => c.charCodeAt(0)));
        const buf = new Uint8Array(atob(d.d).split("").map(c => c.charCodeAt(0)));
        const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, buf);
        get('m-manual').classList.add('hidden');
        get('m-auto').classList.add('hidden');
        get('v-decrypted').classList.remove('hidden');
        get('content').innerText = new TextDecoder().decode(dec);
        let tl = 300;
        const tick = () => {
            tl--;
            let m = Math.floor(tl / 60), s = tl % 60;
            get('tText').innerText = window.L.js_timer + m.toString().padStart(2, '0') + ':' + s.toString().padStart(2, '0');
            const p = (tl / 300 * 100);
            const fill = get('tFill');
            fill.style.width = p + '%';
            if (tl < 60) fill.style.background = 'var(--danger)'; else if (tl < 150) fill.style.background = '#f59e0b'; else fill.style.background = 'var(--accent)';
            if (tl <= 0) location.reload();
        };
        setInterval(tick, 1000);
        tick();
    } catch (e) { modal(window.L.js_error, e.message); } finally { setL(get(bid), 0); }
}

var _tsToken = null;
var _autoMode = false;
function onTurnstileSuccess(token) {
  _tsToken = token;
  if (_autoMode) {
    unlockA();
  } else {
    var btnM = get('btnM');
    if (btnM) btnM.disabled = false;
  }
}
function onTsFile(token) {
  var btn = get('btnDl');
  if (btn) btn.disabled = false;
  var form = get('dlForm');
  var hasPwd = form && form.querySelector('input[name="pwd"]');
  if (form && !hasPwd) form.submit();
}

const unlockM = () => start(get('recvP').value, 'btnM');
const unlockA = () => start(decodeURIComponent(location.hash.substring(1)), 'btnA');

if (location.pathname === '/gen' && location.search.includes('t=file')) loadS();
if (location.hash.length > 1 && get('btnA')) {
    _autoMode = true;
    get('m-manual').classList.add('hidden');
    get('m-auto').classList.remove('hidden');
    get('btnM').classList.add('hidden');
    get('btnA').classList.remove('hidden');
}
${LANG_PICKER_JS}
</script>
`

const BASE_HTML = (body: string, langCode: LangCode = 'en', langPickerHtml: string = '', tailScript: string = ''): string =>
  `<!DOCTYPE html><html lang="${langCode}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Edge Secrets</title><style>${CSS}</style></head><body><button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="Toggle theme">\u2600</button>${langPickerHtml}${body}<div class="overlay" id="qrOv" onclick="if(event.target===this)this.style.display='none'" style="display:none"><div class="modal" style="max-width:280px;padding:28px"><h3 style="margin-bottom:18px" id="qrTitle"></h3><img id="qrImg" class="qr-modal-img" alt="QR Code" src=""><p id="qrTxt" style="font-size:0.6rem;word-break:break-all;color:var(--text-muted);margin-bottom:18px;text-align:center;line-height:1.5"></p><button class="modal-btn" onclick="get('qrOv').style.display='none'" id="qrCloseBtn"></button></div></div>${CLIENT_JS}${tailScript}</body></html>`

function renderGen(type: string, t: Translations, langCode: LangCode): string {
  const isLink = type === 'link'
  const isFile = type === 'file'
  const isCred = !isLink && !isFile
  const lp = renderLangPicker(langCode)
  const body = `
  <script>window.L = ${JSON.stringify(t)};</script>
  <div class="card">
      <div class="brand-header"><span class="brand-logo" id="brandName">EDGE SECRETS</span><p class="brand-tagline" id="brandTagline" style="display:none"></p></div>
      <div class="tabs">
          <a href="?t=cred" class="tab ${isCred ? 'active' : ''}">${t.tab_creds}</a>
          <a href="?t=file" class="tab ${isFile ? 'active' : ''}">${t.tab_files}</a>
          <a href="?t=link" class="tab ${isLink ? 'active' : ''}">${t.tab_links}</a>
      </div>
      ${
        isCred
          ? `
      <div id="v-create">
          <div class="label-row"><span>${t.label_secret}</span><span class="action-link" onclick="genS()">${t.action_gen_password}</span></div>
          <textarea id="body" placeholder="${t.placeholder_secret}"></textarea>
          <div class="label-row"><span>${t.label_encrypt_key}</span><span class="action-link" onclick="genK()">${t.action_gen_key}</span></div>
          <input type="text" id="pass" placeholder="${t.placeholder_encrypt}">
          <div class="label-row"><span>${t.label_ttl}</span></div>
          <select id="ttl"><option value="3600">${t.ttl_1h}</option><option value="86400" selected>${t.ttl_24h}</option><option value="259200">${t.ttl_72h}</option></select>
          <button class="btn" onclick="processStore()" id="btnGo"><span>${t.btn_generate_links}</span><div class="spinner"></div></button>
      </div>
      <div id="v-result" class="hidden">
          <div class="res-box">
              <div class="label-row">${t.option1_manual}</div>
              <div class="input-group"><input type="text" id="linkS" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('linkS').value)">${t.copy}</button><button class="btn-qr" onclick="showQR(get('linkS').value)" title="QR">QR</button></div>
              <div class="label-row">${t.option2_fast}</div>
              <div class="input-group"><input type="text" id="linkE" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('linkE').value)">${t.copy}</button><button class="btn-qr" onclick="showQR(get('linkE').value)" title="QR">QR</button></div>
          </div>
          <button class="btn" style="background:transparent; color:var(--text); border:1px solid var(--border-strong); margin-top:20px;" onclick="location.reload()">${t.btn_new_operation}</button>
      </div>`
          : isFile ? `
      <div id="v-file-upload">
          <div class="drop-zone" onclick="get('f').click()">
              <div style="font-size:30px; margin-bottom:10px;">
                  <span id="dtxt" style="font-weight:600; font-size:0.85rem; color:var(--accent); letter-spacing:0.06em;">${t.js_click_select}</span>
              </div>
          </div>
          <input type="file" id="f" style="display:none" onchange="showFile()">
          <div class="label-row">${t.label_pwd_optional}</div>
          <input type="text" id="fpwd" placeholder="${t.placeholder_leave_empty}">
          <div style="display:flex; gap:15px">
              <div style="flex:1"><div class="label-row">${t.label_retention}</div><select id="fttl"><option value="43200000">${t.ttl_12h}</option><option value="172800000" selected>${t.ttl_2d}</option><option value="604800000">${t.ttl_7d}</option></select></div>
              <div style="flex:1"><div class="label-row">${t.label_download_limit}</div><select id="flimit"><option value="1" selected>${t.limit_1}</option><option value="5">${t.limit_5}</option><option value="-1">${t.limit_unlimited}</option></select></div>
          </div>
          <button class="btn" onclick="upl()" id="btnF"><span>${t.btn_send_file}</span><div class="spinner"></div></button>
          <div id="fmsg" style="margin-top:15px; font-weight:600; text-align:center; color:var(--accent); font-size:0.85rem; letter-spacing:0.04em;"></div>
          <div class="res-box hidden" id="f-res">
             <div class="label-row">${t.option1_manual}</div>
             <div class="input-group"><input type="text" id="flinkS" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('flinkS').value)">${t.copy}</button><button class="btn-qr" onclick="showQR(get('flinkS').value)" title="QR">QR</button></div>
             <div id="f-auto-row" class="hidden"><div class="label-row">${t.option2_fast}</div><div class="input-group"><input type="text" id="flinkE" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('flinkE').value)">${t.copy}</button><button class="btn-qr" onclick="showQR(get('flinkE').value)" title="QR">QR</button></div></div>
          </div>
      </div>
      <div style="margin-top:36px; padding-top:20px; border-top:1px solid var(--border);">
          <div class="label-row">${t.label_storage}</div>
          <div class="storage-info"><span id="st_txt">${t.loading}</span></div>
          <div class="timer-wrap"><div id="bar" class="timer-fill"></div></div>
          <table id="tbl"><tbody></tbody></table>
      </div>` : `
      <div id="v-link">
          <div class="label-row"><span>${t.label_target_url}</span></div>
          <input type="url" id="lurl" placeholder="https://..." autocomplete="off">
          <div style="display:flex;gap:15px">
              <div style="flex:1"><div class="label-row">${t.label_expiry}</div><select id="lttl"><option value="3600">${t.ttl_1h}</option><option value="86400" selected>${t.ttl_24h}</option><option value="604800">${t.ttl_7d}</option><option value="-1">${t.ttl_never}</option></select></div>
              <div style="flex:1"><div class="label-row">${t.label_click_limit}</div><select id="lclicks"><option value="1">${t.limit_1}</option><option value="10">${t.limit_10}</option><option value="100">${t.limit_100}</option><option value="-1" selected>${t.limit_unlimited}</option></select></div>
          </div>
          <button class="btn" onclick="shorten()" id="btnLink"><span>${t.btn_shorten}</span><div class="spinner"></div></button>
          <div class="res-box hidden" id="link-res">
              <div class="label-row">${t.label_short_link}</div>
              <div class="input-group"><input type="text" id="shortLink" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this,get('shortLink').value)">${t.copy}</button><button class="btn-qr" onclick="showQR(get('shortLink').value)" title="QR">QR</button></div>
              <button class="btn" style="background:transparent;color:var(--text);border:1px solid var(--border-strong);margin-top:16px" onclick="get('link-res').classList.add('hidden');get('lurl').value='';get('lurl').focus()">${t.btn_new_link}</button>
          </div>
      </div>`
      }
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>
  <div class="cfg-toggle" id="cfgToggle" onclick="document.getElementById('cfgPanel').classList.toggle('hidden');this.classList.toggle('open')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
  </div>
  <div class="cfg-panel hidden" id="cfgPanel">
    <div class="cfg-section">
      <div class="cfg-section-label">${t.cfg_accent}</div>
      <div class="cfg-presets">
        <div class="cfg-preset" style="background:#818cf8" onclick="pickPreset('#818cf8')" title="Indigo"></div>
        <div class="cfg-preset" style="background:#a78bfa" onclick="pickPreset('#a78bfa')" title="Violet"></div>
        <div class="cfg-preset" style="background:#60a5fa" onclick="pickPreset('#60a5fa')" title="Blue"></div>
        <div class="cfg-preset" style="background:#22d3ee" onclick="pickPreset('#22d3ee')" title="Cyan"></div>
        <div class="cfg-preset" style="background:#34d399" onclick="pickPreset('#34d399')" title="Emerald"></div>
        <div class="cfg-preset" style="background:#fb7185" onclick="pickPreset('#fb7185')" title="Rose"></div>
        <div class="cfg-preset" style="background:#fbbf24" onclick="pickPreset('#fbbf24')" title="Amber"></div>
        <div class="cfg-preset" style="background:#f8fafc" onclick="pickPreset('#f8fafc')" title="White"></div>
      </div>
      <div class="cfg-picker-row">
        <div class="cfg-swatch" id="cfgSwatch"></div>
        <input type="color" class="cfg-color" id="accentPicker" value="#818cf8" oninput="setAccent(this.value)">
        <span class="cfg-label" id="cfgAccentHex" style="flex:1;text-align:right">#818cf8</span>
      </div>
    </div>
    <div class="cfg-divider"></div>
    <div class="cfg-section">
      <div class="cfg-section-label">${t.cfg_bg}</div>
      <div class="cfg-presets">
        <div class="cfg-preset-bg" style="background:#000000;border:1px solid rgba(255,255,255,0.15)" onclick="pickBgPreset('#000000')" title="Pure Black"></div>
        <div class="cfg-preset-bg" style="background:#080810" onclick="pickBgPreset('#080810')" title="Indigo Black"></div>
        <div class="cfg-preset-bg" style="background:#05080f" onclick="pickBgPreset('#05080f')" title="Navy Black"></div>
        <div class="cfg-preset-bg" style="background:#0d0610" onclick="pickBgPreset('#0d0610')" title="Violet Black"></div>
        <div class="cfg-preset-bg" style="background:#060f08" onclick="pickBgPreset('#060f08')" title="Forest Black"></div>
        <div class="cfg-preset-bg" style="background:#100608" onclick="pickBgPreset('#100608')" title="Crimson Black"></div>
        <div class="cfg-preset-bg" style="background:#0f0c05" onclick="pickBgPreset('#0f0c05')" title="Amber Black"></div>
      </div>
      <div class="cfg-picker-row">
        <div class="cfg-swatch" id="cfgBgSwatch" style="background:#000"></div>
        <input type="color" class="cfg-color" id="bgPicker" value="#000000" oninput="setBg(this.value)">
        <span class="cfg-label" id="cfgBgHex" style="flex:1;text-align:right">#000000</span>
      </div>
    </div>
    <div class="cfg-divider"></div>
    <div class="cfg-section">
      <div class="cfg-section-label">${t.cfg_branding}</div>
      <div class="cfg-row" style="margin-bottom:8px">
        <span class="cfg-label">${t.cfg_name}</span>
        <input type="text" class="cfg-input" id="cfgBrandName" placeholder="EDGE SECRETS" maxlength="32" oninput="previewBrand()">
      </div>
      <div class="cfg-row">
        <span class="cfg-label">${t.cfg_tagline_label}</span>
        <input type="text" class="cfg-input" id="cfgTagline" placeholder="${t.cfg_tagline_placeholder}" maxlength="60" oninput="previewBrand()">
      </div>
    </div>
    <div class="cfg-divider"></div>
    <div class="cfg-section">
      <div class="cfg-section-label">${t.cfg_logo_label} <span style="font-weight:400;opacity:0.6">${t.cfg_logo_specs}</span></div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <img id="logoPreview" class="cfg-logo-preview" src="/ui/logo" onload="this.style.display='inline-block'" onerror="this.style.display='none'" style="display:none">
        <span class="cfg-label" id="logoStatus">${t.js_no_logo}</span>
      </div>
      <div style="display:flex;gap:6px">
        <span class="cfg-upload" onclick="get('logoInput').click()">${t.cfg_upload}</span>
        <span class="cfg-upload cfg-upload-del" onclick="removeLogo()">${t.cfg_delete}</span>
      </div>
      <input type="file" id="logoInput" accept="image/png,image/svg+xml,image/jpeg,image/webp" style="display:none" onchange="uploadLogo()">
    </div>
    <div class="cfg-divider"></div>
    <div class="cfg-section">
      <div class="cfg-section-label">${t.cfg_turnstile}</div>
      <div class="cfg-row" style="margin-bottom:8px">
        <span class="cfg-label">${t.cfg_turnstile_site_key}</span>
        <input type="text" class="cfg-input" id="cfgTsSiteKey" placeholder="0x4AAAAAAA..." maxlength="128">
      </div>
      <div class="ts-toggle-row">
        <span class="cfg-label">${t.cfg_turnstile_creds}</span>
        <label class="ts-toggle"><input type="checkbox" id="cfgTsCreds"><span class="ts-track"></span><span class="ts-thumb"></span></label>
      </div>
      <div class="ts-toggle-row" style="margin-top:6px">
        <span class="cfg-label">${t.cfg_turnstile_files}</span>
        <label class="ts-toggle"><input type="checkbox" id="cfgTsFiles"><span class="ts-track"></span><span class="ts-thumb"></span></label>
      </div>
    </div>
    <div class="cfg-divider"></div>
    <button class="cfg-save" id="cfgSave" onclick="saveConfig()">${t.js_save}</button>
  </div>`
  return BASE_HTML(body, langCode, lp)
}

function renderReceiveCred(_id: string, lang: Lang, langCode: LangCode, turnstileSiteKey: string | null): string {
  const lp = renderLangPicker(langCode)
  const tsWidget = turnstileSiteKey
    ? `<div class="ts-verify-wrap"><span class="ts-verify-label">${lang.ts_verify}</span><div class="cf-turnstile" data-sitekey="${escapeHtml(turnstileSiteKey)}" data-callback="onTurnstileSuccess" data-theme="auto"></div></div>`
    : ''
  const tsScript = turnstileSiteKey
    ? `<script src="https://challenges.cloudflare.com/turnstile/v1/api.js" async defer></script>`
    : ''
  const body = `
  <script>window.L = ${JSON.stringify(lang)};</script>
  <div class="card">
    <div class="brand-header"><span class="brand-logo">EDGE SECRETS</span></div>
    <h2 style="text-align:center; font-size:1.1rem; margin-bottom:24px; color:var(--text); font-weight:600; letter-spacing:0.04em;">${lang.title_cred}</h2>
    <div id="m-manual">
      <div class="label-row">${lang.label_key}</div>
      <input type="password" id="recvP" placeholder="${lang.placeholder_key}">
    </div>
    <div id="m-auto" class="hidden" style="text-align:center">
      <div style="background:var(--accent-dim); padding:18px; font-weight:600; margin-bottom:20px; color:var(--accent); border:1px solid var(--border-strong); font-size:0.82rem; letter-spacing:0.08em; text-align:center;">${lang.ready_msg}</div>
    </div>
    ${tsWidget}
    <button class="btn" onclick="unlockM()" id="btnM" ${turnstileSiteKey ? 'disabled' : ''}><span>${lang.btn_decrypt}</span><div class="spinner"></div></button>
    <button class="btn hidden" onclick="unlockA()" id="btnA" ${turnstileSiteKey ? 'disabled' : ''}><span>${lang.btn_open}</span><div class="spinner"></div></button>
    <div id="v-decrypted" class="hidden">
      <div class="label-row">${lang.label_decrypted}</div>
      <pre id="content"></pre>
      <div style="position:relative; margin-top:20px;">
          <div class="timer-wrap" style="height:28px; margin-bottom:0;"><div id="tFill" class="timer-fill"></div></div>
          <div id="tText" class="timer-text" style="top:0; line-height:28px;"></div>
      </div>
      <button class="btn" style="margin-top:20px;" onclick="copyBtn(this, get('content').innerText)"><span>${lang.btn_copy}</span></button>
    </div>
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>`
  return BASE_HTML(body, langCode, lp, tsScript)
}

function renderReceiveFile(filename: string, lang: Lang, langCode: LangCode): string {
  const safeName = escapeHtml(filename) as string
  const lp = renderLangPicker(langCode)
  const body = `
  <script>window.L = ${JSON.stringify(lang)};</script>
  <div class="card">
      <div class="brand-header"><span class="brand-logo" id="brandName">EDGE SECRETS</span><p class="brand-tagline" id="brandTagline" style="display:none"></p></div>
      <h2 style="text-align:center; font-size:1.1rem; margin-bottom:24px; color:var(--text); font-weight:600; letter-spacing:0.04em;">${lang.title_file}</h2>
      <div style="text-align:center; padding: 20px 0;">
          <div style="font-size:3rem; margin-bottom:15px; text-shadow: 0 4px 6px rgba(0,0,0,0.1)">\u{1F4E6}</div>
          <h2 style="border:none; margin:0; font-size:1.3rem; word-break: break-all; font-weight:600; color:var(--text)">${safeName}</h2>
          <p style="font-size:0.9rem; font-weight:500; color:var(--text-muted); margin-top:5px">${lang.file_protected}</p>
      </div>
      <form onsubmit="event.preventDefault(); location.href=location.pathname+'?pwd='+get('p').value">
          <input type="password" id="p" placeholder="${lang.placeholder_key}" autofocus>
          <button class="btn"><span>${lang.btn_unlock}</span></button>
      </form>
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>`
  return BASE_HTML(body, langCode, lp)
}

function renderFileTurnstileGate(
  id: string,
  filename: string,
  hasPassword: boolean,
  lang: Lang,
  langCode: LangCode,
  siteKey: string,
  _showError: boolean
): string {
  const safeName = escapeHtml(filename) as string
  const safeSiteKey = escapeHtml(siteKey) as string
  const lp = renderLangPicker(langCode)
  const passwordField = hasPassword
    ? `<input type="password" name="pwd" id="p" placeholder="${lang.placeholder_key}" style="margin-top:14px">`
    : ''
  const tailScript = `
  <script src="https://challenges.cloudflare.com/turnstile/v1/api.js" defer></script>`
  const body = `
  <script>window.L = ${JSON.stringify(lang)};</script>
  <div class="card">
      <div class="brand-header"><span class="brand-logo" id="brandName">EDGE SECRETS</span><p class="brand-tagline" id="brandTagline" style="display:none"></p></div>
      <h2 style="text-align:center; font-size:1.1rem; margin-bottom:24px; color:var(--text); font-weight:600; letter-spacing:0.04em;">${lang.title_file}</h2>
      <div style="text-align:center; padding:20px 0 10px;">
          <div style="font-size:3rem; margin-bottom:15px;">\u{1F4E6}</div>
          <h2 style="border:none; margin:0; font-size:1.3rem; word-break:break-all; font-weight:600; color:var(--text)">${safeName}</h2>
          ${hasPassword ? `<p style="font-size:0.9rem; font-weight:500; color:var(--text-muted); margin-top:5px">${lang.file_protected}</p>` : ''}
      </div>
      <form id="dlForm" method="POST" action="/share/${id}" style="margin-top:10px">
          <div class="ts-verify-wrap">
              <span class="ts-verify-label">${lang.ts_verify}</span>
              <div class="cf-turnstile" data-sitekey="${safeSiteKey}" data-callback="onTsFile" data-theme="auto"></div>
          </div>
          ${passwordField}
          <button class="btn" id="btnDl" style="margin-top:14px" ${hasPassword ? 'disabled' : ''}><span>${lang.btn_unlock}</span></button>
      </form>
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>`
  return BASE_HTML(body, langCode, lp, tailScript)
}
