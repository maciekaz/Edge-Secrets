import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'

// ── Config ────────────────────────────────────────────────────────────────────

const CONFIG = {
  maxTtl: 259200,
  defaultTtl: 86400,
  maxAttempts: 3,
  maxStorage: 9 * 1024 * 1024 * 1024,
  visualTtl: 300,
} as const

// ── i18n ──────────────────────────────────────────────────────────────────────

const I18N = {
  pl: {
    title_cred: 'Odbierz wiadomość',
    title_file: 'Pobieranie Pliku',
    label_key: 'WPROWADŹ KLUCZ DESZYFRUJĄCY',
    placeholder_key: 'Klucz dostępu...',
    btn_decrypt: 'ODSZYFRUJ',
    ready_msg: 'DANE GOTOWE DO ODCZYTU',
    btn_open: 'OTWÓRZ WIADOMOŚĆ',
    label_decrypted: 'DANE ODSZYFROWANE:',
    btn_copy: 'KOPIUJ TREŚĆ',
    file_protected: 'PLIK ZABEZPIECZONY HASŁEM',
    btn_unlock: 'ODBLOKUJ I POBIERZ',
    js_copied: 'Skopiowano!',
    js_manual: 'Skopiuj ręcznie: ',
    js_nopass: 'Brak hasła',
    js_timer: 'ZAPOMINANIE ZA: ',
  },
  en: {
    title_cred: 'Secure Data Retrieval',
    title_file: 'Secure File Download',
    label_key: 'ENTER DECRYPTION KEY',
    placeholder_key: 'Access key...',
    btn_decrypt: 'DECRYPT',
    ready_msg: 'DATA READY TO READ',
    btn_open: 'OPEN MESSAGE',
    label_decrypted: 'DECRYPTED DATA:',
    btn_copy: 'COPY CONTENT',
    file_protected: 'PASSWORD PROTECTED FILE',
    btn_unlock: 'UNLOCK & DOWNLOAD',
    js_copied: 'Copied!',
    js_manual: 'Copy manually: ',
    js_nopass: 'Password required',
    js_timer: 'AUTO-DELETE IN: ',
  },
} as const

// ── Types ─────────────────────────────────────────────────────────────────────

type Bindings = {
  DB: D1Database
  BUCKET: R2Bucket
  SECRETS_STORE: KVNamespace
  PEPPER: string
}

type Lang = (typeof I18N)['pl'] | (typeof I18N)['en']

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
    "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://ins.com.pl; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://ins.com.pl; object-src 'none'; frame-ancestors 'none';",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getLang(req: Request): Lang {
  const header = req.headers.get('Accept-Language') ?? ''
  return header.toLowerCase().includes('pl') ? I18N.pl : I18N.en
}

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

const hashPwd = async (p: string | null | undefined, pepper: string): Promise<string | null> => {
  if (!p) return null
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(p + pepper))
  return Array.from(new Uint8Array(buf))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('')
}

// RFC 5987 percent-encoding for Content-Disposition filename — prevents header injection
function encodeFilename(filename: string): string {
  return `UTF-8''${encodeURIComponent(filename)}`
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
  if (!c.env.DB || !c.env.BUCKET || !c.env.SECRETS_STORE || !c.env.PEPPER) {
    return c.text('System Error: Missing Bindings (DB/BUCKET/KV/PEPPER)', 500)
  }
  return next()
})

// ── Routes ────────────────────────────────────────────────────────────────────

app.get('/', (c) => c.redirect('/gen', 302))

app.get('/gen', (c) =>
  c.html(renderGen(c.req.query('t') ?? 'cred'), 200, HTML_SECURITY_HEADERS)
)

app.get('/receive/:id', (c) =>
  c.html(
    renderReceiveCred(c.req.param('id'), getLang(c.req.raw)),
    200,
    HTML_SECURITY_HEADERS
  )
)

app.get('/share/:id', (c) => handleFileDownload(c))

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
  const { verifierCandidate } = await c.req.json<{ verifierCandidate: string }>()
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

// ── File Download Handler ─────────────────────────────────────────────────────

async function handleFileDownload(c: Context<{ Bindings: Bindings }>): Promise<Response> {
  const id = c.req.param('id')
  if (!id) return c.text('BAD_REQUEST', 400)
  const env = c.env
  const lang = getLang(c.req.raw)

  const f = await env.DB.prepare('SELECT * FROM files WHERE id=?')
    .bind(id)
    .first<FileRecord>()
  if (!f) return c.html('FILE_NOT_FOUND', 404, HTML_SECURITY_HEADERS)
  if (f.status === 'downloaded' || f.expires_at < Date.now()) {
    return c.html('LINK_EXPIRED', 410, HTML_SECURITY_HEADERS)
  }

  if (f.password_hash) {
    const pwdParam = c.req.query('pwd')
    if (!pwdParam) {
      return c.html(renderReceiveFile(f.filename, lang), 200, HTML_SECURITY_HEADERS)
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
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
:root {
    --primary: #0d6efd; --primary-dark: #0043a8; --primary-grad: linear-gradient(135deg, #0d6efd 0%, #0043a8 100%);
    --bg-grad: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    --card-bg: #ffffff; --text: #1e293b; --text-muted: #64748b; --border: #e2e8f0; --success: #10b981; --danger: #ef4444;
}
* { box-sizing: border-box; font-family: 'Poppins', sans-serif; }
body { background: var(--bg-grad); display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; color: var(--text); }
.card { background: var(--card-bg); width: 100%; max-width: 650px; border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.35); padding: 45px; position: relative; z-index: 1; animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
@keyframes fadeUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
.brand-header { text-align: center; margin-bottom: 35px; }
.brand-logo { height: 75px; width: auto; transition: transform 0.3s ease; }
.brand-logo:hover { transform: scale(1.05); }
.tabs { display: flex; background: #f1f5f9; padding: 6px; border-radius: 14px; margin-bottom: 30px; }
.tab { flex: 1; text-align: center; padding: 12px; border-radius: 10px; font-weight: 600; font-size: 0.95rem; text-decoration: none; color: var(--text-muted); transition: all 0.2s; border: none; }
.tab:hover { color: var(--primary); background: rgba(255,255,255,0.6); }
.tab.active { background: #fff; color: var(--primary-dark); box-shadow: 0 4px 10px -2px rgba(0,0,0,0.1); }
.label-row { display: flex; justify-content: space-between; align-items: center; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 10px; color: var(--text-muted); letter-spacing: 0.8px; }
.action-link { cursor: pointer; color: var(--primary); font-size: 0.75rem; background: #eff6ff; padding: 3px 10px; border-radius: 6px; transition: 0.2s; font-weight: 600; }
.action-link:hover { background: var(--primary); color: #fff; }
textarea, input, select { width: 100%; border: 2px solid var(--border); padding: 16px; font-size: 1rem; border-radius: 12px; margin-bottom: 24px; outline: none; background: #f8fafc; color: var(--text); transition: all 0.2s; }
textarea:focus, input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 4px rgba(13, 110, 253, 0.15); background: #fff; }
textarea { min-height: 140px; font-family: 'Poppins', monospace; resize: vertical; }
.btn { width: 100%; padding: 18px; background: var(--primary-grad); color: #fff; border: none; border-radius: 14px; font-weight: 600; font-size: 1.05rem; text-transform: uppercase; letter-spacing: 1px; cursor: pointer; display: flex; justify-content: center; align-items: center; gap: 12px; transition: all 0.2s; box-shadow: 0 8px 20px -4px rgba(13, 110, 253, 0.4); position: relative; overflow: hidden; }
.btn > * { pointer-events: none; }
.btn:hover { transform: translateY(-2px); box-shadow: 0 12px 25px -5px rgba(13, 110, 253, 0.5); filter: brightness(1.1); }
.btn:active { transform: translateY(0); }
.btn-del { padding: 6px 14px; font-size: 0.75rem; background: #fee2e2; color: var(--danger); border: none; border-radius: 8px; cursor: pointer; font-weight: 700; transition: 0.2s; }
.btn-del:hover { background: var(--danger); color: #fff; }
.storage-info { display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 600; color: var(--text-muted); margin-bottom: 5px; }
.timer-wrap { background: #e2e8f0; height: 12px; border-radius: 6px; overflow: hidden; margin-bottom: 25px; }
.timer-fill { height: 100%; background: var(--success); width: 0%; transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1); border-radius: 6px; }
.drop-zone { border: 3px dashed #cbd5e1; padding: 40px 20px; text-align: center; cursor: pointer; background: #f8fafc; border-radius: 16px; margin-bottom: 24px; transition: 0.2s; position: relative; }
.drop-zone > * { pointer-events: none; }
.drop-zone:hover { border-color: var(--primary); background: #eff6ff; transform: scale(1.01); }
.input-group { display: flex; gap: 10px; margin-bottom: 20px; }
.input-group input { margin-bottom: 0; border-radius: 10px; flex: 1; }
.btn-copy { background: #e2e8f0; color: var(--text-muted); border: none; border-radius: 10px; font-weight: 700; padding: 0 24px; cursor: pointer; min-width: 100px; transition: 0.2s; display: flex; align-items: center; justify-content: center; }
.btn-copy > * { pointer-events: none; }
.btn-copy:hover { background: #cbd5e1; color: var(--text); }
.overlay { position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(5px); z-index: 100; display: none; justify-content: center; align-items: center; }
.modal { background: #fff; padding: 30px; border-radius: 20px; text-align: center; max-width: 400px; width: 90%; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); animation: fadeUp 0.3s; }
.modal h3 { margin-top: 0; color: var(--primary-dark); }
.modal-btn { margin-top: 20px; width: 100%; padding: 12px; background: var(--primary-grad); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; text-transform: uppercase; }
.modal-btn:hover { filter: brightness(1.1); }
pre { background: #0f172a; color: #4ade80; padding: 25px; border-radius: 12px; white-space: pre-wrap; word-break: break-all; font-size: 1.1rem; margin-bottom: 25px; font-family: 'Courier New', monospace; border: 1px solid #334155; box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.3); }
.hidden { display: none !important; }
.spinner { width: 24px; height: 24px; border: 3px solid rgba(255,255,255,0.3); border-top-color: #fff; border-radius: 50%; animation: rot 0.8s linear infinite; display: none; }
@keyframes rot { to { transform: rotate(360deg); } }
.meta-tag { font-size: 0.7rem; background: #e2e8f0; padding: 3px 8px; border-radius: 6px; color: var(--text-muted); margin-left: 10px; font-weight: 600; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9rem; }
td, th { padding: 14px 10px; border-bottom: 1px solid var(--border); text-align: left; color: var(--text); }
td:first-child { font-weight: 600; color: var(--primary-dark); }
footer { margin-top: 30px; color: rgba(255,255,255,0.5); font-size: 0.8rem; text-align: center; }
`

const CLIENT_JS = `
<script>
const get = (id) => document.getElementById(id);
const modal = (t, m) => { get('mT').innerText = t; get('mMsg').innerText = m; get('ov').style.display = 'flex'; };
const setL = (btn, s) => { if (btn) { btn.disabled = s; const sp = btn.querySelector('.spinner'); if (sp) sp.style.display = s ? 'block' : 'none'; } };

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
        d.parentNode.style.borderColor = 'var(--primary)';
        d.parentNode.style.backgroundColor = '#eff6ff';
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
    if (!b || !p) return modal('BŁĄD', 'Wpisz dane.');
    setL(get('btnGo'), 1);
    try {
        const id = crypto.randomUUID(), key = await derive(p, id, 'k'), iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(b)), vf = await derive(p, id, 'v');
        await fetch('/api/store', { method: 'POST', body: JSON.stringify({ id, verifier: vf, ttl, encryptedData: JSON.stringify({ iv: btoa(String.fromCharCode(...iv)), d: btoa(String.fromCharCode(...new Uint8Array(enc))) }) }) });
        get('v-create').classList.add('hidden'); get('v-result').classList.remove('hidden');
        const base = location.origin + '/receive/' + id;
        get('linkS').value = base; get('linkE').value = base + '#' + encodeURIComponent(p);
    } catch (e) { modal('BŁĄD', 'Server error'); } finally { setL(get('btnGo'), 0); }
}

const CHUNK = 50 * 1024 * 1024;
const CONCURRENCY = 4;

async function upl() {
    const f = get('f').files[0];
    if (!f) return modal('INFO', 'Wybierz plik');
    setL(get('btnF'), 1);
    const m = get('fmsg');
    m.innerText = 'Inicjowanie...';
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
                m.innerText = 'Wysyłanie: ' + Math.round((completed / tot) * 100) + '%';
            }
        };

        const threads = [];
        for(let t=0; t < CONCURRENCY; t++) threads.push(worker());
        await Promise.all(threads);

        await fetch('/api/upload/complete', { method: 'POST', body: JSON.stringify({ key: init.key, uploadId: init.uploadId, parts: parts, fileId: init.fileId }) });
        m.innerText = 'Gotowe!';
        get('f-res').classList.remove('hidden');
        const base = location.origin + '/share/' + init.fileId;
        get('flinkS').value = base;
        if (get('fpwd').value) {
            get('f-auto-row').classList.remove('hidden');
            get('flinkE').value = base + '?pwd=' + encodeURIComponent(get('fpwd').value);
        }
        get('f').value = '';
        get('dtxt').innerHTML = 'KLIKNIJ ABY WYBRAĆ PLIK';
        get('dtxt').parentNode.style.backgroundColor = '#f8fafc';
        get('dtxt').parentNode.style.borderColor = 'var(--border)';
        loadS();
    } catch (e) { m.innerText = 'Błąd: ' + e.message; } finally { setL(get('btnF'), 0); }
}

async function loadS() {
    if (!get('tbl')) return;
    try {
        const r = await fetch('/api/stats');
        const d = await r.json();
        const p = (d.used / d.limit) * 100;
        get('bar').style.width = p + '%';
        if (p > 90) get('bar').style.background = 'var(--danger)';
        get('st_txt').innerText = 'Użyto: ' + (d.used / 1e9).toFixed(2) + ' GB / 9.00 GB';
        get('tbl').innerHTML = d.files.map(f => {
            const lim = f.max_downloads === -1 ? '\u221e' : f.max_downloads;
            return '<tr><td>' + escapeHtml(f.filename) + '</td><td>' + (f.size / 1e6).toFixed(1) + 'MB</td><td style="color:var(--text-muted)">Pobrań: ' + f.download_count + '/' + lim + '</td><td style="text-align:right"><button class="btn-del" onclick="del(\\'' + f.id + '\\')">USUŃ</button></td></tr>';
        }).join('');
    } catch (e) { }
}

async function del(id) {
    if (confirm('Usunąć plik trwale?')) {
        await fetch('/api/del/' + id, { method: 'DELETE' });
        loadS();
    }
}

async function start(p, bid) {
    if (!p) return modal('BŁĄD', window.L.js_nopass);
    setL(get(bid), 1);
    try {
        const id = location.pathname.split('/').pop();
        const vf = await derive(p, id, 'v');
        const res = await fetch('/api/retrieve/' + id, { method: 'POST', body: JSON.stringify({ verifierCandidate: vf }) });
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
            if (tl < 60) fill.style.background = 'var(--danger)'; else if (tl < 150) fill.style.background = '#f59e0b'; else fill.style.background = 'var(--primary)';
            if (tl <= 0) location.reload();
        };
        setInterval(tick, 1000);
        tick();
    } catch (e) { modal('BŁĄD', e.message); } finally { setL(get(bid), 0); }
}

const unlockM = () => start(get('recvP').value, 'btnM');
const unlockA = () => start(decodeURIComponent(location.hash.substring(1)), 'btnA');

if (location.pathname === '/gen' && location.search.includes('t=file')) loadS();
if (location.hash.length > 1 && get('m-auto')) {
    get('m-manual').classList.add('hidden');
    get('m-auto').classList.remove('hidden');
}
</script>
`

const BASE_HTML = (body: string): string =>
  `<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>INS Secrets </title><link rel="icon" href="https://ins.com.pl/assets/favicon.png"><style>${CSS}</style></head><body>${body}<footer>Powered by <strong>INS SOLUTIONS</strong></footer>${CLIENT_JS}</body></html>`

function renderGen(type: string): string {
  const isCred = type === 'cred'
  const body = `
  <script>window.L = ${JSON.stringify(I18N.pl)};</script>
  <div class="card">
      <div class="brand-header">
          <a href="https://ins.com.pl">
              <img src="https://ins.com.pl/assets/ins_white_onlylogo.png" alt="INS Logo" class="brand-logo" style="filter: brightness(0) saturate(100%) invert(32%) sepia(99%) saturate(1352%) hue-rotate(211deg) brightness(96%) contrast(105%);">
          </a>
      </div>
      <div class="tabs">
          <a href="?t=cred" class="tab ${isCred ? 'active' : ''}">POŚWIADCZENIA</a>
          <a href="?t=file" class="tab ${!isCred ? 'active' : ''}">PLIKI (5GB)</a>
      </div>
      ${
        isCred
          ? `
      <div id="v-create">
          <div class="label-row"><span>TREŚĆ SEKRETU</span><span class="action-link" onclick="genS()">GENERUJ HASŁO</span></div>
          <textarea id="body" placeholder="Wklej poufne dane tutaj..."></textarea>
          <div class="label-row"><span>KLUCZ SZYFRUJĄCY</span><span class="action-link" onclick="genK()">LOSUJ KLUCZ</span></div>
          <input type="text" id="pass" placeholder="Hasło do odblokowania...">
          <div class="label-row"><span>CZAS WYGAŚNIĘCIA</span></div>
          <select id="ttl"><option value="3600">1 Godzina</option><option value="86400" selected>24 Godziny</option><option value="259200">72 Godziny</option></select>
          <button class="btn" onclick="processStore()" id="btnGo"><span>GENERUJ LINKI</span><div class="spinner"></div></button>
      </div>
      <div id="v-result" class="hidden">
          <div class="res-box">
              <div class="label-row">OPCJA 1: MANUAL (BEZ HASŁA)</div>
              <div class="input-group"><input type="text" id="linkS" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('linkS').value)">KOPIUJ</button></div>
              <div class="label-row">OPCJA 2: FAST (LINK Z HASŁEM)</div>
              <div class="input-group"><input type="text" id="linkE" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('linkE').value)">KOPIUJ</button></div>
          </div>
          <button class="btn" style="background:#fff; color:var(--text); border:2px solid var(--border); margin-top:20px;" onclick="location.reload()">NOWA OPERACJA</button>
      </div>`
          : `
      <div id="v-file-upload">
          <div class="drop-zone" onclick="get('f').click()">
              <div style="font-size:30px; margin-bottom:10px;">
                  <span id="dtxt" style="font-weight:600; font-size:0.9rem; color:var(--primary);">KLIKNIJ ABY WYBRAĆ PLIK</span>
              </div>
          </div>
          <input type="file" id="f" style="display:none" onchange="showFile()">
          <div class="label-row">HASŁO (OPCJONALNE)</div>
          <input type="text" id="fpwd" placeholder="Zostaw puste dla linku publicznego">
          <div style="display:flex; gap:15px">
              <div style="flex:1"><div class="label-row">RETENCJA</div><select id="fttl"><option value="43200000">12 Godzin</option><option value="172800000" selected>2 Dni</option><option value="604800000">7 Dni</option></select></div>
              <div style="flex:1"><div class="label-row">LIMIT POBRAŃ</div><select id="flimit"><option value="1" selected>1 Raz</option><option value="5">5 Razy</option><option value="-1">Bez limitu</option></select></div>
          </div>
          <button class="btn" onclick="upl()" id="btnF"><span>WYŚLIJ PLIK</span><div class="spinner"></div></button>
          <div id="fmsg" style="margin-top:15px; font-weight:600; text-align:center; color:var(--primary)"></div>
          <div class="res-box hidden" id="f-res">
             <div class="label-row">OPCJA 1: MANUAL (BEZ HASŁA)</div>
             <div class="input-group"><input type="text" id="flinkS" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('flinkS').value)">KOPIUJ</button></div>
             <div id="f-auto-row" class="hidden"><div class="label-row">OPCJA 2: FAST (LINK Z HASŁEM)</div><div class="input-group"><input type="text" id="flinkE" readonly onclick="this.select()"><button class="btn-copy" onclick="copyBtn(this, get('flinkE').value)">KOPIUJ</button></div></div>
          </div>
      </div>
      <div style="margin-top:40px; padding-top:20px; border-top:1px solid var(--border);">
          <div class="label-row">STORAGE</div>
          <div class="storage-info"><span id="st_txt">Ładowanie...</span></div>
          <div class="timer-wrap"><div id="bar" class="timer-fill"></div></div>
          <table id="tbl"><tbody></tbody></table>
      </div>`
      }
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>`
  return BASE_HTML(body)
}

function renderReceiveCred(_id: string, lang: Lang): string {
  const body = `
  <script>window.L = ${JSON.stringify(lang)};</script>
  <div class="card">
    <div class="brand-header"><a href="https://ins.com.pl"><img src="https://ins.com.pl/assets/ins_white_onlylogo.png" style="filter: brightness(0) saturate(100%) invert(32%) sepia(99%) saturate(1352%) hue-rotate(211deg) brightness(96%) contrast(105%);" class="brand-logo"></a></div>
    <h2 style="text-align:center; font-size:1.4rem; margin-bottom:20px; color:var(--text); font-weight:600">${lang.title_cred}</h2>
    <div id="m-manual">
      <div class="label-row">${lang.label_key}</div>
      <input type="password" id="recvP" placeholder="${lang.placeholder_key}">
      <button class="btn" onclick="unlockM()" id="btnM"><span>${lang.btn_decrypt}</span><div class="spinner"></div></button>
    </div>
    <div id="m-auto" class="hidden" style="text-align:center">
      <div style="background:#eff6ff; padding:20px; border-radius:12px; font-weight:600; margin-bottom:20px; color:var(--primary); border:2px solid #dbeafe">${lang.ready_msg}</div>
      <button class="btn" onclick="unlockA()" id="btnA"><span>${lang.btn_open}</span><div class="spinner"></div></button>
    </div>
    <div id="v-decrypted" class="hidden">
      <div class="label-row">${lang.label_decrypted}</div>
      <pre id="content"></pre>
      <div style="position:relative; margin-top:20px;">
          <div class="timer-wrap" style="height:36px; border-radius:18px; margin-bottom:0;"><div id="tFill" class="timer-fill" style="border-radius:18px;"></div></div>
          <div id="tText" class="timer-text" style="top:0; line-height:36px; text-shadow:0 1px 2px rgba(0,0,0,0.3);"></div>
      </div>
      <button class="btn" style="margin-top:20px;" onclick="copyBtn(this, get('content').innerText)"><span>${lang.btn_copy}</span></button>
    </div>
  </div><div id="ov" class="overlay"><div class="modal"><h3 id="mT"></h3><p id="mMsg"></p><button class="modal-btn" onclick="get('ov').style.display='none'">OK</button></div></div>`
  return BASE_HTML(body)
}

function renderReceiveFile(filename: string, lang: Lang): string {
  const safeName = escapeHtml(filename) as string
  const body = `
  <script>window.L = ${JSON.stringify(lang)};</script>
  <div class="card">
      <div class="brand-header"><a href="https://ins.com.pl"><img src="https://ins.com.pl/assets/ins_white_onlylogo.png" style="filter: brightness(0) saturate(100%) invert(32%) sepia(99%) saturate(1352%) hue-rotate(211deg) brightness(96%) contrast(105%);" class="brand-logo"></a></div>
      <h2 style="text-align:center; font-size:1.4rem; margin-bottom:20px; color:var(--text); font-weight:600">${lang.title_file}</h2>
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
  return BASE_HTML(body)
}
