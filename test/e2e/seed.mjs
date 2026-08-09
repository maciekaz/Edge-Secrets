// Seeds a device-bound or WebAuthn-bound secret straight into the LOCAL
// Miniflare stores, so the browser test can start from a link without needing a
// Cloudflare Access session for /gen.
//
// The verifier has to match exactly what the page derives in-browser, so it is
// computed here with the same Argon2id parameters and the same `<id>_v` salt.
import { execFileSync } from 'node:child_process'
import { argon2id } from 'hash-wasm'

const ARGON2 = { memorySize: 19456, iterations: 2, parallelism: 1, hashLength: 32 }
const NS = process.env.KV_NAMESPACE_ID
if (!NS) throw new Error('KV_NAMESPACE_ID must be set')

export async function deriveVerifier(passphrase, id) {
  const bytes = await argon2id({
    password: new TextEncoder().encode(passphrase),
    salt: new TextEncoder().encode(`${id}_v`),
    ...ARGON2,
    outputType: 'binary',
  })
  return Buffer.from(bytes).toString('base64')
}

const wrangler = (args) =>
  execFileSync('npx', ['wrangler', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })

/**
 * Same derivation the page uses for the AES key: Argon2id over the passphrase
 * with the bare secret id as salt (the verifier uses `<id>_v` instead, so the
 * two never collide). Encrypting here means the browser really has to decrypt,
 * which keeps the E2EE path inside the test rather than around it.
 */
async function encryptFor(passphrase, id, plaintext) {
  const raw = await argon2id({
    password: new TextEncoder().encode(passphrase),
    salt: new TextEncoder().encode(id),
    ...ARGON2,
    outputType: 'binary',
  })
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
  ])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  )
  return JSON.stringify({
    iv: Buffer.from(iv).toString('base64'),
    d: Buffer.from(new Uint8Array(ct)).toString('base64'),
  })
}

export const PLAINTEXT = 'e2e-secret-payload'

export async function seedBoundSecret({ id, passphrase, bindMode, allowFallback = false, ttl = 3600 }) {
  const verifier = await deriveVerifier(passphrase, id)
  const expiresAt = Math.floor(Date.now() / 1000) + ttl
  const metadata = JSON.stringify({
    verifier,
    attempts: 0,
    algoVersion: 'argon2id-v1',
    expiresAt,
    bindMode,
  })

  const value = await encryptFor(passphrase, id, PLAINTEXT)

  wrangler([
    'kv', 'key', 'put', id, value,
    '--namespace-id', NS, '--local',
    '--metadata', metadata,
    '--ttl', String(ttl),
  ])

  wrangler([
    'd1', 'execute', 'secret-db', '--local', '--command',
    `INSERT OR REPLACE INTO secret_bindings (secret_id,mode,allow_fallback,bound_factor,bound_hash,pubkey,cred_id,sign_count,bound_at,expires_at,read_count) VALUES ('${id}','${bindMode}',${allowFallback ? 1 : 0},NULL,NULL,NULL,NULL,0,NULL,${expiresAt},0)`,
  ])

  return { verifier, expiresAt }
}

export function readBinding(id) {
  const out = wrangler([
    'd1', 'execute', 'secret-db', '--local', '--json', '--command',
    `SELECT mode,bound_factor,cred_id,read_count FROM secret_bindings WHERE secret_id='${id}'`,
  ])
  return JSON.parse(out)[0].results[0] ?? null
}
