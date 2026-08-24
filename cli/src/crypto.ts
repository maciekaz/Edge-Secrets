// Key derivation and encryption, kept byte-identical to the browser client in
// `src/index.ts`. Both sides call hash-wasm with the same parameters, so a
// secret written here decrypts in the browser and vice versa. If ARGON2_PARAMS
// ever changes in the Worker, it has to change here in the same commit.

import { argon2id } from 'hash-wasm'
// The Web Crypto types come from Node rather than the DOM lib: pulling in DOM
// would put browser globals in scope and hide genuine runtime differences.
import type { webcrypto } from 'node:crypto'

export const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 19456, // KiB — 19 MiB, the OWASP baseline
  hashLength: 32,
} as const

export const ALGO_VERSION = 'argon2id-v1'

/** Domain separation: `<id>` derives the AES key, `<id>_v` the server-side verifier. */
export type DeriveKind = 'k' | 'v'

async function deriveBytes(passphrase: string, id: string, kind: DeriveKind): Promise<Uint8Array> {
  const enc = new TextEncoder()
  return argon2id({
    password: enc.encode(passphrase),
    salt: enc.encode(kind === 'v' ? `${id}_v` : id),
    outputType: 'binary',
    ...ARGON2_PARAMS,
  })
}

/** Base64 verifier — the only derived value the server is ever shown. */
export async function deriveVerifier(passphrase: string, id: string): Promise<string> {
  return Buffer.from(await deriveBytes(passphrase, id, 'v')).toString('base64')
}

export async function deriveKey(passphrase: string, id: string): Promise<webcrypto.CryptoKey> {
  const bytes = await deriveBytes(passphrase, id, 'k')
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
}

/**
 * Encrypt a text secret into the exact JSON envelope the retrieval page expects:
 * `{ iv, d }`, both base64. A different shape here is a silently unreadable secret.
 */
export async function encryptSecret(plaintext: string, passphrase: string, id: string): Promise<string> {
  const key = await deriveKey(passphrase, id)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext))
  return JSON.stringify({
    iv: Buffer.from(iv).toString('base64'),
    d: Buffer.from(new Uint8Array(ct)).toString('base64'),
  })
}

/**
 * Encrypt file bytes and return IV ‖ ciphertext, matching what the browser
 * uploads: the recipient peels the first 12 bytes off before decrypting.
 */
export async function encryptFile(plaintext: Uint8Array, passphrase: string, id: string): Promise<Uint8Array> {
  const key = await deriveKey(passphrase, id)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext))
  const out = new Uint8Array(12 + ct.length)
  out.set(iv, 0)
  out.set(ct, 12)
  return out
}
