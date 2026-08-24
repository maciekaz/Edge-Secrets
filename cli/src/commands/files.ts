// File sharing: multipart upload in both the server-visible and the
// end-to-end-encrypted mode, plus storage inspection and deletion.

import { basename } from 'node:path'
import { open, stat } from 'node:fs/promises'
import type { FileHandle } from 'node:fs/promises'
import { Client, type InitUploadResponse, type StatsResponse, type UploadedPart } from '../api.js'
import { ALGO_VERSION, deriveVerifier, encryptFile } from '../crypto.js'
import { generatePassphrase } from '../generate.js'
import { co } from '../colors.js'
import type { Options } from '../options.js'
import {
  askHidden,
  confirm,
  deliverLink,
  fail,
  formatBytes,
  formatDuration,
  isTty,
  note,
  ok,
  parseTtl,
  progress,
  result,
  warn,
} from '../ui.js'

// Both mirror the browser client: parts of the same size except the last, and
// four in flight at once.
const CHUNK = 50 * 1024 * 1024
const CONCURRENCY = 4

// Enforced by the server too; checked here so a 150 MiB+ file fails before it
// is read and encrypted rather than after.
const E2EE_MAX = 150 * 1024 * 1024
const DEFAULT_TTL = 86400

/**
 * Read exactly `end - start` bytes, looping until the buffer is full.
 *
 * Two deliberate choices. `Buffer.alloc` rather than `allocUnsafe`, because an
 * uninitialised buffer that is only partially filled would ship whatever the
 * process had in that heap page — another file, a token, a passphrase —
 * straight into the upload. And the loop, because a short read is legal: the
 * returned `bytesRead` is the only thing that says how much actually arrived.
 */
async function readExactly(handle: FileHandle, start: number, end: number): Promise<Buffer> {
  const length = end - start
  const buffer = Buffer.alloc(length)
  let filled = 0
  while (filled < length) {
    const { bytesRead } = await handle.read(buffer, filled, length - filled, start + filled)
    if (bytesRead === 0) throw new Error('the file ended before its declared size — was it modified during upload?')
    filled += bytesRead
  }
  return buffer
}

async function uploadParts(
  client: Client,
  init: InitUploadResponse,
  total: number,
  read: (start: number, end: number) => Promise<Uint8Array>,
): Promise<UploadedPart[]> {
  const count = Math.ceil(total / CHUNK)
  const parts = new Array<UploadedPart>(count)
  const queue: number[] = []
  for (let i = 0; i < count; i++) queue.push(i)
  let done = 0

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = queue.shift()
      if (index === undefined) return
      const chunk = await read(index * CHUNK, Math.min((index + 1) * CHUNK, total))
      const query = `key=${encodeURIComponent(init.key)}&id=${encodeURIComponent(init.uploadId)}&num=${index + 1}`
      parts[index] = await client.putBytes<UploadedPart>(`/api/v1/admin/files/part?${query}`, chunk)
      done++
      progress('uploading', done, count)
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, count) }, worker))
  return parts
}

export async function upload(path: string | undefined, opts: Options, baseUrl: string): Promise<void> {
  if (!path) fail('which file? `esecrets file <path>`')

  const info = await stat(path).catch(() => fail(`cannot read ${path}`))
  if (!info.isFile()) fail(`${path} is not a regular file`)

  // Everything the arguments alone can rule out is ruled out before a session is
  // opened, so a typo never costs a round trip or a browser sign-in.
  const ttl = opts.ttl ? parseTtl(opts.ttl) : DEFAULT_TTL
  const limit = opts.limit ?? 1
  if (!Number.isInteger(limit) || limit < 1) fail('--limit must be a whole number of downloads, at least 1')
  const filename = basename(path)

  if (opts.e2ee && info.size > E2EE_MAX) {
    fail(
      `end-to-end encryption is capped at ${formatBytes(E2EE_MAX)} and this file is ${formatBytes(info.size)} — ` +
        'upload it without --e2ee, or split it',
    )
  }

  const client = new Client(baseUrl)
  client.ensureSession()

  if (opts.e2ee) {
    await uploadEncrypted(client, path, filename, info.size, ttl, limit, opts, baseUrl)
    return
  }

  let password: string | undefined
  if (opts.password) {
    password = await askHidden('Download password')
    if (!password) fail('the password is empty')
    warn('without --e2ee the file is stored unencrypted and the server can read it')
  }

  const init = await client.postJson<InitUploadResponse>('/api/v1/admin/files/init', {
    filename,
    size: info.size,
    password,
    // Milliseconds here, unlike secrets: `files.expires_at` predates the
    // seconds-based tables and still carries the original unit.
    ttl: ttl * 1000,
    limit,
  })

  const handle = await open(path, 'r')
  try {
    const parts = await uploadParts(client, init, info.size, (start, end) => readExactly(handle, start, end))
    await client.postJson('/api/v1/admin/files/complete', {
      key: init.key,
      uploadId: init.uploadId,
      parts,
      fileId: init.fileId,
    })
  } finally {
    await handle.close()
  }

  const link = `${baseUrl}/share/${init.fileId}`
  if (opts.json) {
    result(JSON.stringify({ id: init.fileId, link, size: info.size, ttl, limit, encrypted: false }))
    return
  }
  deliverLink(link, `${formatBytes(info.size)} · expires in ${formatDuration(ttl)} · ${limit} download(s)`, {
    print: opts.print === true,
    copy: opts.copy !== false,
  })
}

async function uploadEncrypted(
  client: Client,
  path: string,
  filename: string,
  size: number,
  ttl: number,
  limit: number,
  opts: Options,
  baseUrl: string,
): Promise<void> {
  const passphrase = generatePassphrase()
  // The client picks the id in this mode, because the verifier is derived from
  // it before the server has ever heard of the file.
  const fileId = crypto.randomUUID()

  note('encrypting locally')
  const handle = await open(path, 'r')
  let plaintext: Buffer
  try {
    plaintext = await readExactly(handle, 0, size)
  } finally {
    await handle.close()
  }

  const [payload, verifier] = await Promise.all([
    encryptFile(plaintext, passphrase, fileId),
    deriveVerifier(passphrase, fileId),
  ])
  plaintext.fill(0)

  const init = await client.postJson<InitUploadResponse>('/api/v1/admin/files/init', {
    id: fileId,
    filename,
    size: payload.length,
    encrypted: true,
    verifier,
    algoVersion: ALGO_VERSION,
    ttl: ttl * 1000,
    limit,
  })

  const parts = await uploadParts(client, init, payload.length, async (start, end) =>
    payload.subarray(start, end),
  )
  await client.postJson('/api/v1/admin/files/complete', {
    key: init.key,
    uploadId: init.uploadId,
    parts,
    fileId: init.fileId,
  })

  const link = `${baseUrl}/share/${init.fileId}#${encodeURIComponent(passphrase)}`
  if (opts.json) {
    result(JSON.stringify({ id: init.fileId, link, size, ttl, limit, encrypted: true }))
    return
  }
  deliverLink(link, `${formatBytes(size)} encrypted · expires in ${formatDuration(ttl)} · ${limit} download(s)`, {
    print: opts.print === true,
    copy: opts.copy !== false,
  })
}

export async function list(opts: Options, baseUrl: string): Promise<void> {
  const client = new Client(baseUrl)
  const stats = await client.getJson<StatsResponse>('/api/v1/admin/stats')

  if (opts.json) {
    result(JSON.stringify(stats))
    return
  }

  note(`${formatBytes(stats.used)} of ${formatBytes(stats.limit)} used · max ${formatBytes(stats.maxUpload)} per file`)
  if (stats.files.length === 0) {
    note('no files stored')
    return
  }
  for (const file of stats.files) {
    const downloads = `${file.download_count}/${file.max_downloads}`
    result(
      `${co.cyan(file.id.slice(0, 8))}  ${co.dim(formatBytes(file.size).padStart(9))}` +
        `  ${co.dim(downloads.padStart(7))}  ${co.bold(file.filename)}`,
    )
  }
}

export async function remove(id: string | undefined, opts: Options, baseUrl: string): Promise<void> {
  if (!id) fail('which file? pass an id — `esecrets files` lists them')
  const client = new Client(baseUrl)

  if (isTty && !opts.yes && !(await confirm(`Delete file ${id}?`, false))) {
    note('left alone')
    return
  }

  // This endpoint sits in the public zone by design: an uploader revokes a link
  // straight after creating it, sometimes from a context with no session.
  await client.delete(`/api/v1/public/files/${encodeURIComponent(id)}`, false)
  if (opts.json) result(JSON.stringify({ id, deleted: true }))
  else ok(`deleted ${co.cyan(id)}`)
}
