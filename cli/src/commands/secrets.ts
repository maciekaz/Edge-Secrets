// Text secrets: create, list, revoke.

import { Client, type LedgerEntry } from '../api.js'
import { ALGO_VERSION, encryptSecret, deriveVerifier } from '../crypto.js'
import { FORMATS, generatePassphrase, generateSecret, type Format } from '../generate.js'
import { co, statusColour } from '../colors.js'
import type { Options } from '../options.js'
import {
  ask,
  askHidden,
  confirm,
  deliverLink,
  fail,
  formatDuration,
  isTty,
  note,
  ok,
  parseTtl,
  readStdin,
  result,
  warn,
} from '../ui.js'

// Server-side ceilings, mirrored here so a doomed request is refused before it
// is sent and the user is told which limit they hit.
const MAX_TTL_ONETIME = 604800 // 7 days
const MAX_TTL_BOUND = 2592000 // 30 days
const DEFAULT_TTL = 86400 // 24 hours — the fast path

const BIND_MODES: Record<string, string | undefined> = {
  once: undefined,
  device: 'device',
  key: 'webauthn',
}

/**
 * Resolve what to send, in priority order: an argument the user insisted on,
 * piped stdin, or an interactive prompt. The prompt doubles as the entry point
 * for generation — an empty answer means "make one for me".
 */
async function resolveBody(positional: string | undefined, opts: Options, baseUrl: string): Promise<string> {
  if (positional !== undefined) {
    warn('a secret passed as an argument is recorded in your shell history and visible in the process list')
    warn('run `esecrets put` with no argument next time — it prompts without echoing')
    return positional
  }

  if (opts.generate) {
    return announceGenerated(opts.generate, baseUrl, opts)
  }

  if (!process.stdin.isTTY) {
    const piped = await readStdin()
    if (!piped) fail('nothing arrived on stdin')
    return piped
  }

  const typed = await askHidden('Secret (empty to generate a password)')
  if (typed) return typed

  const chosen = await ask(`Format [${FORMATS.join('/')}]`, 'nist')
  if (!FORMATS.includes(chosen as Format)) fail(`unknown format "${chosen}"`)
  return announceGenerated(chosen as Format, baseUrl, opts)
}

async function announceGenerated(format: Format, baseUrl: string, opts: Options): Promise<string> {
  const generated = await generateSecret(format, baseUrl)
  note(`generated a ${generated.label} value — ${generated.entropy} bits`)
  // The value is deliberately not printed: it travels in the link. Anyone who
  // also needs it locally can ask for it explicitly.
  if (opts.show) note(`value: ${generated.value}`)
  return generated.value
}

export async function put(positional: string | undefined, opts: Options, baseUrl: string): Promise<void> {
  const client = new Client(baseUrl)
  client.ensureSession()

  const body = await resolveBody(positional, opts, baseUrl)
  if (!body) fail('the secret is empty')

  let bindKey = opts.bind
  if (!bindKey && isTty && positional === undefined && !opts.ttl && !opts.yes) {
    bindKey = (await ask('Access [once/device/key]', 'once')) || 'once'
  }
  bindKey = bindKey ?? 'once'
  if (!(bindKey in BIND_MODES)) fail(`unknown access mode "${bindKey}" — use once, device or key`)
  const bindMode = BIND_MODES[bindKey]

  let ttl = DEFAULT_TTL
  if (opts.ttl) ttl = parseTtl(opts.ttl)
  else if (isTty && positional === undefined && !opts.yes) ttl = parseTtl(await ask('Expires in', '24h'))

  const ceiling = bindMode ? MAX_TTL_BOUND : MAX_TTL_ONETIME
  if (ttl > ceiling) {
    fail(
      bindMode
        ? `a device-bound secret can live at most ${formatDuration(ceiling)}`
        : `a one-time secret can live at most ${formatDuration(ceiling)} — use --bind device for longer`,
    )
  }

  const passphrase = generatePassphrase()
  const id = crypto.randomUUID()

  const [encryptedData, verifier] = await Promise.all([
    encryptSecret(body, passphrase, id),
    deriveVerifier(passphrase, id),
  ])

  await client.postJson('/api/v1/admin/secrets', {
    id,
    encryptedData,
    verifier,
    ttl,
    algoVersion: ALGO_VERSION,
    bindMode,
    allowFallback: bindMode ? opts.allowFallback === true : undefined,
  })

  const link = `${baseUrl}/receive/${id}#${encodeURIComponent(passphrase)}`

  if (opts.json) {
    result(JSON.stringify({ id, link, ttl, bindMode: bindKey, expiresAt: Date.now() + ttl * 1000 }))
    return
  }

  const summary = `expires in ${formatDuration(ttl)}${bindMode ? ` · ${bindKey}-bound` : ''} · ${id.slice(0, 8)}`
  deliverLink(link, summary, { print: opts.print === true, copy: opts.copy !== false })
}

function describeEntry(entry: LedgerEntry): string {
  const created = new Date(entry.created_at * 1000).toISOString().replace('T', ' ').slice(0, 16)
  const state =
    entry.status === 'opened' ? `opened ×${entry.open_count}` : entry.status === 'pending' ? 'not opened' : entry.status
  const attempts = entry.failed_attempts > 0 ? co.red(` · ${entry.failed_attempts} failed`) : ''
  const bound = entry.bind_mode ? co.dim(` · ${entry.bind_mode}`) : ''
  return `${co.cyan(entry.secret_id.slice(0, 8))}  ${co.dim(created)}  ${statusColour(entry.status)(state)}${attempts}${bound}`
}

export async function ls(opts: Options, baseUrl: string): Promise<void> {
  const client = new Client(baseUrl)
  const { secrets } = await client.getJson<{ secrets: LedgerEntry[] }>('/api/v1/admin/secrets')

  if (opts.json) {
    result(JSON.stringify(secrets))
    return
  }
  if (secrets.length === 0) {
    note('no secrets on your ledger')
    return
  }
  for (const entry of secrets) result(describeEntry(entry))
}

export async function rm(id: string | undefined, opts: Options, baseUrl: string): Promise<void> {
  if (!id) fail('which secret? pass an id — `esecrets ls` lists them')
  const client = new Client(baseUrl)

  if (isTty && !opts.yes && !(await confirm(`Destroy ${id}?`, false))) {
    note('left alone')
    return
  }

  await client.delete(`/api/v1/admin/secrets/${encodeURIComponent(id)}`)
  if (opts.json) result(JSON.stringify({ id, revoked: true }))
  else ok(`destroyed ${co.cyan(id)}`)
}
