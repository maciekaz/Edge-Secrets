// Authentication is delegated wholesale to `cloudflared access`. This CLI owns
// no token storage, no refresh logic and no crypto for the session — it asks
// cloudflared for a JWT and puts it in a header. The upside is that the session
// is a real Zero Trust user identity (so the ledger and revocation work), and
// that nothing long-lived ends up on disk under our control.

import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { readdirSync, rmSync, existsSync } from 'node:fs'

export class CloudflaredMissing extends Error {
  constructor() {
    super('cloudflared is not installed')
    this.name = 'CloudflaredMissing'
  }
}

export function installHint(): string {
  switch (process.platform) {
    case 'darwin':
      return 'brew install cloudflared'
    case 'win32':
      return 'winget install --id Cloudflare.cloudflared'
    default:
      return 'see https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/'
  }
}

export function haveCloudflared(): boolean {
  const probe = spawnSync('cloudflared', ['--version'], { stdio: 'ignore' })
  return !probe.error && probe.status === 0
}

/**
 * The Access application covers both `/gen` and `/api/v1/admin/*` under a single
 * audience, so one token authenticates every call this CLI makes.
 */
export function appUrl(baseUrl: string): string {
  return `${baseUrl}/gen`
}

function looksLikeJwt(value: string): boolean {
  const parts = value.split('.')
  return parts.length === 3 && parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p))
}

/**
 * An externally supplied token wins over the cloudflared cache. This is the
 * escape hatch for environments where the binary cannot be installed; the
 * Worker still re-verifies the signature, so this changes where the CLI looks
 * for a token, not whether the token is trusted.
 */
function overrideToken(): string | null {
  const supplied = process.env.ESECRETS_TOKEN?.trim()
  return supplied ? supplied : null
}

export function hasOverrideToken(): boolean {
  return overrideToken() !== null
}

/**
 * Fetch a cached token. Returns null when there is none or it expired —
 * cloudflared reports both by writing a human sentence rather than a JWT, so
 * the shape check is what actually distinguishes success from failure.
 */
export function cachedToken(baseUrl: string): string | null {
  const supplied = overrideToken()
  if (supplied) return supplied
  if (!haveCloudflared()) throw new CloudflaredMissing()
  const res = spawnSync('cloudflared', ['access', 'token', '--app', appUrl(baseUrl)], { encoding: 'utf8' })
  if (res.error || res.status !== 0) return null
  const out = (res.stdout ?? '').trim()
  return looksLikeJwt(out) ? out : null
}

/**
 * Run the interactive browser login. stdio is inherited so the user sees
 * cloudflared's own prompt and, on a headless box, the URL to open elsewhere.
 */
export function login(baseUrl: string): void {
  if (overrideToken()) throw new Error('ESECRETS_TOKEN is set — unset it to sign in interactively')
  if (!haveCloudflared()) throw new CloudflaredMissing()
  const res = spawnSync('cloudflared', ['access', 'login', '--app', appUrl(baseUrl), '--auto-close'], {
    stdio: 'inherit',
  })
  if (res.error || res.status !== 0) throw new Error('cloudflared login did not complete')
}

/** A token, logging in first if there is not already a usable one. */
export function ensureToken(baseUrl: string): string {
  const existing = cachedToken(baseUrl)
  if (existing) return existing
  login(baseUrl)
  const fresh = cachedToken(baseUrl)
  if (!fresh) throw new Error('logged in, but cloudflared still returned no token')
  return fresh
}

export interface Identity {
  email?: string
  subject?: string
  expiresAt?: Date
}

/**
 * Read the identity out of the token. This is display only — the Worker
 * re-verifies the RS256 signature against the JWKS on every request, so nothing
 * here is trusted for access decisions.
 */
export function describeToken(token: string): Identity {
  const segment = token.split('.')[1]
  if (!segment) return {}
  try {
    const payload = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>
    const exp = typeof payload.exp === 'number' ? new Date(payload.exp * 1000) : undefined
    return {
      email: typeof payload.email === 'string' ? payload.email : undefined,
      subject: typeof payload.sub === 'string' ? payload.sub : undefined,
      expiresAt: exp,
    }
  } catch {
    return {}
  }
}

function cacheDir(): string {
  return join(homedir(), '.cloudflared')
}

/**
 * `cloudflared access` has no logout subcommand, so this removes the cached
 * token files directly. Only files named for this deployment's hostname are
 * touched; the org token is shared with every other app in the Zero Trust
 * organisation, so it is left alone unless explicitly asked for.
 */
export function logout(baseUrl: string, alsoOrgToken: boolean): string[] {
  const dir = cacheDir()
  if (!existsSync(dir)) return []
  const host = new URL(baseUrl).hostname
  const removed: string[] = []
  for (const entry of readdirSync(dir)) {
    const isAppToken = entry.startsWith(`${host}-`) && entry.endsWith('-token')
    const isOrgToken = alsoOrgToken && entry.endsWith('-org-token')
    if (!isAppToken && !isOrgToken) continue
    rmSync(join(dir, entry), { force: true })
    removed.push(entry)
  }
  return removed
}
