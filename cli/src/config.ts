// Profile storage. This file holds deployment URLs and nothing else — tokens
// live in cloudflared's own cache, so leaking this config discloses no
// credential. Keep it that way.

import { homedir } from 'node:os'
import { join } from 'node:path'
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'

export interface Profile {
  url: string
}

export interface Config {
  default?: string
  profiles: Record<string, Profile>
}

function configDir(): string {
  if (process.env.ESECRETS_CONFIG_DIR) return process.env.ESECRETS_CONFIG_DIR
  if (process.platform === 'win32' && process.env.APPDATA) return join(process.env.APPDATA, 'esecrets')
  const xdg = process.env.XDG_CONFIG_HOME
  return join(xdg && xdg.trim() ? xdg : join(homedir(), '.config'), 'esecrets')
}

function configPath(): string {
  return join(configDir(), 'config.json')
}

export function readConfig(): Config {
  const path = configPath()
  if (!existsSync(path)) return { profiles: {} }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<Config>
    return { default: parsed.default, profiles: parsed.profiles ?? {} }
  } catch {
    throw new Error(`config at ${path} is not valid JSON`)
  }
}

export function writeConfig(config: Config): string {
  const dir = configDir()
  mkdirSync(dir, { recursive: true })
  const path = configPath()
  // 0600 is honoured on POSIX and ignored on Windows. It costs nothing and this
  // file holds no secret, so the mode is tidiness rather than a control.
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 })
  return path
}

/**
 * Turn user input into a bare origin, refusing anything ambiguous.
 *
 * This is security-relevant rather than cosmetic: whatever comes out is where
 * the Access token gets sent. Bare hostnames are accepted as a convenience, so
 * the rules below exist to stop that convenience from quietly turning nonsense
 * into a plausible-looking host — `file:///etc/passwd` used to normalise to
 * `https://file` rather than being rejected.
 */
export function normaliseUrl(raw: string): string {
  const input = raw.trim()

  // A scheme we do not handle is an error, never something to paper over by
  // prefixing https:// and hoping the result parses.
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(input)
  if (scheme && !/^https?$/i.test(scheme[1]!)) {
    throw new Error(`"${raw}" uses an unsupported scheme — give an https:// URL or a hostname`)
  }

  const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`
  let parsed: URL
  try {
    parsed = new URL(withScheme)
  } catch {
    throw new Error(`"${raw}" is not a valid URL`)
  }

  if (parsed.username || parsed.password) {
    throw new Error('credentials in the deployment URL are not accepted')
  }

  const host = parsed.hostname
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '[::1]'
  if (parsed.protocol !== 'https:' && !isLoopback) {
    throw new Error('refusing a plaintext http:// deployment — the Access token would travel in the clear')
  }
  // A deployment is reached by a fully qualified name. Anything without a dot
  // is either a typo or a mangled paste.
  if (!isLoopback && !host.includes('.')) {
    throw new Error(`"${raw}" does not name a host — did you mean something like secrets.example.com?`)
  }

  return parsed.origin
}

/**
 * Resolve the deployment to talk to. An explicit `--url` wins, then `--profile`,
 * then the configured default, then a lone profile if there is exactly one.
 */
export function resolveUrl(opts: { url?: string; profile?: string }): string {
  if (opts.url) return normaliseUrl(opts.url)
  if (process.env.ESECRETS_URL && !opts.profile) return normaliseUrl(process.env.ESECRETS_URL)

  const config = readConfig()
  const names = Object.keys(config.profiles)

  // Re-validated on read as well as on write: config.json is a plain file and
  // nothing stops it being edited by hand into an http:// endpoint.
  if (opts.profile) {
    const found = config.profiles[opts.profile]
    if (!found) throw new Error(`no profile named "${opts.profile}" — run: esecrets config add ${opts.profile} <url>`)
    return normaliseUrl(found.url)
  }
  if (config.default) {
    const found = config.profiles[config.default]
    if (found) return normaliseUrl(found.url)
  }
  if (names.length === 1) return normaliseUrl(config.profiles[names[0]!]!.url)

  throw new Error(
    names.length === 0
      ? 'no deployment configured — run: esecrets config add <name> <url>'
      : `several profiles configured (${names.join(', ')}) and no default — pass --profile or run: esecrets config default <name>`,
  )
}
