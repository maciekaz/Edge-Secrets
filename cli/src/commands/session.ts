// Session and profile management.

import { cachedToken, describeToken, hasOverrideToken, haveCloudflared, installHint, login, logout } from '../auth.js'
import { normaliseUrl, readConfig, writeConfig } from '../config.js'
import { c, co } from '../colors.js'
import type { Options } from '../options.js'
import { detail, fail, note, ok, result } from '../ui.js'

function requireCloudflared(): void {
  // A token supplied through the environment replaces the sign-in entirely.
  if (hasOverrideToken()) return
  if (haveCloudflared()) return
  fail(`cloudflared is not installed — sign-in needs it\n\n  ${installHint()}\n`)
}

export function signIn(opts: Options, baseUrl: string): void {
  requireCloudflared()
  login(baseUrl)
  const token = cachedToken(baseUrl)
  if (!token) fail('login finished but no token was cached')
  const who = describeToken(token)
  if (opts.json) {
    result(JSON.stringify({ signedIn: true, email: who.email, expiresAt: who.expiresAt?.toISOString() }))
    return
  }
  ok(`signed in${who.email ? ` as ${c.bold(who.email)}` : ''}`)
}

export function whoami(opts: Options, baseUrl: string): void {
  requireCloudflared()
  const token = cachedToken(baseUrl)
  if (!token) {
    if (opts.json) {
      result(JSON.stringify({ signedIn: false }))
      return
    }
    note('not signed in — run: esecrets login')
    return
  }

  const who = describeToken(token)
  if (opts.json) {
    result(
      JSON.stringify({
        signedIn: true,
        email: who.email,
        subject: who.subject,
        expiresAt: who.expiresAt?.toISOString(),
        deployment: baseUrl,
      }),
    )
    return
  }

  result(co.bold(who.email ?? who.subject ?? 'signed in'))
  detail(`deployment: ${baseUrl}`)
  if (who.expiresAt) {
    const minutes = Math.round((who.expiresAt.getTime() - Date.now()) / 60000)
    if (minutes > 0) detail(`session valid for another ${minutes} min`)
    else note('session has expired — run: esecrets login')
  }
}

export function signOut(opts: Options, baseUrl: string): void {
  const removed = logout(baseUrl, opts.all === true)
  if (opts.json) {
    result(JSON.stringify({ signedOut: true, removed: removed.length }))
    return
  }
  if (removed.length === 0) {
    note('nothing cached for this deployment')
    return
  }
  note(`signed out of ${baseUrl}`)
  if (!opts.all) note('the organisation-wide token is untouched — pass --all to drop that too')
}

/** `config` covers `add`, `default`, `list` and `path`. */
export function configure(args: string[], opts: Options): void {
  const [action, ...rest] = args
  const config = readConfig()

  switch (action) {
    case 'add': {
      const [name, url] = rest
      if (!name || !url) fail('usage: esecrets config add <name> <url>')
      config.profiles[name] = { url: normaliseUrl(url) }
      config.default ??= name
      const path = writeConfig(config)
      ok(`saved profile ${c.bold(name)} → ${config.profiles[name]!.url}`)
      detail(`config: ${path}`)
      return
    }

    case 'default': {
      const [name] = rest
      if (!name) fail('usage: esecrets config default <name>')
      if (!config.profiles[name]) fail(`no profile named "${name}"`)
      config.default = name
      writeConfig(config)
      note(`default profile is now "${name}"`)
      return
    }

    case 'rm': {
      const [name] = rest
      if (!name) fail('usage: esecrets config rm <name>')
      if (!config.profiles[name]) fail(`no profile named "${name}"`)
      delete config.profiles[name]
      if (config.default === name) delete config.default
      writeConfig(config)
      note(`removed profile "${name}"`)
      return
    }

    case undefined:
    case 'list': {
      const names = Object.keys(config.profiles)
      if (opts.json) {
        result(JSON.stringify(config))
        return
      }
      if (names.length === 0) {
        note('no profiles — run: esecrets config add <name> <url>')
        return
      }
      for (const name of names) {
        const isDefault = name === config.default
        const marker = isDefault ? co.green('*') : ' '
        result(`${marker} ${isDefault ? co.bold(name) : name}  ${co.dim(config.profiles[name]!.url)}`)
      }
      return
    }

    default:
      fail(`unknown config action "${action}" — use add, default, rm or list`)
  }
}
