#!/usr/bin/env node
// esecrets — command-line client for a self-hosted Edge Secrets deployment.
//
// Two invariants run through the whole tool:
//   · a secret value never travels through argv, and
//   · a finished link never lands in scrollback on an interactive terminal.

import { CloudflaredMissing, installHint } from './auth.js'
import { resolveUrl } from './config.js'
import { parseArgs } from './options.js'
import { fail, note, result } from './ui.js'
import * as secrets from './commands/secrets.js'
import * as files from './commands/files.js'
import * as links from './commands/links.js'
import * as session from './commands/session.js'

const VERSION = '0.1.0'

const HELP = `esecrets — share secrets, files and links from the terminal

USAGE
  esecrets <command> [options]

SECRETS
  put                     create a secret; prompts for the value, 24h by default
  ls                      list the secrets you created
  rm <id>                 destroy a secret you created

FILES
  file <path>             upload a file and get a share link
  files                   storage usage and stored files
  rm --file <id>          delete a stored file

LINKS
  link <url>              create a short link

SESSION
  login                   sign in through your browser (uses cloudflared)
  who                     show the current identity and session
  logout                  drop the cached token for this deployment
  config add <name> <url> register a deployment
  config list             show registered deployments

COMMON OPTIONS
  -t, --ttl <duration>    lifetime: 30m, 24h, 7d
      --bind <mode>       secret access mode: once (default), device, key
      --generate [fmt]    generate the secret: nist, eff, bip39, legacy, api
      --e2ee              encrypt a file locally before upload (max 150 MiB)
      --password          prompt for a file download password
      --limit <n>         download limit for a file (default 1)
      --max-clicks <n>    click limit for a short link
  -p, --profile <name>    which deployment to use
  -u, --url <url>         deployment URL, bypassing profiles
  -j, --json              machine-readable output on stdout
      --print             print the link instead of copying it
      --show              also print a generated value
  -y, --yes               skip prompts and confirmations
      --no-color          disable colour (NO_COLOR is honoured too)

The link is the credential: anyone holding it can open the secret. On an
interactive terminal it is copied to the clipboard rather than displayed, so it
does not linger in your scrollback.
`

async function main(): Promise<void> {
  const { command, args, options } = parseArgs(process.argv.slice(2))

  // Set before anything prints. The palettes read this on every call, so a
  // flag parsed here still reaches code imported long before.
  if (options.noColor) process.env.NO_COLOR = '1'

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stderr.write(HELP)
    return
  }
  if (command === 'version' || command === '--version' || command === '-V') {
    result(VERSION)
    return
  }

  // `config` is the one command that must work before a deployment is known.
  if (command === 'config') {
    session.configure(args, options)
    return
  }

  const baseUrl = resolveUrl(options)

  switch (command) {
    case 'put':
    case 'send':
      return secrets.put(args[0], options, baseUrl)
    case 'ls':
      return secrets.ls(options, baseUrl)
    case 'rm':
      return options.file ? files.remove(args[0], options, baseUrl) : secrets.rm(args[0], options, baseUrl)
    case 'file':
      return files.upload(args[0], options, baseUrl)
    case 'files':
      return files.list(options, baseUrl)
    case 'link':
      return links.shorten(args[0], options, baseUrl)
    case 'login':
      return session.signIn(options, baseUrl)
    case 'who':
    case 'whoami':
      return session.whoami(options, baseUrl)
    case 'logout':
      return session.signOut(options, baseUrl)
    default:
      fail(`unknown command "${command}" — run \`esecrets help\``)
  }
}

main().catch((error: unknown) => {
  if (error instanceof CloudflaredMissing) {
    note('')
    fail(`cloudflared is required to sign in\n\n  ${installHint()}\n`)
  }
  if (error instanceof Error && error.message === 'cancelled') {
    note('cancelled')
    process.exit(130)
  }
  fail(error instanceof Error ? error.message : String(error))
})
