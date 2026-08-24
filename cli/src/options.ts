// Parsed command-line options, shared by every command.

import { FORMATS, type Format } from './generate.js'

export interface Options {
  // Deployment selection
  url?: string
  profile?: string

  // Output shape
  json?: boolean
  print?: boolean
  copy?: boolean
  show?: boolean
  yes?: boolean

  // Secrets
  ttl?: string
  bind?: string
  allowFallback?: boolean
  generate?: Format

  // Files
  e2ee?: boolean
  password?: boolean
  limit?: number
  file?: boolean

  // Links
  maxClicks?: number

  // Session
  all?: boolean

  noColor?: boolean
}

export interface Parsed {
  command: string
  args: string[]
  options: Options
}

const NEEDS_VALUE = new Set(['--url', '--profile', '--ttl', '--bind', '--generate', '--limit', '--max-clicks'])

const ALIASES: Record<string, string> = {
  '-p': '--profile',
  '-u': '--url',
  '-t': '--ttl',
  '-y': '--yes',
  '-j': '--json',
}

/**
 * A hand-rolled parser rather than a dependency. The surface is small, and the
 * one runtime dependency this package has is the Argon2id implementation, which
 * has to match the browser's. Nothing else earns a place in the tree.
 */
export function parseArgs(argv: string[]): Parsed {
  const options: Options = {}
  const positional: string[] = []

  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i]!
    if (ALIASES[arg]) arg = ALIASES[arg]!

    if (!arg.startsWith('-')) {
      positional.push(arg)
      continue
    }

    // `--secret` is deliberately absent: a secret value never belongs in argv.
    let value: string | undefined
    const eq = arg.indexOf('=')
    if (eq !== -1) {
      value = arg.slice(eq + 1)
      arg = arg.slice(0, eq)
    } else if (NEEDS_VALUE.has(arg)) {
      value = argv[++i]
      if (value === undefined) throw new Error(`${arg} needs a value`)
    }

    switch (arg) {
      case '--url':
        options.url = value
        break
      case '--profile':
        options.profile = value
        break
      case '--ttl':
        options.ttl = value
        break
      case '--bind':
        options.bind = value
        break
      case '--generate': {
        const format = value ?? 'nist'
        if (!FORMATS.includes(format as Format)) {
          throw new Error(`unknown format "${format}" — use one of: ${FORMATS.join(', ')}`)
        }
        options.generate = format as Format
        break
      }
      case '--limit':
        options.limit = Number(value)
        break
      case '--max-clicks':
        options.maxClicks = Number(value)
        break
      case '--json':
        options.json = true
        break
      case '--print':
        options.print = true
        break
      case '--copy':
        options.copy = true
        break
      case '--no-copy':
        options.copy = false
        break
      case '--show':
        options.show = true
        break
      case '--yes':
        options.yes = true
        break
      case '--allow-fallback':
        options.allowFallback = true
        break
      case '--e2ee':
        options.e2ee = true
        break
      case '--password':
        options.password = true
        break
      case '--file':
        options.file = true
        break
      case '--all':
        options.all = true
        break
      case '--no-color':
        options.noColor = true
        break
      default:
        throw new Error(`unknown option ${arg}`)
    }
  }

  return { command: positional.shift() ?? '', args: positional, options }
}
