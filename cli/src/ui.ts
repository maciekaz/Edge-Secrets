// Terminal I/O. Two rules shape this file:
//
//   1. stdout carries the result and nothing else, so `esecrets put | pbcopy`
//      works. Everything conversational goes to stderr.
//   2. On an interactive terminal the finished link goes to the clipboard
//      instead of the screen, because a link carrying `#passphrase` in
//      scrollback is a live credential sitting in the user's window.

import { spawnSync } from 'node:child_process'
import { createInterface } from 'node:readline'
import { c, co } from './colors.js'

export const isTty = process.stdout.isTTY === true && process.stdin.isTTY === true

export function note(message: string): void {
  process.stderr.write(`${message}\n`)
}

/** Secondary detail — present, but not competing with the result. */
export function detail(message: string): void {
  process.stderr.write(`${c.dim(message)}\n`)
}

export function ok(message: string): void {
  process.stderr.write(`${c.green('✓')} ${message}\n`)
}

export function warn(message: string): void {
  process.stderr.write(`${c.yellow('!')} ${message}\n`)
}

export function result(line: string): void {
  process.stdout.write(`${line}\n`)
}

export function fail(message: string): never {
  process.stderr.write(`${c.red('error')} ${message}\n`)
  process.exit(1)
}

export async function ask(question: string, fallback?: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr })
  try {
    const answer = await new Promise<string>((resolve) => {
      rl.question(fallback ? `${question} (${fallback}): ` : `${question}: `, resolve)
    })
    const trimmed = answer.trim()
    return trimmed || fallback || ''
  } finally {
    rl.close()
  }
}

/**
 * Read a line without echoing it. Used for every secret value, so that nothing
 * confidential is ever visible on screen or recoverable from scrollback.
 */
export function askHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) return readStdin()
  process.stderr.write(`${question}: `)
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    const wasRaw = stdin.isRaw === true
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')
    let buffer = ''

    const done = (value: string | null) => {
      stdin.setRawMode(wasRaw)
      stdin.pause()
      stdin.removeListener('data', onData)
      process.stderr.write('\n')
      if (value === null) reject(new Error('cancelled'))
      else resolve(value)
    }

    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done(buffer)
        if (ch === '\u0003') return done(null) // Ctrl-C
        if (ch === '\u007f' || ch === '\b') {
          buffer = buffer.slice(0, -1)
          continue
        }
        // Ignore other control characters rather than embedding them in a secret.
        if (ch >= ' ') buffer += ch
      }
    }

    stdin.on('data', onData)
  })
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk))
  // A trailing newline is an artefact of `echo`, not part of the secret.
  return Buffer.concat(chunks).toString('utf8').replace(/\n$/, '')
}

export async function confirm(question: string, defaultYes = true): Promise<boolean> {
  const answer = await ask(`${question} [${defaultYes ? 'Y/n' : 'y/N'}]`)
  if (!answer) return defaultYes
  return /^y(es)?$/i.test(answer.trim())
}

function clipboardCommand(): [string, string[]] | null {
  switch (process.platform) {
    case 'darwin':
      return ['pbcopy', []]
    case 'win32':
      return ['clip', []]
    default:
      if (process.env.WSL_DISTRO_NAME) return ['clip.exe', []]
      if (spawnSync('sh', ['-c', 'command -v wl-copy'], { stdio: 'ignore' }).status === 0) return ['wl-copy', []]
      if (spawnSync('sh', ['-c', 'command -v xclip'], { stdio: 'ignore' }).status === 0) {
        return ['xclip', ['-selection', 'clipboard']]
      }
      return null
  }
}

export function copyToClipboard(text: string): boolean {
  const command = clipboardCommand()
  if (!command) return false
  const res = spawnSync(command[0], command[1], { input: text })
  return !res.error && res.status === 0
}

/**
 * Deliver a finished link. Interactive terminals get it on the clipboard and a
 * short confirmation on stderr; redirected output gets the raw link on stdout.
 * `--print` forces the link onto the screen for anyone who wants it there.
 */
export function deliverLink(link: string, summary: string, opts: { print: boolean; copy: boolean }): void {
  if (!isTty || opts.print) {
    result(co.link(link))
    detail(summary)
    return
  }
  if (opts.copy && copyToClipboard(link)) {
    ok(`copied to clipboard  ${c.dim(summary)}`)
    return
  }
  result(co.link(link))
  detail(summary)
}

export function progress(label: string, done: number, total: number): void {
  if (!process.stderr.isTTY) return
  const ratio = total === 0 ? 1 : done / total
  const width = 24
  const filled = Math.round(ratio * width)
  const bar = `${'\u2501'.repeat(filled)}${c.dim('\u2501'.repeat(width - filled))}`
  process.stderr.write(`\r${label} ${c.cyan(bar)} ${String(Math.round(ratio * 100)).padStart(3)}%`)
  if (done >= total) process.stderr.write('\n')
}

const TTL_UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }

/** Parse `30m`, `24h`, `7d` into seconds. Bare digits are read as seconds. */
export function parseTtl(input: string): number {
  const match = /^(\d+)\s*([smhd])?$/i.exec(input.trim())
  if (!match) throw new Error(`cannot read "${input}" as a duration — use 30m, 24h or 7d`)
  const amount = Number(match[1])
  const unit = (match[2] ?? 's').toLowerCase()
  const seconds = amount * TTL_UNITS[unit]!
  if (seconds <= 0) throw new Error('duration must be positive')
  return seconds
}

export function formatDuration(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`
}
