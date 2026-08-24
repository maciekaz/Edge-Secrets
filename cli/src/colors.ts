// Colour, applied to fixed semantic roles rather than picked per message:
//
//   red      something failed
//   yellow   a warning the user should read but that did not stop anything
//   green    an action completed
//   cyan     an identifier or a link — anything the user might copy
//   bold     a heading or a value worth the eye landing on first
//   dim      secondary detail: durations, sizes, counts
//
// Two independent decisions, one per stream. stdout is coloured only when it is
// a terminal, so `esecrets put | pbcopy` still yields a clean link and never a
// string with escape codes in it. stderr is decided separately because it stays
// interactive even when stdout is redirected.
//
// NO_COLOR and FORCE_COLOR are honoured (no-color.org), as is TERM=dumb.

const CODES = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  underline: '\u001b[4m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  cyan: '\u001b[36m',
} as const

type Style = keyof Omit<typeof CODES, 'reset'>

function enabled(isTty: boolean): boolean {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true
  if (process.env.TERM === 'dumb') return false
  return isTty
}

export interface Palette {
  readonly on: boolean
  bold(text: string): string
  dim(text: string): string
  red(text: string): string
  green(text: string): string
  yellow(text: string): string
  cyan(text: string): string
  link(text: string): string
}

function makePalette(isTty: boolean): Palette {
  // Evaluated per call rather than once at import: the entry point may disable
  // colour after this module has already been loaded.
  const wrap = (style: Style) => (text: string) =>
    enabled(isTty) ? `${CODES[style]}${text}${CODES.reset}` : text
  return {
    get on() {
      return enabled(isTty)
    },
    bold: wrap('bold'),
    dim: wrap('dim'),
    red: wrap('red'),
    green: wrap('green'),
    yellow: wrap('yellow'),
    cyan: wrap('cyan'),
    // Links get underlined as well, because they are the one thing on screen a
    // user is most likely to reach for.
    link: (text: string) =>
      enabled(isTty) ? `${CODES.cyan}${CODES.underline}${text}${CODES.reset}` : text,
  }
}

/** Palette for messages, prompts and progress. */
export const c = makePalette(process.stderr.isTTY === true)
/** Palette for results. Off whenever stdout is piped, so output stays parseable. */
export const co = makePalette(process.stdout.isTTY === true)

/** Status colours for the ledger, so a glance is enough to read a list. */
export function statusColour(status: string): (text: string) => string {
  switch (status) {
    case 'opened':
      return co.green
    case 'pending':
      return co.yellow
    case 'revoked':
    case 'burned':
    case 'expired':
      return co.red
    default:
      return co.dim
  }
}
