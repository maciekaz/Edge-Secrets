// Password and passphrase generation, mirroring the browser generator in
// `src/index.ts`. Same alphabets, same rejection sampling, same stated entropy —
// a figure quoted here is a floor, never a flattering upper bound.

// Body alphabet stays broad: generated secrets are AES-encrypted and never
// enter a URL.
const ALPHA_BODY = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!?@'
// Fragment alphabet: RFC 3986 unreserved minus visual confusables, so a
// passphrase never needs percent-encoding and never collides with a separator.
const ALPHA_URL_KEY = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_~'

const ALPHA_LOWER = 'abcdefghijklmnopqrstuvwxyz'
const ALPHA_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const ALPHA_DIGIT = '0123456789'
const ALPHA_LEGACY_SPECIAL = '!@#$%^&*'

/**
 * Unbiased draw. Bytes at or above the largest whole multiple of the alphabet
 * size are rejected and redrawn rather than folded in with a modulo, which
 * would quietly favour the front of the alphabet.
 */
function randString(alphabet: string, length: number): string {
  const n = alphabet.length
  const threshold = 256 - (256 % n)
  const out: string[] = []
  while (out.length < length) {
    const buf = crypto.getRandomValues(new Uint8Array(length * 2))
    for (let i = 0; i < buf.length && out.length < length; i++) {
      const b = buf[i]!
      if (b < threshold) out.push(alphabet[b % n]!)
    }
  }
  return out.join('')
}

function randIndex(n: number): number {
  const threshold = 65536 - (65536 % n)
  for (;;) {
    const buf = crypto.getRandomValues(new Uint16Array(1))
    const v = buf[0]!
    if (v < threshold) return v % n
  }
}

function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randIndex(i + 1)
    const a = items[i]!
    items[i] = items[j]!
    items[j] = a
  }
  return items
}

/** 20 characters from a 58-character alphabet — 117 bits, the link's entropy. */
export function generatePassphrase(): string {
  return randString(ALPHA_URL_KEY, 20)
}

export const FORMATS = ['nist', 'eff', 'bip39', 'legacy', 'api'] as const
export type Format = (typeof FORMATS)[number]

export interface Generated {
  value: string
  /** Lower bound, in bits. */
  entropy: number
  label: string
}

const WORDLISTS = {
  eff: { path: '/ui/words-eff.v1.txt', size: 7776, words: 6, bitsPerWord: 12.925 },
  bip39: { path: '/ui/words-bip39.v1.txt', size: 2048, words: 12, bitsPerWord: 11 },
} as const

const wordCache = new Map<string, string[]>()

/**
 * Wordlists are pulled from the deployment's own public routes, exactly as the
 * browser does, so the CLI can never draw from a list the app does not ship.
 * The size assertion matters: a truncated or substituted list would silently
 * reduce entropy below what we print.
 */
async function loadWords(baseUrl: string, list: keyof typeof WORDLISTS): Promise<string[]> {
  const cached = wordCache.get(list)
  if (cached) return cached
  const spec = WORDLISTS[list]
  const res = await fetch(`${baseUrl}${spec.path}`)
  if (!res.ok) throw new Error(`could not fetch the ${list} wordlist (HTTP ${res.status})`)
  const words = (await res.text()).split('\n').map((w) => w.trim()).filter(Boolean)
  if (words.length !== spec.size) {
    throw new Error(`${list} wordlist has ${words.length} entries, expected ${spec.size} — refusing to use it`)
  }
  wordCache.set(list, words)
  return words
}

/**
 * Generate a secret body in the requested standard. `baseUrl` is only touched
 * by the passphrase modes, so the default path stays offline-capable.
 */
export async function generateSecret(format: Format, baseUrl: string): Promise<Generated> {
  switch (format) {
    case 'nist':
      // 20 chars from 58 — no forced symbol classes, per SP 800-63B.
      return { value: randString(ALPHA_BODY, 20), entropy: 117, label: 'NIST SP 800-63B' }

    case 'eff':
    case 'bip39': {
      const spec = WORDLISTS[format]
      const words = await loadWords(baseUrl, format)
      const picked: string[] = []
      for (let i = 0; i < spec.words; i++) picked.push(words[randIndex(words.length)]!)
      return {
        value: picked.join('-'),
        entropy: Math.floor(spec.words * spec.bitsPerWord),
        label: format === 'eff' ? 'EFF Long Wordlist' : 'BIP-39 English',
      }
    }

    case 'legacy': {
      // Exactly 12 characters with one of each class. Entropy is counted at the
      // real class alphabet sizes and the shuffle is not credited, because its
      // permutations overlap.
      const chars = [
        ALPHA_LOWER[randIndex(ALPHA_LOWER.length)]!,
        ALPHA_UPPER[randIndex(ALPHA_UPPER.length)]!,
        ALPHA_DIGIT[randIndex(ALPHA_DIGIT.length)]!,
        ALPHA_LEGACY_SPECIAL[randIndex(ALPHA_LEGACY_SPECIAL.length)]!,
      ]
      const rest = ALPHA_LOWER + ALPHA_UPPER + ALPHA_DIGIT + ALPHA_LEGACY_SPECIAL
      for (let i = chars.length; i < 12; i++) chars.push(rest[randIndex(rest.length)]!)
      return { value: shuffle(chars).join(''), entropy: 64, label: 'legacy corporate' }
    }

    case 'api': {
      const bytes = crypto.getRandomValues(new Uint8Array(32))
      return { value: Buffer.from(bytes).toString('base64'), entropy: 256, label: 'API key (32 bytes)' }
    }
  }
}
