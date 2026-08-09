import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { ORIGIN } from './helpers'

async function fetchList(path: string) {
  const res = await SELF.fetch(`${ORIGIN}${path}`)
  return { res, words: (await res.text()).split('\n').filter(Boolean) }
}

describe('published wordlists', () => {
  it('serves the EFF Long list at its documented size', async () => {
    const { res, words } = await fetchList('/ui/words-eff.v1.txt')
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toContain('immutable')
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')

    // 7776 is 6^5, one entry per five-dice roll, and the figure the stated
    // 12.9 bits per word depends on.
    expect(words.length).toBe(7776)
    expect(new Set(words).size).toBe(7776)
    expect(words[0]).toBe('abacus')
    expect(words[words.length - 1]).toBe('zoom')
  })

  it('serves the BIP-39 English list unmodified', async () => {
    const { res, words } = await fetchList('/ui/words-bip39.v1.txt')
    expect(res.status).toBe(200)
    expect(words.length).toBe(2048)
    expect(new Set(words).size).toBe(2048)
    expect(words[0]).toBe('abandon')
    expect(words[words.length - 1]).toBe('zoo')
    // The spec requires the first four letters to identify a word uniquely.
    expect(new Set(words.map((w) => w.slice(0, 4))).size).toBe(2048)
    // Canonical order is part of the standard.
    expect([...words].sort()).toEqual(words)
  })

  it('keeps both lists off the recipient page', async () => {
    const page = await (await SELF.fetch(`${ORIGIN}/receive/whatever`)).text()
    expect(page).not.toContain('words-eff')
    expect(page).not.toContain('words-bip39')
  })
})

describe('generator UI', () => {
  it('offers every standard and fetches lists rather than inlining them', async () => {
    const js = await (await SELF.fetch(`${ORIGIN}/ui/app.v1.js`)).text()
    for (const mode of ['nist', 'eff', 'bip39', 'legacy', 'key256', 'key512']) {
      expect(js).toContain(mode)
    }
    expect(js).toContain('/ui/words-eff.v1.txt')
    expect(js).toContain('/ui/words-bip39.v1.txt')
    // A wordlist inlined into the shared bundle would land on every page load.
    expect(js).not.toContain('abacus')
    expect(js).not.toContain('abandon\nability')
  })
})

describe('QR rendering', () => {
  it('serves the encoder to the browser instead of drawing codes server-side', async () => {
    const res = await SELF.fetch(`${ORIGIN}/ui/qrcode.v1.js`)
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toContain('immutable')
    expect(res.headers.get('Content-Type')).toContain('javascript')
    const js = await res.text()
    expect(js).toContain('QR Code Generator for JavaScript')
    // Loaded as a classic script, so the factory has to land on window.
    expect(js).toMatch(/^\s*var qrcode = function\(\)/m)
  })

  it('no longer exposes a server route that accepts a link', async () => {
    // The endpoint took the whole URL as a query parameter, which for the
    // fast link meant handing the fragment to the Worker. Rendering moved to
    // the client, so the route is gone rather than merely unused.
    const res = await SELF.fetch(`${ORIGIN}/ui/qr?d=https%3A%2F%2Fexample.test%2Fx%23secret`)
    expect(res.status).toBe(404)
  })

})
