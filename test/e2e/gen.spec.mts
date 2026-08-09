import { expect, test, type Page } from '@playwright/test'

const MODES = ['nist', 'eff', 'bip39', 'legacy', 'key256', 'key512']

/**
 * The create form lives behind Cloudflare Access, which cannot be satisfied
 * from a local dev server. The generator itself ships in the public bundle, so
 * these tests load that bundle on a public page and mount the same elements
 * and the same data-click attributes the form uses. The delegated dispatcher
 * under test is the real one.
 */
async function mountGenerator(page: Page) {
  await page.goto('/receive/generator-probe')
  await page.waitForFunction(() => typeof (window as any).genS === 'function')
  await page.evaluate((modes) => {
    const host = document.createElement('div')
    host.innerHTML =
      '<select id="genMode" data-change="onGenMode">' +
      modes.map((m) => '<option value="' + m + '">' + m + '</option>').join('') +
      '</select><textarea id="body"></textarea><div id="genMeta"></div>' +
      '<button id="probeGen" data-click="genS">go</button>'
    document.body.appendChild(host)
  }, MODES)
}

async function draw(page: Page, mode: string) {
  await page.selectOption('#genMode', mode)
  await page.locator('#probeGen').click()
  await expect(page.locator('#body')).not.toHaveValue('')
  const v = await page.locator('#body').inputValue()
  await page.locator('#body').fill('')
  return v
}

async function listWords(page: Page, url: string): Promise<string[]> {
  return page.evaluate(
    async (u) => (await (await fetch(u)).text()).split('\n').filter(Boolean),
    url
  )
}

/**
 * Four EFF entries contain a hyphen themselves (t-shirt, yo-yo, drop-down,
 * felt-tip), so counting separators would be wrong. This asks the only question
 * that matters: can the phrase be segmented into exactly `count` entries of the
 * published list?
 */
function segmentsInto(phrase: string, words: Set<string>, count: number): boolean {
  const parts = phrase.split('-')
  // reach[i] = set of word counts that can consume the first i parts.
  const reach: Set<number>[] = Array.from({ length: parts.length + 1 }, () => new Set())
  reach[0]!.add(0)
  for (let i = 0; i < parts.length; i++) {
    if (reach[i]!.size === 0) continue
    for (let j = i + 1; j <= Math.min(parts.length, i + 3); j++) {
      if (!words.has(parts.slice(i, j).join('-'))) continue
      for (const n of reach[i]!) reach[j]!.add(n + 1)
    }
  }
  return reach[parts.length]!.has(count)
}

test('every standard produces the shape it promises', async ({ page }) => {
  await mountGenerator(page)
  const out: Record<string, string> = {}
  for (const mode of MODES) out[mode] = await draw(page, mode)

  expect(out.nist).toMatch(/^[\w!?@]{20}$/)

  const eff = new Set(await listWords(page, '/ui/words-eff.v1.txt'))
  expect(eff.size).toBe(7776)
  expect(segmentsInto(out.eff!, eff, 6), out.eff).toBe(true)

  const bip = new Set(await listWords(page, '/ui/words-bip39.v1.txt'))
  expect(bip.size).toBe(2048)
  expect(out.bip39!.split('-')).toHaveLength(12)
  for (const w of out.bip39!.split('-')) expect(bip.has(w), w).toBe(true)

  // The whole point of this mode is the character-class rules an auditor checks.
  expect(out.legacy).toMatch(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{12}$/)

  expect(Buffer.from(out.key256!, 'base64')).toHaveLength(32)
  expect(Buffer.from(out.key512!, 'base64')).toHaveLength(64)
})

test('every drawn word really comes from the published list', async ({ page }) => {
  await mountGenerator(page)
  const eff = new Set(await listWords(page, '/ui/words-eff.v1.txt'))
  for (let i = 0; i < 15; i++) {
    const v = await draw(page, 'eff')
    expect(segmentsInto(v, eff, 6), v).toBe(true)
  }
})

test('the legacy rules hold across many draws, not just one lucky one', async ({ page }) => {
  await mountGenerator(page)
  for (let i = 0; i < 25; i++) {
    const v = await draw(page, 'legacy')
    expect(v, `draw ${i}`).toMatch(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{12}$/)
  }
})

test('passphrases do not repeat, and generating one is free', async ({ page }) => {
  await mountGenerator(page)
  const seen = new Set<string>()
  for (let i = 0; i < 12; i++) seen.add(await draw(page, 'eff'))
  expect(seen.size).toBe(12)

  const cost = await page.evaluate(async () => {
    const words = (await (await fetch('/ui/words-eff.v1.txt')).text()).split('\n').filter(Boolean)
    const t0 = performance.now()
    for (let i = 0; i < 1000; i++) (window as any)._genPassphrase(words, 6)
    return { words: words.length, per1000Ms: performance.now() - t0 }
  })
  expect(cost.words).toBe(7776)
  // Generation is not something the UI ever needs to show a spinner for.
  expect(cost.per1000Ms).toBeLessThan(200)
})

test('a list is fetched once, only on demand, and never drags in the other', async ({ page }) => {
  const hits: string[] = []
  page.on('request', (r) => { if (r.url().includes('/ui/words-')) hits.push(r.url()) })

  await mountGenerator(page)
  await draw(page, 'nist')
  expect(hits, 'never fetched for a mode that does not use it').toHaveLength(0)

  for (let i = 0; i < 5; i++) await draw(page, 'eff')
  expect(hits, 'fetched once, then cached in the page').toHaveLength(1)
  expect(hits[0]).toContain('words-eff')

  await draw(page, 'bip39')
  expect(hits).toHaveLength(2)
  expect(hits[1]).toContain('words-bip39')
})

test('recipients are never sent a wordlist', async ({ page }) => {
  const hits: string[] = []
  page.on('request', (r) => { if (r.url().includes('/ui/words-')) hits.push(r.url()) })
  await page.goto('/receive/generator-probe')
  await page.waitForFunction(() => !!(window as any).hashwasm?.argon2id)
  expect(hits).toHaveLength(0)
})

test('the vendored QR encoder matches the installed package byte for byte', async () => {
  const fs = await import('node:fs/promises')
  const [vendored, installed] = await Promise.all([
    fs.readFile('src/qrcode-vendor.js', 'utf8'),
    fs.readFile('node_modules/qrcode-generator/dist/qrcode.js', 'utf8'),
  ])
  // Vendored only because the package's exports map hides the dist file. If an
  // upgrade changes it, this fails rather than shipping a stale copy.
  expect(vendored).toBe(installed)
})

test('QR codes are built in the browser, with the link never leaving it', async ({ page }) => {
  const outbound: string[] = []
  page.on('request', (r) => {
    if (r.url().includes('/ui/qr') || r.url().includes('secret-passphrase')) outbound.push(r.url())
  })

  await page.goto('/receive/qr-probe')
  await page.waitForFunction(() => typeof (window as any).showQR === 'function')

  const link = 'https://example.test/receive/abc#secret-passphrase-must-not-leave'
  await page.evaluate(async (u) => { await (window as any).showQR(u) }, link)

  const src = await page.locator('#qrImg').getAttribute('src')
  expect(src, 'the code must be inlined, not fetched').toMatch(/^data:image\/svg\+xml/)
  expect(decodeURIComponent(src!)).toContain('<svg')

  // Exactly one request, for the encoder itself, and nothing carrying the link.
  expect(outbound).toEqual([expect.stringContaining('/ui/qrcode.v1.js')])
  for (const url of outbound) expect(url).not.toContain('secret-passphrase')
})

test('the encoder is fetched once and not at all until a code is drawn', async ({ page }) => {
  const hits: string[] = []
  page.on('request', (r) => { if (r.url().includes('/ui/qrcode.v1.js')) hits.push(r.url()) })

  await page.goto('/receive/qr-probe')
  await page.waitForFunction(() => typeof (window as any).showQR === 'function')
  expect(hits).toHaveLength(0)

  for (let i = 0; i < 4; i++) {
    await page.evaluate(async (i) => { await (window as any).showQR('https://example.test/' + i) }, i)
  }
  expect(hits).toHaveLength(1)
})

test('the client draws exactly what the server used to draw', async ({ page }) => {
  const { createRequire } = await import('node:module')
  const qrcode = createRequire(import.meta.url)('qrcode-generator')

  // The server built the SVG from the module grid with a 4-module quiet zone at
  // error-correction level M. Reproducing that here and comparing byte for byte
  // shows the move to the browser changed where the code is drawn, not what.
  const reference = (url: string) => {
    const qr = qrcode(0, 'M')
    qr.addData(url, 'Byte')
    qr.make()
    const n = qr.getModuleCount()
    const pad = 4
    const cells: string[] = []
    for (let r = 0; r < n; r++)
      for (let c = 0; c < n; c++)
        if (qr.isDark(r, c)) cells.push(`<rect x="${c + pad}" y="${r + pad}" width="1" height="1"/>`)
    const size = n + pad * 2
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="white"/><g fill="black">${cells.join('')}</g></svg>`
  }

  await page.goto('/receive/qr-probe')
  await page.waitForFunction(() => typeof (window as any).showQR === 'function')

  const urls = [
    'https://secrets.example.com/receive/8f14e45f-ceea-467a-9e73-1f0b2c3d4e5f',
    'https://secrets.example.com/receive/8f14e45f-ceea-467a-9e73-1f0b2c3d4e5f#corn-flute-ridge-amber-vault-lunar',
    'https://secrets.example.com/s/aB3xY9z',
  ]

  for (const url of urls) {
    await page.evaluate(async (u) => { await (window as any).showQR(u) }, url)
    const src = await page.locator('#qrImg').getAttribute('src')
    const svg = decodeURIComponent(src!.replace('data:image/svg+xml;charset=utf-8,', ''))
    expect(svg, url).toBe(reference(url))
  }
})
