import { expect, test, type Page } from '@playwright/test'
import { randomUUID } from 'node:crypto'
import { seedSecretWithBody } from './seed.mjs'

const PAYLOADS = [
  '<img src=x onerror="window.__pwned=1">',
  '</textarea></pre><script>window.__pwned=1</script>',
  '"><svg onload="window.__pwned=1">',
  "'\"><body onload=window.__pwned=1>",
  '${window.__pwned=1}',
  '$& $1 $` $\' backreference bait',
  '!@#$%^&*()_+-=[]{}|;:,.<>?/~`',
  'javascript:window.__pwned=1',
  '‮gnp.exe',
  'line1\nline2\ttabbed',
]

async function openAndUnlock(page: Page, id: string, passphrase: string) {
  await page.goto('about:blank')
  await page.goto(`/receive/${id}#${encodeURIComponent(passphrase)}`)
  await page.waitForFunction(() => !!(window as any).hashwasm?.argon2id)
  await page.locator('#btnA').click()
  await expect(page.locator('#v-decrypted')).toBeVisible()
}

test('hostile secret content is rendered as text, never as markup', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))

  for (const payload of PAYLOADS) {
    const id = randomUUID()
    const passphrase = 'XSS-Probe-Key-2026'
    await seedSecretWithBody({ id, passphrase, body: payload })
    await openAndUnlock(page, id, passphrase)

    // What matters is what the recipient walks away with, so the assertion is
    // on innerText, which is both what is displayed and what Copy reads. Note
    // that the innerText setter turns a newline into a <br> element, so
    // textContent would not round-trip a multi-line secret even though nothing
    // is lost.
    const shown = await page.evaluate(() => (document.getElementById('content') as HTMLElement).innerText)
    expect(shown, `payload did not round-trip: ${JSON.stringify(payload)}`).toBe(payload)

    const pwned = await page.evaluate(() => (window as any).__pwned)
    expect(pwned, `payload executed: ${payload}`).toBeUndefined()

    // Nothing hostile should have become a real element.
    // <br> is the one element the innerText setter is allowed to create.
    const injected = await page.evaluate(() =>
      [...document.querySelectorAll('#content *')].map((e) => e.tagName).filter((t) => t !== 'BR')
    )
    expect(injected, `payload parsed as markup: ${payload}`).toEqual([])
  }

  expect(errors).toEqual([])
})

test('a passphrase full of special characters survives the fragment round trip', async ({ page }) => {
  const passphrase = '!@#$%^&*()_+ ~`|\\"\'<>?/ąćęłńóśźż 漢字 🔐'
  const id = randomUUID()
  const body = 'payload-for-special-key'
  await seedSecretWithBody({ id, passphrase, body })

  await openAndUnlock(page, id, passphrase)
  await expect(page.locator('#content')).toHaveText(body)
})

test('the list renderer escapes markup in values it did not author', async ({ page }) => {
  await page.goto('/receive/escape-probe')
  await page.waitForFunction(() => typeof (window as any)._sentRow === 'function')

  const result = await page.evaluate(() => {
    const w = window as any
    w.L = w.L || {}
    const row = w._sentRow({
      secret_id: '<img src=x onerror="window.__pwned=1">',
      created_at: Math.floor(Date.now() / 1000),
      status: 'pending',
      open_count: 0,
      failed_attempts: 0,
    })
    const host = document.createElement('div')
    host.innerHTML = row
    document.body.appendChild(host)
    return {
      html: row,
      imgs: host.querySelectorAll('img').length,
      text: host.querySelector('.hist-id')?.textContent,
    }
  })

  expect(result.imgs, 'identifier was parsed as markup').toBe(0)
  expect(result.html).toContain('&lt;img')
  expect(result.text).toBe('<img src=x onerror="window.__pwned=1">')
  expect(await page.evaluate(() => (window as any).__pwned)).toBeUndefined()
})
