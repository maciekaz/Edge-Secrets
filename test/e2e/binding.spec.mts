import { expect, test, type Page } from '@playwright/test'
import { randomUUID } from 'node:crypto'
import { readBinding, seedBoundSecret } from './seed.mjs'

const PASSPHRASE = 'E2E-Test-Key-2026'

/**
 * Attaches a CDP virtual authenticator. `backupEligible` is the flag that
 * decides whether the credential counts as device-bound (false) or as a synced
 * passkey (true). The Worker refuses the latter, because a credential that
 * exists on every device the user owns cannot bind a secret to one of them.
 */
async function addAuthenticator(page: Page, backupEligible: boolean) {
  const client = await page.context().newCDPSession(page)
  await client.send('WebAuthn.enable')
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'usb',
      hasResidentKey: false,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: backupEligible,
      defaultBackupState: backupEligible,
    },
  })
  return { client, authenticatorId }
}

async function openSecret(page: Page, id: string) {
  // Re-visiting a URL that differs only in its fragment is a same-document
  // navigation, so the second open would otherwise inherit the first one's
  // post-unlock DOM. Bounce through about:blank to force a real load.
  await page.goto('about:blank')
  await page.goto(`/receive/${id}#${encodeURIComponent(PASSPHRASE)}`)
  // Argon2id ships as a separate bundle; unlocking before it lands would fail.
  await page.waitForFunction(() => !!(window as any).hashwasm?.argon2id)
  await expect(page.locator('#btnA')).toBeVisible()
}

/** Clicks through the unlock button and the irreversible-bind consent gate. */
async function unlockAndConsent(page: Page) {
  await page.locator('#btnA').click()
  const gate = page.locator('#bindOv')
  await expect(gate).toBeVisible()
  await page.locator('[data-click="bindConfirm"]').click()
}

test.describe('device binding (non-extractable ECDSA in IndexedDB)', () => {
  test('binds the first browser, then re-opens without a second consent prompt', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'device' })

    await openSecret(page, id)
    await unlockAndConsent(page)
    await expect(page.locator('#v-decrypted')).toBeVisible()

    const row = readBinding(id)
    expect(row.bound_factor).toBe('ecdsa')
    expect(row.read_count).toBe(1)

    // The binding cookie must be invisible to page scripts.
    const visible = await page.evaluate(() => document.cookie)
    expect(visible).not.toContain(`es_${id}`)

    // A second open is silent: the consent gate belongs to the bind, not to
    // every read.
    await openSecret(page, id)
    await page.locator('#btnA').click()
    await expect(page.locator('#v-decrypted')).toBeVisible()
    await expect(page.locator('#bindOv')).toBeHidden()
    expect(readBinding(id).read_count).toBe(2)
  })

  test('shows the remaining access window rather than an auto-delete countdown', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'device' })
    await openSecret(page, id)
    await unlockAndConsent(page)

    await expect(page.locator('#bindUntil')).toBeVisible()
    await expect(page.locator('#tText')).not.toContainText('AUTO-DELETE')
  })

  test('locks out a different browser profile that has the link and the key', async ({ browser, page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'device' })

    await openSecret(page, id)
    await unlockAndConsent(page)
    await expect(page.locator('#v-decrypted')).toBeVisible()

    // Separate context = separate cookie jar and IndexedDB, i.e. another device.
    const other = await browser.newContext()
    const otherPage = await other.newPage()
    await openSecret(otherPage, id)
    await otherPage.locator('#btnA').click()
    await expect(otherPage.locator('#ov')).toBeVisible()
    await expect(otherPage.locator('#mMsg')).toContainText('another browser')
    await expect(otherPage.locator('#v-decrypted')).toBeHidden()
    await other.close()
  })

  test('declining the consent gate leaves the secret unclaimed', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'device' })

    await openSecret(page, id)
    await page.locator('#btnA').click()
    await expect(page.locator('#bindOv')).toBeVisible()
    await page.locator('[data-click="bindCancel"]').click()

    await expect(page.locator('#v-decrypted')).toBeHidden()
    expect(readBinding(id).bound_factor).toBeNull()
  })
})

test.describe('webauthn binding (CDP virtual authenticator)', () => {
  test('binds to a device-bound credential and re-asserts on the next read', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'webauthn' })
    await addAuthenticator(page, /* backupEligible */ false)

    await openSecret(page, id)
    await unlockAndConsent(page)
    await expect(page.locator('#v-decrypted')).toBeVisible()

    const row = readBinding(id)
    expect(row.bound_factor).toBe('webauthn')
    expect(row.cred_id).toBeTruthy()

    // Second read goes through a fresh challenge and a real assertion.
    await openSecret(page, id)
    await page.locator('#btnA').click()
    await expect(page.locator('#v-decrypted')).toBeVisible()
    expect(readBinding(id).read_count).toBe(2)
  })

  test('refuses a synced passkey and explains why', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'webauthn' })
    await addAuthenticator(page, /* backupEligible */ true)

    await openSecret(page, id)
    await unlockAndConsent(page)

    await expect(page.locator('#ov')).toBeVisible()
    await expect(page.locator('#mMsg')).toContainText('synced passkey')
    await expect(page.locator('#v-decrypted')).toBeHidden()
    expect(readBinding(id).bound_factor).toBeNull()
  })

  test('falls back to cookie-only when there is no authenticator and the sender allowed it', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'webauthn', allowFallback: true })
    // Emulate a browser without WebAuthn support at all, which is the branch
    // the fallback exists for. Simply attaching no authenticator would instead
    // leave create() waiting on a picker that never appears.
    await page.addInitScript(() => { delete (window as any).PublicKeyCredential })

    await openSecret(page, id)
    await unlockAndConsent(page)
    await expect(page.locator('#v-decrypted')).toBeVisible()
    expect(readBinding(id).bound_factor).toBe('cookie')
  })

  test('locks out entirely when there is no authenticator and no fallback', async ({ page }) => {
    const id = randomUUID()
    await seedBoundSecret({ id, passphrase: PASSPHRASE, bindMode: 'webauthn', allowFallback: false })
    await page.addInitScript(() => { delete (window as any).PublicKeyCredential })

    await openSecret(page, id)
    await unlockAndConsent(page)

    await expect(page.locator('#ov')).toBeVisible()
    await expect(page.locator('#v-decrypted')).toBeHidden()
    expect(readBinding(id).bound_factor).toBeNull()
  })
})
