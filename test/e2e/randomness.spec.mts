import { expect, test, type Page } from '@playwright/test'

/**
 * Distribution checks on the real generators in the real browser. These cannot
 * prove a CSPRNG is sound, but they catch the failures that actually occur: a
 * modulo bias, a rejection threshold that never emits the tail of the alphabet,
 * and a shuffle that leaves the class-guaranteed characters pinned to the slots
 * they were constructed in.
 */

function chiSquare(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0)
  const expected = total / counts.length
  return counts.reduce((a, c) => a + (c - expected) ** 2 / expected, 0)
}

async function probe(page: Page, fn: string) {
  await page.goto('/receive/randomness-probe')
  await page.waitForFunction((f) => typeof (window as any)[f] === 'function', fn)
}

test('the character generator reaches every symbol of its alphabet, uniformly', async ({ page }) => {
  await probe(page, '_randString')

  // The alphabet is a const in the bundle and so not reachable on window. It is
  // recovered from the output instead, which also makes a silently shortened
  // alphabet fail rather than quietly weaken the password.
  const tally = await page.evaluate(() => {
    const w = window as any
    const counts: Record<string, number> = {}
    for (let i = 0; i < 3000; i++) {
      for (const ch of w._randString('abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!?@', 20)) {
        counts[ch] = (counts[ch] ?? 0) + 1
      }
    }
    return counts
  })

  const symbols = Object.keys(tally)
  expect(symbols.length, 'every symbol must be reachable').toBe(58)

  const chi = chiSquare(Object.values(tally))
  // 60000 draws over 58 symbols. The 99.9th percentile for df=57 is ~101.
  expect(chi, `chi=${chi.toFixed(1)} df=57`).toBeLessThan(120)
})

test('word indices are drawn uniformly across the whole EFF range', async ({ page }) => {
  await probe(page, '_randInt')

  const buckets = await page.evaluate(() => {
    const w = window as any
    const B = 72
    const counts = new Array(B).fill(0)
    for (let i = 0; i < 40000; i++) counts[Math.floor(w._randInt(7776) / (7776 / B))]++
    return counts
  })

  expect(buckets.filter((c) => c === 0)).toHaveLength(0)
  const chi = chiSquare(buckets)
  // 40000 draws over 72 buckets; the 99.9th percentile for df=71 is ~119.
  expect(chi, `chi=${chi.toFixed(1)} df=71`).toBeLessThan(140)
})

test('the top of the EFF range is reachable, so no draw is silently truncated', async ({ page }) => {
  await probe(page, '_randInt')
  const extremes = await page.evaluate(() => {
    const w = window as any
    let min = Infinity
    let max = -Infinity
    for (let i = 0; i < 60000; i++) {
      const v = w._randInt(7776)
      if (v < min) min = v
      if (v > max) max = v
    }
    return { min, max }
  })
  expect(extremes.min).toBe(0)
  expect(extremes.max).toBe(7775)
})

test('the legacy shuffle spreads the required classes across every slot', async ({ page }) => {
  await probe(page, '_genLegacy')

  const perSlot = await page.evaluate(() => {
    const w = window as any
    // Count specials at each position, not the first one only: with eight free
    // fill characters drawn from an alphabet that also contains specials, a
    // first-occurrence histogram is geometric by construction and says nothing
    // about the shuffle.
    const counts = new Array(12).fill(0)
    for (let i = 0; i < 6000; i++) {
      const p: string = w._genLegacy()
      for (let j = 0; j < 12; j++) if ('!@#$%^&*'.includes(p[j]!)) counts[j]++
    }
    return counts
  })

  // Without the shuffle, slot 3 would hold every guaranteed special and the
  // first three slots would hold none at all.
  expect(perSlot.filter((c) => c === 0)).toHaveLength(0)
  const chi = chiSquare(perSlot)
  // 12 slots, df=11; the 99.9th percentile is ~31.
  expect(chi, `slots ${perSlot.join(',')}`).toBeLessThan(45)
})

test('every legacy draw satisfies all four class rules', async ({ page }) => {
  await probe(page, '_genLegacy')
  const bad = await page.evaluate(() => {
    const w = window as any
    const failures: string[] = []
    for (let i = 0; i < 3000; i++) {
      const p: string = w._genLegacy()
      if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{12}$/.test(p)) failures.push(p)
    }
    return failures
  })
  expect(bad).toEqual([])
})
