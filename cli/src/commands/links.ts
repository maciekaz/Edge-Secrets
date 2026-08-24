// URL shortener.

import { Client } from '../api.js'
import type { Options } from '../options.js'
import { deliverLink, fail, formatDuration, parseTtl, result } from '../ui.js'

const DEFAULT_TTL = 604800 // the server's own ceiling for a short link

export async function shorten(target: string | undefined, opts: Options, baseUrl: string): Promise<void> {
  if (!target) fail('which URL? `esecrets link <url>`')

  let parsed: URL
  try {
    parsed = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`)
  } catch {
    fail(`"${target}" is not a valid URL`)
  }

  const ttl = opts.ttl ? parseTtl(opts.ttl) : DEFAULT_TTL
  const maxClicks = opts.maxClicks ?? -1
  if (maxClicks !== -1 && (!Number.isInteger(maxClicks) || maxClicks < 1)) {
    fail('--max-clicks must be a whole number of clicks, at least 1')
  }

  const client = new Client(baseUrl)
  const created = await client.postJson<{ id: string; shortUrl: string }>('/api/v1/admin/links', {
    url: parsed.toString(),
    ttl,
    maxClicks,
  })

  if (opts.json) {
    result(JSON.stringify(created))
    return
  }

  const clicks = maxClicks === -1 ? 'unlimited clicks' : `${maxClicks} click(s)`
  deliverLink(created.shortUrl, `expires in ${formatDuration(ttl)} · ${clicks}`, {
    print: opts.print === true,
    copy: opts.copy !== false,
  })
}
