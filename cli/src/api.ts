// HTTP client for the admin and public zones. Every admin call carries the
// Access JWT in `Cf-Access-Jwt-Assertion`; a 401 mid-session means the Access
// session expired, which is recoverable by logging in again rather than a
// reason to abort halfway through an upload.

import { ensureToken, cachedToken, hasOverrideToken, login } from './auth.js'
import { note, warn } from './ui.js'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(explain(status, code))
    this.name = 'ApiError'
  }
}

/** Turn the server's machine-readable codes into something worth reading. */
function explain(status: number, code: string): string {
  switch (code) {
    case 'ID_TAKEN':
      return 'that identifier already belongs to another sender'
    case 'UPLOAD_LIMIT':
      return 'the file is larger than this deployment allows per upload'
    case 'E2EE_UPLOAD_LIMIT':
      return 'end-to-end encrypted uploads are capped at 150 MiB by the server'
    case 'STORAGE_LIMIT':
      return 'the deployment is out of storage'
    case 'SIZE_MISMATCH':
      return 'the uploaded size did not match what was declared — upload rejected'
    case 'INVALID_SIZE':
      return 'the server rejected the declared file size'
    case 'NOT_FOUND':
      return 'not found'
    default:
      return code ? `${code} (HTTP ${status})` : `HTTP ${status}`
  }
}

export class Client {
  private token: string | null = null

  constructor(readonly baseUrl: string) {}

  private authHeader(): Record<string, string> {
    if (!this.token) {
      // cloudflared hands back a token scoped to one Access application. A
      // token from the environment carries no such guarantee, so it is about to
      // be sent wherever this profile points — worth saying out loud.
      if (hasOverrideToken()) warn(`using ESECRETS_TOKEN — it will be sent to ${this.baseUrl}`)
      this.token = ensureToken(this.baseUrl)
    }
    return { 'Cf-Access-Jwt-Assertion': this.token }
  }

  /**
   * One retry on 401 only. Anything more would loop a user through their IdP
   * repeatedly when the real problem is an Access policy that excludes them.
   */
  private async send(path: string, init: RequestInit, authenticated: boolean): Promise<Response> {
    const url = `${this.baseUrl}${path}`
    const headers = new Headers(init.headers)
    if (authenticated) for (const [k, v] of Object.entries(this.authHeader())) headers.set(k, v)

    let res = await fetch(url, { ...init, headers })
    if (res.status === 401 && authenticated) {
      note('Access session expired — signing in again')
      login(this.baseUrl)
      this.token = cachedToken(this.baseUrl)
      if (!this.token) throw new Error('could not obtain a new Access token')
      headers.set('Cf-Access-Jwt-Assertion', this.token)
      res = await fetch(url, { ...init, headers })
    }
    return res
  }

  private static async decode(res: Response): Promise<never> {
    let code = ''
    try {
      const body = (await res.json()) as { error?: unknown }
      if (typeof body.error === 'string') code = body.error
    } catch {
      /* a non-JSON body carries nothing worth surfacing */
    }
    throw new ApiError(res.status, code)
  }

  async getJson<T>(path: string): Promise<T> {
    const res = await this.send(path, { method: 'GET' }, true)
    if (!res.ok) await Client.decode(res)
    return (await res.json()) as T
  }

  async postJson<T>(path: string, body: unknown): Promise<T> {
    const res = await this.send(
      path,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
      true,
    )
    if (!res.ok) await Client.decode(res)
    return (await res.json()) as T
  }

  async delete(path: string, authenticated = true): Promise<void> {
    const res = await this.send(path, { method: 'DELETE' }, authenticated)
    if (!res.ok) await Client.decode(res)
  }

  async putBytes<T>(path: string, body: Uint8Array): Promise<T> {
    const res = await this.send(path, { method: 'PUT', body }, true)
    if (!res.ok) await Client.decode(res)
    return (await res.json()) as T
  }

  /** Warm the token before a long operation, so login never interrupts an upload. */
  ensureSession(): void {
    if (!this.token) this.token = ensureToken(this.baseUrl)
  }
}

export interface LedgerEntry {
  secret_id: string
  created_at: number
  expires_at: number
  bind_mode: string | null
  status: string
  first_opened_at: number | null
  last_opened_at: number | null
  open_count: number
  failed_attempts: number
  revoked_at: number | null
}

export interface StatsResponse {
  used: number
  limit: number
  maxUpload: number
  files: {
    id: string
    filename: string
    size: number
    created_at: number
    expires_at: number
    status: string
    password_hash: string | null
    max_downloads: number
    download_count: number
    failed_attempts: number
  }[]
}

export interface InitUploadResponse {
  key: string
  uploadId: string
  fileId: string
}

export interface UploadedPart {
  partNumber: number
  etag: string
}
