/**
 * Fetch wrapper for the local API. Every error body is {"detail": "..."}
 * (plan section 14); this turns it into a thrown ApiError carrying that message
 * and the status, so callers can show `error.message` as written.
 */

import { retryAfterText } from '@/lib/format'

export const API_BASE = '/api'

export class ApiError extends Error {
  readonly status: number
  /** Seconds from the response's Retry-After header (503s, 429s), or null when absent. */
  readonly retryAfterS: number | null

  constructor(message: string, status: number, retryAfterS: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.retryAfterS = retryAfterS
  }
}

/**
 * A Retry-After header value in seconds. Accepts both forms HTTP allows:
 * delta-seconds ("30") and an HTTP date. Null when absent or unreadable.
 */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | null {
  if (value === null) return null
  const trimmed = value.trim()
  if (/^\d+$/.test(trimmed)) return Number(trimmed)
  const date = Date.parse(trimmed)
  if (Number.isNaN(date)) return null
  return Math.max(0, Math.round((date - now) / 1000))
}

/** Status 0: the request never got an HTTP response (server down, offline, aborted). */
export const NETWORK_ERROR_STATUS = 0

/** The per-client rate limit: the server says why, and Retry-After says when. */
export const TOO_MANY_REQUESTS_STATUS = 429

/**
 * A 429's message: the server's reason, then when to try again. Never retried
 * automatically, so the user is told how long to wait.
 */
export function rateLimitMessage(
  detail: string | null,
  retryAfterS: number | null,
  now: Date = new Date(),
): string {
  const reason = detail ?? 'Too many requests from this address.'
  const when = retryAfterS === null ? 'Try again later.' : retryAfterText(retryAfterS, now)
  return `${reason} ${when}`
}

function detailFromBody(body: unknown): string | null {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail: unknown = body.detail
    if (typeof detail === 'string' && detail.trim()) return detail
    // FastAPI's raw validation shape, in case a route escapes normalisation.
    if (Array.isArray(detail) && detail.length > 0) {
      const first = detail[0] as { msg?: unknown }
      if (typeof first.msg === 'string') return first.msg
    }
  }
  return null
}

function messageFromBody(
  body: unknown,
  status: number,
  statusText: string,
  retryAfterS: number | null,
): string {
  const detail = detailFromBody(body)
  if (status === TOO_MANY_REQUESTS_STATUS) return rateLimitMessage(detail, retryAfterS)
  if (detail !== null) return detail
  if (status >= 500) {
    return `The analysis service is not responding (HTTP ${status}). Check that the API is running.`
  }
  return statusText ? `${status} ${statusText}` : `Request failed with status ${status}`
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

/** Fetch `/api{path}`. Throws ApiError for non-2xx and network failures. */
async function send(path: string, init: RequestInit): Promise<Response> {
  let response: Response
  try {
    const headers = new Headers(init.headers)
    if (!headers.has('Accept')) headers.set('Accept', 'application/json')
    response = await fetch(`${API_BASE}${path}`, { ...init, headers })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError(
      'Could not reach the analysis service. Check that the API is running.',
      NETWORK_ERROR_STATUS,
    )
  }
  if (!response.ok) {
    const retryAfterS = parseRetryAfter(response.headers.get('Retry-After'))
    throw new ApiError(
      messageFromBody(await readBody(response), response.status, response.statusText, retryAfterS),
      response.status,
      retryAfterS,
    )
  }
  return response
}

/** Fetch `/api{path}` and parse JSON. Throws ApiError for non-2xx and network failures. */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  return (await readBody(await send(path, init))) as T
}

/** A file the API sent: its bytes, and the name Content-Disposition gives, if any. */
export interface ApiFile {
  blob: Blob
  filename: string | null
}

/**
 * The file name in a Content-Disposition header, or null. Prefers the
 * RFC 5987 `filename*=UTF-8''...` form, then `filename="..."` or bare.
 */
export function filenameFromDisposition(header: string | null): string | null {
  if (header === null) return null
  const extended = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(header)?.[1]
  if (extended !== undefined) {
    try {
      return decodeURIComponent(extended.trim())
    } catch {
      // Malformed escapes: fall back to the plain parameter.
    }
  }
  const plain = /filename\s*=\s*(?:"([^"]*)"|([^;]*))/i.exec(header)
  const name = (plain?.[1] ?? plain?.[2] ?? '').trim()
  return name || null
}

/** GET `/api{path}` as a file. Errors are ApiErrors, as for apiFetch. */
export async function fetchFile(path: string, init?: RequestInit): Promise<ApiFile> {
  const headers = new Headers(init?.headers)
  headers.set('Accept', '*/*')
  const response = await send(path, { ...init, method: 'GET', headers })
  return {
    blob: await response.blob(),
    filename: filenameFromDisposition(response.headers.get('Content-Disposition')),
  }
}

export function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, { ...init, method: 'GET' })
}

export function postJson<T>(path: string, payload: unknown, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Content-Type', 'application/json')
  return apiFetch<T>(path, { ...init, method: 'POST', headers, body: JSON.stringify(payload) })
}

/** Multipart POST. The browser sets the boundary, so no Content-Type header here. */
export function postForm<T>(path: string, form: FormData, init?: RequestInit): Promise<T> {
  return apiFetch<T>(path, { ...init, method: 'POST', body: form })
}

/** Bounds for retrying a busy analyser. */
export interface BusyRetryOptions {
  /** Attempts in all, the first included. */
  maxAttempts?: number
  /** Total time spent waiting between attempts, in milliseconds. */
  maxWaitMs?: number
  /** Called before each wait, with the attempt about to be made (2, 3, ...). */
  onRetry?: (attempt: number) => void
  /** For tests. */
  sleep?: (ms: number) => Promise<void>
}

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

/**
 * Runs `request`, and runs it again when the API answers 503 with a
 * Retry-After header: the analyser is busy with another job and says when to
 * come back. A 503 without the header is a lasting condition (a service that
 * is not configured) and is thrown at once, as is anything else. Gives up
 * after `maxAttempts` attempts or once waiting would pass `maxWaitMs`.
 */
export async function withBusyRetry<T>(
  request: () => Promise<T>,
  { maxAttempts = 3, maxWaitMs = 10_000, onRetry, sleep = wait }: BusyRetryOptions = {},
): Promise<T> {
  let waited = 0
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await request()
    } catch (error) {
      const busy = error instanceof ApiError && error.status === 503 && error.retryAfterS !== null
      if (!busy || attempt >= maxAttempts) throw error
      // At least a moment: "Retry-After: 0" should not become a tight loop.
      const delay = Math.max(250, error.retryAfterS * 1000)
      if (waited + delay > maxWaitMs) throw error
      waited += delay
      onRetry?.(attempt + 1)
      await sleep(delay)
    }
  }
}
