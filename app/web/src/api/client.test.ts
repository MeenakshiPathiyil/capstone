import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  ApiError,
  apiFetch,
  fetchFile,
  filenameFromDisposition,
  parseRetryAfter,
  rateLimitMessage,
  withBusyRetry,
} from './client'

const busy = (retryAfterS: number | null) => new ApiError('busy', 503, retryAfterS)
const noSleep = () => Promise.resolve()

describe('withBusyRetry', () => {
  it('retries a busy 503 after the time Retry-After gives', async () => {
    const sleep = vi.fn(noSleep)
    const onRetry = vi.fn()
    const request = vi.fn<() => Promise<string>>()
    request.mockRejectedValueOnce(busy(2)).mockResolvedValueOnce('done')
    await expect(withBusyRetry(request, { sleep, onRetry })).resolves.toBe('done')
    expect(request).toHaveBeenCalledTimes(2)
    expect(sleep).toHaveBeenCalledWith(2000)
    expect(onRetry).toHaveBeenCalledWith(2)
  })

  it('gives up after three attempts', async () => {
    const request = vi.fn(() => Promise.reject(busy(1)))
    await expect(withBusyRetry(request, { sleep: noSleep })).rejects.toThrow('busy')
    expect(request).toHaveBeenCalledTimes(3)
  })

  it('gives up rather than wait past the time budget', async () => {
    const request = vi.fn(() => Promise.reject(busy(8)))
    await expect(withBusyRetry(request, { sleep: noSleep })).rejects.toThrow('busy')
    // 8 s, then another 8 s would pass 10 s.
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('does not retry a 503 without Retry-After, or other errors', async () => {
    const permanent = vi.fn(() => Promise.reject(busy(null)))
    await expect(withBusyRetry(permanent, { sleep: noSleep })).rejects.toThrow('busy')
    expect(permanent).toHaveBeenCalledTimes(1)
    const missing = vi.fn(() => Promise.reject(new ApiError('gone', 404)))
    await expect(withBusyRetry(missing, { sleep: noSleep })).rejects.toThrow('gone')
    expect(missing).toHaveBeenCalledTimes(1)
  })

  it('waits at least a moment when Retry-After is 0', async () => {
    const sleep = vi.fn(noSleep)
    const request = vi.fn<() => Promise<string>>()
    request.mockRejectedValueOnce(busy(0)).mockResolvedValueOnce('done')
    await withBusyRetry(request, { sleep })
    expect(sleep).toHaveBeenCalledWith(250)
  })

  it('reports each retry with the attempt about to run, and none on success', async () => {
    const onRetry = vi.fn()
    const request = vi.fn<() => Promise<string>>()
    request.mockRejectedValueOnce(busy(1)).mockRejectedValueOnce(busy(1)).mockResolvedValue('ok')
    await withBusyRetry(request, { sleep: noSleep, onRetry })
    expect(onRetry.mock.calls).toEqual([[2], [3]])

    onRetry.mockClear()
    await withBusyRetry(() => Promise.resolve('fine'), { sleep: noSleep, onRetry })
    expect(onRetry).not.toHaveBeenCalled()
  })

  it('honours maxAttempts and rethrows anything that is not an ApiError at once', async () => {
    const request = vi.fn(() => Promise.reject(busy(1)))
    await expect(withBusyRetry(request, { sleep: noSleep, maxAttempts: 5 })).rejects.toThrow('busy')
    expect(request).toHaveBeenCalledTimes(5)

    const broken = vi.fn(() => Promise.reject(new TypeError('boom')))
    await expect(withBusyRetry(broken, { sleep: noSleep })).rejects.toThrow('boom')
    expect(broken).toHaveBeenCalledTimes(1)
  })

  it('does not retry a 429 or 500 even with Retry-After', async () => {
    for (const status of [429, 500]) {
      const request = vi.fn(() => Promise.reject(new ApiError('no', status, 5)))
      await expect(withBusyRetry(request, { sleep: noSleep })).rejects.toThrow('no')
      expect(request).toHaveBeenCalledTimes(1)
    }
  })
})

describe('parseRetryAfter', () => {
  const now = Date.parse('2026-10-25T10:00:00Z')

  it('reads delta-seconds', () => {
    expect(parseRetryAfter('30')).toBe(30)
    expect(parseRetryAfter(' 0 ')).toBe(0)
  })

  it('reads an HTTP date as seconds from now, never negative', () => {
    expect(parseRetryAfter('Sun, 25 Oct 2026 10:00:45 GMT', now)).toBe(45)
    expect(parseRetryAfter('Sun, 25 Oct 2026 09:00:00 GMT', now)).toBe(0)
  })

  it('is null when absent or unreadable', () => {
    expect(parseRetryAfter(null)).toBeNull()
    expect(parseRetryAfter('soon')).toBeNull()
    expect(parseRetryAfter('')).toBeNull()
  })
})

describe('rate limits', () => {
  const now = new Date('2026-10-25T10:00:00Z')
  const detail = 'Too many analyses from this address: the limit is 20 per 10 minutes.'

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('says why, then when to try again', () => {
    expect(rateLimitMessage(detail, 240, now)).toBe(`${detail} Try again in about 4 min.`)
    expect(rateLimitMessage(detail, 30, now)).toBe(`${detail} Try again in 30 s.`)
    expect(rateLimitMessage(detail, 3600, now)).toBe(
      `${detail} Try again after 25 Oct 2026, 11:00 UTC.`,
    )
  })

  it('has its own words when the server gives no reason or no time', () => {
    expect(rateLimitMessage(null, 60, now)).toBe(
      'Too many requests from this address. Try again in 60 s.',
    )
    expect(rateLimitMessage(detail, null, now)).toBe(`${detail} Try again later.`)
  })

  it('is the message of a 429 ApiError, with its Retry-After', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ detail }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', 'Retry-After': '600' },
          }),
        ),
      ),
    )
    const error = await apiFetch('/analyses/sample', { method: 'POST' }).catch(
      (caught: unknown) => caught,
    )
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 429,
      retryAfterS: 600,
      message: `${detail} Try again in about 10 min.`,
    })
  })
})

describe('files', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reads the file name from Content-Disposition', () => {
    expect(filenameFromDisposition('attachment; filename="report-a1.pdf"')).toBe('report-a1.pdf')
    expect(filenameFromDisposition('attachment; filename=report.pdf; size=3')).toBe('report.pdf')
    expect(
      filenameFromDisposition(
        `attachment; filename="fallback.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`,
      ),
    ).toBe('résumé.pdf')
    expect(filenameFromDisposition(`attachment; filename*=UTF-8''%E0; filename="b.pdf"`)).toBe(
      'b.pdf',
    )
    expect(filenameFromDisposition('attachment')).toBeNull()
    expect(filenameFromDisposition('attachment; filename=""')).toBeNull()
    expect(filenameFromDisposition(null)).toBeNull()
  })

  it('fetches a file with its name, and throws the API error otherwise', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValueOnce(
      new Response('%PDF', {
        headers: { 'Content-Disposition': 'attachment; filename="a.pdf"' },
      }),
    )
    const file = await fetchFile('/analyses/a1/report.pdf?top=5')
    expect(file.filename).toBe('a.pdf')
    expect(await file.blob.text()).toBe('%PDF')
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/analyses/a1/report.pdf?top=5')
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('GET')

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'Another report is being rendered.' }), {
        status: 503,
        headers: { 'Retry-After': '5' },
      }),
    )
    await expect(fetchFile('/analyses/a1/report.pdf?top=5')).rejects.toMatchObject({
      status: 503,
      retryAfterS: 5,
      message: 'Another report is being rendered.',
    })
  })
})
