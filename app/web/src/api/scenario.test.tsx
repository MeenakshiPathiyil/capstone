import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './client'
import {
  SCENARIO_ERROR_GRACE_MS,
  SCENARIO_MAX_BACKOFF_MS,
  SCENARIO_POLL_MS,
  scenarioRetryDelay,
  shouldRetryScenario,
  useScenario,
} from './scenario'

describe('shouldRetryScenario', () => {
  const boom = new ApiError('boom', 500)
  const now = 1_000_000

  it('keeps retrying while the job is active, until the failures have lasted long enough', () => {
    for (const status of ['queued', 'warming_up', 'running'] as const) {
      const fresh = { status, updatedAt: now - 1000 }
      expect(shouldRetryScenario(7, boom, fresh, now), status).toBe(true)
    }
    const almost = { status: 'running', updatedAt: now - (SCENARIO_ERROR_GRACE_MS - 1) } as const
    expect(shouldRetryScenario(9, boom, almost, now)).toBe(true)
    const lapsed = { status: 'running', updatedAt: now - SCENARIO_ERROR_GRACE_MS } as const
    expect(shouldRetryScenario(9, boom, lapsed, now)).toBe(false)
  })

  it('retries once when no job is known to be running', () => {
    expect(shouldRetryScenario(0, boom, { status: undefined, updatedAt: 0 }, now)).toBe(true)
    expect(shouldRetryScenario(1, boom, { status: undefined, updatedAt: 0 }, now)).toBe(false)
    expect(shouldRetryScenario(0, boom, { status: 'idle', updatedAt: now }, now)).toBe(true)
    expect(shouldRetryScenario(1, boom, { status: 'done', updatedAt: now }, now)).toBe(false)
  })

  it('never retries a missing or non-exported path', () => {
    const running = { status: 'running', updatedAt: now } as const
    expect(shouldRetryScenario(0, new ApiError('gone', 404), running, now)).toBe(false)
    expect(shouldRetryScenario(0, new ApiError('below level', 409), running, now)).toBe(false)
  })
})

describe('scenarioRetryDelay', () => {
  it('backs off from the poll interval to a bound', () => {
    expect([0, 1, 2, 3, 4, 10].map(scenarioRetryDelay)).toEqual([
      SCENARIO_POLL_MS,
      SCENARIO_POLL_MS * 2,
      SCENARIO_POLL_MS * 4,
      SCENARIO_MAX_BACKOFF_MS,
      SCENARIO_MAX_BACKOFF_MS,
      SCENARIO_MAX_BACKOFF_MS,
    ])
  })
})

/** Advances fake time in one-second steps inside act, so renders and each retry's promises settle between timers. */
async function advance(ms: number) {
  for (let elapsed = 0; elapsed < ms; elapsed += 1_000) {
    await act(() => vi.advanceTimersByTimeAsync(1_000))
  }
}

/** Advances in one-second steps until `done()` holds; fails if it does not within `limitMs`. */
async function advanceUntil(done: () => boolean, limitMs: number) {
  for (let elapsed = 0; elapsed < limitMs; elapsed += 1_000) {
    if (done()) return
    await advance(1_000)
  }
  expect(done()).toBe(true)
}

describe('useScenario polling through failures', () => {
  const fetchMock = vi.fn<typeof fetch>()
  const state = (status: string) =>
    new Response(
      JSON.stringify({
        status,
        queue_position: null,
        elapsed_s: 3,
        eta_s: null,
        scenario: null,
        error: null,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )
  const failure = () =>
    new Response(JSON.stringify({ detail: 'boom' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })

  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  function mount() {
    const client = new QueryClient()
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
    return renderHook(() => useScenario('a1', 'AP-001', true), { wrapper })
  }

  it('keeps the running job on screen through a short outage and picks up the result', async () => {
    // Running at first, then 20 s of failures, then the job finishes.
    const outageStart = 3_000
    const outageEnd = 23_000
    const t0 = Date.now()
    fetchMock.mockImplementation(() => {
      const elapsed = Date.now() - t0
      if (elapsed < outageStart) return Promise.resolve(state('running'))
      if (elapsed < outageEnd) return Promise.resolve(failure())
      return Promise.resolve(state('done'))
    })
    const { result } = mount()

    await advance(1_000)
    expect(result.current.state.data?.status).toBe('running')

    await advance(outageEnd - 1_000 - 1_000)
    // Mid-outage: still the last known status, no error state.
    expect(result.current.state.isError).toBe(false)
    expect(result.current.state.data?.status).toBe('running')
    const callsDuringOutage = fetchMock.mock.calls.length
    expect(callsDuringOutage).toBeGreaterThan(3)

    await advance(15_000)
    expect(result.current.state.isError).toBe(false)
    expect(result.current.state.data?.status).toBe('done')
  })

  it('reports the error once failures outlast the grace period, and recovers when the API returns', async () => {
    let healthy = false
    const t0 = Date.now()
    fetchMock.mockImplementation(() =>
      Promise.resolve(healthy || Date.now() - t0 < 1_000 ? state('running') : failure()),
    )
    const { result } = mount()
    await advance(500)
    expect(result.current.state.data?.status).toBe('running')

    // Failures began at once; the grace period counts from the last good answer.
    await advance(SCENARIO_ERROR_GRACE_MS - 10_000)
    expect(result.current.state.isError).toBe(false)
    await advanceUntil(
      () => result.current.state.isError,
      SCENARIO_ERROR_GRACE_MS + 2 * SCENARIO_MAX_BACKOFF_MS,
    )
    expect(result.current.state.isError).toBe(true)
    // The last known status is still active, so it keeps looking, slowly.
    const before = fetchMock.mock.calls.length
    await advance(SCENARIO_MAX_BACKOFF_MS * 3)
    expect(fetchMock.mock.calls.length).toBeGreaterThan(before)

    healthy = true
    await advanceUntil(() => !result.current.state.isError, SCENARIO_MAX_BACKOFF_MS * 3)
    expect(result.current.state.isError).toBe(false)
    expect(result.current.state.data?.status).toBe('running')
  })

  it('gives up quickly when no job was ever seen running', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(failure()))
    const { result } = mount()
    await advance(10_000)
    expect(result.current.state.isError).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
