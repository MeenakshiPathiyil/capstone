import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { isActiveStatus } from '@/lib/scenario'

import { ApiError, apiFetch, getJson } from './client'
import type { Health, ScenarioState } from './types'

/** How often a queued, warming-up or running scenario is polled. */
export const SCENARIO_POLL_MS = 2000

/** The longest wait between two attempts while a poll is failing. */
export const SCENARIO_MAX_BACKOFF_MS = 10_000

/**
 * How long GETs may keep failing, counted from the last good answer, while
 * the job is known to be running before the panel gives up and says so.
 */
export const SCENARIO_ERROR_GRACE_MS = 30_000

export const scenarioQueryKeys = {
  health: ['health'] as const,
  scenario: (analysisId: string, sourceId: string) =>
    ['analysis', analysisId, 'scenario', sourceId] as const,
}

/**
 * Whether a failed GET is tried again. While the last known status is queued,
 * warming up or running the job goes on without us, so a blip (a restart, a
 * dropped connection) must not end the polling: keep trying until the
 * failures have lasted SCENARIO_ERROR_GRACE_MS since the last good answer.
 * Otherwise one more try; a missing or non-exported path does not change on
 * a second try.
 */
export function shouldRetryScenario(
  failureCount: number,
  error: Error,
  last: { status: ScenarioState['status'] | undefined; updatedAt: number },
  now: number = Date.now(),
): boolean {
  if (error instanceof ApiError && (error.status === 404 || error.status === 409)) return false
  if (isActiveStatus(last.status)) return now - last.updatedAt < SCENARIO_ERROR_GRACE_MS
  return failureCount < 1
}

/** Milliseconds before a retry: 2, 4, 8, then 10 s at most. `failureCount` is 0 before the first retry. */
export function scenarioRetryDelay(failureCount: number): number {
  return Math.min(SCENARIO_POLL_MS * 2 ** failureCount, SCENARIO_MAX_BACKOFF_MS)
}

function scenarioPath(analysisId: string, sourceId: string): string {
  return `/analyses/${encodeURIComponent(analysisId)}/paths/${encodeURIComponent(sourceId)}/scenario`
}

/**
 * Core readiness plus the optional PDF and model capabilities. The API
 * caches the Space's stage and quota for a short TTL, so polling is cheap;
 * once a minute keeps "live generation unavailable" honest on an open page.
 */
export function useHealth({ enabled = true } = {}) {
  return useQuery({
    queryKey: scenarioQueryKeys.health,
    queryFn: ({ signal }) => getJson<Health>('/health', { signal }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    enabled,
  })
}

/**
 * A path's scenario state, and the request that starts or joins a generation.
 *
 * GET answers 409 for a path below the minimum level, so callers pass
 * `enabled: false` for those. While the state is queued, warming_up or running
 * the query polls every two seconds, and a failing poll is retried with
 * backoff for up to SCENARIO_ERROR_GRACE_MS before the query reports the
 * error. A browser refresh reattaches to the same job through the same
 * endpoint. `generate` POSTs: 200 serves a cached result,
 * 202 a new or joined job, both written straight into the query; a 503 is an
 * ApiError carrying the server's detail and `retryAfterS`.
 */
export function useScenario(analysisId: string, sourceId: string, enabled: boolean) {
  const queryClient = useQueryClient()
  const queryKey = scenarioQueryKeys.scenario(analysisId, sourceId)
  const path = scenarioPath(analysisId, sourceId)

  const state = useQuery({
    queryKey,
    queryFn: ({ signal }) => getJson<ScenarioState>(path, { signal }),
    enabled: enabled && analysisId !== '' && sourceId !== '',
    // After the failures have lasted too long the query is in error, but the
    // job may still be running: keep looking, slowly, so the panel recovers
    // when the API comes back.
    refetchInterval: (query) =>
      isActiveStatus(query.state.data?.status)
        ? query.state.status === 'error'
          ? SCENARIO_MAX_BACKOFF_MS
          : SCENARIO_POLL_MS
        : false,
    retry: (failureCount, error) => {
      const last = queryClient.getQueryState<ScenarioState>(queryKey)
      return shouldRetryScenario(failureCount, error, {
        status: last?.data?.status,
        updatedAt: last?.dataUpdatedAt ?? 0,
      })
    },
    retryDelay: scenarioRetryDelay,
  })

  const generate = useMutation({
    mutationFn: () => apiFetch<ScenarioState>(path, { method: 'POST' }),
    onSuccess: (next) => queryClient.setQueryData(queryKey, next),
    onError: (error) => {
      // A refusal can mean the model's availability changed since the last
      // health read; refresh it so the idle state explains why.
      if (error instanceof ApiError && error.status === 503) {
        void queryClient.invalidateQueries({ queryKey: scenarioQueryKeys.health })
      }
    },
  })

  return { state, generate }
}
