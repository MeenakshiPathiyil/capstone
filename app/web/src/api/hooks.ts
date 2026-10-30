import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { AttackLevel } from '@/lib/severity'

import { busyKeys, retryWhileBusy } from './busy'
import { ApiError, apiFetch, getJson, postForm, postJson } from './client'
import type { Analysis, FixImpactResult, Meta, SampleRequest } from './types'

/** Fix-impact scope: a positive integer or "all", as the API's `top` parameter. */
export type FixScope = number | 'all'

export const queryKeys = {
  meta: ['meta'] as const,
  analysis: (id: string) => ['analysis', id] as const,
  fixes: (id: string, top: FixScope) => ['analysis', id, 'fixes', String(top)] as const,
}

/** Styles, enums, samples and limits. Static for the life of the server. */
export function useMeta() {
  return useQuery({
    queryKey: queryKeys.meta,
    queryFn: ({ signal }) => getJson<Meta>('/meta', { signal }),
    staleTime: Infinity,
    gcTime: Infinity,
  })
}

/** A saved analysis. Immutable once created, so it never goes stale. */
export function useAnalysis(id: string) {
  return useQuery({
    queryKey: queryKeys.analysis(id),
    queryFn: ({ signal }) => getJson<Analysis>(`/analyses/${encodeURIComponent(id)}`, { signal }),
    staleTime: Infinity,
    // A missing analysis stays missing; other failures get the default single retry.
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.status === 404) && failureCount < 1,
    enabled: id !== '',
  })
}

/**
 * Fix impact for a scope. POST computes it once and returns the saved result
 * on every later call, so it doubles as the read: no GET that is expected to
 * 404 on a fresh analysis.
 */
export function fetchFixImpact(id: string, top: FixScope) {
  return retryWhileBusy(busyKeys.fixes(id, top), () =>
    apiFetch<FixImpactResult>(`/analyses/${encodeURIComponent(id)}/fixes?top=${String(top)}`, {
      method: 'POST',
    }),
  )
}

/**
 * The query for a scope's fix impact, shared by the overview and the report
 * download. The request takes no abort signal: the server finishes the
 * computation either way, and a cancelled request would be sent again on the
 * next mount while the first still runs, which the API refuses as busy (503).
 * Left running, the next mount picks up the same request.
 */
export function fixImpactQuery(id: string, top: FixScope) {
  return {
    queryKey: queryKeys.fixes(id, top),
    queryFn: () => fetchFixImpact(id, top),
    staleTime: Infinity,
    // Each attempt re-runs the analysis once per candidate finding, so
    // failures are not retried here; only a busy analyser is waited out
    // (fetchFixImpact), and callers offer a retry for the rest.
    retry: false,
  } as const
}

/** Fix impact for a scope, computed on first use. */
export function useFixImpact(id: string, top: FixScope, { enabled = true } = {}) {
  return useQuery({ ...fixImpactQuery(id, top), enabled: enabled && id !== '' })
}

export interface UploadInput {
  file: File
  industry: string
  minLevel: AttackLevel
}

/** POST /analyses (multipart). Resolves with the 201 Analysis and seeds its cache entry. */
export function useCreateAnalysis() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ file, industry, minLevel }: UploadInput) => {
      const form = new FormData()
      form.append('file', file, file.name)
      form.append('industry', industry)
      form.append('min_level', minLevel)
      return retryWhileBusy(busyKeys.upload, () => postForm<Analysis>('/analyses', form))
    },
    onSuccess: (analysis) => queryClient.setQueryData(queryKeys.analysis(analysis.id), analysis),
  })
}

/** POST /analyses/sample. Resolves with the 201 Analysis and seeds its cache entry. */
export function useCreateSampleAnalysis() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (request: SampleRequest) =>
      retryWhileBusy(busyKeys.sample, () => postJson<Analysis>('/analyses/sample', request)),
    onSuccess: (analysis) => queryClient.setQueryData(queryKeys.analysis(analysis.id), analysis),
  })
}
