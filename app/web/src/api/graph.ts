import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'

import { getJson } from './client'
import { queryKeys } from './hooks'
import type { GraphView } from './types'

/** "state" draws resources, "attack" draws attacker states and moves. */
export type GraphViewKind = GraphView['view']

export const GRAPH_VIEWS: readonly GraphViewKind[] = ['state', 'attack']

export function isGraphViewKind(value: unknown): value is GraphViewKind {
  return value === 'state' || value === 'attack'
}

/** Under the analysis key, so invalidating an analysis drops its graphs too. */
export function graphQueryKey(id: string, view: GraphViewKind) {
  return [...queryKeys.analysis(id), 'graph', view] as const
}

function fetchGraph(id: string, view: GraphViewKind, signal?: AbortSignal) {
  return getJson<GraphView>(`/analyses/${encodeURIComponent(id)}/graph?view=${view}`, { signal })
}

/** One drawable graph of an analysis. An analysis never changes, so neither does its graph. */
export function useGraph(id: string, view: GraphViewKind) {
  return useQuery({
    queryKey: graphQueryKey(id, view),
    queryFn: ({ signal }) => fetchGraph(id, view, signal),
    staleTime: Infinity,
  })
}

/** Fetch the other view in the background once this one is in, so the toggle is instant. */
export function usePrefetchGraph(id: string, view: GraphViewKind, enabled: boolean) {
  const queryClient = useQueryClient()
  useEffect(() => {
    if (!enabled) return
    queryClient
      .query({
        queryKey: graphQueryKey(id, view),
        queryFn: ({ signal }) => fetchGraph(id, view, signal),
        staleTime: Infinity,
      })
      // A failed prefetch is retried when the view is opened, where its error shows.
      .catch(() => undefined)
  }, [queryClient, id, view, enabled])
}
