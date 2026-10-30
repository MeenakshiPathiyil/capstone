import { useCallback } from 'react'
import { useSearchParams } from 'react-router'

import { RESOURCE_PARAM, withResourceParam } from '@/lib/analysis'

/**
 * The resource sheet lives in the URL as ?resource=<id>, so any view (the
 * findings table, a chain diagram, the graph) opens it just by setting the
 * param, and the open sheet survives reload. Both changes replace the history
 * entry, like tab changes, so Back leaves the page instead of toggling sheets.
 */
export function useResourceParam() {
  const [searchParams, setSearchParams] = useSearchParams()
  const resourceId = searchParams.get(RESOURCE_PARAM)

  const openResource = useCallback(
    (id: string) => {
      setSearchParams((previous) => withResourceParam(previous, id), { replace: true })
    },
    [setSearchParams],
  )

  const closeResource = useCallback(() => {
    setSearchParams((previous) => withResourceParam(previous, null), { replace: true })
  }, [setSearchParams])

  return { resourceId, openResource, closeResource }
}
