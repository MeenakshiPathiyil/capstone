/**
 * Which requests are waiting out a busy analyser (see withBusyRetry), so the
 * UI can say "Analyser busy, retrying" wherever the request is shown, even
 * when it runs inside a shared query.
 */
import { useSyncExternalStore } from 'react'

import { withBusyRetry } from './client'

const retrying = new Set<string>()
const listeners = new Set<() => void>()

function set(key: string, on: boolean) {
  if (on === retrying.has(key)) return
  if (on) retrying.add(key)
  else retrying.delete(key)
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** withBusyRetry, marking `key` as retrying while it waits for another attempt. */
export async function retryWhileBusy<T>(key: string, request: () => Promise<T>): Promise<T> {
  try {
    return await withBusyRetry(request, { onRetry: () => set(key, true) })
  } finally {
    set(key, false)
  }
}

/** True while the request under `key` is waiting out a busy analyser. */
export function useRetrying(key: string): boolean {
  return useSyncExternalStore(subscribe, () => retrying.has(key))
}

/** Keys for the requests that retry. */
export const busyKeys = {
  upload: 'upload',
  sample: 'sample',
  fixes: (id: string, top: number | 'all') => `fixes:${id}:${String(top)}`,
}

/** What to show while retrying. */
export const RETRYING_TEXT = 'Analyser busy, retrying…'
