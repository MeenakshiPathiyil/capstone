/**
 * The suite's `test`: Playwright's, plus an automatic fixture that keeps tests
 * from leaking work into each other.
 *
 * The server runs one analysis job at a time (uploads, samples, fix impact);
 * anything else gets 503 with Retry-After, which the UI retries a few times.
 * An Overview page starts a fix-impact run that keeps the slot for a second
 * or two, and the server finishes it even if the page has moved on. So after
 * each test, wait for every fix-impact run the page started, and the next
 * test begins with the slot free.
 */
import { test as base, type Request } from '@playwright/test'

import { fixImpactSaved } from './api'

const FIXES_PATH = /^\/api\/analyses\/([^/]+)\/fixes$/

export const test = base.extend<{ settleFixImpact: undefined }>({
  settleFixImpact: [
    async ({ page, request }, use, testInfo) => {
      const started: { id: string; request: Request }[] = []
      page.on('request', (r) => {
        const id = FIXES_PATH.exec(new URL(r.url()).pathname)?.[1]
        if (id && r.method() === 'POST') started.push({ id, request: r })
      })

      await use(undefined)

      for (const run of started) {
        const response = await run.request.response().catch(() => null)
        // Answered: finished (2xx) or refused without running (503); nothing left on the server.
        if (response) continue
        // The page went away before the answer; the server is still computing it.
        if (!(await fixImpactSaved(request, run.id, 30_000))) {
          testInfo.annotations.push({
            type: 'warning',
            description: `fix impact for ${run.id} was still unsaved after the test`,
          })
        }
      }
    },
    { auto: true },
  ],
})

export { expect } from '@playwright/test'
