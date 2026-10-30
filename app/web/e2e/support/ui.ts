/** Page interactions shared by the specs, all through what a user can see or reach. */
import path from 'node:path'

import { expect, type Locator, type Page, type Response } from '@playwright/test'

import { REPO_ROOT, WEB_DIR } from './env'

/** The sample template the plan's numbers come from: 15 resources, 22 findings, 22 paths. */
export const SAMPLE_TEMPLATE = path.join(REPO_ROOT, 'sample_yamls', 'cloudformation5.yml')

/** Small inputs for the error flows, committed next to the specs. */
export function fixtureFile(name: string): string {
  return path.join(WEB_DIR, 'e2e', 'fixtures', name)
}

/** Picks a file the way a user does: "browse files" opens the native chooser. */
export async function pickFile(page: Page, file: string): Promise<void> {
  const chooser = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: 'browse files' }).click()
  await (await chooser).setFiles(file)
}

/** Picks a file the page accepts: it then shows as the selected template. */
export async function chooseTemplate(page: Page, file: string): Promise<void> {
  await pickFile(page, file)
  await expect(page.getByRole('button', { name: `Remove ${path.basename(file)}` })).toBeVisible()
}

/**
 * Clicks "Analyse template" and returns the upload's final answer. While the
 * server's one analysis slot is taken it answers 503 with Retry-After and the
 * page tries again, so busy answers are skipped here, but each must have said
 * when to retry: without that header the page gives up, and so does this.
 */
export async function submitUpload(page: Page): Promise<Response> {
  const busy: Response[] = []
  const answered = page.waitForResponse((response) => {
    const upload =
      response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/analyses'
    if (!upload) return false
    if (response.status() !== 503) return true
    busy.push(response)
    return false
  })
  await page.getByRole('button', { name: 'Analyse template' }).click()
  const response = await answered
  for (const answer of busy) {
    expect(answer.headers()['retry-after'], 'a busy answer says when to retry').toBeTruthy()
  }
  return response
}

/** Chooses a file and submits it; resolves with the new analysis id once the page shows it. */
export async function uploadTemplate(page: Page, file: string): Promise<string> {
  await chooseTemplate(page, file)
  expect((await submitUpload(page)).status()).toBe(201)
  return analysisIdFromUrl(page)
}

/** Waits for /analysis/<id> and returns the id. */
export async function analysisIdFromUrl(page: Page): Promise<string> {
  await page.waitForURL(/\/analysis\/[0-9a-f-]{36}(?:[/?]|$)/)
  const match = /\/analysis\/([0-9a-f-]{36})/.exec(page.url())
  if (!match?.[1]) throw new Error(`no analysis id in ${page.url()}`)
  return match[1]
}

/** Presses Tab until `target` has focus; fails if it never does. */
export async function tabTo(page: Page, target: Locator, maxPresses = 40): Promise<void> {
  for (let presses = 0; presses < maxPresses; presses += 1) {
    if (await target.evaluate((element) => element === document.activeElement)) return
    await page.keyboard.press('Tab')
  }
  await expect(target, `reachable with at most ${String(maxPresses)} Tab presses`).toBeFocused()
}

/** The analysis page's section tabs. */
export function analysisTab(page: Page, name: 'Overview' | 'Findings' | 'Paths' | 'Graph') {
  return page
    .getByRole('tablist', { name: 'Analysis sections' })
    .getByRole('tab', { name: new RegExp(`^${name}`) })
}

/** The overview's stat tile with this label. */
export function statTile(page: Page, label: string): Locator {
  return page.getByRole('group', { name: label, exact: true })
}

/** Escapes text for use inside a RegExp. */
export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
