/**
 * Screenshot baselines for the overview and the top path's detail at
 * 1440x900. Baselines are recorded on macOS; other platforms rasterise fonts
 * differently, so there the comparison is skipped rather than failed.
 * Update them with: npx playwright test visual --update-snapshots
 */
import { type APIRequestContext, type Page } from '@playwright/test'

import { expect, test } from './support/test'

import { createSampleAnalysis, getMeta, TIMESTAMP, topPath, waitForFixImpact } from './support/api'

const BASELINE_PLATFORM = 'darwin'

test.skip(
  process.platform !== BASELINE_PLATFORM,
  `Screenshot baselines exist for ${BASELINE_PLATFORM} only; this is ${process.platform}.`,
)

async function settle(page: Page) {
  await page.evaluate(() => document.fonts.ready)
}

/** One analysis for both baselines, with an industry no scenario has been generated for. */
async function analysisForBaselines(request: APIRequestContext) {
  const meta = await getMeta(request)
  // A fixed industry, so the header reads the same in every run.
  const industry = meta.industries.find((i) => i !== meta.default_industry) ?? meta.default_industry
  return createSampleAnalysis(request, { industry })
}

test('overview at 1440x900', async ({ page, request }) => {
  const analysis = await analysisForBaselines(request)
  await page.goto(`/analysis/${analysis.id}`)
  await expect(page.getByRole('region', { name: 'Top fixes' })).toContainText('candidate finding', {
    timeout: 30_000,
  })
  await waitForFixImpact(request, analysis.id)
  await settle(page)
  await expect(page).toHaveScreenshot('overview.png', { mask: [page.getByText(TIMESTAMP)] })
})

test('top path detail at 1440x900', async ({ page, request }) => {
  const analysis = await analysisForBaselines(request)
  const path = topPath(analysis)
  await page.goto(`/analysis/${analysis.id}/paths/${path.source_id}`)
  await expect(page.getByRole('heading', { level: 1, name: path.source_id })).toBeVisible()
  const panel = page.getByRole('region', { name: 'Attack scenario' })
  await expect(panel.getByRole('button', { name: 'Generate scenario' })).toBeEnabled()
  await settle(page)
  await expect(page).toHaveScreenshot('path-detail.png', { mask: [page.getByText(TIMESTAMP)] })
})
