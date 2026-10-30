/**
 * The scenario panel against fake model Spaces that misbehave. Each test runs
 * only in the project whose server has its mode (the tag; see
 * playwright.config.ts).
 */
import { type APIRequestContext, type Page } from '@playwright/test'

import { expect, test } from './support/test'

import {
  createSampleAnalysis,
  formatCount,
  getHealth,
  getScenario,
  topPath,
  uniqueIndustry,
} from './support/api'

async function openTopPath(page: Page, request: APIRequestContext, label: string) {
  const analysis = await createSampleAnalysis(request, { industry: uniqueIndustry(label) })
  const path = topPath(analysis)
  expect(path.exported).toBe(true)
  await page.goto(`/analysis/${analysis.id}/paths/${path.source_id}`)
  const panel = page.getByRole('region', { name: 'Attack scenario' })
  await expect(panel).toBeVisible()
  return { analysis, path, panel }
}

test(
  'truncated output names the missing attack graph and the token limit',
  { tag: '@truncated' },
  async ({ page, request }) => {
    const { analysis, path, panel } = await openTopPath(page, request, 'truncated')
    await panel.getByRole('button', { name: 'Generate scenario' }).click()
    await expect(panel.getByRole('button', { name: 'Copy' })).toBeVisible({ timeout: 30_000 })

    const { scenario } = await getScenario(request, analysis.id, path.source_id)
    expect(scenario?.reached_token_cap).toBe(true)
    expect(scenario?.sections.missing).toContain('attack_graph')
    const tokens = scenario?.new_tokens ?? 0

    const missing = panel.getByRole('region', { name: 'Attack graph missing' })
    await expect(missing).toContainText('token limit')
    await expect(missing).toContainText(`${formatCount(tokens)} tokens`)
    // The sections the model did write are still shown.
    await expect(panel.getByRole('heading', { level: 3, name: 'Narrative' })).toBeVisible()
    await expect(
      panel.getByRole('heading', { level: 3, name: 'Mathematical expression' }),
    ).toBeVisible()
    await expect(panel.getByRole('heading', { level: 3, name: 'Attack graph' })).toHaveCount(0)
  },
)

test(
  'a provider error shows an alert, and Retry starts a new generation',
  { tag: '@error' },
  async ({ page, request }) => {
    const { analysis, path, panel } = await openTopPath(page, request, 'error')
    await panel.getByRole('button', { name: 'Generate scenario' }).click()

    const alert = panel.getByRole('alert')
    await expect(alert).toContainText('Scenario generation failed', { timeout: 30_000 })
    const state = await getScenario(request, analysis.id, path.source_id)
    expect(state.status).toBe('failed')
    await expect(alert).toContainText(state.error ?? '')

    const retried = page.waitForResponse(
      (r) =>
        r.request().method() === 'POST' &&
        new URL(r.url()).pathname.endsWith(`/paths/${path.source_id}/scenario`),
    )
    await alert.getByRole('button', { name: 'Retry' }).click()
    expect((await retried).status()).toBe(202)
    // The panel follows the new job, which fails the same way, and the alert comes back.
    await expect(alert).toHaveCount(0)
    await expect(alert).toContainText('Scenario generation failed', { timeout: 30_000 })
    await expect(alert.getByRole('button', { name: 'Retry' })).toBeEnabled()
  },
)

test(
  'without a model configuration, Generate is disabled and says why',
  { tag: '@off' },
  async ({ page, request }) => {
    const health = await getHealth(request)
    expect(health.space_configured).toBe(false)
    const reason = health.model_unavailable_reason ?? ''
    expect(reason).not.toBe('')

    const { analysis, path, panel } = await openTopPath(page, request, 'off')
    await expect(panel.getByRole('button', { name: 'Generate scenario' })).toBeDisabled()
    await expect(panel.getByText('Live generation is unavailable')).toBeVisible()
    await expect(panel).toContainText(reason)

    // The API refuses the generation too, so the disabled button is not just cosmetic.
    const refused = await request.post(
      `/api/analyses/${analysis.id}/paths/${path.source_id}/scenario`,
    )
    expect(refused.status()).toBe(503)
  },
)
