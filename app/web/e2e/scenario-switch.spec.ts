/**
 * The scenario panel while the user pages through paths. The fake model
 * server in "ok" mode takes a few seconds per generation (GENERATION_DELAY_S),
 * long enough to move to the next path mid-job.
 */
import { expect, test } from './support/test'

import { createSampleAnalysis, uniqueIndustry } from './support/api'

test('switching paths while a scenario generates does not carry its state over', async ({
  page,
  request,
}) => {
  const analysis = await createSampleAnalysis(request, { industry: uniqueIndustry('switch') })
  const [first, second] = [...analysis.paths].sort((a, b) => a.rank - b.rank)
  if (!first || !second) throw new Error('the sample has fewer than two paths')
  expect(first.exported && second.exported).toBe(true)

  const panel = page.getByRole('region', { name: 'Attack scenario' })
  await page.goto(`/analysis/${analysis.id}/paths/${first.source_id}`)
  await panel.getByRole('button', { name: 'Generate scenario' }).click()
  await expect(
    panel.getByRole('button', { name: /^(Queued|Starting the model|Generating)/ }),
  ).toBeVisible()

  // Next path: its own panel, idle, with nothing of the running job in it.
  await page.getByRole('link', { name: `Next path, ${second.source_id}` }).click()
  await expect(page.getByRole('heading', { level: 1, name: second.source_id })).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Generate scenario' })).toBeEnabled()
  await expect(panel.getByText('Writing the scenario')).toHaveCount(0)
  await expect(panel.getByRole('alert')).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Copy' })).toHaveCount(0)

  // The first path's job went on without the page and finishes there.
  await page.getByRole('link', { name: `Previous path, ${first.source_id}` }).click()
  await expect(page.getByRole('heading', { level: 1, name: first.source_id })).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Copy' })).toBeVisible({ timeout: 30_000 })

  // And the finished scenario stays with it.
  await page.getByRole('link', { name: `Next path, ${second.source_id}` }).click()
  await expect(page.getByRole('heading', { level: 1, name: second.source_id })).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Generate scenario' })).toBeEnabled()
  await expect(panel.getByRole('button', { name: 'Copy' })).toHaveCount(0)
})

test('a refused generation does not show its notice on the next path', async ({
  page,
  request,
}) => {
  const analysis = await createSampleAnalysis(request, { industry: uniqueIndustry('refused') })
  const [first, second] = [...analysis.paths].sort((a, b) => a.rank - b.rank)
  if (!first || !second) throw new Error('the sample has fewer than two paths')

  // The first path's start is refused; nothing is generated, so the server's one job slot stays free.
  await page.route(`**/api/analyses/${analysis.id}/paths/${first.source_id}/scenario`, (route) =>
    route.request().method() === 'POST'
      ? route.fulfill({ status: 503, json: { detail: 'The model is busy.' } })
      : route.continue(),
  )
  const panel = page.getByRole('region', { name: 'Attack scenario' })
  await page.goto(`/analysis/${analysis.id}/paths/${first.source_id}`)
  await panel.getByRole('button', { name: 'Generate scenario' }).click()
  await expect(panel.getByRole('alert')).toContainText('Could not start a generation')

  await page.getByRole('link', { name: `Next path, ${second.source_id}` }).click()
  await expect(page.getByRole('heading', { level: 1, name: second.source_id })).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Generate scenario' })).toBeEnabled()
  await expect(panel.getByRole('alert')).toHaveCount(0)
  await expect(panel.getByText('Could not start a generation')).toHaveCount(0)
})
