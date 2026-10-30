/** Keyboard-only use of the upload page and the analysis tabs. */
import { expect, test } from './support/test'

import { getAnalysis, getMeta, waitForFixImpact } from './support/api'
import { analysisIdFromUrl, analysisTab, escapeRegExp, tabTo } from './support/ui'

test('keyboard: run a sample, switch tabs, open and close a resource', async ({
  page,
  request,
}) => {
  const meta = await getMeta(request)
  const sample = meta.samples[0]
  expect(sample).toBeDefined()
  if (!sample) return

  await test.step('Tab from the top of the upload page to a sample card, Enter runs it', async () => {
    await page.goto('/')
    const card = page.getByRole('button', { name: new RegExp(`^${escapeRegExp(sample.name)}`) })
    // Enabled once /api/meta has filled in the industry.
    await expect(card).toBeEnabled()
    await tabTo(page, card)
    await page.keyboard.press('Enter')
  })

  const id = await analysisIdFromUrl(page)
  const analysis = await getAnalysis(request, id)

  await test.step('the overview settles', async () => {
    await expect(page.getByRole('heading', { level: 1, name: analysis.input_name })).toBeVisible()
    await expect(page.getByRole('region', { name: 'Top fixes' })).toContainText(
      'candidate finding',
      { timeout: 30_000 },
    )
    await waitForFixImpact(request, id)
  })

  await test.step('arrow keys move between the analysis tabs', async () => {
    const overview = analysisTab(page, 'Overview')
    await tabTo(page, overview)
    await expect(overview).toHaveAttribute('aria-selected', 'true')

    await page.keyboard.press('ArrowRight')
    await expect(analysisTab(page, 'Findings')).toBeFocused()
    await expect(analysisTab(page, 'Findings')).toHaveAttribute('aria-selected', 'true')
    await expect(page).toHaveURL(/[?&]tab=findings\b/)
    await expect(page.getByRole('searchbox', { name: 'Search findings' })).toBeVisible()

    await page.keyboard.press('ArrowRight')
    await expect(analysisTab(page, 'Paths')).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByRole('list', { name: 'Attack paths by chain' })).toBeVisible()

    await page.keyboard.press('ArrowRight')
    await expect(analysisTab(page, 'Graph')).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByRole('tablist', { name: 'Graph view' })).toBeVisible()

    await page.keyboard.press('Home')
    await expect(overview).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByRole('region', { name: 'Top paths' })).toBeVisible()

    await page.keyboard.press('ArrowRight')
    await expect(analysisTab(page, 'Findings')).toHaveAttribute('aria-selected', 'true')
  })

  await test.step('Enter on a finding row opens its resource; Escape returns focus', async () => {
    const row = page
      .getByRole('table')
      .getByRole('row')
      .filter({ has: page.getByRole('cell') })
    const first = row.first()
    await tabTo(page, first)
    const name = (await first.getAttribute('aria-label')) ?? ''
    const resource = name.slice(name.lastIndexOf(' on ') + ' on '.length)
    expect(analysis.resources.map((r) => r.id)).toContain(resource)
    await page.keyboard.press('Enter')
    const sheet = page.getByRole('dialog', { name: resource })
    await expect(sheet).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(sheet).toBeHidden()
    await expect(first).toBeFocused()
  })
})
