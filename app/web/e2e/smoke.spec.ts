import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'

import { type Page, type Request } from '@playwright/test'

import { expect, test } from './support/test'

import type { Analysis, Finding, GraphView } from '../src/api/types'
import {
  formatCount,
  getAnalysis,
  getScenario,
  createSampleAnalysis,
  topPath,
  uniqueIndustry,
  waitForFixImpact,
} from './support/api'
import {
  baseUrl,
  cacheDirFor,
  FAKE_SERVER_SCRIPT,
  portFor,
  PYTHON,
  REPO_ROOT,
  RESTART_PORT,
  serverEnv,
} from './support/env'
import {
  analysisTab,
  chooseTemplate,
  escapeRegExp,
  analysisIdFromUrl,
  SAMPLE_TEMPLATE,
  statTile,
  submitUpload,
} from './support/ui'

/** The overview's five tiles and the summary numbers they show. */
async function expectSummaryTiles(page: Page, analysis: Analysis) {
  const { summary } = analysis
  const tiles: [string, string][] = [
    ['Resources', formatCount(summary.resources)],
    ['Findings', formatCount(summary.findings)],
    ['Attack paths', formatCount(summary.paths)],
    ['Entry points', formatCount(summary.entry_points)],
    ['Top score', summary.top_score === null ? '-' : summary.top_score.toFixed(2)],
  ]
  for (const [label, value] of tiles) {
    await expect(statTile(page, label).getByText(value, { exact: true })).toBeVisible()
  }
}

/** The findings search, as src/lib/analysis.ts findingSearchText defines it: every term must match. */
function matchesSearch(finding: Finding, query: string): boolean {
  const text = [
    finding.resource,
    finding.resource_type,
    finding.rule.display_name,
    finding.rule_id,
    finding.source_id,
    finding.semantic ?? '',
    ...finding.rule.attack_techniques.flatMap((t) => [t.id, t.name]),
  ]
    .join(' ')
    .toLowerCase()
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => text.includes(term))
}

function rowName(finding: Finding): string {
  return `${finding.rule.display_name} on ${finding.resource}`
}

/** Accessible names of the findings table's body rows, sorted. */
async function visibleRowNames(page: Page): Promise<string[]> {
  const rows = page
    .getByRole('table')
    .getByRole('row')
    .filter({ has: page.getByRole('cell') })
  const names = await rows.evaluateAll((elements) =>
    elements.map((element) => element.getAttribute('aria-label') ?? ''),
  )
  return names.sort()
}

/** Graph edges a highlighted path lights up; each names its step numbers ("Step 2 of AP-001: ..."). */
function pathEdges(page: Page, sourceId: string) {
  return page.getByRole('img', {
    name: new RegExp(`^Step [\\d and]+ of ${escapeRegExp(sourceId)}\\b`),
  })
}

async function stepNumbersOnEdges(page: Page, sourceId: string): Promise<number[]> {
  const labels = await pathEdges(page, sourceId).evaluateAll((elements) =>
    elements.map((element) => element.getAttribute('aria-label') ?? ''),
  )
  return labels
    .flatMap((label) => (/^Step ([\d and]+) of/.exec(label)?.[1] ?? '').split(' and '))
    .map(Number)
    .sort((a, b) => a - b)
}

test('upload, inspect, generate a scenario, download the report and reload', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000)
  const industry = uniqueIndustry('smoke')
  let id = ''
  let analysis = {} as Analysis

  await test.step('upload the sample template through the file input', async () => {
    await page.goto('/')
    await chooseTemplate(page, SAMPLE_TEMPLATE)
    await page.getByLabel('Industry').fill(industry)
    expect((await submitUpload(page)).status()).toBe(201)
    id = await analysisIdFromUrl(page)
    analysis = await getAnalysis(request, id)
  })

  await test.step('overview counts equal the API summary', async () => {
    await expect(page.getByRole('heading', { level: 1, name: analysis.input_name })).toBeVisible()
    await expect(page.getByText(industry, { exact: true })).toBeVisible()
    await expectSummaryTiles(page, analysis)
    await expect(analysisTab(page, 'Findings')).toContainText(
      formatCount(analysis.summary.findings),
    )
    await expect(analysisTab(page, 'Paths')).toContainText(formatCount(analysis.summary.paths))
    // The fix-impact run holds the server's one analysis slot; let it finish here.
    await expect(page.getByRole('region', { name: 'Top fixes' })).toContainText(
      'candidate finding',
      {
        timeout: 30_000,
      },
    )
    await waitForFixImpact(request, id)
  })

  await test.step('findings: search, severity filter, resource sheet and focus return', async () => {
    await analysisTab(page, 'Findings').click()
    await expect(page).toHaveURL(/[?&]tab=findings\b/)
    const all = analysis.findings.map(rowName).sort()
    await expect.poll(() => visibleRowNames(page)).toEqual(all)

    // Search for the resource the top path ends at.
    const query = topPath(analysis).target_id
    const matching = analysis.findings.filter((f) => matchesSearch(f, query))
    expect(matching.length).toBeGreaterThan(0)
    expect(matching.length).toBeLessThan(analysis.findings.length)
    const search = page.getByRole('searchbox', { name: 'Search findings' })
    await search.fill(query)
    await expect.poll(() => visibleRowNames(page)).toEqual(matching.map(rowName).sort())
    await expect(
      page.getByText(
        `${formatCount(matching.length)} of ${formatCount(analysis.findings.length)} findings`,
      ),
    ).toBeVisible()
    await search.fill('')
    await expect.poll(() => visibleRowNames(page)).toEqual(all)

    // Severity filter: only critical findings, then back to all.
    const critical = analysis.findings.filter((f) => f.severity === 'critical')
    expect(critical.length).toBeGreaterThan(0)
    const criticalToggle = page
      .getByRole('group', { name: 'Filter by severity' })
      .getByRole('button', { name: /^Critical/ })
    await criticalToggle.click()
    await expect(criticalToggle).toHaveAttribute('aria-pressed', 'true')
    await expect.poll(() => visibleRowNames(page)).toEqual(critical.map(rowName).sort())
    await criticalToggle.click()
    await expect(criticalToggle).toHaveAttribute('aria-pressed', 'false')
    await expect.poll(() => visibleRowNames(page)).toEqual(all)

    // A row opens its resource; Escape closes the sheet and focus goes back to the row.
    const [finding] = matching
    if (!finding) throw new Error(`no finding matches ${query}`)
    const resource = analysis.resources.find((r) => r.id === finding.resource)
    expect(resource).toBeDefined()
    const row = page.getByRole('row', { name: rowName(finding), exact: true })
    await row.click()
    const sheet = page.getByRole('dialog', { name: finding.resource })
    await expect(sheet).toBeVisible()
    await expect(page).toHaveURL(new RegExp(`[?&]resource=${escapeRegExp(finding.resource)}\\b`))
    const count = resource?.findings.length ?? 0
    await expect(sheet).toContainText(`${formatCount(count)} finding${count === 1 ? '' : 's'}`)
    await page.keyboard.press('Escape')
    await expect(sheet).toBeHidden()
    await expect(row).toBeFocused()
    await expect(page).not.toHaveURL(/[?&]resource=/)
  })

  const top = topPath(analysis)

  await test.step('paths: grouped by chain, then the top path', async () => {
    await analysisTab(page, 'Paths').click()
    const list = page.getByRole('list', { name: 'Attack paths by chain' })
    await expect(list).toBeVisible()
    const chains = new Set(analysis.paths.map((p) => p.chain_group))
    await expect(list.getByRole('list', { name: /^Chain \d+$/ })).toHaveCount(chains.size)
    await expect(list.getByRole('link')).toHaveCount(analysis.paths.length)
    await list
      .getByRole('link', {
        name: `${top.source_id}, ${top.attack_level}, ${top.objective_name}, score ${String(top.score)}`,
      })
      .click()
    await expect(page).toHaveURL(new RegExp(`/analysis/${id}/paths/${top.source_id}$`))
  })

  await test.step('path detail: steps and the score breakdown', async () => {
    await expect(page.getByRole('heading', { level: 1, name: top.source_id })).toBeVisible()
    const steps = page.getByRole('region', { name: 'Steps' })
    await expect(steps.getByRole('heading', { level: 3 })).toHaveCount(top.steps.length)

    const b = top.breakdown
    await page
      .getByRole('button', { name: `Score ${top.score.toFixed(2)}. Show the breakdown` })
      .click()
    const popover = page.getByRole('dialog').filter({ hasText: `How ${top.source_id} was scored` })
    await expect(popover).toBeVisible()
    await expect(popover).toContainText(
      `(${String(b.severity_total)} + ${String(b.objective_weight)}) × 0.85`,
    )
    if (b.public_entry) await expect(popover).toContainText(`× ${String(b.boost)} = `)
    await expect(popover).toContainText(`= ${b.score.toFixed(2)}`)
    await expect(popover).toContainText('(finding weights + objective weight) × 0.85')
    await page.keyboard.press('Escape')
    await expect(popover).toBeHidden()
  })

  await test.step('path detail: the contextual risk card', async () => {
    const risk = top.risk
    if (!risk) throw new Error(`${top.source_id} has no contextual risk`)
    const card = page.getByRole('region', { name: 'Contextual risk' })
    await expect(card).toContainText(risk.score.toFixed(2))
    await expect(card).toContainText(`Rank ${String(risk.rank)} of `)
    await expect(card.getByRole('meter', { name: 'Path ease' })).toHaveAttribute(
      'aria-valuenow',
      String(risk.path_ease),
    )
    await card.getByRole('button', { name: 'How contextual risk is computed' }).click()
    const popover = page.getByRole('dialog').filter({ hasText: 'by the second model' })
    await expect(popover).toContainText(`= ${risk.score.toFixed(2)}`)
    await page.keyboard.press('Escape')
    await expect(popover).toBeHidden()
  })

  await test.step('view on graph: the path is highlighted in both views', async () => {
    await page.getByRole('link', { name: 'View on graph' }).click()
    await expect(page).toHaveURL(/[?&]tab=graph\b/)
    await expect(page).toHaveURL(new RegExp(`[?&]path=${top.source_id}\\b`))
    await expect(page.getByRole('complementary', { name: `Path ${top.source_id}` })).toBeVisible()

    const expectedSteps = top.steps.map((_, index) => index + 1)
    await expect(pathEdges(page, top.source_id)).toHaveCount(top.steps.length)
    expect(await stepNumbersOnEdges(page, top.source_id)).toEqual(expectedSteps)
    // Resources view: one node per hop.
    const onPath = page.getByRole('group', { name: new RegExp(`, on ${top.source_id}\\.`) })
    await expect(onPath).toHaveCount(new Set(top.hops).size)

    await page
      .getByRole('tablist', { name: 'Graph view' })
      .getByRole('tab', { name: 'Attack moves' })
      .click()
    await expect(page).toHaveURL(/[?&]view=attack\b/)
    const attack = (await (
      await request.get(`/api/analyses/${id}/graph?view=attack`)
    ).json()) as GraphView
    const attackEdges = attack.edges.filter((e) => e.path_ids.includes(top.source_id))
    expect(attackEdges).toHaveLength(top.steps.length)
    await expect(pathEdges(page, top.source_id)).toHaveCount(top.steps.length)
    expect(await stepNumbersOnEdges(page, top.source_id)).toEqual(expectedSteps)
    await expect(onPath).toHaveCount(new Set(attackEdges.flatMap((e) => [e.source, e.target])).size)
    await expect(page.getByText('could not be matched to exact attack moves')).toHaveCount(0)
  })

  await test.step('scenario: generate on the top path, running to done, then copy', async () => {
    await page.getByRole('link', { name: 'Open path details' }).click()
    await expect(page).toHaveURL(new RegExp(`/paths/${top.source_id}$`))
    const panel = page.getByRole('region', { name: 'Attack scenario' })
    await panel.getByRole('button', { name: 'Generate scenario' }).click()
    await expect(panel.getByRole('button', { name: /^Generating… / })).toBeVisible({
      timeout: 15_000,
    })
    await expect(panel.getByRole('button', { name: 'Copy' })).toBeVisible({ timeout: 30_000 })
    for (const title of ['Narrative', 'Mathematical expression', 'Attack graph']) {
      await expect(panel.getByRole('heading', { level: 3, name: title, exact: true })).toBeVisible()
    }

    const state = await getScenario(request, id, top.source_id)
    expect(state.status).toBe('done')
    const text = state.scenario?.text ?? ''
    expect(text).not.toBe('')
    await panel.getByRole('button', { name: 'Copy' }).click()
    await expect(panel.getByRole('button', { name: 'Copied' })).toBeVisible()
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(text)
  })

  await test.step('download the PDF report', async () => {
    await page
      .getByRole('navigation', { name: 'Breadcrumb' })
      .getByRole('link', {
        name: analysis.input_name,
      })
      .click()
    await expect(page).toHaveURL(new RegExp(`/analysis/${id}$`))
    const downloading = page.waitForEvent('download')
    // The report control: a plain link, or a button that prepares fix impact first.
    const name = 'Download report'
    await page
      .getByRole('button', { name, exact: true })
      .or(page.getByRole('link', { name, exact: true }))
      .click()
    const download = await downloading
    expect(download.suggestedFilename()).toMatch(/\.pdf$/)
    const file = await download.path()
    await test.info().attach('report.pdf', { path: file, contentType: 'application/pdf' })
    const bytes = fs.readFileSync(file)
    expect(bytes.length).toBeGreaterThan(1000)
    expect(bytes.subarray(0, 4).toString('latin1')).toBe('%PDF')
  })

  await test.step('reload: the saved analysis is read back, not recomputed', async () => {
    const posts: Request[] = []
    page.on('request', (r) => {
      if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/analyses') posts.push(r)
    })
    const read = page.waitForResponse(
      (response) => new URL(response.url()).pathname === `/api/analyses/${id}`,
    )
    await page.reload()
    const response = await read
    expect(response.status()).toBe(200)
    expect(await response.json()).toEqual(analysis)
    await expectSummaryTiles(page, analysis)
    expect(posts).toHaveLength(0)
  })
})

const withRestart = test.extend<{ restartedServer: string }>({
  // A second API process over the first one's store, as after a restart.
  // eslint-disable-next-line no-empty-pattern
  restartedServer: async ({}, use) => {
    const env = {
      ...serverEnv('ok', RESTART_PORT),
      FAKE_SCENARIO_CACHE_DIR: cacheDirFor(portFor('ok')),
    }
    const server = spawn(PYTHON, [FAKE_SERVER_SCRIPT], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env },
      stdio: 'ignore',
    })
    const exited = new Promise<void>((resolve) => server.once('exit', () => resolve()))
    try {
      const url = baseUrl(RESTART_PORT)
      await expect
        .poll(
          async () => {
            try {
              return (await fetch(`${url}/api/meta`)).status
            } catch {
              return 0
            }
          },
          { message: 'the restarted server answers', timeout: 30_000 },
        )
        .toBe(200)
      await use(url)
    } finally {
      server.kill('SIGTERM')
      await exited
    }
  },
})

withRestart(
  'a restarted server serves a saved analysis from the store',
  async ({ page, request, restartedServer }) => {
    const analysis = await createSampleAnalysis(request, { industry: uniqueIndustry('restart') })
    const saved = path.join(cacheDirFor(portFor('ok')), 'analyses', analysis.id, 'analysis.json')
    withRestart.skip(
      !fs.existsSync(saved),
      `The server on ${baseUrl(portFor('ok'))} was reused and keeps its store elsewhere.`,
    )
    expect(JSON.parse(fs.readFileSync(saved, 'utf8'))).toEqual(analysis)

    const restarted = await page.request.get(`${restartedServer}/api/analyses/${analysis.id}`)
    expect(restarted.status()).toBe(200)
    expect(await restarted.json()).toEqual(analysis)

    await page.goto(`${restartedServer}/analysis/${analysis.id}?tab=paths`)
    await expect(page.getByRole('heading', { level: 1, name: analysis.input_name })).toBeVisible()
    await expect(
      page.getByRole('list', { name: 'Attack paths by chain' }).getByRole('link'),
    ).toHaveCount(analysis.paths.length)
    const top = topPath(analysis)
    await expect(page.getByRole('link', { name: new RegExp(`^${top.source_id}, `) })).toBeVisible()
  },
)
