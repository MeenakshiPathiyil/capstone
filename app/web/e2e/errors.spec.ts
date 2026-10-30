import fs from 'node:fs'
import path from 'node:path'

import { type APIRequestContext, type Page } from '@playwright/test'

import { expect, test } from './support/test'

import type { Meta } from '../src/api/types'
import { formatCount, getAnalysis, getMeta } from './support/api'
import {
  analysisTab,
  chooseTemplate,
  fixtureFile,
  pickFile,
  statTile,
  submitUpload,
  uploadTemplate,
} from './support/ui'

/** What the API answers when this file is uploaded directly, once the analysis slot is free. */
async function uploadDirectly(request: APIRequestContext, meta: Meta, file: string) {
  let answer = { status: 0, detail: '' }
  await expect(async () => {
    const response = await request.post('/api/analyses', {
      multipart: {
        file: {
          name: path.basename(file),
          mimeType: 'application/octet-stream',
          buffer: fs.readFileSync(file),
        },
        industry: meta.default_industry,
        min_level: 'HIGH',
      },
    })
    const body = (await response.json()) as { detail?: string }
    answer = { status: response.status(), detail: body.detail ?? '' }
    expect(answer.status, 'the analysis slot is free').not.toBe(503)
  }).toPass({ intervals: [250, 500, 1_000, 2_000], timeout: 30_000 })
  return answer
}

function uploadPosts(page: Page): string[] {
  const posts: string[] = []
  page.on('request', (r) => {
    if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/analyses') posts.push(r.url())
  })
  return posts
}

test('malformed YAML shows the API 422 detail under the dropzone', async ({ page, request }) => {
  const meta = await getMeta(request)
  const file = fixtureFile('malformed.yaml')
  const expected = await uploadDirectly(request, meta, file)
  expect(expected.status).toBe(422)

  await page.goto('/')
  await chooseTemplate(page, file)
  expect((await submitUpload(page)).status()).toBe(422)
  await expect(page.getByRole('alert')).toHaveText(expected.detail)
  await expect(page).toHaveURL(/\/$/)
})

test('a file with the wrong extension is refused before upload', async ({ page, request }) => {
  const { limits } = await getMeta(request)
  const posts = uploadPosts(page)
  await page.goto('/')
  await pickFile(page, fixtureFile('notes.txt'))
  const alert = page.getByRole('alert')
  await expect(alert).toContainText('notes.txt is not a template file')
  for (const extension of limits.accepted_extensions) await expect(alert).toContainText(extension)
  await expect(page.getByRole('button', { name: 'Analyse template' })).toBeDisabled()
  expect(posts).toHaveLength(0)
})

test('the API 415 message is shown when the client lets an extension through', async ({
  page,
  request,
}) => {
  const meta = await getMeta(request)
  const file = fixtureFile('notes.txt')
  const expected = await uploadDirectly(request, meta, file)
  expect(expected.status).toBe(415)

  // Simulate a client whose limits are out of date: it accepts .txt, the server does not.
  await page.route('**/api/meta', async (route) => {
    const response = await route.fetch()
    const body = (await response.json()) as Meta
    const limits = {
      ...body.limits,
      accepted_extensions: [...body.limits.accepted_extensions, '.txt'],
    }
    await route.fulfill({ response, json: { ...body, limits } })
  })
  await page.goto('/')
  await chooseTemplate(page, file)
  expect((await submitUpload(page)).status()).toBe(415)
  await expect(page.getByRole('alert')).toHaveText(expected.detail)
})

test('an empty template gives an honest empty analysis', async ({ page, request }) => {
  await page.goto('/')
  const id = await uploadTemplate(page, fixtureFile('empty-resources.yaml'))
  const analysis = await getAnalysis(request, id)
  expect(analysis.summary.resources).toBe(0)

  await expect(page.getByRole('heading', { level: 1, name: analysis.input_name })).toBeVisible()
  for (const [label, value] of [
    ['Resources', analysis.summary.resources],
    ['Findings', analysis.summary.findings],
    ['Attack paths', analysis.summary.paths],
    ['Entry points', analysis.summary.entry_points],
  ] as const) {
    await expect(statTile(page, label).getByText(formatCount(value), { exact: true })).toBeVisible()
  }
  await expect(page.getByText('This template declares no resources')).toBeVisible()

  await analysisTab(page, 'Findings').click()
  await expect(page.getByText('No findings', { exact: true })).toBeVisible()
  await expect(page.getByRole('table')).toHaveCount(0)

  await analysisTab(page, 'Paths').click()
  await expect(page.getByText('No attack paths', { exact: true })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Attack paths by chain' })).toHaveCount(0)

  await analysisTab(page, 'Graph').click()
  await expect(page.getByText('Nothing to draw', { exact: true })).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'Highlight a path' })).toBeDisabled()
})
