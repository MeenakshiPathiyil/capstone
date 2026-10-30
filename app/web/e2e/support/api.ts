/**
 * Direct API calls the specs use to set up state and to compute what the UI
 * should show, so expectations come from the same data the page renders.
 */
import { expect, type APIRequestContext, type APIResponse } from '@playwright/test'

import type { Analysis, Health, Meta, Path, ScenarioState } from '../../src/api/types'

async function json<T>(response: APIResponse, what: string): Promise<T> {
  expect(response.ok(), `${what}: HTTP ${String(response.status())} ${await response.text()}`).toBe(
    true,
  )
  return (await response.json()) as T
}

export async function getMeta(request: APIRequestContext): Promise<Meta> {
  return json<Meta>(await request.get('/api/meta'), 'GET /api/meta')
}

export async function getHealth(request: APIRequestContext): Promise<Health> {
  return json<Health>(await request.get('/api/health'), 'GET /api/health')
}

export async function getAnalysis(request: APIRequestContext, id: string): Promise<Analysis> {
  return json<Analysis>(await request.get(`/api/analyses/${id}`), `GET analysis ${id}`)
}

export async function getScenario(
  request: APIRequestContext,
  id: string,
  sourceId: string,
): Promise<ScenarioState> {
  return json<ScenarioState>(
    await request.get(`/api/analyses/${id}/paths/${sourceId}/scenario`),
    `GET scenario ${sourceId}`,
  )
}

/**
 * POST /api/analyses/sample, as the upload page's sample cards do. The server
 * runs one analysis at a time and answers 503 when busy; like any client
 * honouring Retry-After, this tries again until the slot is free.
 */
export async function createSampleAnalysis(
  request: APIRequestContext,
  { sampleId = 'cloudformation5', industry }: { sampleId?: string; industry: string },
): Promise<Analysis> {
  let response: APIResponse | undefined
  await expect(async () => {
    response = await request.post('/api/analyses/sample', {
      data: { sample_id: sampleId, industry, min_level: 'HIGH' },
    })
    expect(response.status(), 'the analysis slot is free').not.toBe(503)
  }).toPass({ intervals: [250, 500, 1_000, 2_000], timeout: 30_000 })
  if (!response) throw new Error(`POST sample ${sampleId} sent no request`)
  return json<Analysis>(response, `POST sample ${sampleId}`)
}

/**
 * Waits until the overview's fix-impact run for this analysis is saved. The
 * server has one analysis slot, so a spec that opened an overview waits here
 * before the next upload instead of racing it into a 503.
 */
export async function waitForFixImpact(request: APIRequestContext, id: string): Promise<void> {
  await expect
    .poll(async () => (await request.get(`/api/analyses/${id}/fixes?top=5`)).status(), {
      message: `fix impact for ${id} is saved`,
      timeout: 30_000,
    })
    .toBe(200)
}

/** Polls until fix impact for this analysis is saved; false if it is not within `timeoutMs`. */
export async function fixImpactSaved(
  request: APIRequestContext,
  id: string,
  timeoutMs: number,
): Promise<boolean> {
  try {
    await expect
      .poll(async () => (await request.get(`/api/analyses/${id}/fixes?top=5`)).status(), {
        timeout: timeoutMs,
      })
      .toBe(200)
    return true
  } catch {
    return false
  }
}

export function pathById(analysis: Analysis, sourceId: string): Path {
  const path = analysis.paths.find((p) => p.source_id === sourceId)
  if (!path) throw new Error(`${sourceId} is not in analysis ${analysis.id}`)
  return path
}

/** The top-ranked path: AP-001 for any analysis with paths. */
export function topPath(analysis: Analysis): Path {
  const [top] = [...analysis.paths].sort((a, b) => a.rank - b.rank)
  if (!top) throw new Error(`analysis ${analysis.id} has no paths`)
  return top
}

/**
 * An industry no earlier run has used. Scenarios are cached by prompt, and the
 * prompt includes the industry, so a fresh one always starts a live
 * generation, even against a server reused from an earlier run.
 */
export function uniqueIndustry(label: string): string {
  return `E2E ${label} ${Date.now().toString(36)}`
}

/** "1,200": counts as the app formats them (en-GB, whatever the browser locale). */
export function formatCount(value: number): string {
  return new Intl.NumberFormat('en-GB', { maximumFractionDigits: 0 }).format(value)
}

/** Timestamps as the app prints them ("24 Oct 2026, 10:28 UTC"), for masking in screenshots. */
export const TIMESTAMP = /\d{1,2} \w{3} \d{4}, \d{2}:\d{2} UTC/
