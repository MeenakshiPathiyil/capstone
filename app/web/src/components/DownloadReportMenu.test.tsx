import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { DownloadReportMenu } from './DownloadReportMenu'

/** The URL a fetch call was made with. */
function urlOf(input: Parameters<typeof fetch>[0]): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function pdf() {
  return new Response('%PDF-fake', {
    status: 200,
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': 'attachment; filename="attack-path-assessment-a1.pdf"',
    },
  })
}

const SAVED = 'attack-path-assessment-a1.pdf'

const RATE_LIMITED = 'Too many analyses from this address: the limit is 20 per 10 minutes.'

const HEALTH = {
  ok: true,
  weasyprint: true,
  pdf_unavailable_reason: null,
  space_configured: false,
  space_stage: null,
  model_unavailable_reason: null,
  gpu_quota_remaining_s: null,
  gpu_quota_resets_at: null,
  est_generations_left: null,
}

const FIXES = {
  analysis_id: 'a1',
  scope_top: 5,
  candidate_count: 0,
  computed_at: '2026-10-25T10:00:00Z',
  results: [],
}

function renderMenu(exportedPaths = 22) {
  const client = new QueryClient()
  render(
    <QueryClientProvider client={client}>
      <DownloadReportMenu analysisId="a1" exportedPaths={exportedPaths} />
    </QueryClientProvider>,
  )
}

describe('DownloadReportMenu', () => {
  const fetchMock = vi.fn<typeof fetch>()
  /** The file names saved, one per finished download. */
  const downloads: string[] = []

  /** Answers for the fix-impact POST and the PDF; /health always answers `health`. */
  let fixes: () => Response | Promise<Response> = () => json(200, FIXES)
  let report: () => Response = pdf
  let health: Response = json(200, HEALTH)
  const callsTo = (part: string) =>
    fetchMock.mock.calls.filter(([input]) => urlOf(input).includes(part))
  const fixCalls = () => callsTo('/fixes')
  const reportCalls = () => callsTo('/report.pdf').map(([input]) => urlOf(input))

  beforeEach(() => {
    fixes = () => json(200, FIXES)
    report = pdf
    health = json(200, HEALTH)
    fetchMock.mockImplementation((input) => {
      const url = urlOf(input)
      if (url.endsWith('/health')) return Promise.resolve(health.clone())
      if (url.includes('/report.pdf')) return Promise.resolve(report())
      return Promise.resolve(fixes())
    })
    vi.stubGlobal('fetch', fetchMock)
    // jsdom has no object URLs.
    URL.createObjectURL = () => 'blob:report'
    URL.revokeObjectURL = () => undefined
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      expect(this.getAttribute('href')).toBe('blob:report')
      downloads.push(this.download)
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    fetchMock.mockReset()
    downloads.length = 0
  })

  it('computes fix impact for the scope before downloading', async () => {
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    await vi.waitFor(() => expect(downloads).toHaveLength(1))
    const [url, init] = fixCalls()[0] ?? []
    expect(url).toBe('/api/analyses/a1/fixes?top=5')
    expect(init?.method).toBe('POST')
    expect(reportCalls()).toEqual(['/api/analyses/a1/report.pdf?top=5'])
    expect(downloads).toEqual([SAVED])
  })

  it('offers a retry when the service is busy', async () => {
    fixes = () => json(503, { detail: 'busy' }, { 'Retry-After': '20' })
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 20 seconds')
    expect(downloads).toHaveLength(0)

    fixes = () => json(200, FIXES)
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
    await vi.waitFor(() => expect(downloads).toEqual([SAVED]))
  })

  it('says when to try again when estimates are rate limited, and offers the report without them', async () => {
    fixes = () => json(429, { detail: RATE_LIMITED }, { 'Retry-After': '240' })
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Fix-impact estimates are not ready')
    expect(alert).toHaveTextContent(`${RATE_LIMITED} Try again in about 4 min.`)
    expect(downloads).toHaveLength(0)

    await userEvent.click(screen.getByRole('button', { name: 'Download without estimates' }))
    await vi.waitFor(() => expect(downloads).toEqual([SAVED]))
    expect(fixCalls()).toHaveLength(1)
  })

  it('shows why the report itself was refused instead of a failed download', async () => {
    report = () =>
      json(
        429,
        { detail: 'Too many PDF reports from this address: the limit is 10 per 10 minutes.' },
        { 'Retry-After': '30' },
      )
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('The report could not be downloaded')
    expect(alert).toHaveTextContent('the limit is 10 per 10 minutes. Try again in 30 s.')
    expect(screen.queryByRole('button', { name: 'Download without estimates' })).toBeNull()
    expect(downloads).toHaveLength(0)

    report = pdf
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
    await vi.waitFor(() => expect(downloads).toEqual([SAVED]))
    // The estimates were computed the first time and are not asked for again.
    expect(fixCalls()).toHaveLength(1)
  })

  it('downloads at once when there are no exported paths to estimate', async () => {
    renderMenu(0)
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    await vi.waitFor(() => expect(downloads).toEqual([SAVED]))
    expect(fixCalls()).toHaveLength(0)
  })

  it('keeps keyboard focus on the button while the report is prepared, and ignores a second press', async () => {
    let finish: (response: Response) => void = () => undefined
    fixes = () =>
      new Promise<Response>((resolve) => {
        finish = resolve
      })
    renderMenu()
    const button = screen.getByRole('button', { name: /download report/i })
    button.focus()
    await userEvent.keyboard('{Enter}')
    await vi.waitFor(() => expect(button).toHaveAttribute('aria-disabled', 'true'))
    expect(button).toHaveFocus()
    expect(button).toBeEnabled()

    await userEvent.keyboard('{Enter}')
    await userEvent.click(button)
    expect(fixCalls()).toHaveLength(1)
    // The options button stays put too, and does not open the menu while busy.
    const options = screen.getByRole('button', { name: 'Report options' })
    expect(options).toHaveAttribute('aria-disabled', 'true')
    await userEvent.click(options)
    expect(screen.queryByRole('menu')).toBeNull()

    finish(json(200, FIXES))
    await vi.waitFor(() => expect(downloads).toHaveLength(1))
    expect(button).toHaveFocus()
    expect(button).not.toHaveAttribute('aria-disabled')
  })

  it('says the report is cut at 50 paths when more are exported', async () => {
    renderMenu(1830)
    await userEvent.click(screen.getByRole('button', { name: 'Report options' }))
    const item = await screen.findByRole('menuitem', { name: /Top 50 exported paths/ })
    expect(item).toHaveTextContent('of 1,830')
    expect(screen.queryByRole('menuitem', { name: /All exported paths/ })).toBeNull()
  })

  it('returns focus to the main button after choosing from the menu', async () => {
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: 'Report options' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /All exported paths/ }))
    await vi.waitFor(() => expect(downloads).toEqual([SAVED]))
    expect(reportCalls()).toEqual(['/api/analyses/a1/report.pdf?top=all'])
    await vi.waitFor(() =>
      expect(screen.getByRole('button', { name: /download report/i })).toHaveFocus(),
    )
  })

  it('returns focus to the main button when the error popover closes', async () => {
    fixes = () => json(503, { detail: 'busy' }, { 'Retry-After': '20' })
    renderMenu()
    await userEvent.click(screen.getByRole('button', { name: /download report/i }))
    await screen.findByRole('alert')
    await userEvent.keyboard('{Escape}')
    await vi.waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    await vi.waitFor(() =>
      expect(screen.getByRole('button', { name: /download report/i })).toHaveFocus(),
    )
  })

  it('is inert and says why when the server cannot render PDFs', async () => {
    health = json(200, {
      ...HEALTH,
      weasyprint: false,
      pdf_unavailable_reason: 'PDF rendering is unavailable: WeasyPrint is not installed.',
    })
    renderMenu()
    const button = screen.getByRole('button', { name: /download report/i })
    await vi.waitFor(() => expect(button).toHaveAttribute('aria-disabled', 'true'))
    expect(button).toHaveAccessibleDescription(
      'PDF rendering is unavailable: WeasyPrint is not installed.',
    )
    expect(button.parentElement).toHaveAttribute(
      'title',
      'PDF rendering is unavailable: WeasyPrint is not installed.',
    )
    await userEvent.click(button)
    await userEvent.click(screen.getByRole('button', { name: 'Report options' }))
    expect(screen.queryByRole('menu')).toBeNull()
    expect(fixCalls()).toHaveLength(0)
    expect(downloads).toHaveLength(0)
  })
})
