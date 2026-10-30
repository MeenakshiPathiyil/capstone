import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { UploadPage } from './UploadPage'

const META = {
  severity_styles: {},
  attack_levels: ['CRITICAL', 'HIGH', 'MEDIUM'],
  objectives: [],
  industries: ['Manufacturing'],
  default_industry: 'Manufacturing',
  samples: [
    { id: 'cloudformation5', name: 'Three-tier', description: 'Three tiers.', kind: 'single' },
  ],
  limits: {
    max_upload_bytes: 2_000_000,
    max_resources: 500,
    accepted_extensions: ['.yaml', '.yml'],
  },
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Lets the mutations that were started send their requests. */
const settled = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, 30)))

describe('UploadPage in-flight guard', () => {
  const fetchMock = vi.fn<typeof fetch>()
  /** Resolves the pending analysis POST. */
  let finish: (response: Response) => void = () => undefined

  const posts = () => fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockImplementation((input, init) => {
      if (init?.method === 'POST') {
        return new Promise<Response>((resolve) => {
          finish = resolve
        })
      }
      return Promise.resolve(
        (typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.href
            : input.url
        ).endsWith('/meta')
          ? json(200, META)
          : json(404, {}),
      )
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  function renderPage() {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <UploadPage />
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('sends one upload when the form is submitted twice before it re-renders', async () => {
    renderPage()
    const input = document.querySelector<HTMLInputElement>('input[type=file]')
    if (!input) throw new Error('no file input')
    await userEvent.upload(input, new File(['Resources: {}'], 'stack.yaml'))
    const analyse = await screen.findByRole('button', { name: 'Analyse template' })
    await waitFor(() => expect(analyse).toBeEnabled())

    // Two Enter presses in one task: the second runs before React re-renders with busy set.
    const form = analyse.closest('form')
    if (!form) throw new Error('no form')
    act(() => {
      fireEvent.submit(form)
      fireEvent.submit(form)
    })
    await settled()
    expect(posts()).toHaveLength(1)

    // A failed upload frees the guard, so the user can try again.
    await act(async () => {
      finish(json(400, { detail: 'not a template' }))
      await Promise.resolve()
    })
    await screen.findByText('not a template')
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Analyse template' })).toBeEnabled(),
    )
    fireEvent.submit(form)
    await waitFor(() => expect(posts()).toHaveLength(2))
  })

  it('sends one sample request when a sample is activated twice at once', async () => {
    renderPage()
    const sample = await screen.findByRole('button', { name: /Three-tier/ })
    await waitFor(() => expect(sample).toBeEnabled())
    act(() => {
      fireEvent.click(sample)
      fireEvent.click(sample)
    })
    await settled()
    expect(posts()).toHaveLength(1)
  })
})
