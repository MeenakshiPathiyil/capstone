import { act, render } from '@testing-library/react'
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ScrollToTop } from './ScrollToTop'

function renderAt(path: string) {
  const router = createMemoryRouter(
    [
      {
        element: (
          <>
            <ScrollToTop />
            <Outlet />
          </>
        ),
        children: [{ path: '*', element: null }],
      },
    ],
    { initialEntries: [path] },
  )
  render(<RouterProvider router={router} />)
  return (to: string) => act(() => router.navigate(to))
}

describe('ScrollToTop', () => {
  const scrollTo = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('scrollTo', scrollTo)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    scrollTo.mockReset()
  })

  it('scrolls to the top when the pathname changes', async () => {
    const go = renderAt('/analysis/a1?tab=paths')
    scrollTo.mockClear()
    await go('/analysis/a1/paths/AP-020')
    expect(scrollTo).toHaveBeenCalledTimes(1)
    expect(scrollTo).toHaveBeenLastCalledWith(0, 0)
    await go('/analysis/a1/paths/AP-021')
    expect(scrollTo).toHaveBeenCalledTimes(2)
  })

  it('leaves the scroll alone when only the search params change', async () => {
    const go = renderAt('/analysis/a1?tab=findings')
    scrollTo.mockClear()
    await go('/analysis/a1?tab=findings&resource=AppServerRole')
    await go('/analysis/a1?tab=graph&path=AP-001')
    expect(scrollTo).not.toHaveBeenCalled()
  })
})
