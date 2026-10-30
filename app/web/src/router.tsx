import { lazy, Suspense } from 'react'
import { createBrowserRouter, Outlet, type RouteObject } from 'react-router'

import { ScrollToTop } from '@/components/ScrollToTop'
import { AnalysisPage } from '@/pages/AnalysisPage'
import { NotFoundPage, RouteErrorPage } from '@/pages/NotFoundPage'
import { PathDetailPage } from '@/pages/PathDetailPage'
import { UploadPage } from '@/pages/UploadPage'

const routes: RouteObject[] = [
  { path: '/', element: <UploadPage />, errorElement: <RouteErrorPage /> },
  // Tabs live in the query string: ?tab=overview|findings|paths|graph
  { path: '/analysis/:id', element: <AnalysisPage />, errorElement: <RouteErrorPage /> },
  {
    path: '/analysis/:id/paths/:sourceId',
    element: <PathDetailPage />,
    errorElement: <RouteErrorPage />,
  },
]

if (import.meta.env.DEV) {
  // Dev only: the design review page. The dynamic import keeps it out of the production bundle.
  const KitchenSinkPage = lazy(() => import('@/pages/dev/KitchenSinkPage'))
  routes.push({
    path: '/dev/kitchen-sink',
    element: (
      <Suspense fallback={null}>
        <KitchenSinkPage />
      </Suspense>
    ),
  })
}

routes.push({ path: '*', element: <NotFoundPage /> })

export const router = createBrowserRouter([
  // Pathless layout route: every page sits under it, so the scroll reset covers them all.
  {
    element: (
      <>
        <ScrollToTop />
        <Outlet />
      </>
    ),
    children: routes,
  },
])
