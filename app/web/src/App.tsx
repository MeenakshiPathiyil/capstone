import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { RouterProvider } from 'react-router'

import { useMeta } from '@/api/hooks'
import { TooltipProvider } from '@/components/ui/tooltip'
import { applySeverityPalette } from '@/lib/severity'
import { router } from '@/router'

function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: false,
      },
    },
  })
}

/** Writes the served severity palette onto :root once /api/meta answers. */
function SeverityPaletteSync() {
  const { data } = useMeta()
  useEffect(() => {
    if (data) applySeverityPalette(data.severity_styles)
  }, [data])
  return null
}

export function App() {
  const [queryClient] = useState(createQueryClient)
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <SeverityPaletteSync />
        <RouterProvider router={router} />
      </TooltipProvider>
    </QueryClientProvider>
  )
}
