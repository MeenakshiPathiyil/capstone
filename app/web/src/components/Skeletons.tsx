import type { ReactNode } from 'react'

import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

/** Screen readers hear one status message instead of a pile of grey boxes. */
function Busy({
  label,
  className,
  children,
}: {
  label: string
  className?: string
  children: ReactNode
}) {
  return (
    <div role="status" aria-live="polite" className={className}>
      <span className="sr-only">{label}</span>
      {children}
    </div>
  )
}

export function StatTilesSkeleton({
  count = 5,
  className,
}: {
  count?: number
  className?: string
}) {
  return (
    <Busy
      label="Loading summary"
      className={cn('grid grid-cols-2 gap-3 md:grid-cols-5', className)}
    >
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="rounded-lg border bg-surface px-4 py-3.5">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="mt-3 h-6 w-12" />
          <Skeleton className="mt-2 h-3 w-24" />
        </div>
      ))}
    </Busy>
  )
}

const CELL_WIDTHS = ['w-16', 'w-40', 'w-28', 'w-56', 'w-20', 'w-24', 'w-10']

export function TableSkeleton({
  rows = 8,
  columns = 6,
  className,
}: {
  rows?: number
  columns?: number
  className?: string
}) {
  return (
    <Busy
      label="Loading table"
      className={cn('overflow-hidden rounded-lg border bg-surface', className)}
    >
      <div className="flex h-8 items-center gap-6 border-b bg-zinc-50/60 px-3">
        {Array.from({ length: columns }, (_, c) => (
          <Skeleton key={c} className="h-2.5 w-14" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex h-9 items-center gap-6 border-b px-3 last:border-0">
          {Array.from({ length: columns }, (_, c) => (
            <Skeleton key={c} className={cn('h-3', CELL_WIDTHS[(r + c) % CELL_WIDTHS.length])} />
          ))}
        </div>
      ))}
    </Busy>
  )
}

export function CardListSkeleton({ count = 3, className }: { count?: number; className?: string }) {
  return (
    <Busy label="Loading" className={cn('flex flex-col gap-3', className)}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="rounded-lg border bg-surface p-4">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-4 w-14" />
            <Skeleton className="ml-auto h-1.5 w-32" />
          </div>
          <div className="mt-3 flex gap-2">
            {Array.from({ length: 4 }, (_, j) => (
              <Skeleton key={j} className="h-6 w-28" />
            ))}
          </div>
        </div>
      ))}
    </Busy>
  )
}

export function AnalysisHeaderSkeleton() {
  return (
    <Busy label="Loading analysis" className="flex flex-col gap-2">
      <Skeleton className="h-6 w-64" />
      <Skeleton className="h-3.5 w-96" />
    </Busy>
  )
}
