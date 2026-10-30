import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'
import type { Tone } from '@/lib/severity'

import { SeverityDot } from './SeverityBadge'

interface StatTileProps {
  label: string
  value: ReactNode
  /** One short line under the value: a breakdown or a unit. */
  hint?: ReactNode
  /** A dot before the label, when the number is about one severity or level. */
  tone?: Tone
  className?: string
}

export function StatTile({ label, value, hint, tone, className }: StatTileProps) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn('flex min-w-0 flex-col rounded-lg border bg-surface px-4 py-3.5', className)}
    >
      <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        {tone && <SeverityDot severity={tone} />}
        <span className="truncate">{label}</span>
      </div>
      <div className="mt-1.5 text-2xl font-semibold text-foreground tabular-nums">{value}</div>
      {hint && <div className="mt-0.5 truncate text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}
