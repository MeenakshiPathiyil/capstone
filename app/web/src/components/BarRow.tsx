import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'
import { formatCount } from '@/lib/format'
import type { Tone } from '@/lib/severity'

import { SeverityDot } from './SeverityBadge'

interface BarRowProps {
  label: ReactNode
  value: number
  /** The value that fills the whole track; usually the largest row in the group. */
  max: number
  tone?: Tone
  /** Replaces the formatted value on the right. */
  valueLabel?: ReactNode
  className?: string
}

/** One labelled horizontal bar. Stack several in a list for a distribution. */
export function BarRow({ label, value, max, tone, valueLabel, className }: BarRowProps) {
  const width = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0
  return (
    <div
      className={cn(
        'grid h-7 grid-cols-[minmax(0,7.5rem)_minmax(0,1fr)_2.5rem] items-center gap-3 text-dense',
        className,
      )}
    >
      <div className="flex min-w-0 items-center gap-2 text-foreground">
        {tone && <SeverityDot severity={tone} />}
        <span className="truncate">{label}</span>
      </div>
      <div data-tone={tone ?? 'clean'} className="h-2 rounded-sm bg-zinc-100" aria-hidden="true">
        {value > 0 && (
          <div
            className={cn('h-full min-w-0.5 rounded-sm', tone ? 'bg-tone-solid' : 'bg-zinc-400')}
            style={{ width: `${(width * 100).toFixed(2)}%` }}
          />
        )}
      </div>
      <div
        className={cn(
          'text-right font-medium tabular-nums',
          value === 0 ? 'text-muted-foreground' : 'text-foreground',
        )}
      >
        {valueLabel ?? formatCount(value)}
      </div>
    </div>
  )
}
