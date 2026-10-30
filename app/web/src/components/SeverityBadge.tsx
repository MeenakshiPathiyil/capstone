import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'
import { severityLabel, type Tone } from '@/lib/severity'

interface SeverityDotProps {
  severity: Tone
  className?: string
}

/** An 8px dot in the severity's fill, ringed in its stroke so it reads on white. */
export function SeverityDot({ severity, className }: SeverityDotProps) {
  return (
    <span
      data-tone={severity}
      aria-hidden="true"
      className={cn(
        'inline-block size-2 shrink-0 rounded-full bg-tone-solid ring-1 ring-tone-stroke/25 ring-inset',
        className,
      )}
    />
  )
}

interface SeverityBadgeProps {
  severity: Tone
  /**
   * soft: a tinted chip, for cards and headers.
   * dot: a dot and a neutral label, for dense tables where many rows repeat it.
   */
  variant?: 'soft' | 'dot'
  /** Overrides the label, for example with a count: "Critical 3". */
  children?: ReactNode
  className?: string
}

export function SeverityBadge({
  severity,
  variant = 'soft',
  children,
  className,
}: SeverityBadgeProps) {
  const label = children ?? severityLabel(severity)
  if (variant === 'dot') {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 text-dense whitespace-nowrap text-foreground',
          className,
        )}
      >
        <SeverityDot severity={severity} />
        {label}
      </span>
    )
  }
  return (
    <span
      data-tone={severity}
      className={cn(
        'inline-flex h-5 items-center gap-1.5 rounded-sm border border-tone-line/30 bg-tone-tint px-1.5 text-xs font-medium whitespace-nowrap text-tone-stroke tabular-nums',
        className,
      )}
    >
      <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-tone-solid" />
      {label}
    </span>
  )
}
