import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface SectionCardProps {
  title: ReactNode
  /** Id for the heading, so the section can be labelled by it. */
  titleId?: string
  /** Muted text after the title, such as a count or scope. */
  meta?: ReactNode
  /** Right side of the header: a link or a small button. */
  action?: ReactNode
  /** Drop the body padding when the content draws its own rows. */
  flush?: boolean
  className?: string
  bodyClassName?: string
  children: ReactNode
}

/** A bordered surface with a one-line header. The dashboard's basic block. */
export function SectionCard({
  title,
  titleId,
  meta,
  action,
  flush = false,
  className,
  bodyClassName,
  children,
}: SectionCardProps) {
  return (
    <section
      aria-labelledby={titleId}
      className={cn('flex min-w-0 flex-col rounded-lg border bg-surface', className)}
    >
      <header className="flex min-h-11 items-center gap-3 border-b px-4 py-2">
        <h2 id={titleId} className="text-sm font-semibold text-foreground">
          {title}
        </h2>
        {meta && <span className="truncate text-xs text-muted-foreground">{meta}</span>}
        {action && <div className="ml-auto flex shrink-0 items-center gap-2">{action}</div>}
      </header>
      <div className={cn(!flush && 'p-4', 'min-w-0 flex-1', bodyClassName)}>{children}</div>
    </section>
  )
}
