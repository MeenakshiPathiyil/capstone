import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: ReactNode
  /** A button or link that gets the user out of the empty state. */
  action?: ReactNode
  /** Draw its own bordered surface. Off when it sits inside a card already. */
  bordered?: boolean
  className?: string
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  bordered = false,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center px-6 py-12 text-center',
        bordered && 'rounded-lg border bg-surface',
        className,
      )}
    >
      {Icon && (
        <div className="mb-3 flex size-9 items-center justify-center rounded-lg border bg-surface text-muted-foreground">
          <Icon aria-hidden="true" className="size-4" />
        </div>
      )}
      <p className="text-sm font-semibold text-foreground">{title}</p>
      {description && (
        <p className="mt-1 max-w-sm text-dense text-pretty text-muted-foreground">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
