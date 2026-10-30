import { CircleAlert, RotateCw } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface ErrorStateProps {
  title?: string
  /** The API's detail message, shown as written. */
  message: string
  onRetry?: () => void
  retrying?: boolean
  /** The retry button's label. */
  retryLabel?: string
  /** inline: one compact row, for a failed card or section. */
  variant?: 'block' | 'inline'
  className?: string
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
  retrying = false,
  retryLabel = 'Try again',
  variant = 'block',
  className,
}: ErrorStateProps) {
  const retry = onRetry && (
    <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying}>
      <RotateCw className={cn(retrying && 'animate-spin')} />
      {retrying ? 'Retrying' : retryLabel}
    </Button>
  )

  if (variant === 'inline') {
    return (
      <div
        role="alert"
        data-tone="critical"
        className={cn(
          'flex items-start gap-3 rounded-lg border border-tone-line/30 bg-tone-tint/50 px-3 py-2.5',
          className,
        )}
      >
        <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-tone-stroke" />
        <div className="min-w-0 flex-1 text-dense">
          <p className="font-medium text-tone-stroke">{title}</p>
          <p className="mt-0.5 [overflow-wrap:anywhere] text-foreground">{message}</p>
        </div>
        {retry}
      </div>
    )
  }

  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center rounded-lg border bg-surface px-6 py-12 text-center',
        className,
      )}
    >
      <div
        data-tone="critical"
        className="mb-3 flex size-9 items-center justify-center rounded-lg border border-tone-line/30 bg-tone-tint text-tone-stroke"
      >
        <CircleAlert aria-hidden="true" className="size-4" />
      </div>
      <p className="text-sm font-semibold text-foreground">{title}</p>
      <p className="mt-1 max-w-md text-dense text-pretty [overflow-wrap:anywhere] text-muted-foreground">
        {message}
      </p>
      {retry && <div className="mt-4">{retry}</div>}
    </div>
  )
}
