import { cn } from '@/lib/utils'
import { formatScore } from '@/lib/format'
import { levelTone, type AttackLevel, type Tone } from '@/lib/severity'

interface ScoreBarProps {
  score: number
  /** The bar's full width. Usually the top score in the list. */
  max: number
  /** Colours the bar by attack level. */
  level?: AttackLevel
  /** Colours the bar by an explicit tone; wins over level. */
  tone?: Tone
  /** Scores to mark with a tick under the track, such as the HIGH and CRITICAL thresholds. */
  markers?: readonly number[]
  /** Hide the number when a neighbouring cell already shows it. */
  showValue?: boolean
  className?: string
  'aria-label'?: string
}

export function ScoreBar({
  score,
  max,
  level,
  tone,
  markers = [],
  showValue = true,
  className,
  'aria-label': ariaLabel = 'Risk score',
}: ScoreBarProps) {
  const resolved: Tone = tone ?? (level ? levelTone(level) : 'clean')
  const scale = max > 0 ? max : 1
  const width = Math.max(0, Math.min(1, score / scale))
  return (
    <div className={cn('flex min-w-0 items-center gap-2.5', className)}>
      <div
        role="meter"
        aria-label={ariaLabel}
        aria-valuemin={0}
        aria-valuemax={scale}
        aria-valuenow={score}
        aria-valuetext={formatScore(score)}
        data-tone={resolved}
        className="relative h-1.5 min-w-12 flex-1 rounded-full bg-zinc-100"
      >
        <div
          className="h-full rounded-full bg-tone-solid"
          style={{ width: `${(width * 100).toFixed(2)}%` }}
        />
        {markers
          .filter((m) => m > 0 && m < scale)
          .map((m) => (
            <span
              key={m}
              aria-hidden="true"
              className="absolute top-full mt-0.5 h-1 w-px bg-zinc-400"
              style={{ left: `${((m / scale) * 100).toFixed(2)}%` }}
            />
          ))}
      </div>
      {showValue && (
        <span className="w-11 shrink-0 text-right text-dense font-medium text-foreground tabular-nums">
          {formatScore(score)}
        </span>
      )}
    </div>
  )
}
