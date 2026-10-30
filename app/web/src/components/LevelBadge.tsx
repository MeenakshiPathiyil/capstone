import { cn } from '@/lib/utils'
import { levelLabel, levelTone, type AttackLevel } from '@/lib/severity'

interface LevelBadgeProps {
  level: AttackLevel
  className?: string
}

/**
 * A path's attack level. Deliberately a different shape from SeverityBadge:
 * solid fill, upper case, no dot. Severity belongs to a finding, level to a path.
 */
export function LevelBadge({ level, className }: LevelBadgeProps) {
  return (
    <span
      data-tone={levelTone(level)}
      title={`${levelLabel(level)} attack level`}
      className={cn(
        'inline-flex h-5 items-center rounded-sm bg-tone-fill px-1.5 text-2xs font-semibold tracking-[0.04em] whitespace-nowrap text-tone-stroke uppercase',
        className,
      )}
    >
      {level}
    </span>
  )
}
