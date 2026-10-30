import { cn } from '@/lib/utils'
import { attackTechniqueUrl, safeHttpUrl } from '@/lib/format'

interface TechniqueChipProps {
  /** ATT&CK technique id, for example T1552.005. */
  id: string
  /** The technique's name, shown as the tooltip and to screen readers. */
  name?: string
  className?: string
}

/** A technique id as a mono chip linking to MITRE ATT&CK. Ids that are not technique ids render as plain chips. */
export function TechniqueChip({ id, name, className }: TechniqueChipProps) {
  const url = safeHttpUrl(attackTechniqueUrl(id))
  const classes = cn(
    'inline-flex h-5 items-center rounded-sm border bg-surface px-1.5 font-mono text-2xs font-medium whitespace-nowrap text-foreground',
    url && 'transition-colors hover:border-border-strong hover:bg-subtle',
    className,
  )
  if (!url) {
    return (
      <span className={classes} title={name}>
        {id}
      </span>
    )
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className={classes}
      title={name ? `${id} ${name}` : id}
      aria-label={
        name
          ? `${id} ${name} (MITRE ATT&CK, opens in a new tab)`
          : `${id} (MITRE ATT&CK, opens in a new tab)`
      }
    >
      {id}
    </a>
  )
}
