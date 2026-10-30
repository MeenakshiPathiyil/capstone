import { ArrowRight, Info, X } from 'lucide-react'
import { Link } from 'react-router'

import type { GraphViewKind } from '@/api/graph'
import type { Path } from '@/api/types'
import { LevelBadge } from '@/components/LevelBadge'
import { Button } from '@/components/ui/button'
import { formatScore, pluralize, sentenceCase } from '@/lib/format'
import { cn } from '@/lib/utils'

import type { PathHighlight } from './highlight'
import { PANEL_WIDTH } from './viewport'

interface PathInspectorProps {
  analysisId: string
  path: Path
  highlight: PathHighlight | null
  view: GraphViewKind
  onClose: () => void
  /** Hovering a step lights up its edges on the canvas. */
  onHoverEdges: (keys: readonly string[]) => void
  /** Clicking a step brings its edge into view. */
  onFocusStep: (index: number) => void
  className?: string
}

/** The selected path beside the canvas: what it is, and its steps in order. */
export function PathInspector({
  analysisId,
  path,
  highlight,
  view,
  onClose,
  onHoverEdges,
  onFocusStep,
  className,
}: PathInspectorProps) {
  const mapped = highlight?.mapped === true
  return (
    <aside
      aria-label={`Path ${path.source_id}`}
      style={{ width: PANEL_WIDTH }}
      className={cn(
        'flex shrink-0 flex-col border-l bg-surface shadow-[-12px_0_24px_-20px_rgb(24_24_27/0.25)]',
        className,
      )}
    >
      <div className="flex items-start gap-2 border-b px-4 pt-3.5 pb-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold tabular-nums">{path.source_id}</span>
            <LevelBadge level={path.attack_level} />
            <span className="text-xs text-muted-foreground tabular-nums">
              score {formatScore(path.score)}
            </span>
          </div>
          <p className="mt-1 text-dense font-medium text-foreground">{path.objective_name}</p>
          <p className="mt-0.5 flex min-w-0 items-center gap-1 font-mono text-2xs text-muted-foreground">
            <span className="truncate" title={path.entry_id}>
              {path.entry_id}
            </span>
            <ArrowRight aria-hidden="true" className="size-3 shrink-0" />
            <span className="truncate" title={path.target_id}>
              {path.target_id}
            </span>
          </p>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Clear the highlighted path"
          title="Clear the highlighted path"
          onClick={onClose}
          className="-mt-0.5 -mr-1.5 text-muted-foreground"
        >
          <X />
        </Button>
      </div>

      {!mapped && (
        <div
          data-tone="medium"
          className="mx-3 mt-3 flex gap-2 rounded-md border border-tone-line/30 bg-tone-tint/60 px-2.5 py-2 text-xs text-foreground"
        >
          <Info aria-hidden="true" className="mt-px size-3.5 shrink-0 text-tone-stroke" />
          <span>
            {view === 'attack'
              ? 'This path could not be matched to exact attack moves, so it is not drawn here. The Resources view shows its hops.'
              : 'This path is not drawn in this view.'}
          </span>
        </div>
      )}

      <div className="flex items-center justify-between px-4 pt-3 pb-1.5">
        <h3 className="text-2xs font-medium tracking-[0.06em] text-muted-foreground uppercase">
          Steps
        </h3>
        <span className="text-2xs text-muted-foreground tabular-nums">
          {pluralize(path.steps.length, 'step')}
        </span>
      </div>
      <ol className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {path.steps.map((step, index) => {
          const keys = highlight?.edgesByStep[index] ?? []
          const drawn = mapped && keys.length > 0
          return (
            <li key={index}>
              <button
                type="button"
                disabled={!drawn}
                onPointerEnter={() => onHoverEdges(drawn ? keys : [])}
                onPointerLeave={() => onHoverEdges([])}
                onFocus={() => onHoverEdges(drawn ? keys : [])}
                onBlur={() => onHoverEdges([])}
                onClick={() => onFocusStep(index)}
                className={cn(
                  'flex w-full gap-2.5 rounded-md px-2 py-2 text-left transition-colors',
                  drawn ? 'cursor-pointer hover:bg-subtle' : 'cursor-default',
                )}
              >
                <span
                  className={cn(
                    'mt-px flex size-4 shrink-0 items-center justify-center rounded-full font-mono text-[10px] leading-none font-medium tabular-nums',
                    drawn ? 'bg-(--emphasis) text-white' : 'bg-subtle text-muted-foreground',
                  )}
                >
                  {index + 1}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-dense leading-snug text-foreground">
                    {step.action || sentenceCase(step.category ?? 'step')}
                  </span>
                  <span className="mt-0.5 flex min-w-0 items-center gap-1 font-mono text-2xs text-muted-foreground">
                    <span className="truncate" title={step.source}>
                      {step.source}
                    </span>
                    <ArrowRight aria-hidden="true" className="size-3 shrink-0" />
                    <span className="truncate" title={step.target}>
                      {step.target}
                    </span>
                  </span>
                  {(step.tactic ?? step.technique) && (
                    <span className="mt-0.5 block text-2xs text-faint">
                      {[step.tactic ? sentenceCase(step.tactic) : null, step.technique]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  )}
                </span>
              </button>
            </li>
          )
        })}
      </ol>

      <div className="border-t px-4 py-2.5">
        <Button asChild variant="outline" size="sm" className="w-full">
          <Link
            to={`/analysis/${encodeURIComponent(analysisId)}/paths/${encodeURIComponent(path.source_id)}`}
          >
            Open path details
            <ArrowRight />
          </Link>
        </Button>
      </div>
    </aside>
  )
}
