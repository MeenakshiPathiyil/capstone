import { Check, ChevronRight, Route } from 'lucide-react'
import { useMemo } from 'react'
import { Link } from 'react-router'

import type { Analysis } from '@/api/types'
import { ChainDiagram } from '@/components/ChainDiagram'
import { EmptyState } from '@/components/EmptyState'
import { LevelBadge } from '@/components/LevelBadge'
import { ScoreBar } from '@/components/ScoreBar'
import {
  chainNodes,
  groupPathsByChain,
  hopsLabel,
  pathDetailUrl,
  resourceIndex,
  selectedPathsText,
  topScore,
} from '@/lib/analysis'
import { formatCount, formatScore, pluralize } from '@/lib/format'

/** One grid for every row in every group, so columns line up down the page. */
const ROW_GRID =
  'grid grid-cols-[2rem_4.5rem_5.5rem_minmax(8rem,15rem)_4.5rem_minmax(0,1fr)_9.5rem_1rem] items-center gap-4'

export function PathsTab({ analysis }: { analysis: Analysis }) {
  const resources = useMemo(() => resourceIndex(analysis), [analysis])
  const groups = useMemo(() => groupPathsByChain(analysis.paths), [analysis.paths])
  const max = topScore(analysis.paths)

  if (analysis.paths.length === 0) {
    return (
      <EmptyState
        bordered
        icon={Route}
        title="No attack paths"
        description={
          analysis.summary.resources === 0
            ? 'The template declares no resources, so there is nothing to route through.'
            : 'No route leads from an entry point to an objective. The findings are still listed.'
        }
      />
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-dense text-muted-foreground">
        {pluralize(analysis.paths.length, 'path')} over {pluralize(groups.length, 'chain')}, ranked
        by score. {selectedPathsText(analysis.summary.paths_exported, analysis.min_level)} are
        exported for scenarios and the report.
      </p>

      <div className="overflow-clip rounded-lg border bg-surface">
        <div
          className={`${ROW_GRID} sticky top-12 z-10 h-9 border-b bg-zinc-50 px-4 text-xs font-medium text-muted-foreground`}
          aria-hidden="true"
        >
          <span className="text-right">#</span>
          <span>Path</span>
          <span>Level</span>
          <span>Score</span>
          <span
            className="text-center"
            title="Contextual risk, a second opinion. The list is ranked by score."
          >
            Contextual
          </span>
          <span>Objective</span>
          <span>Status</span>
          <span />
        </div>
        <ol aria-label="Attack paths by chain">
          {groups.map((group) => (
            <li key={group.group} className="border-b last:border-0">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2 bg-zinc-50/50 px-4 py-2.5">
                <ChainDiagram
                  size="compact"
                  nodes={chainNodes(group.hops, resources)}
                  aria-label={`Chain ${String(group.group)}`}
                  className="min-w-0"
                />
                <span className="ml-auto text-xs whitespace-nowrap text-muted-foreground tabular-nums">
                  {hopsLabel(group.hops.length - 1)} · {pluralize(group.paths.length, 'objective')}
                </span>
              </div>
              <ol>
                {group.paths.map((path) => (
                  <li key={path.source_id} className="border-t">
                    <Link
                      to={pathDetailUrl(analysis.id, path.source_id)}
                      aria-label={`${path.source_id}, ${path.attack_level}, ${path.objective_name}, score ${String(path.score)}${path.risk ? `, contextual risk ${formatScore(path.risk.score)}` : ''}`}
                      className={`${ROW_GRID} group h-10 px-4 text-dense hover:bg-zinc-50`}
                    >
                      <span className="text-right text-muted-foreground tabular-nums">
                        {formatCount(path.rank)}
                      </span>
                      <span className="font-mono text-xs font-medium text-foreground">
                        {path.source_id}
                      </span>
                      <span className="flex items-center">
                        <LevelBadge level={path.attack_level} />
                      </span>
                      <ScoreBar score={path.score} max={max} level={path.attack_level} />
                      <span className="text-center text-muted-foreground tabular-nums">
                        {formatScore(path.risk?.score)}
                      </span>
                      <span className="truncate text-foreground">{path.objective_name}</span>
                      <span className="flex items-center">
                        {path.exported ? (
                          <span className="inline-flex items-center gap-1 text-xs text-foreground">
                            <Check aria-hidden="true" className="size-3.5 text-muted-foreground" />
                            Exported
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">Below minimum level</span>
                        )}
                      </span>
                      <ChevronRight
                        aria-hidden="true"
                        className="size-4 text-faint transition-colors group-hover:text-foreground"
                      />
                    </Link>
                  </li>
                ))}
              </ol>
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}
