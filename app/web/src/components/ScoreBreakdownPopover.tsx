import { Info } from 'lucide-react'

import type { Path } from '@/api/types'
import { LevelBadge } from '@/components/LevelBadge'
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  hopsLabel,
  lengthFactorText,
  levelBandsText,
  scoreFormula,
  scoreFormulaTemplate,
  severityWeightsText,
} from '@/lib/analysis'
import { formatFactor, formatScore } from '@/lib/format'

/** The path's score, as a button that opens how it was computed. */
export function ScoreBreakdownPopover({ path }: { path: Path }) {
  const b = path.breakdown
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="group flex cursor-pointer flex-col items-end rounded-md px-2 py-1 text-right hover:bg-subtle aria-expanded:bg-subtle"
          aria-label={`Score ${formatScore(path.score)}. Show the breakdown`}
        >
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            Risk score
            <Info aria-hidden="true" className="size-3 group-hover:text-foreground" />
          </span>
          <span className="text-2xl font-semibold text-foreground tabular-nums">
            {formatScore(path.score)}
          </span>
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 gap-3 p-4">
        <PopoverHeader>
          <div className="flex items-center justify-between gap-3">
            <PopoverTitle className="tabular-nums">Score {formatScore(b.score)}</PopoverTitle>
            <LevelBadge level={path.attack_level} />
          </div>
          <PopoverDescription>How {path.source_id} was scored</PopoverDescription>
        </PopoverHeader>
        <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1.5 text-dense tabular-nums">
          <dt className="text-muted-foreground">
            Finding weights
            <span className="block text-2xs">Distinct findings on the path, by severity</span>
          </dt>
          <dd className="text-right">{formatFactor(b.severity_total)}</dd>
          <dt className="text-muted-foreground">
            Objective weight
            <span className="block text-2xs">{path.objective_name}</span>
          </dt>
          <dd className="text-right">+ {formatFactor(b.objective_weight)}</dd>
          <dt className="text-muted-foreground">
            Length factor
            <span className="block text-2xs">
              {hopsLabel(b.hops)}, <WithExponents text={lengthFactorText(b)} />
            </span>
          </dt>
          <dd className="text-right">× {formatFactor(b.length_factor)}</dd>
          <dt className="text-muted-foreground">
            Entry boost
            <span className="block text-2xs">
              {b.public_entry ? 'Public entry point' : 'Not a public entry, no boost'}
            </span>
          </dt>
          <dd className="text-right">{b.public_entry ? `× ${formatFactor(b.boost)}` : '× 1'}</dd>
          <dt className="border-t pt-1.5 font-medium text-foreground">Score</dt>
          <dd className="border-t pt-1.5 text-right font-medium text-foreground">
            {formatScore(b.score)}
          </dd>
        </dl>
        <div className="flex flex-col gap-1 rounded-md border bg-zinc-50 px-3 py-2">
          <p className="font-mono text-xs text-foreground">
            <WithExponents text={scoreFormula(b)} />
          </p>
          <p className="text-2xs text-pretty text-muted-foreground">
            <WithExponents text={scoreFormulaTemplate(b)} />
          </p>
        </div>
        <p className="text-xs text-muted-foreground">
          Finding weights: {severityWeightsText()}. {levelBandsText(b)}
        </p>
      </PopoverContent>
    </Popover>
  )
}

/** "0.85^3" and "0.85^(hops - 1)" with the exponent raised. */
export function WithExponents({ text }: { text: string }) {
  return text.split(/\^(\([^)]*\)|\d+)/).map((part, index) =>
    index % 2 === 1 ? (
      <sup key={index} className="text-[0.75em]">
        {part.replace(/^\((.*)\)$/, '$1')}
      </sup>
    ) : (
      part
    ),
  )
}
