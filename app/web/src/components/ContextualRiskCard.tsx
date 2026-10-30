import { Info } from 'lucide-react'

import type { Path, PathRisk } from '@/api/types'
import { ScoreBar } from '@/components/ScoreBar'
import { WithExponents } from '@/components/ScoreBreakdownPopover'
import { SectionCard } from '@/components/SectionCard'
import { Button } from '@/components/ui/button'
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  contextualFormula,
  contextualFormulaTemplate,
  contextualRankText,
  contextualTieText,
  reachabilityDetail,
  reachabilityLabel,
  riskMetadata,
} from '@/lib/analysis'
import { formatScore } from '@/lib/format'

const COMPONENTS = [
  { key: 'impact', label: 'Impact' },
  { key: 'exposure', label: 'Exposure' },
  { key: 'path_ease', label: 'Path ease' },
] as const

/**
 * The contextual risk model's second opinion on a path. Renders nothing for an
 * analysis saved before the model existed.
 */
export function ContextualRiskCard({
  path,
  paths,
}: {
  path: Path
  /** Every path in the analysis, for the rank count and ties. */
  paths: readonly Path[]
}) {
  const risk = path.risk
  if (!risk) return null
  const tie = contextualTieText(risk, paths)

  return (
    <SectionCard
      title="Contextual risk"
      titleId="contextual-risk"
      meta="Second opinion"
      action={<ContextualRiskPopover sourceId={path.source_id} risk={risk} />}
    >
      <p className="text-2xl font-semibold text-foreground tabular-nums">
        {formatScore(risk.score)}
      </p>
      <p className="text-xs text-muted-foreground tabular-nums">
        {contextualRankText(risk, paths)}
        {tie && `, ${tie}`}
      </p>

      <div className="mt-3 grid grid-cols-[4.5rem_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5">
        {COMPONENTS.map(({ key, label }) => (
          <div key={key} className="contents">
            <span className="text-dense text-muted-foreground">{label}</span>
            <ScoreBar score={risk[key]} max={100} tone="clean" aria-label={label} />
          </div>
        ))}
      </div>

      <dl className="mt-3 grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1.5 border-t pt-3 text-dense">
        <dt className="text-muted-foreground">Reachability</dt>
        <dd className="text-right text-foreground">{reachabilityLabel(risk.reachability)}</dd>
        {riskMetadata(risk).map(({ label, value }) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className={value ? 'text-right text-foreground' : 'text-right text-faint'}>
              {value ?? 'Not tagged'}
            </dd>
          </div>
        ))}
      </dl>

      <p className="mt-3 border-t pt-3 text-xs text-muted-foreground">
        Weights are provisional and not calibrated.
      </p>
    </SectionCard>
  )
}

/** How the contextual score was computed, mirroring the risk score's breakdown popover. */
function ContextualRiskPopover({ sourceId, risk }: { sourceId: string; risk: PathRisk }) {
  const reached = `${reachabilityLabel(risk.reachability)}: ${reachabilityDetail(risk.reachability)}`
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon-xs"
          className="text-muted-foreground aria-expanded:bg-subtle"
          aria-label="How contextual risk is computed"
        >
          <Info aria-hidden="true" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 gap-3 p-4">
        <PopoverHeader>
          <PopoverTitle className="tabular-nums">
            Contextual risk {formatScore(risk.score)}
          </PopoverTitle>
          <PopoverDescription>How {sourceId} was scored by the second model</PopoverDescription>
        </PopoverHeader>
        <p className="text-dense text-pretty text-muted-foreground">
          Impact is how much the target matters, from its tags and how many resources it reaches.
          Exposure is how the target is reached ({reached}). Path ease falls with each hop.
        </p>
        <div className="flex flex-col gap-1 rounded-md border bg-zinc-50 px-3 py-2">
          <p className="font-mono text-xs text-foreground">
            <WithExponents text={contextualFormula(risk)} />
          </p>
          <p className="text-2xs text-pretty text-muted-foreground">
            <WithExponents text={contextualFormulaTemplate()} />
          </p>
        </div>
        <p className="text-xs text-muted-foreground">
          The weights are provisional and not calibrated. Equal scores share a rank. The risk score,
          level and ranking do not use this model.
        </p>
      </PopoverContent>
    </Popover>
  )
}
