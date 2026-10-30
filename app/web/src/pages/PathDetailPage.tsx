import { ChevronLeft, ChevronRight, Network, Route } from 'lucide-react'
import { useMemo, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'

import { useAnalysis } from '@/api/hooks'
import type { Analysis, Finding, Path } from '@/api/types'
import { AppShell, Container } from '@/components/AppShell'
import { ChainDiagram } from '@/components/ChainDiagram'
import { ContextualRiskCard } from '@/components/ContextualRiskCard'
import { EmptyState } from '@/components/EmptyState'
import { LevelBadge } from '@/components/LevelBadge'
import { ResourceSheet } from '@/components/ResourceSheet'
import { ScenarioPanel } from '@/components/ScenarioPanel'
import { ScoreBreakdownPopover } from '@/components/ScoreBreakdownPopover'
import { SectionCard } from '@/components/SectionCard'
import { SeverityDot } from '@/components/SeverityBadge'
import { CardListSkeleton } from '@/components/Skeletons'
import { StepTimeline } from '@/components/StepTimeline'
import { TechniqueChip } from '@/components/TechniqueChip'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useResourceParam } from '@/hooks/useResourceParam'
import {
  chainNodes,
  graphUrl,
  hopsLabel,
  pathDetailUrl,
  resourceIndex,
  stepTechnique,
  techniqueNames,
} from '@/lib/analysis'
import { formatCount, pluralize } from '@/lib/format'
import { compareSeverity, levelLabel } from '@/lib/severity'

import { AnalysisLoadError, NewAnalysisButton } from './AnalysisPage'

/** /analysis/:id/paths/:sourceId[?resource=<id>] */
export function PathDetailPage() {
  const { id = '', sourceId = '' } = useParams()
  const analysis = useAnalysis(id)

  let body: ReactNode
  if (analysis.isPending) {
    body = <PathDetailLoading sourceId={sourceId} />
  } else if (analysis.isError) {
    body = (
      <Container className="py-16">
        <AnalysisLoadError
          error={analysis.error}
          onRetry={() => void analysis.refetch()}
          retrying={analysis.isFetching}
        />
      </Container>
    )
  } else {
    const path = analysis.data.paths.find((p) => p.source_id === sourceId)
    body = path ? (
      <>
        <PathDetail analysis={analysis.data} path={path} />
        <ResourceSheet analysis={analysis.data} />
      </>
    ) : (
      <>
        <PathHeaderBand analysis={analysis.data} sourceId={sourceId} />
        <Container className="py-6">
          <EmptyState
            bordered
            icon={Route}
            title={`${sourceId} is not in this analysis`}
            description={`This analysis has ${pluralize(analysis.data.paths.length, 'path')}. Path ids follow the overall ranking, so they can differ between analyses.`}
            action={
              <Button asChild variant="outline" size="sm">
                <Link to={`/analysis/${encodeURIComponent(id)}?tab=paths`}>All paths</Link>
              </Button>
            }
          />
        </Container>
      </>
    )
  }

  return <AppShell headerActions={<NewAnalysisButton />}>{body}</AppShell>
}

function Breadcrumb({ analysis, sourceId }: { analysis: Analysis | null; sourceId: string }) {
  const base = analysis ? `/analysis/${encodeURIComponent(analysis.id)}` : null
  return (
    <nav aria-label="Breadcrumb">
      <ol className="flex min-w-0 items-center gap-1 text-dense text-muted-foreground">
        <li className="min-w-0">
          {base && analysis ? (
            <Link to={base} className="block truncate rounded-sm hover:text-foreground">
              {analysis.input_name}
            </Link>
          ) : (
            <Skeleton className="h-3.5 w-28" />
          )}
        </li>
        <li aria-hidden="true">
          <ChevronRight className="size-3.5" />
        </li>
        <li>
          {base ? (
            <Link to={`${base}?tab=paths`} className="rounded-sm hover:text-foreground">
              Paths
            </Link>
          ) : (
            'Paths'
          )}
        </li>
        <li aria-hidden="true">
          <ChevronRight className="size-3.5" />
        </li>
        <li aria-current="page" className="font-mono text-xs text-foreground">
          {sourceId}
        </li>
      </ol>
    </nav>
  )
}

function PathHeaderBand({
  analysis,
  sourceId,
  children,
}: {
  analysis: Analysis | null
  sourceId: string
  children?: ReactNode
}) {
  return (
    <div className="border-b bg-surface">
      <Container className="flex flex-col gap-3 pt-5 pb-5">
        <Breadcrumb analysis={analysis} sourceId={sourceId} />
        {children}
      </Container>
    </div>
  )
}

function PathDetail({ analysis, path }: { analysis: Analysis; path: Path }) {
  const { openResource } = useResourceParam()
  const resources = useMemo(() => resourceIndex(analysis), [analysis])
  const names = useMemo(() => techniqueNames(analysis), [analysis])
  const ranked = useMemo(
    () => [...analysis.paths].sort((a, b) => a.rank - b.rank),
    [analysis.paths],
  )
  const position = ranked.findIndex((p) => p.source_id === path.source_id)
  const previous = ranked[position - 1]
  const next = ranked[position + 1]
  const edgeLabels = path.steps.map((step) => stepTechnique(step, names)?.id ?? null)

  return (
    <>
      <PathHeaderBand analysis={analysis} sourceId={path.source_id}>
        <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h1 className="font-mono text-xl font-semibold text-foreground">{path.source_id}</h1>
              <LevelBadge level={path.attack_level} />
              <span className="text-lg font-medium text-foreground">{path.objective_name}</span>
            </div>
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-dense text-muted-foreground">
              <span className="tabular-nums">
                Rank {formatCount(path.rank)} of {formatCount(analysis.paths.length)}
              </span>
              <Dot />
              <span>{hopsLabel(path.length)}</span>
              <Dot />
              <span>{path.public_entry ? 'Public entry' : 'Internal entry'}</span>
              <Dot />
              {path.exported ? (
                <span>
                  Exported, at or above{' '}
                  <span className="text-foreground">{levelLabel(analysis.min_level)}</span>
                </span>
              ) : (
                <span>Below the minimum level ({levelLabel(analysis.min_level)})</span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <ScoreBreakdownPopover path={path} />
            <span aria-hidden="true" className="h-10 w-px bg-border" />
            <Button asChild variant="outline">
              <Link to={graphUrl(analysis.id, path.source_id)}>
                <Network />
                View on graph
              </Link>
            </Button>
            <div className="flex items-center">
              <PagerButton analysisId={analysis.id} path={previous} direction="previous" />
              <PagerButton analysisId={analysis.id} path={next} direction="next" />
            </div>
          </div>
        </div>
      </PathHeaderBand>

      <Container className="flex flex-col gap-6 py-6">
        <SectionCard
          title="Chain"
          titleId="chain"
          meta={`${pluralize(path.hops.length, 'resource')}. Select one for its findings and attributes.`}
        >
          <ChainDiagram
            nodes={chainNodes(path.hops, resources)}
            edgeLabels={edgeLabels}
            onNodeSelect={openResource}
            aria-label={`${path.source_id} chain`}
          />
        </SectionCard>

        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
          <SectionCard title="Steps" titleId="steps" meta={pluralize(path.steps.length, 'step')}>
            {path.steps.length > 0 ? (
              <StepTimeline
                steps={path.steps}
                techniqueNames={names}
                onResourceSelect={openResource}
              />
            ) : (
              <p className="text-dense text-muted-foreground">This path has no recorded steps.</p>
            )}
          </SectionCard>
          <div className="flex min-w-0 flex-col gap-6">
            <PathFindings analysis={analysis} path={path} onSelect={openResource} />
            <ObjectiveCard path={path} names={names} />
            <ContextualRiskCard path={path} paths={analysis.paths} />
          </div>
        </div>

        {/* Keyed by path: Next and Previous reuse this component, and the panel's mutation state must not follow. */}
        <ScenarioPanel
          key={path.source_id}
          analysisId={analysis.id}
          sourceId={path.source_id}
          exported={path.exported}
        />
      </Container>
    </>
  )
}

function Dot() {
  return (
    <span aria-hidden="true" className="text-faint">
      ·
    </span>
  )
}

function PagerButton({
  analysisId,
  path,
  direction,
}: {
  analysisId: string
  path: Path | undefined
  direction: 'previous' | 'next'
}) {
  const Icon = direction === 'previous' ? ChevronLeft : ChevronRight
  const label = path
    ? `${direction === 'previous' ? 'Previous' : 'Next'} path, ${path.source_id}`
    : `No ${direction} path`
  const shape = direction === 'previous' ? 'rounded-r-none' : 'rounded-l-none -ml-px'
  if (!path) {
    return (
      <Button variant="outline" size="icon" className={shape} disabled aria-label={label}>
        <Icon />
      </Button>
    )
  }
  return (
    <Button asChild variant="outline" size="icon" className={shape}>
      <Link to={pathDetailUrl(analysisId, path.source_id)} aria-label={label} title={label}>
        <Icon />
      </Link>
    </Button>
  )
}

function PathFindings({
  analysis,
  path,
  onSelect,
}: {
  analysis: Analysis
  path: Path
  onSelect: (resourceId: string) => void
}) {
  const findings = useMemo(() => {
    const byId = new Map(analysis.findings.map((f) => [f.id, f]))
    const hopOrder = new Map(path.hops.map((hop, index) => [hop, index]))
    return path.finding_ids
      .map((id) => byId.get(id))
      .filter((f): f is Finding => f !== undefined)
      .sort(
        (a, b) =>
          (hopOrder.get(a.resource) ?? 0) - (hopOrder.get(b.resource) ?? 0) ||
          compareSeverity(a.severity, b.severity),
      )
  }, [analysis.findings, path])

  return (
    <SectionCard
      title="Findings on this path"
      titleId="path-findings"
      meta={formatCount(findings.length)}
      flush
    >
      {findings.length === 0 ? (
        <p className="px-4 py-3 text-dense text-muted-foreground">No findings are on this path.</p>
      ) : (
        <ul className="divide-y">
          {findings.map((finding) => (
            <li key={finding.id}>
              <button
                type="button"
                onClick={() => onSelect(finding.resource)}
                className="flex w-full cursor-pointer items-start gap-2.5 px-4 py-2.5 text-left hover:bg-zinc-50"
              >
                <SeverityDot severity={finding.severity} className="mt-1.5" />
                <span className="flex min-w-0 flex-col">
                  <span className="text-dense text-foreground">{finding.rule.display_name}</span>
                  <span className="truncate font-mono text-2xs text-muted-foreground">
                    {finding.resource}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  )
}

function ObjectiveCard({ path, names }: { path: Path; names: ReadonlyMap<string, string> }) {
  return (
    <SectionCard title="Objective" titleId="objective">
      <p className="text-sm font-medium text-foreground">{path.objective_name}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">
        Reached at <span className="font-mono text-foreground">{path.target_id}</span>
      </p>
      {path.objective_techniques.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {path.objective_techniques.map((id) => (
            <TechniqueChip key={id} id={id} name={names.get(id)} />
          ))}
        </div>
      )}
      {path.exported && (
        <div className="mt-3 border-t pt-3">
          <Badge variant="secondary">Exported</Badge>
          <span className="ml-2 text-xs text-muted-foreground">In the report and scenarios</span>
        </div>
      )}
    </SectionCard>
  )
}

function PathDetailLoading({ sourceId }: { sourceId: string }) {
  return (
    <>
      <PathHeaderBand analysis={null} sourceId={sourceId}>
        <div role="status" aria-live="polite" className="flex items-end justify-between gap-6">
          <span className="sr-only">Loading path</span>
          <div className="flex flex-col gap-2">
            <Skeleton className="h-6 w-72" />
            <Skeleton className="h-3.5 w-96" />
          </div>
          <Skeleton className="h-10 w-48" />
        </div>
      </PathHeaderBand>
      <Container className="flex flex-col gap-6 py-6">
        <Skeleton className="h-28 rounded-lg" />
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
          <CardListSkeleton count={3} />
          <Skeleton className="h-64 rounded-lg" />
        </div>
      </Container>
    </>
  )
}
