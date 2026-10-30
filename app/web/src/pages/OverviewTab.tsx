import { ArrowRight, Boxes, ChevronRight, CircleAlert, Info, RotateCw, Route } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'

import { busyKeys, RETRYING_TEXT, useRetrying } from '@/api/busy'
import { useFixImpact } from '@/api/hooks'
import type { Analysis, Finding, FixImpact, FixImpactResult, Path } from '@/api/types'
import { BarRow } from '@/components/BarRow'
import { ChainDiagram } from '@/components/ChainDiagram'
import { EmptyState } from '@/components/EmptyState'
import { LevelBadge } from '@/components/LevelBadge'
import { ScoreBar } from '@/components/ScoreBar'
import { SectionCard } from '@/components/SectionCard'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Spinner } from '@/components/Spinner'
import { StatTile } from '@/components/StatTile'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useResourceParam } from '@/hooks/useResourceParam'
import {
  chainNodes,
  effectiveFixes,
  fixAddedText,
  fixRemovedText,
  fixScopeText,
  FIX_SUPPRESSION_NOTE,
  pathDetailUrl,
  resourceIndex,
  selectedPathsText,
  topScore,
  warningTitle,
} from '@/lib/analysis'
import { formatCount, formatDateTime, formatScore, pluralize } from '@/lib/format'
import {
  ATTACK_LEVELS,
  levelLabel,
  levelTone,
  SEVERITIES,
  severityLabel,
  type AttackLevel,
} from '@/lib/severity'

const TOP_PATHS = 5
const FIX_SCOPE = 5
const FIXES_SHOWN = 3

export function OverviewTab({ analysis }: { analysis: Analysis }) {
  const { summary } = analysis

  if (summary.resources === 0) {
    return (
      <div className="flex flex-col gap-6">
        <SummaryTiles analysis={analysis} />
        <EmptyState
          bordered
          icon={Boxes}
          title="This template declares no resources"
          description="It parsed, but there is nothing to analyse: no findings, no entry points and no attack paths. Upload a template with resources to see results."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/">New analysis</Link>
            </Button>
          }
        />
        <SideNotices analysis={analysis} />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <SummaryTiles analysis={analysis} />
      <Distributions analysis={analysis} />
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <TopPaths analysis={analysis} />
        <div className="flex min-w-0 flex-col gap-6">
          <TopFixes analysis={analysis} />
          <SideNotices analysis={analysis} />
        </div>
      </div>
    </div>
  )
}

// -- Summary ------------------------------------------------------------------------------

function SummaryTiles({ analysis }: { analysis: Analysis }) {
  const { summary } = analysis
  const best = analysis.paths.reduce<Path | null>(
    (top, path) => (top === null || path.rank < top.rank ? path : top),
    null,
  )
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
      <StatTile
        label="Resources"
        value={formatCount(summary.resources)}
        hint={pluralize(summary.edges, 'dependency edge')}
      />
      <StatTile
        label="Findings"
        value={formatCount(summary.findings)}
        hint={findingsHint(summary.findings_by_severity)}
      />
      <StatTile
        label="Attack paths"
        value={formatCount(summary.paths)}
        hint={selectedPathsText(summary.paths_exported, analysis.min_level)}
      />
      <StatTile
        label="Entry points"
        value={formatCount(summary.entry_points)}
        hint="Reachable from outside"
      />
      <StatTile
        label="Top score"
        value={formatScore(summary.top_score)}
        tone={best ? levelTone(best.attack_level) : undefined}
        hint={best ? `${best.source_id}, ${levelLabel(best.attack_level)}` : 'No paths'}
      />
    </div>
  )
}

/** "6 critical, 12 high": the two most severe non-zero counts. */
function findingsHint(bySeverity: Record<string, number>): string {
  const parts = SEVERITIES.filter((s) => (bySeverity[s] ?? 0) > 0)
    .slice(0, 2)
    .map((s) => `${formatCount(bySeverity[s] ?? 0)} ${s}`)
  return parts.length > 0 ? parts.join(', ') : 'No rule flagged a resource'
}

function Distributions({ analysis }: { analysis: Analysis }) {
  const { summary } = analysis
  // Unknown is listed only when something is unknown.
  const severities = SEVERITIES.filter(
    (s) => s !== 'unknown' || (summary.findings_by_severity[s] ?? 0) > 0,
  )
  const findingMax = Math.max(0, ...severities.map((s) => summary.findings_by_severity[s] ?? 0))
  const levelMax = Math.max(0, ...ATTACK_LEVELS.map((l) => summary.paths_by_level[l] ?? 0))
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <SectionCard
        title="Findings by severity"
        titleId="findings-by-severity"
        meta={pluralize(summary.findings, 'finding')}
        action={<TabLink tab="findings">View findings</TabLink>}
        bodyClassName="py-3"
      >
        {severities.map((s) => (
          <BarRow
            key={s}
            label={severityLabel(s)}
            tone={s}
            value={summary.findings_by_severity[s] ?? 0}
            max={findingMax}
          />
        ))}
      </SectionCard>
      <SectionCard
        title="Paths by level"
        titleId="paths-by-level"
        meta={selectedPathsText(summary.paths_exported, analysis.min_level)}
        action={<TabLink tab="paths">View paths</TabLink>}
        bodyClassName="py-3"
      >
        {ATTACK_LEVELS.map((l) => (
          <BarRow
            key={l}
            label={levelLabel(l)}
            tone={levelTone(l)}
            value={summary.paths_by_level[l] ?? 0}
            max={levelMax}
          />
        ))}
        <p className="mt-1 flex h-7 items-center text-xs text-muted-foreground">
          {belowText(summary.paths - summary.paths_exported, analysis.min_level)}
        </p>
      </SectionCard>
    </div>
  )
}

/** The paths the minimum level leaves out of the export. */
function belowText(count: number, minLevel: AttackLevel): string {
  if (count === 0) return `Every path is at or above ${levelLabel(minLevel)}, so all are exported.`
  return `${pluralize(count, 'path')} below ${levelLabel(minLevel)} ${count === 1 ? 'is' : 'are'} listed but not exported.`
}

function TabLink({ tab, children }: { tab: string; children: string }) {
  return (
    <Link
      to={{ search: `?tab=${tab}` }}
      className="inline-flex items-center gap-1 rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground"
    >
      {children}
      <ArrowRight aria-hidden="true" className="size-3" />
    </Link>
  )
}

// -- Top paths ----------------------------------------------------------------------------

function TopPaths({ analysis }: { analysis: Analysis }) {
  const resources = useMemo(() => resourceIndex(analysis), [analysis])
  const ranked = useMemo(
    () => [...analysis.paths].sort((a, b) => a.rank - b.rank),
    [analysis.paths],
  )
  const top = ranked.slice(0, TOP_PATHS)
  const max = topScore(analysis.paths)

  return (
    <SectionCard
      title="Top paths"
      titleId="top-paths"
      meta={
        analysis.paths.length > 0
          ? `${formatCount(top.length)} of ${formatCount(analysis.paths.length)}, by score`
          : undefined
      }
      action={analysis.paths.length > TOP_PATHS && <TabLink tab="paths">All paths</TabLink>}
      flush
    >
      {top.length === 0 ? (
        <EmptyState
          icon={Route}
          title="No attack paths"
          description="No route leads from an entry point to an objective. The findings are still listed."
        />
      ) : (
        <ol className="divide-y">
          {top.map((path) => (
            <li key={path.source_id}>
              <Link
                to={pathDetailUrl(analysis.id, path.source_id)}
                className="group flex flex-col gap-2.5 px-4 py-3.5 hover:bg-zinc-50/80"
              >
                <div className="grid grid-cols-[minmax(0,1fr)_11rem_1rem] items-center gap-4">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span className="font-mono text-xs font-medium text-foreground">
                      {path.source_id}
                    </span>
                    <LevelBadge level={path.attack_level} />
                    <span className="truncate text-sm font-medium text-foreground">
                      {path.objective_name}
                    </span>
                  </div>
                  <ScoreBar score={path.score} max={max} level={path.attack_level} />
                  <ChevronRight
                    aria-hidden="true"
                    className="size-4 text-faint transition-colors group-hover:text-foreground"
                  />
                </div>
                <ChainDiagram
                  size="compact"
                  nodes={chainNodes(path.hops, resources)}
                  aria-label={`${path.source_id} chain`}
                />
              </Link>
            </li>
          ))}
        </ol>
      )}
    </SectionCard>
  )
}

// -- Top fixes ----------------------------------------------------------------------------

function TopFixes({ analysis }: { analysis: Analysis }) {
  const hasSelected = analysis.summary.paths_exported > 0
  const fixes = useFixImpact(analysis.id, FIX_SCOPE, { enabled: hasSelected })
  const retrying = useRetrying(busyKeys.fixes(analysis.id, FIX_SCOPE))

  return (
    <SectionCard
      title="Top fixes"
      titleId="top-fixes"
      meta={
        hasSelected
          ? `Findings on ${fixScopeText(fixes.data ? fixes.data.scope_top : FIX_SCOPE)}`
          : undefined
      }
      flush
    >
      {!hasSelected ? (
        <p className="px-4 py-4 text-dense text-muted-foreground">
          No path is at or above {levelLabel(analysis.min_level)}, so there is no selected path to
          estimate fixes against.
        </p>
      ) : fixes.isPending ? (
        <FixesLoading retrying={retrying} />
      ) : fixes.isError ? (
        <div role="alert" className="flex flex-col items-start gap-3 px-4 py-4">
          <div className="flex gap-2.5">
            <CircleAlert
              aria-hidden="true"
              data-tone="critical"
              className="mt-0.5 size-4 shrink-0 text-tone-stroke"
            />
            <div className="min-w-0 text-dense">
              <p className="font-medium text-foreground">Could not estimate fix impact</p>
              <p className="mt-0.5 text-pretty [overflow-wrap:anywhere] text-muted-foreground">
                {fixes.error.message}
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="ml-6.5"
            onClick={() => void fixes.refetch()}
            disabled={fixes.isFetching}
          >
            <RotateCw className={fixes.isFetching ? 'animate-spin' : undefined} />
            {fixes.isFetching ? 'Retrying' : 'Try again'}
          </Button>
        </div>
      ) : (
        <FixList analysis={analysis} result={fixes.data} />
      )}
    </SectionCard>
  )
}

function FixesLoading({ retrying }: { retrying: boolean }) {
  return (
    <div role="status" aria-live="polite" className="flex flex-col">
      <p className="flex items-center gap-2 border-b px-4 py-2.5 text-xs text-muted-foreground">
        <Spinner className="size-3.5" />
        {retrying
          ? RETRYING_TEXT
          : 'Estimating impact: suppressing each finding in turn and re-running the analysis'}
      </p>
      {[0, 1, 2].map((i) => (
        <div key={i} className="flex flex-col gap-2 border-b px-4 py-3.5 last:border-0">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-14" />
            <Skeleton className="h-3.5 w-44" />
          </div>
          <Skeleton className="h-3 w-28" />
          <Skeleton className="h-3 w-full" />
        </div>
      ))}
    </div>
  )
}

function FixList({ analysis, result }: { analysis: Analysis; result: FixImpactResult }) {
  const [expanded, setExpanded] = useState(false)
  const findings = useMemo(
    () => new Map(analysis.findings.map((f) => [f.id, f])),
    [analysis.findings],
  )
  const effective = effectiveFixes(result.results)
  const shown = expanded ? effective : effective.slice(0, FIXES_SHOWN)
  const inert = result.results.length - effective.length

  return (
    <div className="flex flex-col">
      {effective.length === 0 ? (
        <p className="border-b px-4 py-4 text-dense text-pretty text-muted-foreground">
          No single finding on {fixScopeText(result.scope_top)} changes which paths are selected
          when it is suppressed on its own. The paths share several findings each.
        </p>
      ) : (
        <ol className="divide-y border-b">
          {shown.map((fix) => (
            <FixRow key={fix.finding_id} fix={fix} finding={findings.get(fix.finding_id)} />
          ))}
        </ol>
      )}
      {effective.length > FIXES_SHOWN && (
        <div className="border-b px-4 py-2">
          <Button
            variant="ghost"
            size="xs"
            className="-ml-2"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? 'Show fewer' : `Show ${formatCount(effective.length - FIXES_SHOWN)} more`}
          </Button>
        </div>
      )}
      <div className="flex flex-col gap-1.5 rounded-b-lg bg-zinc-50/60 px-4 py-3 text-xs text-pretty text-muted-foreground">
        <p>{FIX_SUPPRESSION_NOTE}</p>
        <p className="tabular-nums">
          {pluralize(result.candidate_count, 'candidate finding')} on{' '}
          {fixScopeText(result.scope_top)}
          {inert > 0 && effective.length > 0 ? `, ${formatCount(inert)} change nothing alone` : ''}.
          Computed <span className="whitespace-nowrap">{formatDateTime(result.computed_at)}</span>.
        </p>
      </div>
    </div>
  )
}

function FixRow({ fix, finding }: { fix: FixImpact; finding: Finding | undefined }) {
  const { openResource } = useResourceParam()
  const [resource = fix.finding_id] = fix.finding_id.split('::')
  const added = fixAddedText(fix)
  return (
    <li className="flex flex-col gap-1.5 px-4 py-3.5">
      <div className="flex items-start gap-2">
        <SeverityBadge severity={finding?.severity ?? 'unknown'} className="mt-px" />
        <span className="min-w-0 text-dense leading-6 font-medium text-foreground">
          {finding?.rule.display_name ?? fix.finding_id}
        </span>
      </div>
      <button
        type="button"
        onClick={() => openResource(resource)}
        className="w-fit cursor-pointer rounded-sm font-mono text-xs text-muted-foreground underline decoration-border-strong underline-offset-4 hover:text-foreground hover:decoration-foreground"
      >
        {resource}
      </button>
      <p className="text-xs text-pretty text-muted-foreground">
        <span className="font-semibold text-foreground tabular-nums">{fixRemovedText(fix)}</span>{' '}
        paths no longer at or above the selected risk level after suppressing this finding
        {added && (
          <>
            {'. '}
            <span className="font-medium text-foreground">{added}</span>
          </>
        )}
        .
      </p>
      {finding?.rule.remediation && (
        <p className="line-clamp-2 text-xs text-pretty text-foreground/80">
          {finding.rule.remediation.fix}
        </p>
      )}
    </li>
  )
}

// -- Notices ------------------------------------------------------------------------------

function SideNotices({ analysis }: { analysis: Analysis }) {
  return (
    <>
      {analysis.warnings.length > 0 && (
        <SectionCard
          title="Notices"
          titleId="notices"
          meta={formatCount(analysis.warnings.length)}
          flush
        >
          <ul className="divide-y">
            {analysis.warnings.map((warning, index) => (
              <li key={`${warning.kind}-${String(index)}`} className="flex gap-2.5 px-4 py-3">
                <Info
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 shrink-0 text-muted-foreground"
                />
                <div className="min-w-0 text-xs">
                  <p className="font-medium text-foreground">{warningTitle(warning.kind)}</p>
                  <p className="mt-0.5 text-pretty [overflow-wrap:anywhere] text-muted-foreground">
                    {warning.message}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </SectionCard>
      )}
      {analysis.nested_report && <NestedReportCard report={analysis.nested_report} />}
    </>
  )
}

function NestedReportCard({ report }: { report: NonNullable<Analysis['nested_report']> }) {
  const total = report.merged.reduce((sum, m) => sum + m.resources, 0)
  return (
    <SectionCard
      title="Nested stacks"
      titleId="nested-stacks"
      meta={`${pluralize(report.merged.length, 'stack')} merged, ${pluralize(total, 'resource')}`}
      flush
    >
      <ul className="divide-y">
        {report.merged.map((m) => (
          <li key={m.stack} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 px-4 py-2.5">
            <span className="truncate text-dense font-medium text-foreground">{m.stack}</span>
            <span className="text-right text-xs text-muted-foreground tabular-nums">
              {pluralize(m.resources, 'resource')}
            </span>
            <span
              className="col-span-2 truncate font-mono text-2xs text-muted-foreground"
              title={m.template}
            >
              {m.template}
            </span>
          </li>
        ))}
        {report.skipped.map((s) => (
          <li key={`skipped-${s.stack}`} className="flex flex-col gap-0.5 px-4 py-2.5">
            <span className="text-dense font-medium text-foreground">
              {s.stack} <span className="font-normal text-muted-foreground">· skipped</span>
            </span>
            <span className="text-xs text-pretty text-muted-foreground">{s.reason}</span>
            {s.url && (
              <span className="truncate font-mono text-2xs text-muted-foreground">{s.url}</span>
            )}
          </li>
        ))}
      </ul>
    </SectionCard>
  )
}
