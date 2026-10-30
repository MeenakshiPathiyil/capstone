import { FileQuestion, Plus } from 'lucide-react'
import { lazy, Suspense, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'

import { ApiError } from '@/api/client'
import { useAnalysis } from '@/api/hooks'
import type { Analysis } from '@/api/types'
import { AppShell, Container } from '@/components/AppShell'
import { DownloadReportMenu } from '@/components/DownloadReportMenu'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { ResourceSheet } from '@/components/ResourceSheet'
import {
  AnalysisHeaderSkeleton,
  CardListSkeleton,
  StatTilesSkeleton,
  TableSkeleton,
} from '@/components/Skeletons'
import { TabErrorBoundary } from '@/components/TabErrorBoundary'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { formatDateTime, shortHash } from '@/lib/format'
import { levelLabel } from '@/lib/severity'
import { tabFromSearch, type AnalysisTab } from '@/lib/tabs'

import { AnalysisLayout, MetaDot } from './AnalysisLayout'
import { FindingsTab } from './FindingsTab'
import { OverviewTab } from './OverviewTab'
import { PathsTab } from './PathsTab'

const GraphTab = lazy(() => import('./GraphTab'))

/**
 * /analysis/:id?tab=overview|findings|paths|graph[&resource=<id>]. The tab and
 * the open resource live in the URL so every view can be linked and survives
 * reload.
 */
export function AnalysisPage() {
  const { id = '' } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = tabFromSearch(searchParams.get('tab'))
  const analysis = useAnalysis(id)

  const changeTab = (next: AnalysisTab) => {
    setSearchParams(
      (previous) => {
        const params = new URLSearchParams(previous)
        params.set('tab', next)
        // A graph path selection belongs to the graph tab only.
        if (next !== 'graph') params.delete('path')
        return params
      },
      { replace: true },
    )
  }

  if (analysis.isPending) {
    return (
      <AppShell headerActions={<NewAnalysisButton />}>
        <AnalysisLoading tab={tab} />
      </AppShell>
    )
  }

  if (analysis.isError) {
    return (
      <AppShell headerActions={<NewAnalysisButton />}>
        <Container className="py-16">
          <AnalysisLoadError
            error={analysis.error}
            onRetry={() => void analysis.refetch()}
            retrying={analysis.isFetching}
          />
        </Container>
      </AppShell>
    )
  }

  const data = analysis.data
  return (
    <AppShell headerActions={<NewAnalysisButton />}>
      <AnalysisLayout
        title={data.input_name}
        meta={<AnalysisMeta analysis={data} />}
        actions={
          <DownloadReportMenu analysisId={data.id} exportedPaths={data.summary.paths_exported} />
        }
        tab={tab}
        onTabChange={changeTab}
        tabCounts={{ findings: data.summary.findings, paths: data.summary.paths }}
      >
        <TabBody tab={tab} analysis={data} />
      </AnalysisLayout>
      <ResourceSheet analysis={data} />
    </AppShell>
  )
}

function TabBody({ tab, analysis }: { tab: AnalysisTab; analysis: Analysis }) {
  switch (tab) {
    case 'overview':
      return <OverviewTab analysis={analysis} />
    case 'findings':
      return <FindingsTab analysis={analysis} />
    case 'paths':
      return <PathsTab analysis={analysis} />
    case 'graph':
      return (
        <TabErrorBoundary label="graph">
          <Suspense fallback={<GraphSkeleton />}>
            <GraphTab analysis={analysis} />
          </Suspense>
        </TabErrorBoundary>
      )
  }
}

function AnalysisMeta({ analysis }: { analysis: Analysis }) {
  return (
    <>
      <span className="max-w-[28rem] truncate" title={analysis.industry}>
        {analysis.industry}
      </span>
      <MetaDot />
      <span>
        Minimum level <span className="text-foreground">{levelLabel(analysis.min_level)}</span>
      </span>
      <MetaDot />
      <span className="tabular-nums">{formatDateTime(analysis.created_at)}</span>
      <MetaDot />
      <span className="font-mono text-xs" title={`sha256 ${analysis.input_sha256}`}>
        sha256 {shortHash(analysis.input_sha256)}
      </span>
    </>
  )
}

export function AnalysisLoadError({
  error,
  onRetry,
  retrying,
}: {
  error: Error
  onRetry: () => void
  retrying: boolean
}) {
  if (error instanceof ApiError && error.status === 404) {
    return (
      <EmptyState
        bordered
        icon={FileQuestion}
        title="Analysis not found"
        description="No saved analysis has this id. It may have been removed from the local store, or the link is incomplete."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/">New analysis</Link>
          </Button>
        }
      />
    )
  }
  return (
    <ErrorState
      title="Could not load this analysis"
      message={error.message}
      onRetry={onRetry}
      retrying={retrying}
    />
  )
}

function AnalysisLoading({ tab }: { tab: AnalysisTab }) {
  let body: ReactNode
  switch (tab) {
    case 'findings':
      body = <TableSkeleton rows={10} columns={7} />
      break
    case 'paths':
      body = <CardListSkeleton count={4} />
      break
    case 'graph':
      body = <GraphSkeleton />
      break
    default:
      body = (
        <div className="flex flex-col gap-6">
          <StatTilesSkeleton />
          <div className="grid gap-6 md:grid-cols-2">
            <Skeleton className="h-44 rounded-lg" />
            <Skeleton className="h-44 rounded-lg" />
          </div>
          <CardListSkeleton count={3} />
        </div>
      )
  }
  return (
    <div className="flex flex-1 flex-col">
      <div className="border-b bg-surface">
        <Container>
          <div className="pt-6 pb-4">
            <AnalysisHeaderSkeleton />
          </div>
          <div className="flex h-10 items-center gap-5">
            {[16, 16, 12, 12].map((w, i) => (
              <Skeleton key={i} className="h-3.5" style={{ width: `${String(w * 4)}px` }} />
            ))}
          </div>
        </Container>
      </div>
      <Container className="py-6">{body}</Container>
    </div>
  )
}

function GraphSkeleton() {
  return (
    <div role="status" aria-live="polite" className="flex flex-col gap-3">
      <span className="sr-only">Loading graph</span>
      <div className="flex items-center gap-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-8 w-56" />
        <Skeleton className="ml-auto h-8 w-24" />
      </div>
      <Skeleton className="h-[34rem] rounded-lg" />
    </div>
  )
}

export function NewAnalysisButton() {
  return (
    <Button asChild variant="outline" size="sm">
      <Link to="/">
        <Plus />
        New analysis
      </Link>
    </Button>
  )
}
