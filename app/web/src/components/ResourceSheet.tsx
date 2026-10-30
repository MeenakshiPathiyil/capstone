import { ArrowUpRight, ChevronRight, FileQuestion, Route, ShieldCheck } from 'lucide-react'
import { Fragment, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router'

import type { Analysis, Finding, Path, Resource } from '@/api/types'
import { EmptyState } from '@/components/EmptyState'
import { LevelBadge } from '@/components/LevelBadge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { TechniqueChip } from '@/components/TechniqueChip'
import { Badge } from '@/components/ui/badge'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useResourceParam } from '@/hooks/useResourceParam'
import { evidenceChips, pathDetailUrl, pathsThroughResource } from '@/lib/analysis'
import {
  formatCount,
  formatResourceType,
  formatScore,
  identifierBreaks,
  safeHttpUrl,
  pluralize,
  sentenceCase,
} from '@/lib/format'
import { compareSeverity, resourceTone } from '@/lib/severity'
import { cn } from '@/lib/utils'

type SheetTab = 'findings' | 'attributes' | 'paths'

/**
 * The resource drawer. Opens whenever the URL has ?resource=<id>; closing it
 * removes the param and puts focus back where it was when the sheet opened.
 */
export function ResourceSheet({ analysis }: { analysis: Analysis }) {
  const { resourceId, openResource, closeResource } = useResourceParam()
  // Keep showing the last resource while the sheet animates closed.
  const [shownId, setShownId] = useState(resourceId)
  if (resourceId !== null && resourceId !== shownId) setShownId(resourceId)
  const returnFocus = useRef<HTMLElement | null>(null)
  const contentRef = useRef<HTMLDivElement>(null)

  return (
    <Sheet
      open={resourceId !== null}
      onOpenChange={(open) => {
        if (!open) closeResource()
      }}
    >
      <SheetContent
        className="w-full gap-0 outline-none sm:max-w-xl"
        ref={contentRef}
        onOpenAutoFocus={(event) => {
          // Runs before focus moves into the sheet: remember the opener, then
          // focus the sheet itself rather than its first tab, so the first
          // Tab press lands on the tabs and no ring flashes on open.
          const active = document.activeElement
          returnFocus.current =
            active instanceof HTMLElement && active !== document.body ? active : null
          event.preventDefault()
          contentRef.current?.focus()
        }}
        onCloseAutoFocus={(event) => {
          const target = returnFocus.current
          if (target?.isConnected) {
            event.preventDefault()
            target.focus()
          }
        }}
      >
        {shownId !== null && (
          <ResourceSheetBody
            key={shownId}
            analysis={analysis}
            resourceId={shownId}
            onOpenResource={openResource}
          />
        )}
      </SheetContent>
    </Sheet>
  )
}

function ResourceSheetBody({
  analysis,
  resourceId,
  onOpenResource,
}: {
  analysis: Analysis
  resourceId: string
  onOpenResource: (id: string) => void
}) {
  const resource = analysis.resources.find((r) => r.id === resourceId)
  const findings = useMemo(() => {
    if (!resource) return []
    const byId = new Map(analysis.findings.map((f) => [f.id, f]))
    return resource.findings
      .map((id) => byId.get(id))
      .filter((f): f is Finding => f !== undefined)
      .sort((a, b) => compareSeverity(a.severity, b.severity) || a.id.localeCompare(b.id))
  }, [analysis.findings, resource])
  const paths = useMemo(
    () => pathsThroughResource(analysis.paths, resourceId),
    [analysis.paths, resourceId],
  )
  const [tab, setTab] = useState<SheetTab>('findings')

  if (!resource) {
    return (
      <>
        <SheetHeader className="pr-12">
          <SheetTitle className="font-mono text-base break-all">{resourceId}</SheetTitle>
          <SheetDescription>Not in this analysis</SheetDescription>
        </SheetHeader>
        <EmptyState
          icon={FileQuestion}
          title="Resource not found"
          description="This analysis has no resource with that logical id. The link may belong to a different template."
        />
      </>
    )
  }

  return (
    <>
      <SheetHeader className="gap-2 pr-12">
        <SheetTitle className="font-mono text-base leading-6 [overflow-wrap:anywhere]">
          {resource.id}
        </SheetTitle>
        <SheetDescription className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-foreground">{formatResourceType(resource.type)}</span>
          <span aria-hidden="true" className="text-faint">
            ·
          </span>
          <span className="font-mono text-xs">{resource.type}</span>
        </SheetDescription>
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={resourceTone(resource.max_severity)} />
          {resource.is_entry && <Badge variant="outline">Entry point</Badge>}
          <span className="text-xs text-muted-foreground tabular-nums">
            {pluralize(findings.length, 'finding')}, on {pluralize(paths.length, 'path')}
          </span>
        </div>
        {resource.is_entry && <EntryReason resource={resource} findings={findings} />}
      </SheetHeader>

      <Tabs
        value={tab}
        onValueChange={(value) => setTab(value as SheetTab)}
        className="min-h-0 flex-1"
      >
        <div className="border-b px-5">
          <TabsList variant="line" aria-label="Resource details" className="-mb-px">
            <TabsTrigger value="findings">
              Findings
              <TabCount value={findings.length} />
            </TabsTrigger>
            <TabsTrigger value="attributes">Attributes</TabsTrigger>
            <TabsTrigger value="paths">
              Paths
              <TabCount value={paths.length} />
            </TabsTrigger>
          </TabsList>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">
          <TabsContent value="findings">
            <FindingsPanel findings={findings} />
          </TabsContent>
          <TabsContent value="attributes">
            <AttributesPanel resource={resource} onOpenResource={onOpenResource} />
          </TabsContent>
          <TabsContent value="paths">
            <PathsPanel analysisId={analysis.id} paths={paths} />
          </TabsContent>
        </div>
      </Tabs>
    </>
  )
}

/**
 * Why the resource is an entry point. The backend's reason names the rules
 * that make it reachable; they are shown by their display names when every
 * one matches a finding here, and as the raw reason otherwise.
 */
function EntryReason({ resource, findings }: { resource: Resource; findings: Finding[] }) {
  const reason = resource.entry_reason
  const causes = findings.filter((f) => reason.includes(f.rule_id))
  const matched = causes.length > 0
  return (
    <p className="text-xs text-pretty [overflow-wrap:anywhere] text-muted-foreground">
      {matched ? (
        <>
          Reachable from outside through{' '}
          {causes.map((f, i) => (
            <span key={f.id}>
              {i > 0 && (i === causes.length - 1 ? ' and ' : ', ')}
              <span className="text-foreground">{f.rule.display_name}</span>
            </span>
          ))}
          .
        </>
      ) : (
        reason
      )}
    </p>
  )
}

function TabCount({ value }: { value: number }) {
  return (
    <span className="rounded-sm bg-subtle px-1.5 text-xs leading-5 font-medium text-muted-foreground tabular-nums">
      {formatCount(value)}
    </span>
  )
}

// -- Findings -------------------------------------------------------------------------

function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No findings"
        description="No rule flagged this resource. It can still sit on a path as a hop between others."
      />
    )
  }
  return (
    <ul className="divide-y">
      {findings.map((finding) => (
        <li key={finding.id} className="px-5 py-4">
          <FindingDetail finding={finding} />
        </li>
      ))}
    </ul>
  )
}

function FindingDetail({ finding }: { finding: Finding }) {
  const { rule } = finding
  const remediation = rule.remediation
  // The remediation link is usually one of the references; list each url once.
  const links = [
    ...(remediation ? [{ label: 'Remediation guide', url: remediation.url }] : []),
    ...rule.references.map((ref) => ({ label: referenceLabel(ref.source, ref.id), url: ref.url })),
  ].filter(
    (link, index, all) =>
      safeHttpUrl(link.url) !== null && all.findIndex((l) => l.url === link.url) === index,
  )

  return (
    <article className="flex flex-col gap-2.5">
      <header className="flex flex-col gap-1.5">
        <div className="flex items-start gap-2">
          <SeverityBadge severity={finding.severity} className="mt-px" />
          <h3 className="min-w-0 text-sm leading-6 font-medium text-foreground">
            {rule.display_name}
          </h3>
        </div>
        <p className="text-dense text-pretty text-muted-foreground">{rule.summary}</p>
      </header>

      <div className="flex flex-wrap items-center gap-1.5">
        {rule.attack_techniques.map((t) => (
          <TechniqueChip key={t.id} id={t.id} name={t.name} />
        ))}
        <span className="font-mono text-2xs [overflow-wrap:anywhere] text-muted-foreground">
          {finding.source_id}
        </span>
        {finding.semantic && (
          <span className="text-2xs text-muted-foreground">· {sentenceCase(finding.semantic)}</span>
        )}
      </div>

      {remediation ? (
        <section
          aria-label="Remediation"
          className="flex flex-col gap-2 rounded-md border bg-zinc-50/60 p-3"
        >
          <p className="text-2xs font-medium tracking-[0.04em] text-muted-foreground uppercase">
            Fix
          </p>
          <p className="text-dense text-pretty text-foreground">{remediation.fix}</p>
          {remediation.snippet && <CodeBlock code={remediation.snippet} label="Template snippet" />}
        </section>
      ) : (
        <p className="text-xs text-muted-foreground">No remediation guidance for this rule yet.</p>
      )}

      {links.length > 0 && (
        <ul className="flex flex-wrap gap-x-4 gap-y-1">
          {links.map((link) => (
            <li key={link.url}>
              <ExternalLink href={link.url}>{link.label}</ExternalLink>
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}

function referenceLabel(source: string, id: string): string {
  const sources: Record<string, string> = { aws_config: 'AWS Config', cis: 'CIS', aws: 'AWS docs' }
  return `${sources[source] ?? sentenceCase(source)} ${id}`
}

function CodeBlock({ code, label }: { code: string; label: string }) {
  return (
    <pre
      aria-label={label}
      className="overflow-x-auto rounded-md border bg-surface px-3 py-2.5 font-mono text-xs leading-5 text-foreground"
    >
      <code>{code.replace(/\n+$/, '')}</code>
    </pre>
  )
}

/** Only http(s) URLs become links; anything else the API sends is dropped. */
function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  const url = safeHttpUrl(href)
  if (!url) return null
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-0.5 rounded-sm text-xs font-medium text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground"
    >
      {children}
      <ArrowUpRight aria-hidden="true" className="size-3 text-muted-foreground" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  )
}

// -- Attributes -------------------------------------------------------------------------

function AttributesPanel({
  resource,
  onOpenResource,
}: {
  resource: Resource
  onOpenResource: (id: string) => void
}) {
  const entries = Object.entries(resource.attributes).sort(([a], [b]) => a.localeCompare(b))
  const rawCount = Object.keys(resource.raw_properties).length
  return (
    <div className="flex flex-col gap-6 px-5 py-4">
      <section aria-labelledby="attributes-heading" className="flex flex-col gap-2">
        <SectionTitle id="attributes-heading">Projected attributes</SectionTitle>
        {entries.length === 0 ? (
          <p className="text-dense text-muted-foreground">No attributes were projected.</p>
        ) : (
          <dl className="divide-y rounded-md border">
            {entries.map(([key, value]) => (
              <div
                key={key}
                className="grid grid-cols-[minmax(0,15rem)_minmax(0,1fr)] gap-3 px-3 py-2 text-dense"
              >
                <dt className="font-mono text-xs leading-5 [overflow-wrap:anywhere] text-muted-foreground">
                  {identifierBreaks(key).map((piece, index) => (
                    <Fragment key={index}>
                      {index > 0 && <wbr />}
                      {piece}
                    </Fragment>
                  ))}
                </dt>
                <dd className="min-w-0">
                  <AttributeValue value={value} />
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section aria-labelledby="connections-heading" className="flex flex-col gap-2">
        <SectionTitle id="connections-heading">Connections</SectionTitle>
        {resource.connections.length === 0 ? (
          <p className="text-dense text-muted-foreground">No connections to other resources.</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {resource.connections.map((c) => (
              <li key={`${c.target}-${c.type}-${c.relation ?? ''}`}>
                <button
                  type="button"
                  onClick={() => onOpenResource(c.target)}
                  className="flex w-full cursor-pointer items-center gap-3 px-3 py-2 text-left text-dense hover:bg-zinc-50"
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">
                    {c.target}
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {sentenceCase(c.type)}
                    {c.relation && c.relation !== c.type ? ` · ${sentenceCase(c.relation)}` : ''}
                  </span>
                  <ChevronRight aria-hidden="true" className="size-3.5 text-muted-foreground" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <details className="group rounded-md border">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded-md px-3 py-2 text-dense font-medium text-foreground hover:bg-zinc-50 [&::-webkit-details-marker]:hidden">
          <ChevronRight
            aria-hidden="true"
            className="size-3.5 text-muted-foreground transition-transform group-open:rotate-90"
          />
          Raw properties
          <span className="ml-auto text-xs font-normal text-muted-foreground tabular-nums">
            {pluralize(rawCount, 'key')}
          </span>
        </summary>
        <pre className="max-h-96 overflow-auto border-t bg-zinc-50/60 px-3 py-2.5 font-mono text-xs leading-5 text-foreground">
          {JSON.stringify(resource.raw_properties, null, 2)}
        </pre>
      </details>
    </div>
  )
}

function SectionTitle({ id, children }: { id: string; children: ReactNode }) {
  return (
    <h3 id={id} className="text-xs font-medium text-muted-foreground">
      {children}
    </h3>
  )
}

function AttributeValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || (Array.isArray(value) && value.length === 0)) {
    return <span className="text-muted-foreground">None</span>
  }
  if (typeof value === 'boolean') {
    return <span className="font-mono text-xs">{String(value)}</span>
  }
  const isPlainList =
    Array.isArray(value) && value.every((item) => item === null || typeof item !== 'object')
  if (typeof value === 'object' && !isPlainList) {
    return (
      <pre className="overflow-x-auto font-mono text-xs leading-5 whitespace-pre text-foreground">
        {JSON.stringify(value, null, 2)}
      </pre>
    )
  }
  const chips = evidenceChips(value)
  if (chips.length === 1) {
    return <span className="font-mono text-xs leading-5 [overflow-wrap:anywhere]">{chips[0]}</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {chips.map((chip, index) => (
        <span
          key={`${chip}-${String(index)}`}
          className="inline-flex h-5 items-center rounded-sm border bg-surface px-1.5 font-mono text-2xs"
        >
          {chip}
        </span>
      ))}
    </span>
  )
}

// -- Paths ------------------------------------------------------------------------------

function PathsPanel({ analysisId, paths }: { analysisId: string; paths: Path[] }) {
  if (paths.length === 0) {
    return (
      <EmptyState
        icon={Route}
        title="Not on any attack path"
        description="No ranked path passes through this resource."
      />
    )
  }
  return (
    <ul className="divide-y">
      {paths.map((path) => (
        <li key={path.source_id}>
          <Link
            to={pathDetailUrl(analysisId, path.source_id)}
            className="grid grid-cols-[4.25rem_5.5rem_minmax(0,1fr)_3rem_1rem] items-center gap-3 px-5 py-2.5 text-dense hover:bg-zinc-50"
          >
            <span className="font-mono text-xs font-medium text-foreground">{path.source_id}</span>
            <span>
              <LevelBadge level={path.attack_level} />
            </span>
            <span className="min-w-0 truncate text-foreground">
              {path.objective_name}
              {!path.exported && (
                <span className="text-muted-foreground"> · below minimum level</span>
              )}
            </span>
            <span className={cn('text-right font-medium tabular-nums')}>
              {formatScore(path.score)}
            </span>
            <ChevronRight aria-hidden="true" className="size-3.5 text-muted-foreground" />
          </Link>
        </li>
      ))}
    </ul>
  )
}
