import {
  columnFilteringFeature,
  createColumnHelper,
  createFilteredRowModel,
  createSortedRowModel,
  globalFilteringFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  tableFeatures,
  useTable,
  type SortingState,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ChevronsUpDown, Search, SearchX, ShieldCheck, X } from 'lucide-react'
import { useMemo, useState, type KeyboardEvent } from 'react'

import type { Analysis, Finding } from '@/api/types'
import { EmptyState } from '@/components/EmptyState'
import { SeverityBadge, SeverityDot } from '@/components/SeverityBadge'
import { TechniqueChip } from '@/components/TechniqueChip'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useResourceParam } from '@/hooks/useResourceParam'
import { findingSearchText } from '@/lib/analysis'
import { formatCount, formatResourceType, sentenceCase } from '@/lib/format'
import { SEVERITIES, severityLabel, severityRank, type Severity } from '@/lib/severity'
import { cn } from '@/lib/utils'

const features = tableFeatures({
  columnFilteringFeature,
  globalFilteringFeature,
  rowSortingFeature,
  filteredRowModel: createFilteredRowModel(),
  sortedRowModel: createSortedRowModel(),
  sortFns: { alphanumeric: sortFn_alphanumeric },
})

const helper = createColumnHelper<typeof features, Finding>()

/** Technique chips that fit the ATT&CK column on one line. */
const MAX_CHIPS = 3

const columns = helper.columns([
  helper.accessor((f) => SEVERITIES.length - severityRank(f.severity), {
    id: 'severity',
    header: 'Severity',
    sortDescFirst: true,
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} variant="dot" />,
  }),
  helper.accessor('resource', {
    header: 'Resource',
    sortFn: 'alphanumeric',
    cell: ({ getValue }) => (
      <span className="block truncate font-mono text-xs text-foreground" title={getValue()}>
        {getValue()}
      </span>
    ),
  }),
  helper.accessor((f) => formatResourceType(f.resource_type), {
    id: 'type',
    header: 'Type',
    sortFn: 'alphanumeric',
    cell: ({ getValue, row }) => (
      <span className="block truncate text-muted-foreground" title={row.original.resource_type}>
        {getValue()}
      </span>
    ),
  }),
  helper.accessor((f) => f.rule.display_name, {
    id: 'finding',
    header: 'Finding',
    sortFn: 'alphanumeric',
    cell: ({ getValue }) => (
      <span className="block truncate text-foreground" title={getValue()}>
        {getValue()}
      </span>
    ),
  }),
  helper.accessor((f) => (f.semantic ? sentenceCase(f.semantic) : ''), {
    id: 'semantic',
    header: 'Semantic',
    sortFn: 'alphanumeric',
    cell: ({ getValue }) => {
      const value = getValue()
      return value ? (
        <span className="block truncate text-muted-foreground">{value}</span>
      ) : (
        <span className="text-faint">-</span>
      )
    },
  }),
  helper.accessor((f) => f.rule.attack_techniques.map((t) => t.id).join(' '), {
    id: 'attack',
    header: 'ATT&CK',
    enableSorting: false,
    cell: ({ row }) => {
      const techniques = row.original.rule.attack_techniques
      if (techniques.length === 0) return <span className="text-faint">-</span>
      // One line: past three chips, the last place says how many more.
      const shown = techniques.length > MAX_CHIPS ? techniques.slice(0, MAX_CHIPS - 1) : techniques
      const hidden = techniques.slice(shown.length)
      return (
        <span className="flex gap-1 overflow-hidden">
          {shown.map((t) => (
            <TechniqueChip key={t.id} id={t.id} name={t.name} className="shrink-0" />
          ))}
          {hidden.length > 0 && (
            <span
              className="inline-flex h-5 shrink-0 items-center rounded-sm bg-subtle px-1.5 text-2xs font-medium text-muted-foreground tabular-nums"
              title={hidden.map((t) => (t.name ? `${t.id} ${t.name}` : t.id)).join('\n')}
            >
              +{hidden.length}
            </span>
          )}
        </span>
      )
    },
  }),
  helper.accessor((f) => f.on_paths.length, {
    id: 'paths',
    header: 'On paths',
    sortDescFirst: true,
    cell: ({ getValue }) => {
      const value = getValue()
      return (
        <span className={value === 0 ? 'text-faint' : 'text-foreground'}>{formatCount(value)}</span>
      )
    },
  }),
])

/**
 * Every cell is one line, so every row is 40px. Widths fit the longest
 * values of real templates: three sub-technique chips, "Network control",
 * "EC2 SecurityGroup". The finding takes the rest; longer text truncates
 * and shows whole on hover and in the resource sheet. Below 1100px Type and
 * Semantic drop out (the resource sheet has both) so the finding keeps room.
 */
const COLUMN_CLASSES: Record<string, string> = {
  severity: 'w-24',
  resource: 'w-40',
  type: 'hidden w-40 min-[1100px]:table-cell',
  finding: '',
  semantic: 'hidden w-32 min-[1100px]:table-cell',
  attack: 'w-58',
  paths: 'w-22 text-right',
}

const DEFAULT_SORTING: SortingState = [{ id: 'severity', desc: true }]

export function FindingsTab({ analysis }: { analysis: Analysis }) {
  const { openResource } = useResourceParam()
  const [sorting, setSorting] = useState<SortingState>(DEFAULT_SORTING)
  const [search, setSearch] = useState('')
  const [severities, setSeverities] = useState<ReadonlySet<Severity>>(new Set())

  const counts = useMemo(() => {
    const map = new Map<Severity, number>(SEVERITIES.map((s) => [s, 0]))
    for (const f of analysis.findings) map.set(f.severity, (map.get(f.severity) ?? 0) + 1)
    return map
  }, [analysis.findings])

  // The severity filter narrows the data; the search box is the table's global filter.
  const data = useMemo(
    () =>
      severities.size === 0
        ? analysis.findings
        : analysis.findings.filter((f) => severities.has(f.severity)),
    [analysis.findings, severities],
  )
  const searchIndex = useMemo(
    () => new Map(analysis.findings.map((f) => [f.id, findingSearchText(f)])),
    [analysis.findings],
  )

  const table = useTable({
    features,
    columns,
    data,
    getRowId: (row) => row.id,
    state: { sorting, globalFilter: search },
    onSortingChange: setSorting,
    onGlobalFilterChange: (updater: unknown) =>
      setSearch((previous) => {
        const value: unknown =
          typeof updater === 'function' ? (updater as (old: string) => unknown)(previous) : updater
        return typeof value === 'string' ? value : ''
      }),
    enableSortingRemoval: false,
    getColumnCanGlobalFilter: (column) => column.id === 'finding',
    globalFilterFn: (row, _columnId, value: string) => {
      const terms = value.toLowerCase().split(/\s+/).filter(Boolean)
      const text = searchIndex.get(row.original.id) ?? ''
      return terms.every((term) => text.includes(term))
    },
  })

  if (analysis.findings.length === 0) {
    return (
      <EmptyState
        bordered
        icon={ShieldCheck}
        title="No findings"
        description={
          analysis.summary.resources === 0
            ? 'The template declares no resources, so no rule had anything to check.'
            : 'No rule flagged any of the resources in this template.'
        }
      />
    )
  }

  const rows = table.getRowModel().rows
  const filtered = search.trim() !== '' || severities.size > 0
  const clearFilters = () => {
    setSearch('')
    setSeverities(new Set())
  }
  const toggleSeverity = (severity: Severity) => {
    setSeverities((previous) => {
      const next = new Set(previous)
      if (next.has(severity)) next.delete(severity)
      else next.add(severity)
      return next
    })
  }
  const onRowKeyDown = (event: KeyboardEvent<HTMLTableRowElement>, finding: Finding) => {
    if (event.target !== event.currentTarget) return
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      openResource(finding.resource)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="relative w-80 max-w-full">
          <Search
            aria-hidden="true"
            className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search resources, findings, techniques"
            aria-label="Search findings"
            className="pl-8 [&::-webkit-search-cancel-button]:hidden"
          />
        </div>
        <div
          role="group"
          aria-label="Filter by severity"
          className="flex flex-wrap items-center gap-1.5"
        >
          {SEVERITIES.filter((s) => s !== 'unknown' || (counts.get(s) ?? 0) > 0).map((s) => {
            const count = counts.get(s) ?? 0
            const active = severities.has(s)
            return (
              <button
                key={s}
                type="button"
                aria-pressed={active}
                disabled={count === 0}
                onClick={() => toggleSeverity(s)}
                className={cn(
                  'inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border px-2.5 text-dense transition-colors disabled:cursor-default disabled:opacity-45',
                  active
                    ? 'border-foreground bg-surface text-foreground'
                    : 'border-border-strong bg-surface text-muted-foreground hover:border-zinc-400 hover:text-foreground',
                )}
              >
                <SeverityDot severity={s} />
                {severityLabel(s)}
                <span className="text-muted-foreground tabular-nums">{formatCount(count)}</span>
              </button>
            )
          })}
          {filtered && (
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              <X />
              Clear
            </Button>
          )}
        </div>
        <p className="ml-auto text-xs text-muted-foreground tabular-nums" aria-live="polite">
          {filtered
            ? `${formatCount(rows.length)} of ${formatCount(analysis.findings.length)} findings`
            : `${formatCount(analysis.findings.length)} findings`}
        </p>
      </div>

      {/*
        overflow-clip, not hidden: the header stays sticky against the page. Below 1100px the
        table scrolls sideways instead, and the header is not sticky: inside a scroll container
        it would stick to the container, not the page.
      */}
      <div className="overflow-x-auto rounded-lg border bg-surface min-[1100px]:overflow-clip">
        <table className="w-full min-w-[800px] table-fixed text-dense tabular-nums">
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted()
                  const canSort = header.column.getCanSort()
                  const right = header.column.id === 'paths'
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={
                        sorted === 'asc'
                          ? 'ascending'
                          : sorted === 'desc'
                            ? 'descending'
                            : undefined
                      }
                      className={cn(
                        'z-10 h-9 bg-zinc-50 px-3 text-left align-middle text-xs font-medium whitespace-nowrap text-muted-foreground shadow-[inset_0_-1px_0_var(--border)] min-[1100px]:sticky min-[1100px]:top-12',
                        COLUMN_CLASSES[header.column.id],
                      )}
                    >
                      {canSort ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className={cn(
                            '-mx-1.5 inline-flex h-6 cursor-pointer items-center gap-1 rounded-sm px-1.5 hover:bg-zinc-200/60 hover:text-foreground',
                            sorted && 'text-foreground',
                            right && 'flex-row-reverse',
                          )}
                        >
                          <table.FlexRender header={header} />
                          {sorted === 'asc' ? (
                            <ArrowUp aria-hidden="true" className="size-3" />
                          ) : sorted === 'desc' ? (
                            <ArrowDown aria-hidden="true" className="size-3" />
                          ) : (
                            <ChevronsUpDown aria-hidden="true" className="size-3 text-faint" />
                          )}
                        </button>
                      ) : (
                        <table.FlexRender header={header} />
                      )}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                tabIndex={0}
                aria-label={`${row.original.rule.display_name} on ${row.original.resource}`}
                onClick={(event) => {
                  if ((event.target as HTMLElement).closest('a, button')) return
                  openResource(row.original.resource)
                }}
                onKeyDown={(event) => onRowKeyDown(event, row.original)}
                className="cursor-pointer border-b transition-colors outline-none last:border-0 hover:bg-zinc-50 focus-visible:bg-zinc-50 focus-visible:shadow-[inset_2px_0_0_var(--foreground)]"
              >
                {row.getAllCells().map((cell) => (
                  <td
                    key={cell.id}
                    className={cn('h-10 px-3 py-2 align-middle', COLUMN_CLASSES[cell.column.id])}
                  >
                    <table.FlexRender cell={cell} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <EmptyState
            icon={SearchX}
            title="No findings match"
            description="Try another search or clear the severity filter."
            action={
              <Button variant="outline" size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            }
          />
        )}
      </div>
    </div>
  )
}
