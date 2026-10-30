import { ReactFlowProvider } from '@xyflow/react'
import { Network, RotateCcw, TriangleAlert } from 'lucide-react'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'

import { isGraphViewKind, useGraph, usePrefetchGraph, type GraphViewKind } from '@/api/graph'
import type { Analysis, GraphView } from '@/api/types'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { GraphCanvas } from '@/components/graph/GraphCanvas'
import { GraphLegend } from '@/components/graph/GraphLegend'
import { PathPicker, ResourceSearch, ViewToggle } from '@/components/graph/GraphToolbar'
import { pathEnds, pathHighlight } from '@/components/graph/highlight'
import { nodeTone } from '@/components/graph/labels'
import { layoutGraph } from '@/components/graph/layout'
import { PathInspector } from '@/components/graph/PathInspector'
import { FOCUS_MAX_ZOOM, motion, nodeBoxes, useGraphViewport } from '@/components/graph/viewport'
import { Spinner } from '@/components/Spinner'
import { Button } from '@/components/ui/button'
import { pluralize } from '@/lib/format'
import { TONES } from '@/lib/severity'

/** Search params this tab reads and writes, next to ?tab=graph. */
const PARAM = { view: 'view', path: 'path', resource: 'resource' } as const

/** How long a search result keeps its ring. */
const SPOTLIGHT_MS = 2400

/** The card fills the window below it, but never gets shorter than this. */
const MIN_HEIGHT = 520
const BOTTOM_GAP = 16

/**
 * The Graph tab: both graph views of an analysis, with a path to highlight,
 * a resource finder and the key. State lives in the URL (?view=, ?path=), so
 * /analysis/:id?tab=graph&path=AP-001 opens with that path lit; a node click
 * sets ?resource= for the page's resource sheet. Every param change replaces the
 * history entry, like tab changes, so Back leaves the page.
 */
export default function GraphTab({ analysis }: { analysis: Analysis }) {
  return (
    <ReactFlowProvider>
      <GraphExplorer analysis={analysis} />
    </ReactFlowProvider>
  )
}

function useFillHeight() {
  const ref = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState(MIN_HEIGHT)
  const measure = useCallback(() => {
    const element = ref.current
    if (!element) return
    const top = element.getBoundingClientRect().top + window.scrollY
    setHeight(Math.max(MIN_HEIGHT, Math.floor(window.innerHeight - top - BOTTOM_GAP)))
  }, [])
  // After every render: content above the card (the warnings) can come and go.
  // Setting the same height again is a no-op, so this settles at once.
  useLayoutEffect(measure)
  useEffect(() => {
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [measure])
  return { ref, height }
}

function GraphExplorer({ analysis }: { analysis: Analysis }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const rawView = searchParams.get(PARAM.view)
  const view: GraphViewKind = isGraphViewKind(rawView) ? rawView : 'state'
  const pathId = searchParams.get(PARAM.path)

  const setParam = useCallback(
    (name: string, value: string | null, replace = true) => {
      setSearchParams(
        (previous) => {
          const params = new URLSearchParams(previous)
          if (value === null) params.delete(name)
          else params.set(name, value)
          return params
        },
        { replace },
      )
    },
    [setSearchParams],
  )

  const graph = useGraph(analysis.id, view)
  usePrefetchGraph(analysis.id, view === 'state' ? 'attack' : 'state', graph.isSuccess)

  const layout = useMemo(() => (graph.data ? layoutGraph(graph.data) : null), [graph.data])
  const selectedPath = useMemo(
    () => analysis.paths.find((path) => path.source_id === pathId) ?? null,
    [analysis.paths, pathId],
  )
  const highlight = useMemo(
    () => (graph.data ? pathHighlight(graph.data.nodes, graph.data.edges, selectedPath) : null),
    [graph.data, selectedPath],
  )

  const ends = useMemo(
    () =>
      graph.data ? pathEnds(graph.data.nodes, graph.data.edges, analysis.paths) : new Set<string>(),
    [graph.data, analysis.paths],
  )
  const panelOpen = selectedPath !== null
  const { fitBoxes } = useGraphViewport(panelOpen, layout)
  const [homeRequest, setHomeRequest] = useState(0)

  /**
   * Bring some boxes into view, readable and clear of the panel, and (unless
   * `moveFocus` is false) focus the first.
   */
  const focusNodes = useCallback(
    async (keys: readonly string[], moveFocus = true) => {
      if (!layout || keys.length === 0) return
      await fitBoxes(nodeBoxes(layout, keys), { duration: motion(400), maxZoom: FOCUS_MAX_ZOOM })
      const first = keys[0]
      if (!moveFocus || first === undefined) return
      const element = document.querySelector<HTMLElement>(
        `.react-flow__node[data-id="${CSS.escape(first)}"]`,
      )
      element?.focus({ preventScroll: true })
    },
    [layout, fitBoxes],
  )
  const [spotlight, setSpotlight] = useState<ReadonlySet<string>>(new Set())
  const [stepHover, setStepHover] = useState<ReadonlySet<string>>(new Set())

  useEffect(() => {
    if (spotlight.size === 0) return
    const timer = window.setTimeout(() => setSpotlight(new Set()), SPOTLIGHT_MS)
    return () => window.clearTimeout(timer)
  }, [spotlight])

  // Keys of the nodes standing for each resource (several per resource in the attack view).
  const nodesByResource = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const node of graph.data?.nodes ?? []) {
      if (!node.resource) continue
      map.set(node.resource, [...(map.get(node.resource) ?? []), node.key])
    }
    return map
  }, [graph.data])

  const isAvailable = useCallback((id: string) => nodesByResource.has(id), [nodesByResource])

  const findResource = useCallback(
    (id: string) => {
      const keys = nodesByResource.get(id) ?? []
      setSpotlight(new Set(keys))
      void focusNodes(keys)
    },
    [nodesByResource, focusNodes],
  )

  const focusStep = useCallback(
    (index: number) => {
      const edgeKeys = new Set(highlight?.edgesByStep[index] ?? [])
      const keys = (graph.data?.edges ?? [])
        .filter((edge) => edgeKeys.has(edge.key))
        .flatMap((edge) => [edge.source, edge.target])
      // Focus stays on the step in the panel; only the canvas moves.
      void focusNodes([...new Set(keys)], false)
    },
    [highlight, graph.data, focusNodes],
  )

  const openResource = useCallback(
    (resource: string) => setParam(PARAM.resource, resource),
    [setParam],
  )

  const tones = useMemo(() => {
    const present = new Set(
      (graph.data?.nodes ?? []).filter((node) => node.resource !== null).map(nodeTone),
    )
    return TONES.filter((tone) => present.has(tone))
  }, [graph.data])

  const { ref, height } = useFillHeight()

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <ViewToggle
          value={view}
          onChange={(next) => setParam(PARAM.view, next === 'state' ? null : next)}
        />
        <PathPicker
          paths={analysis.paths}
          value={selectedPath?.source_id ?? null}
          onChange={(next) => setParam(PARAM.path, next)}
        />
        <ResourceSearch
          resources={analysis.resources}
          isAvailable={isAvailable}
          onSelect={findResource}
        />
        <Button
          variant="outline"
          onClick={() => setHomeRequest((count) => count + 1)}
          disabled={!layout || layout.nodes.length === 0}
          className="ml-auto"
          title={selectedPath ? 'Back to the highlighted path' : 'Back to the opening view'}
        >
          <RotateCcw />
          Reset view
        </Button>
      </div>

      {graph.data && <GraphWarnings graph={graph.data} />}

      <div
        ref={ref}
        style={{ height }}
        className="flex flex-col overflow-hidden rounded-lg border bg-surface"
      >
        <div className="relative min-h-0 flex-1">
          {graph.isPending && (
            <div
              role="status"
              className="flex size-full items-center justify-center gap-2 text-dense text-muted-foreground"
            >
              <Spinner />
              Loading the graph
            </div>
          )}
          {graph.isError && (
            <div className="flex size-full items-center justify-center p-6">
              <ErrorState
                title="The graph could not be loaded"
                message={graph.error.message}
                onRetry={() => void graph.refetch()}
                retrying={graph.isRefetching}
                className="border-0"
              />
            </div>
          )}
          {layout?.nodes.length === 0 && (
            <EmptyState
              icon={Network}
              title="Nothing to draw"
              description="This template has no resources this view can show."
              className="size-full"
            />
          )}
          {layout && layout.nodes.length > 0 && (
            <GraphCanvas
              layout={layout}
              highlight={highlight}
              spotlight={spotlight}
              externalHover={stepHover}
              onOpenResource={openResource}
              panelOpen={panelOpen}
              homeRequest={homeRequest}
              pathEnds={ends}
            />
          )}
          {selectedPath && (
            <PathInspector
              analysisId={analysis.id}
              path={selectedPath}
              highlight={highlight}
              view={view}
              onClose={() => setParam(PARAM.path, null)}
              onHoverEdges={(keys) => setStepHover(new Set(keys))}
              onFocusStep={focusStep}
              className="absolute inset-y-0 right-0 z-10"
            />
          )}
        </div>
        <GraphLegend view={view} tones={tones} />
      </div>
    </div>
  )
}

/** Shown when the drawing is incomplete: a truncated attack graph, or paths or edges that could not be mapped. */
function GraphWarnings({ graph }: { graph: GraphView }) {
  const [expanded, setExpanded] = useState(false)
  const messages = graph.warnings
    .filter((warning) => warning.kind === 'graph_truncated' || warning.kind === 'graph_mapping')
    .map((warning) => warning.message)
  if (graph.truncated && !graph.warnings.some((warning) => warning.kind === 'graph_truncated')) {
    messages.unshift('The attack graph reached its state limit and is incomplete.')
  }
  if (messages.length === 0) return null

  const visible = expanded ? messages : messages.slice(0, 2)
  const hidden = messages.length - visible.length
  return (
    <div
      role="status"
      data-tone="medium"
      className="flex items-start gap-2.5 rounded-lg border border-tone-line/30 bg-tone-tint/50 px-3 py-2.5 text-dense"
    >
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-tone-stroke" />
      <div className="min-w-0 flex-1">
        <p className="font-medium text-foreground">
          {graph.truncated ? 'This graph is incomplete' : 'Some paths are not drawn exactly'}
        </p>
        <ul className="mt-0.5 flex flex-col gap-0.5 text-muted-foreground">
          {visible.map((message, index) => (
            <li key={`${String(index)}-${message}`}>{message}</li>
          ))}
        </ul>
        {(hidden > 0 || expanded) && (
          <button
            type="button"
            className="mt-1 cursor-pointer text-xs font-medium text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? 'Show fewer' : `Show ${pluralize(hidden, 'more warning')}`}
          </button>
        )}
      </div>
    </div>
  )
}
