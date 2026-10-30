import '@xyflow/react/dist/base.css'
import './graph.css'

import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  useStore,
  type EdgeTypes,
  type NodeTypes,
} from '@xyflow/react'
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'

import { severityLabel } from '@/lib/severity'
import { cn } from '@/lib/utils'

import { buildFlow, type GraphFlowNode } from './flow'
import { GraphEdgeView } from './GraphEdge'
import type { PathHighlight } from './highlight'
import { nodeText, nodeTone } from './labels'
import type { GraphLayout, PlacedNode } from './layout'
import { ResourceNode, StackGroupNode } from './ResourceNode'
import { AttackerNode, StateNode } from './StateNode'
import {
  CORNER_MARGIN,
  FOCUS_MAX_ZOOM,
  homeBoxes,
  showsWhole,
  MINIMAP,
  motion,
  nodeBoxes,
  PANEL_WIDTH,
  useGraphViewport,
} from './viewport'

const nodeTypes: NodeTypes = {
  resource: ResourceNode,
  group: StackGroupNode,
  state: StateNode,
  attacker: AttackerNode,
}

const edgeTypes: EdgeTypes = { graph: GraphEdgeView }

function ariaLabel(placed: PlacedNode, highlight: PathHighlight | null): string {
  const { node } = placed
  if (placed.kind === 'attacker') return 'Attacker: where every path starts'
  const text = nodeText(node)
  const parts = [text.title]
  if (placed.kind === 'group') parts.push('nested stack')
  else if (text.type) parts.push(text.type)
  if (placed.kind !== 'group') parts.push(severityLabel(nodeTone(node)))
  if (node.is_entry) parts.push('entry point')
  if (node.facts && node.facts.length > 0) parts.push(`attacker holds ${node.facts.join(', ')}`)
  if (highlight?.mapped && highlight.nodeKeys.has(placed.key)) parts.push(`on ${highlight.pathId}`)
  return `${parts.join(', ')}. Press Enter for details.`
}

interface GraphCanvasProps {
  layout: GraphLayout
  highlight: PathHighlight | null
  /** Nodes a search just found. */
  spotlight: ReadonlySet<string>
  /** Edges hovered from outside the canvas, such as a step in the path panel. */
  externalHover: ReadonlySet<string>
  onOpenResource: (resource: string) => void
  /** The path panel is laid over the right of the canvas. */
  panelOpen: boolean
  /** Bumped to go back to the opening view (the toolbar's Reset view). */
  homeRequest: number
  /** Nodes where paths end: kept in view when the whole graph does not fit. */
  pathEnds: ReadonlySet<string>
  className?: string
}

/** The overview button in the zoom controls: everything at once, however small. */
const WHOLE_GRAPH = { padding: 0.06, maxZoom: 1 } as const

/**
 * The drawing: fixed positions from the layout, custom edges along the
 * layout's routes, design-system controls and minimap. Opens on the whole
 * graph, or on the path when one is selected, never smaller than readable;
 * refits on resize until the user pans or zooms.
 */
export function GraphCanvas({
  layout,
  highlight,
  spotlight,
  externalHover,
  onOpenResource,
  panelOpen,
  homeRequest,
  pathEnds,
  className,
}: GraphCanvasProps) {
  const { fitBoxes, whole } = useGraphViewport(panelOpen, layout)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null)

  const hoveredEdges = useMemo(() => {
    const keys = new Set(externalHover)
    if (hoveredEdge) keys.add(hoveredEdge)
    return keys
  }, [externalHover, hoveredEdge])

  const { nodes, edges } = useMemo(
    () =>
      buildFlow({
        nodes: layout.nodes,
        edges: layout.edges,
        highlight,
        hoveredNode,
        hoveredEdges,
        spotlight,
        onEdgeHoverChange: setHoveredEdge,
        ariaLabel: (placed) => ariaLabel(placed, highlight),
      }),
    [layout, highlight, hoveredNode, hoveredEdges, spotlight],
  )

  const byKey = useMemo(() => new Map(layout.nodes.map((n) => [n.key, n])), [layout])

  // The opening view: the path when one is drawn, else the whole graph.
  const pathId = highlight?.mapped ? highlight.pathId : null
  const pathNodes = highlight?.mapped ? highlight.nodeKeys : null
  const home = useMemo(
    () => homeBoxes(layout, pathNodes),
    // pathNodes follows pathId; a new Set for the same path is the same view.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [layout, pathId],
  )
  const width = useStore((state) => state.width)
  const height = useStore((state) => state.height)
  const [ready, setReady] = useState(false)
  // Set once the user pans or zooms: a resize then leaves their view alone.
  const userMoved = useRef(false)
  const fitted = useRef<{ layout: GraphLayout; home: typeof home; request: number } | null>(null)
  useEffect(() => {
    if (width === 0 || height === 0) return
    const previous = fitted.current
    const changed = previous?.home !== home || previous.request !== homeRequest
    if (!changed && userMoved.current) return
    userMoved.current = false
    fitted.current = { layout, home, request: homeRequest }
    // A new path or a reset glides there; a new layout or a resize jumps.
    const glide = changed && previous?.layout === layout
    // Without a path, where the paths end is what must stay in sight.
    const focus = pathId ? undefined : nodeBoxes(layout, pathEnds)
    // A path starts at the attacker: show it too when there is room.
    const extra = pathId ? layout.nodes.filter((node) => node.kind === 'attacker') : []
    void fitBoxes(home, { duration: glide ? motion(350) : 0, focus, extra }).then(() =>
      setReady(true),
    )
    // pathEnds follows the layout; pathId follows home.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout, home, homeRequest, width, height, fitBoxes])

  // The minimap only when there is somewhere to go: part of the graph is out of view.
  const overflowing = useStore((state) => {
    if (!whole || state.width === 0) return false
    const [x, y, zoom] = state.transform
    return !showsWhole(whole, { x, y, zoom }, state, panelOpen)
  })

  const open = useCallback(
    (key: string) => {
      const resource = byKey.get(key)?.node.resource
      if (resource) onOpenResource(resource)
    },
    [byKey, onOpenResource],
  )

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'Enter') return
    const target = event.target as HTMLElement
    if (!target.classList.contains('react-flow__node')) return
    const key = target.dataset.id
    if (key) {
      event.preventDefault()
      open(key)
    }
  }

  return (
    <div
      className={cn(
        'graph-canvas relative size-full transition-opacity duration-150',
        !ready && 'opacity-0',
        className,
      )}
      onKeyDown={onKeyDown}
    >
      <ReactFlow<GraphFlowNode>
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        minZoom={0.15}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        edgesFocusable={false}
        zoomOnDoubleClick={false}
        onNodeClick={(_, node) => open(node.id)}
        onNodeMouseEnter={(_, node) => {
          if (node.type !== 'group') setHoveredNode(node.id)
        }}
        onNodeMouseLeave={() => setHoveredNode(null)}
        // Also what makes edges take the pointer at all: React Flow leaves
        // unselectable edges without a click handler inert.
        onEdgeClick={(_, edge) => {
          const boxes = nodeBoxes(layout, [edge.source, edge.target])
          void fitBoxes(boxes, { duration: motion(350), maxZoom: FOCUS_MAX_ZOOM })
        }}
        onMoveStart={(event) => {
          // Programmatic moves carry no event; only the user's own count.
          if (event) userMoved.current = true
        }}
        onEdgeMouseEnter={(_, edge) => setHoveredEdge(edge.id)}
        onEdgeMouseLeave={() => setHoveredEdge(null)}
        attributionPosition="bottom-center"
        ariaLabelConfig={{
          'node.a11yDescription.default':
            'Press Enter to open the resource. Tab moves between resources.',
          'controls.fitView.ariaLabel': 'Show the whole graph',
        }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="var(--border-strong)"
        />
        <Controls
          position="bottom-left"
          orientation="horizontal"
          showInteractive={false}
          fitViewOptions={{ ...WHOLE_GRAPH, duration: motion(300) }}
          aria-label="Zoom controls"
        />
        {overflowing && (
          <MiniMap
            position="bottom-right"
            style={{
              width: MINIMAP.width,
              height: MINIMAP.height,
              margin: CORNER_MARGIN,
              right: panelOpen ? PANEL_WIDTH : 0,
            }}
            pannable
            zoomable
            ariaLabel="Overview of the graph"
            nodeBorderRadius={3}
            nodeColor={(node) => {
              const placed = (node as GraphFlowNode).data.placed
              if (placed.kind === 'group') return 'transparent'
              if (placed.kind === 'attacker') return 'var(--foreground)'
              return `var(--sev-${nodeTone(placed.node)}-fill)`
            }}
            nodeStrokeColor={(node) => {
              const placed = (node as GraphFlowNode).data.placed
              return placed.kind === 'group' ? 'var(--border-strong)' : 'transparent'
            }}
            nodeStrokeWidth={2}
            maskColor="rgb(244 244 245 / 0.72)"
            maskStrokeColor="var(--border-strong)"
            maskStrokeWidth={1}
          />
        )}
      </ReactFlow>
    </div>
  )
}
