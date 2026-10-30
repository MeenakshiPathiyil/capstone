/**
 * The React Flow side of the graph: node and edge records built from a layout,
 * the current path highlight and hover. Pure, so the canvas only renders.
 */
import type { Edge, Node } from '@xyflow/react'

import { cn } from '@/lib/utils'

import type { PathHighlight } from './highlight'
import type { PlacedEdge, PlacedNode } from './layout'

export interface GraphNodeData extends Record<string, unknown> {
  placed: PlacedNode
  /** A path is selected and this node is not on it. */
  dimmed: boolean
  /** The node a search just found: drawn with a ring for a moment. */
  spotlit: boolean
  /** The node the pointer is on, or one end of the hovered edge. */
  hovered: boolean
}

/** How an edge is drawn, strongest first. */
export type EdgeTone = 'path' | 'hover' | 'default' | 'dim'

export interface GraphEdgeData extends Record<string, unknown> {
  placed: PlacedEdge
  tone: EdgeTone
  /** Step numbers when the edge is on the selected path. */
  steps: number[]
  /** Show the edge's text card: the pointer or a path step is on it. */
  showText: boolean
  onHoverChange: (key: string | null) => void
}

export type GraphFlowNode = Node<GraphNodeData, 'resource' | 'state' | 'attacker' | 'group'>
export type GraphFlowEdge = Edge<GraphEdgeData, 'graph'>

export interface FlowInput {
  nodes: readonly PlacedNode[]
  edges: readonly PlacedEdge[]
  highlight: PathHighlight | null
  hoveredNode: string | null
  hoveredEdges: ReadonlySet<string>
  spotlight: ReadonlySet<string>
  onEdgeHoverChange: (key: string | null) => void
  ariaLabel: (placed: PlacedNode) => string
}

/** Is a start connector (attacker to entry) part of the highlighted path? */
function startOnPath(edge: PlacedEdge, highlight: PathHighlight | null) {
  return edge.kind === 'start' && highlight?.entryKeys.has(edge.target) === true
}

export function edgeTone(
  edge: PlacedEdge,
  highlight: PathHighlight | null,
  hoveredNode: string | null,
  hoveredEdges: ReadonlySet<string>,
): EdgeTone {
  const active = highlight?.mapped === true
  if (active && (highlight.edgeKeys.has(edge.key) || startOnPath(edge, highlight))) return 'path'
  if (hoveredEdges.has(edge.key)) return 'hover'
  if (hoveredNode !== null && (edge.source === hoveredNode || edge.target === hoveredNode)) {
    return 'hover'
  }
  return active ? 'dim' : 'default'
}

export function buildFlow(input: FlowInput): { nodes: GraphFlowNode[]; edges: GraphFlowEdge[] } {
  const { highlight, hoveredNode, hoveredEdges, spotlight } = input
  const active = highlight?.mapped === true
  const pathNodes = new Set(highlight?.nodeKeys)
  // The attacker root is on every path: it is where each one starts.
  if (active) {
    for (const placed of input.nodes) if (placed.kind === 'attacker') pathNodes.add(placed.key)
  }

  // Ends of the hovered edges read as hovered too.
  const hoveredEnds = new Set<string>()
  for (const edge of input.edges) {
    if (hoveredEdges.has(edge.key)) {
      hoveredEnds.add(edge.source)
      hoveredEnds.add(edge.target)
    }
  }

  const nodes: GraphFlowNode[] = input.nodes.map((placed) => ({
    id: placed.key,
    type: placed.kind,
    position: { x: placed.x, y: placed.y },
    width: placed.width,
    height: placed.height,
    // The layout sized every box exactly, so it counts as measured from the start.
    measured: { width: placed.width, height: placed.height },
    draggable: false,
    selectable: false,
    connectable: false,
    focusable: placed.kind !== 'attacker',
    ariaLabel: input.ariaLabel(placed),
    // Stack boxes sit under the edges that cross them.
    zIndex: placed.kind === 'group' ? -1 : 0,
    // Only a stack's title takes clicks; its empty area pans like the canvas.
    style: placed.kind === 'group' ? { pointerEvents: 'none' } : undefined,
    data: {
      placed,
      dimmed: active && placed.kind !== 'group' && !pathNodes.has(placed.key),
      spotlit: spotlight.has(placed.key),
      hovered: hoveredNode === placed.key || hoveredEnds.has(placed.key),
    },
  }))

  const edges: GraphFlowEdge[] = input.edges.map((placed) => {
    const tone = edgeTone(placed, highlight, hoveredNode, hoveredEdges)
    const steps = active ? (highlight.stepsByEdge.get(placed.key) ?? []) : []
    return {
      id: placed.key,
      type: 'graph',
      source: placed.source,
      target: placed.target,
      selectable: false,
      focusable: false,
      // A selected path's edges name their steps; the rest keep React Flow's default label.
      ariaLabel:
        active && steps.length > 0
          ? `Step ${steps.join(' and ')} of ${highlight.pathId}${placed.edge?.label ? `: ${placed.edge.label}` : ''}`
          : undefined,
      // Highlighted and hovered edges draw over the rest.
      zIndex: tone === 'path' ? 2 : tone === 'hover' ? 1 : 0,
      data: {
        placed,
        tone,
        steps,
        showText: hoveredEdges.has(placed.key),
        onHoverChange: input.onEdgeHoverChange,
      },
    }
  })

  return { nodes, edges }
}

/** The box's frame: a dashed stroke for entry points, and the interaction states. */
export function nodeFrameClass(data: GraphNodeData, fill: string) {
  return cn(
    'relative size-full cursor-pointer rounded-md border transition-[opacity,box-shadow,filter] duration-200 hover:brightness-[0.97]',
    data.placed.node.is_entry ? 'border-dashed border-tone-stroke/80' : 'border-tone-line/60',
    fill,
    data.hovered && 'shadow-[0_0_0_3px_rgb(24_24_27/0.08)]',
    data.dimmed && 'opacity-40',
    data.spotlit && 'graph-spotlight',
  )
}
