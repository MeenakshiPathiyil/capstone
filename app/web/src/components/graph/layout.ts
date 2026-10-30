/**
 * Graph layout: dagre, left to right, sized from what each box will show.
 *
 * Plan 10.5: rankdir LR, boxes sized from their label lines. Long ids wrap at
 * their CamelCase breaks rather than widening the box: these graphs are long
 * chains, far wider than tall, so width is what limits how large the whole
 * graph can be drawn.
 *
 * Every edge gets a small slot of its own in the layout (dagre lays edge
 * labels out as boxes). Parallel edges between one pair therefore get
 * separate lanes and separate curves, and a path's step numbers sit in those
 * slots without ever landing on a node or each other. Edge text is shown on
 * demand (hover, the path panel), not reserved, because reserving room for it
 * would halve the scale of the whole drawing.
 *
 * Positions are final: nodes are not draggable, and edges follow the routes
 * computed here rather than React Flow's handles.
 */
import dagre from '@dagrejs/dagre'

import type { GraphEdge, GraphNode, GraphView } from '@/api/types'
import { sentenceCase } from '@/lib/format'

import {
  categoryText,
  factRowText,
  interWidth,
  isStackType,
  monoWidth,
  nodeText,
  sortedFacts,
  wrapIdentifier,
  wrapText,
  type Fact,
} from './labels'

// -- Metrics shared with the node and edge components -------------------------

export const METRICS = {
  nodePadX: 8,
  nodePadY: 5,
  border: 1,
  titlePx: 12,
  titleLineHeight: 16,
  textPx: 11,
  textLineHeight: 15,
  /** Header text never runs wider than this, so boxes stay narrow. */
  headerMaxWidth: 104,
  minNodeWidth: 84,
  maxStateWidth: 128,
  factPx: 10.5,
  factIcon: 12,
  factGap: 6,
  factRowHeight: 16,
  factPadY: 4,
  maxGainedRows: 4,
  attackerWidth: 112,
  attackerHeight: 32,
  /** The slot every edge gets: room for a step number. */
  slotWidth: 22,
  slotHeight: 18,
  cardPx: 12,
  cardMaxWidth: 240,
  groupHeader: 18,
} as const

/** Extra width on a fact row, over the estimate. */
const FACT_SLACK = 4

/*
 * Tight on purpose: at READABLE_ZOOM (viewport.ts) the cloudformation5
 * sample fits a 1440 by 900 window whole in both views, and every exported
 * path fits beside the path panel. Loosen these and measure again.
 */
const RANKSEP = 20
const NODESEP = 10
const EDGESEP = 10
/** Compound graphs need room inside each stack box for its title. */
const GROUP_NODESEP = 60
const MARGIN = 24

export type NodeKind = 'resource' | 'state' | 'attacker' | 'group'
export type EdgeKind = 'move' | 'start'

export interface Point {
  x: number
  y: number
}

export interface Box {
  x: number
  y: number
  width: number
  height: number
}

/** The lines a box draws, decided here so the box is exactly as large as its text. */
export interface NodeLines {
  title: string[]
  type: string[]
  extra: string[]
}

/**
 * What an attacker state shows: the facts the move into it gained, and a
 * count of those carried over from before. The full list is in the tooltip.
 */
export interface StateFacts {
  gained: Fact[]
  /** Gained facts beyond the rows shown. */
  moreGained: number
  carried: number
  all: Fact[]
}

export interface PlacedNode extends Box {
  key: string
  kind: NodeKind
  node: GraphNode
  lines: NodeLines
  facts: StateFacts | null
  /** The stack box this node sits in, for nested templates. */
  parent: string | null
}

export interface PlacedLabel extends Box {
  /** The edge's text, shown on hover: categories, or the action's name. */
  lines: string[]
  /** A quieter second part: tactic and technique of an attack move. */
  meta: string | null
}

export interface PlacedEdge {
  key: string
  kind: EdgeKind
  source: string
  target: string
  /** Route from the source's side to the target's side, through dagre's waypoints. */
  points: Point[]
  /** Unit tangent leaving the source and arriving at the target. */
  startDir: Point
  endDir: Point
  label: PlacedLabel | null
  /** The API edge; null for the attacker's start connectors, which the API does not send. */
  edge: GraphEdge | null
}

export interface GraphLayout {
  nodes: PlacedNode[]
  edges: PlacedEdge[]
  width: number
  height: number
}

// -- Sizes --------------------------------------------------------------------

const titleWidth = (s: string) => monoWidth(s, METRICS.titlePx)
const textWidth = (s: string) => interWidth(s, METRICS.textPx)
const factWidth = (s: string) => monoWidth(s, METRICS.factPx)

/** The kind of box a node is drawn as, before grouping. */
export function nodeKind(node: GraphNode, view: GraphView['view']): NodeKind {
  if (view === 'attack') return node.resource === null ? 'attacker' : 'state'
  return 'resource'
}

/** Title, type and any extra line, wrapped to the header width. */
export function nodeLines(node: GraphNode): NodeLines {
  const text = nodeText(node)
  const max = METRICS.headerMaxWidth
  return {
    title: wrapIdentifier(text.title, max, titleWidth),
    type: text.type ? wrapText(text.type, max, textWidth, 2) : [],
    extra: text.extra.flatMap((line) => wrapText(line, max, textWidth, 2)),
  }
}

/**
 * Facts gained by the move into a state: those its predecessors did not all
 * hold already. An entry state (no way in) shows everything it starts with.
 */
export function stateFacts(
  facts: readonly string[],
  predecessors: readonly (readonly string[])[],
  { entry = false } = {},
): StateFacts {
  const all = sortedFacts(facts)
  const [first, ...rest] = predecessors
  const held = first
    ? rest.reduce(
        (acc, previous) => new Set([...acc].filter((fact) => previous.includes(fact))),
        new Set(first),
      )
    : null
  const gainedAll = held ? all.filter((fact) => !held.has(fact.raw)) : all
  // An entry state's Entry tab already says it is reachable from the internet.
  const listed = entry ? gainedAll.filter((fact) => fact.kind !== 'internet_reachable') : gainedAll
  const gained = listed.slice(0, METRICS.maxGainedRows)
  return {
    gained,
    moreGained: listed.length - gained.length,
    carried: all.length - gainedAll.length,
    all,
  }
}

/**
 * The facts a state box holds but does not list: gained beyond the rows
 * shown, plus those carried over. The tooltip lists them all.
 */
export function unlistedFacts(facts: StateFacts): number {
  return facts.moreGained + facts.carried
}

/**
 * A muted row of its own, for a box that lists no gained fact, or null. A box
 * that lists some ends its last row with "+N" instead, which costs no height.
 */
export function factSummary(facts: StateFacts): string | null {
  if (facts.gained.length > 0 || facts.carried === 0) return null
  return `${String(facts.carried)} carried over`
}

/** The "+N" after the last listed fact, or null. */
export function factSuffix(facts: StateFacts): string | null {
  const unlisted = unlistedFacts(facts)
  return facts.gained.length > 0 && unlisted > 0 ? `+${String(unlisted)}` : null
}

/** Width and height of a node's box, from the lines it will show. */
export function nodeSize(
  kind: NodeKind,
  lines: NodeLines,
  facts: StateFacts | null,
  resource: string | null = null,
): { width: number; height: number } {
  const m = METRICS
  if (kind === 'attacker') return { width: m.attackerWidth, height: m.attackerHeight }

  const headerWidths = [
    ...lines.title.map(titleWidth),
    ...lines.type.map(textWidth),
    ...lines.extra.map(textWidth),
  ]
  let contentWidth = Math.max(0, ...headerWidths)
  let height =
    2 * m.nodePadY +
    2 * m.border +
    lines.title.length * m.titleLineHeight +
    (lines.type.length + lines.extra.length) * m.textLineHeight
  let maxWidth = m.headerMaxWidth + 2 * m.nodePadX + 2 * m.border

  if (kind === 'state' && facts) {
    const summary = factSummary(facts)
    const rows = facts.gained.length + (summary ? 1 : 0)
    if (rows > 0) {
      maxWidth = m.maxStateWidth
      const suffix = factSuffix(facts)
      const widths = facts.gained.map((fact, index) => {
        const row = factRowText(fact, resource)
        const text = row.mono ? factWidth(row.text) : interWidth(row.text, m.factPx)
        const last = index === facts.gained.length - 1
        const tail = last && suffix ? m.factGap + textWidth(suffix) : 0
        // The estimate runs a pixel or two short of Inter at this size, and a
        // row that misses by one truncates; a little slack keeps it whole.
        return m.factIcon + m.factGap + text + tail + FACT_SLACK
      })
      if (summary) widths.push(m.factIcon + m.factGap + textWidth(summary))
      contentWidth = Math.max(contentWidth, ...widths)
      height += 2 * m.factPadY + rows * m.factRowHeight + m.border
    }
  }

  const width = Math.min(
    maxWidth,
    Math.max(m.minNodeWidth, contentWidth + 2 * m.nodePadX + 2 * m.border),
  )
  return { width: Math.ceil(width), height: Math.ceil(height) }
}

/** The text an edge shows on hover. */
export function edgeText(
  edge: GraphEdge,
  view: GraphView['view'],
): { lines: string[]; meta: string | null } {
  const measure = (s: string) => interWidth(s, METRICS.cardPx)
  if (view === 'attack') {
    const meta = [edge.tactic ? sentenceCase(edge.tactic) : null, edge.technique]
      .filter(Boolean)
      .join(' · ')
    return { lines: wrapText(edge.label, METRICS.cardMaxWidth, measure, 3), meta: meta || null }
  }
  return {
    lines: [categoryText(edge)],
    meta: edge.reversed ? 'Reversed: the template declares this link the other way' : null,
  }
}

// -- Grouping (nested stacks) -------------------------------------------------

/**
 * Nested templates name a child "Parent.Child" and keep the parent stack as a
 * resource of type AWS::CloudFormation::Stack. Such a stack is drawn as a box
 * around its children, unless an edge touches it (dagre cannot route edges to
 * a box that has children).
 */
export function stackParents(nodes: readonly GraphNode[], edges: readonly GraphEdge[]) {
  const touched = new Set(edges.flatMap((edge) => [edge.source, edge.target]))
  const stacks = nodes
    .filter((node) => isStackType(node.label_lines[1] ?? null) && !touched.has(node.key))
    .map((node) => node.key)
    .sort((a, b) => b.length - a.length)

  const parents = new Map<string, string>()
  for (const node of nodes) {
    // The deepest stack whose name prefixes this one.
    const parent = stacks.find((stack) => stack !== node.key && node.key.startsWith(`${stack}.`))
    if (parent) parents.set(node.key, parent)
  }
  const groups = new Set(parents.values())
  return { parents, groups }
}

// -- Layout ---------------------------------------------------------------------

type Side = 'left' | 'right' | 'top' | 'bottom'

const SIDE_DIR: Record<Side, Point> = {
  left: { x: -1, y: 0 },
  right: { x: 1, y: 0 },
  top: { x: 0, y: -1 },
  bottom: { x: 0, y: 1 },
}

/** Which side of `box` faces `toward`. */
function facingSide(box: Box, toward: Point): Side {
  if (toward.x >= box.x + box.width - 0.5) return 'right'
  if (toward.x <= box.x + 0.5) return 'left'
  return toward.y < box.y + box.height / 2 ? 'top' : 'bottom'
}

function sidePoint(box: Box, side: Side): Point {
  const cx = box.x + box.width / 2
  const cy = box.y + box.height / 2
  switch (side) {
    case 'left':
      return { x: box.x, y: cy }
    case 'right':
      return { x: box.x + box.width, y: cy }
    case 'top':
      return { x: cx, y: box.y }
    case 'bottom':
      return { x: cx, y: box.y + box.height }
  }
}

/** Replace dagre's border intersections with side midpoints, so edges leave and arrive level. */
export function anchorRoute(
  waypoints: readonly Point[],
  source: Box,
  target: Box,
): { points: Point[]; startDir: Point; endDir: Point } {
  const inner = waypoints.slice(1, -1)
  const targetCentre = { x: target.x + target.width / 2, y: target.y + target.height / 2 }
  const sourceCentre = { x: source.x + source.width / 2, y: source.y + source.height / 2 }
  const startSide = facingSide(source, inner[0] ?? targetCentre)
  const endSide = facingSide(target, inner[inner.length - 1] ?? sourceCentre)
  const startDir = SIDE_DIR[startSide]
  const endOut = SIDE_DIR[endSide]
  return {
    points: [sidePoint(source, startSide), ...inner, sidePoint(target, endSide)],
    startDir,
    // 0 - n, not -n: a level direction stays +0, never -0.
    endDir: { x: 0 - endOut.x, y: 0 - endOut.y },
  }
}

interface DagreNodeLabel {
  width: number
  height: number
  x?: number
  y?: number
}

interface DagreEdgeLabel {
  width?: number
  height?: number
  labelpos?: 'l' | 'c' | 'r'
  minlen?: number
  weight?: number
  x?: number
  y?: number
  points?: Point[]
}

/** Lay out one graph view. Pure: the same view always gives the same layout. */
export function layoutGraph(view: GraphView): GraphLayout {
  const kindOf = (node: GraphNode) => nodeKind(node, view.view)
  const { parents, groups } =
    view.view === 'state'
      ? stackParents(view.nodes, view.edges)
      : { parents: new Map<string, string>(), groups: new Set<string>() }
  const compound = groups.size > 0

  const g = new dagre.graphlib.Graph<Record<string, unknown>, DagreNodeLabel, DagreEdgeLabel>({
    multigraph: true,
    compound,
  })
  g.setGraph({
    rankdir: 'LR',
    nodesep: compound ? GROUP_NODESEP : NODESEP,
    ranksep: RANKSEP,
    edgesep: EDGESEP,
    marginx: MARGIN,
    marginy: MARGIN,
  })

  const byKey = new Map(view.nodes.map((node) => [node.key, node]))
  const drawn = view.edges.filter((edge) => byKey.has(edge.source) && byKey.has(edge.target))

  // What each attacker state held before its move: the facts of every state with a move into it.
  const predecessors = new Map<string, (readonly string[])[]>()
  for (const edge of drawn) {
    const facts = byKey.get(edge.source)?.facts
    if (!facts || byKey.get(edge.source)?.resource === null) continue
    predecessors.set(edge.target, [...(predecessors.get(edge.target) ?? []), facts])
  }

  const content = new Map<string, { lines: NodeLines; facts: StateFacts | null }>()
  for (const node of view.nodes) {
    const kind = kindOf(node)
    const lines = nodeLines(node)
    const facts =
      kind === 'state'
        ? stateFacts(node.facts ?? [], predecessors.get(node.key) ?? [], { entry: node.is_entry })
        : null
    content.set(node.key, { lines, facts })
    if (groups.has(node.key)) {
      g.setNode(node.key, { width: 0, height: 0 })
    } else {
      g.setNode(node.key, nodeSize(kind, lines, facts, node.resource))
    }
  }
  for (const [child, parent] of parents) g.setParent(child, parent)

  // The attack graph has no edges out of the attacker root; every path starts
  // at an entry state. Connect them, so the root reads as where it all begins.
  const attacker =
    view.view === 'attack' ? view.nodes.find((node) => node.resource === null) : undefined
  const starts: { key: string; source: string; target: string }[] = attacker
    ? view.nodes
        // Entry states reached by a move already have a way in; only the others need one.
        .filter(
          (node) =>
            node.is_entry &&
            node.key !== attacker.key &&
            !drawn.some((edge) => edge.target === node.key),
        )
        .map((node) => ({ key: `start:${node.key}`, source: attacker.key, target: node.key }))
    : []

  for (const edge of drawn) {
    g.setEdge(
      edge.source,
      edge.target,
      { width: METRICS.slotWidth, height: METRICS.slotHeight, labelpos: 'c' },
      edge.key,
    )
  }
  for (const start of starts) {
    // A light weight: the moves decide the shape, not the connectors.
    g.setEdge(start.source, start.target, { weight: 0.5 }, start.key)
  }

  dagre.layout(g)

  const placed = new Map<string, PlacedNode>()
  for (const node of view.nodes) {
    const box = g.node(node.key)
    const width = box.width
    const height = box.height
    const x = (box.x ?? 0) - width / 2
    const y = (box.y ?? 0) - height / 2
    placed.set(node.key, {
      key: node.key,
      kind: groups.has(node.key) ? 'group' : kindOf(node),
      node,
      parent: parents.get(node.key) ?? null,
      lines: content.get(node.key)?.lines ?? { title: [node.key], type: [], extra: [] },
      facts: content.get(node.key)?.facts ?? null,
      x,
      y,
      width,
      height,
    })
  }

  const route = (key: string, source: string, target: string) => {
    const routed = g.edge({ v: source, w: target, name: key })
    const from = placed.get(source)
    const to = placed.get(target)
    if (!from || !to) return null
    return { routed, ...anchorRoute(routed.points ?? [], from, to) }
  }

  const edges: PlacedEdge[] = []
  for (const edge of drawn) {
    const text = edgeText(edge, view.view)
    const result = route(edge.key, edge.source, edge.target)
    if (!result) continue
    const { routed, points, startDir, endDir } = result
    edges.push({
      key: edge.key,
      kind: 'move',
      source: edge.source,
      target: edge.target,
      points,
      startDir,
      endDir,
      label: {
        ...text,
        width: METRICS.slotWidth,
        height: METRICS.slotHeight,
        x: (routed.x ?? 0) - METRICS.slotWidth / 2,
        y: (routed.y ?? 0) - METRICS.slotHeight / 2,
      },
      edge,
    })
  }
  for (const start of starts) {
    const result = route(start.key, start.source, start.target)
    if (!result) continue
    edges.push({
      key: start.key,
      kind: 'start',
      source: start.source,
      target: start.target,
      points: result.points,
      startDir: result.startDir,
      endDir: result.endDir,
      label: null,
      edge: null,
    })
  }

  const graph = g.graph()
  return {
    // Stack boxes first, so they draw underneath their children.
    nodes: [...placed.values()].sort(
      (a, b) => Number(b.kind === 'group') - Number(a.kind === 'group'),
    ),
    edges,
    width: Number(graph.width ?? 0),
    height: Number(graph.height ?? 0),
  }
}

// -- Edge geometry --------------------------------------------------------------

/**
 * An SVG path through the route's points. Each segment is a cubic whose
 * tangents are level at internal points and follow the side directions at the
 * ends, so an edge leaves a box straight, bends once between ranks, and
 * arrives straight. `endInset` stops the line short of the target, under the
 * arrowhead.
 */
export function edgePath(
  points: readonly Point[],
  startDir: Point,
  endDir: Point,
  endInset = 0,
): string {
  if (points.length < 2) return ''
  const pts = points.map((p) => ({ ...p }))
  const last = pts[pts.length - 1]
  if (last && endInset > 0) {
    last.x -= endDir.x * endInset
    last.y -= endDir.y * endInset
  }

  const tangent = (index: number): Point => {
    if (index === 0) return startDir
    if (index === pts.length - 1) return endDir
    const prev = pts[index - 1]
    const next = pts[index + 1]
    const dx = (next?.x ?? 0) - (prev?.x ?? 0)
    return { x: dx < 0 ? -1 : 1, y: 0 }
  }

  const round = (n: number) => Math.round(n * 100) / 100
  const first = pts[0]
  if (!first) return ''
  let d = `M ${round(first.x)} ${round(first.y)}`
  for (let i = 0; i < pts.length - 1; i += 1) {
    const a = pts[i]
    const b = pts[i + 1]
    if (!a || !b) continue
    const ta = tangent(i)
    const tb = tangent(i + 1)
    const reach = (t: Point) =>
      Math.max(8, (t.x !== 0 ? Math.abs(b.x - a.x) : Math.abs(b.y - a.y)) / 2)
    const ka = reach(ta)
    const kb = reach(tb)
    d +=
      ` C ${round(a.x + ta.x * ka)} ${round(a.y + ta.y * ka)}` +
      ` ${round(b.x - tb.x * kb)} ${round(b.y - tb.y * kb)}` +
      ` ${round(b.x)} ${round(b.y)}`
  }
  return d
}

/** A filled triangle whose tip is `tip`, pointing along `dir`. */
export function arrowheadPath(tip: Point, dir: Point, length: number, halfWidth: number): string {
  const baseX = tip.x - dir.x * length
  const baseY = tip.y - dir.y * length
  const nx = -dir.y
  const ny = dir.x
  const r = (n: number) => Math.round(n * 100) / 100
  return (
    `M ${r(tip.x)} ${r(tip.y)}` +
    ` L ${r(baseX + nx * halfWidth)} ${r(baseY + ny * halfWidth)}` +
    ` L ${r(baseX - nx * halfWidth)} ${r(baseY - ny * halfWidth)} Z`
  )
}

/** The box around a set of placed boxes, or null for none. */
export function boundsOf(boxes: readonly Box[]): Box | null {
  if (boxes.length === 0) return null
  let minX = Infinity
  let minY = Infinity
  let maxX = -Infinity
  let maxY = -Infinity
  for (const box of boxes) {
    minX = Math.min(minX, box.x)
    minY = Math.min(minY, box.y)
    maxX = Math.max(maxX, box.x + box.width)
    maxY = Math.max(maxY, box.y + box.height)
  }
  return { x: minX, y: minY, width: maxX - minX, height: maxY - minY }
}
