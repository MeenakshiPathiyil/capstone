/**
 * Which edges and nodes a selected path lights up, and the step number on each.
 *
 * The backend already decided which edges a path uses (edge.path_ids, matched
 * exactly in the attack view). This only orders them: step i of the path is
 * the path edge leaving the node the attacker reached at step i - 1, between
 * the step's two resources and, in the attack view, by the step's action. A
 * path the backend could not map carries no edges, and nothing is highlighted.
 */
import type { GraphEdge, GraphNode, Path, Step } from '@/api/types'

export interface PathHighlight {
  pathId: string
  /** Edges the path walks. */
  edgeKeys: Set<string>
  /** Nodes at either end of those edges. */
  nodeKeys: Set<string>
  /** 1-based step numbers per edge key; an edge walked twice carries both. */
  stepsByEdge: Map<string, number[]>
  /** Edge keys per step, in step order; empty where a step found no edge. */
  edgesByStep: string[][]
  /** Where step 1 starts. */
  entryKeys: Set<string>
  /** False when no edge carries the path: the backend could not map it in this view. */
  mapped: boolean
  /** True when every step found its edge. */
  complete: boolean
}

type PathLike = Pick<Path, 'source_id'> & {
  steps: readonly Pick<Step, 'source' | 'target' | 'action_id'>[]
}

export function pathHighlight(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  path: PathLike | null | undefined,
): PathHighlight | null {
  if (!path) return null
  const pathId = path.source_id
  const resourceOf = new Map(nodes.map((node) => [node.key, node.resource ?? node.key]))
  const onPath = edges.filter((edge) => edge.path_ids.includes(pathId))

  const edgeKeys = new Set(onPath.map((edge) => edge.key))
  const nodeKeys = new Set(onPath.flatMap((edge) => [edge.source, edge.target]))
  const stepsByEdge = new Map<string, number[]>()
  const edgesByStep: string[][] = []
  const entryKeys = new Set<string>()

  // Where the attacker stands; null before the first step matches.
  let at: Set<string> | null = null
  path.steps.forEach((step, index) => {
    const fits = (edge: GraphEdge) =>
      resourceOf.get(edge.source) === step.source &&
      resourceOf.get(edge.target) === step.target &&
      (edge.action_id === null || edge.action_id === step.action_id)
    const from = at
    let matches = onPath.filter((edge) => fits(edge) && (from === null || from.has(edge.source)))
    // Lost the thread (an unmapped step before this one): match on resources alone.
    if (matches.length === 0 && from !== null) matches = onPath.filter(fits)
    edgesByStep.push(matches.map((edge) => edge.key))
    if (matches.length === 0) {
      at = null
      return
    }
    for (const edge of matches) {
      const numbers = stepsByEdge.get(edge.key) ?? []
      numbers.push(index + 1)
      stepsByEdge.set(edge.key, numbers)
      if (index === 0) entryKeys.add(edge.source)
    }
    at = new Set(matches.map((edge) => edge.target))
  })

  return {
    pathId,
    edgeKeys,
    nodeKeys,
    stepsByEdge,
    edgesByStep,
    entryKeys,
    mapped: onPath.length > 0,
    complete: path.steps.length > 0 && edgesByStep.every((keys) => keys.length > 0),
  }
}

/** Paths for the picker: exported ones first, each group by rank. */
export function orderedPaths<T extends Pick<Path, 'exported' | 'rank'>>(paths: readonly T[]): T[] {
  return [...paths].sort((a, b) => Number(b.exported) - Number(a.exported) || a.rank - b.rank)
}

/**
 * Where each path ends in this drawing: the node its last drawn step arrives
 * at. These are the targets a view must keep in sight when it cannot show
 * everything.
 */
export function pathEnds(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  paths: readonly PathLike[],
): Set<string> {
  const targets = new Map(edges.map((edge) => [edge.key, edge.target]))
  const ends = new Set<string>()
  for (const path of paths) {
    const highlight = pathHighlight(nodes, edges, path)
    const steps = highlight?.edgesByStep.filter((keys) => keys.length > 0) ?? []
    for (const key of steps[steps.length - 1] ?? []) {
      const target = targets.get(key)
      if (target) ends.add(target)
    }
  }
  return ends
}
