import { describe, expect, it } from 'vitest'

import type { GraphEdge, GraphNode } from '@/api/types'

import { sampleAttack } from './__fixtures__/sample-attack'
import { samplePaths } from './__fixtures__/sample-paths'
import { sampleState } from './__fixtures__/sample-state'
import { buildFlow, edgeTone } from './flow'
import { orderedPaths, pathHighlight } from './highlight'
import { layoutGraph } from './layout'

function path(id: string) {
  const found = samplePaths.find((p) => p.source_id === id)
  if (!found) throw new Error(id)
  return found
}

function edge(
  key: string,
  source: string,
  target: string,
  extra: Partial<GraphEdge> = {},
): GraphEdge {
  return {
    key,
    source,
    target,
    label: key,
    categories: ['identity'],
    reversed: false,
    path_ids: [],
    action_id: null,
    tactic: null,
    technique: null,
    ...extra,
  }
}

function state(key: string, resource: string | null): GraphNode {
  return {
    key,
    label_lines: [resource ?? 'Attacker'],
    style: 'high',
    is_entry: false,
    resource,
    facts: [],
  }
}

describe('pathHighlight on the attack view', () => {
  it('lights AP-001 along its four exact moves, numbered in order', () => {
    const lit = pathHighlight(sampleAttack.nodes, sampleAttack.edges, path('AP-001'))
    expect(lit?.mapped).toBe(true)
    expect(lit?.complete).toBe(true)
    expect(lit?.edgesByStep).toEqual([['e0'], ['e1'], ['e4'], ['e6']])
    expect(Object.fromEntries(lit?.stepsByEdge ?? [])).toEqual({
      e0: [1],
      e1: [2],
      e4: [3],
      e6: [4],
    })
    expect([...(lit?.nodeKeys ?? [])].sort()).toEqual(['s10', 's12', 's2', 's3', 's8'])
    expect([...(lit?.entryKeys ?? [])]).toEqual(['s2'])
  })

  it('maps every step of every sample path to exactly one move', () => {
    let steps = 0
    for (const p of samplePaths) {
      const lit = pathHighlight(sampleAttack.nodes, sampleAttack.edges, p)
      expect(lit?.complete, p.source_id).toBe(true)
      for (const keys of lit?.edgesByStep ?? []) expect(keys, p.source_id).toHaveLength(1)
      steps += p.steps.length
    }
    expect(steps).toBe(97)
  })

  it('does not light the parallel move a path did not take', () => {
    // e9 and e10 both run s11 -> s15; AP-007 uses the attached identity, not pass-role.
    const lit = pathHighlight(sampleAttack.nodes, sampleAttack.edges, path('AP-007'))
    expect(lit?.edgeKeys.has('e9')).toBe(true)
    expect(lit?.edgeKeys.has('e10')).toBe(false)
  })
})

describe('pathHighlight on the state view', () => {
  it('lights AP-001 resource by resource', () => {
    const lit = pathHighlight(sampleState.nodes, sampleState.edges, path('AP-001'))
    expect(lit?.edgesByStep).toEqual([
      ['OpenSecurityGroup->PublicEC2Instance'],
      ['PublicEC2Instance->OverPermissiveInstanceProfile'],
      ['OverPermissiveInstanceProfile->OverPermissiveRole'],
      ['OverPermissiveRole->InsecureS3Bucket'],
    ])
    expect(lit?.complete).toBe(true)
    expect(lit?.nodeKeys.size).toBe(5)
  })

  it('maps every sample path completely', () => {
    for (const p of samplePaths) {
      expect(pathHighlight(sampleState.nodes, sampleState.edges, p)?.complete, p.source_id).toBe(
        true,
      )
    }
  })
})

describe('pathHighlight edge cases', () => {
  it('returns null without a path', () => {
    expect(pathHighlight(sampleState.nodes, sampleState.edges, null)).toBeNull()
  })

  it('draws nothing for a path the backend could not map', () => {
    const lit = pathHighlight(sampleAttack.nodes, sampleAttack.edges, {
      source_id: 'AP-999',
      steps: [{ source: 'OpenSecurityGroup', target: 'PublicEC2Instance', action_id: 'X' }],
    })
    expect(lit?.mapped).toBe(false)
    expect(lit?.complete).toBe(false)
    expect(lit?.edgeKeys.size).toBe(0)
    expect(lit?.edgesByStep).toEqual([[]])
  })

  it('follows the state the attacker reached when one resource pair appears twice', () => {
    // Two states of B, each with a move to C. Only the one the path stood on counts.
    const nodes = [
      state('a', 'A'),
      state('b1', 'B'),
      state('b2', 'B'),
      state('c1', 'C'),
      state('c2', 'C'),
    ]
    const edges = [
      edge('ab', 'a', 'b1', { path_ids: ['AP-1'], action_id: 'MOVE' }),
      edge('bc1', 'b1', 'c1', { path_ids: ['AP-1'], action_id: 'READ' }),
      edge('bc2', 'b2', 'c2', { path_ids: ['AP-1'], action_id: 'READ' }),
    ]
    const lit = pathHighlight(nodes, edges, {
      source_id: 'AP-1',
      steps: [
        { source: 'A', target: 'B', action_id: 'MOVE' },
        { source: 'B', target: 'C', action_id: 'READ' },
      ],
    })
    expect(lit?.edgesByStep).toEqual([['ab'], ['bc1']])
    expect(lit?.stepsByEdge.has('bc2')).toBe(false)
  })

  it('numbers an edge walked twice with both steps', () => {
    const nodes = [state('a', 'A'), state('b', 'B')]
    const edges = [
      edge('ab', 'a', 'b', { path_ids: ['AP-1'] }),
      edge('ba', 'b', 'a', { path_ids: ['AP-1'] }),
    ]
    const lit = pathHighlight(nodes, edges, {
      source_id: 'AP-1',
      steps: [
        { source: 'A', target: 'B', action_id: null },
        { source: 'B', target: 'A', action_id: null },
        { source: 'A', target: 'B', action_id: null },
      ],
    })
    expect(lit?.stepsByEdge.get('ab')).toEqual([1, 3])
    expect(lit?.stepsByEdge.get('ba')).toEqual([2])
  })
})

describe('orderedPaths', () => {
  it('lists exported paths first, each group by rank', () => {
    const ordered = orderedPaths([
      { exported: false, rank: 2 },
      { exported: true, rank: 3 },
      { exported: false, rank: 1 },
      { exported: true, rank: 1 },
    ])
    expect(ordered).toEqual([
      { exported: true, rank: 1 },
      { exported: true, rank: 3 },
      { exported: false, rank: 1 },
      { exported: false, rank: 2 },
    ])
  })
})

describe('buildFlow with a highlight', () => {
  const layout = layoutGraph(sampleAttack)
  const highlight = pathHighlight(sampleAttack.nodes, sampleAttack.edges, path('AP-001'))
  const flow = buildFlow({
    nodes: layout.nodes,
    edges: layout.edges,
    highlight,
    hoveredNode: null,
    hoveredEdges: new Set(),
    spotlight: new Set(),
    onEdgeHoverChange: () => undefined,
    ariaLabel: (placed) => placed.key,
  })

  it('emphasises path edges, including the attacker start into its entry, and dims the rest', () => {
    const tones = Object.fromEntries(flow.edges.map((e) => [e.id, e.data?.tone]))
    expect(tones.e0).toBe('path')
    expect(tones.e6).toBe('path')
    expect(tones['start:s2']).toBe('path')
    expect(tones.e2).toBe('dim')
    expect(tones['start:s6']).toBe('dim')
    expect(flow.edges.find((e) => e.id === 'e4')?.data?.steps).toEqual([3])
  })

  it('dims nodes off the path but never the attacker', () => {
    const dimmed = (key: string) => flow.nodes.find((n) => n.id === key)?.data.dimmed
    expect(dimmed('s0')).toBe(false)
    expect(dimmed('s10')).toBe(false)
    expect(dimmed('s15')).toBe(true)
  })

  it('treats nodes as measured, so the canvas can fit before the browser measures', () => {
    for (const n of flow.nodes) expect(n.measured).toEqual({ width: n.width, height: n.height })
  })

  it('draws hover above default and below the path', () => {
    const placed = layout.edges.find((e) => e.key === 'e2')
    if (!placed) throw new Error('e2')
    expect(edgeTone(placed, null, 's6', new Set())).toBe('hover')
    expect(edgeTone(placed, null, null, new Set(['e2']))).toBe('hover')
    expect(edgeTone(placed, null, null, new Set())).toBe('default')
    expect(edgeTone(placed, highlight, 's6', new Set())).toBe('hover')
  })
})
