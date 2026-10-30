import { describe, expect, it } from 'vitest'

import type { GraphNode, GraphView } from '@/api/types'

import { nestedState } from './__fixtures__/nested-state'
import { sampleAttack } from './__fixtures__/sample-attack'
import { sampleState } from './__fixtures__/sample-state'
import { factRowText, interWidth, monoWidth, sortedFacts, wrapIdentifier, wrapText } from './labels'
import {
  anchorRoute,
  arrowheadPath,
  edgePath,
  factSuffix,
  factSummary,
  layoutGraph,
  METRICS,
  nodeLines,
  nodeSize,
  stackParents,
  stateFacts,
  type Box,
  type GraphLayout,
} from './layout'

function overlaps(a: Box, b: Box) {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height
}

function expectNoOverlaps(layout: GraphLayout) {
  const boxes = layout.nodes.filter((node) => node.kind !== 'group')
  for (let i = 0; i < boxes.length; i += 1) {
    for (let j = i + 1; j < boxes.length; j += 1) {
      const a = boxes[i]
      const b = boxes[j]
      if (a && b) expect(overlaps(a, b), `${a.key} overlaps ${b.key}`).toBe(false)
    }
  }
}

function node(overrides: Partial<GraphNode> & Pick<GraphNode, 'key'>): GraphNode {
  return {
    label_lines: [overrides.key, 'AWS::IAM::Role'],
    style: 'high',
    is_entry: false,
    resource: overrides.key,
    facts: null,
    ...overrides,
  }
}

describe('text wrapping', () => {
  const mono = (s: string) => monoWidth(s, 12)

  it('breaks identifiers at CamelCase boundaries and keeps every character', () => {
    const lines = wrapIdentifier('OverPermissiveInstanceProfile', 150, mono)
    expect(lines).toEqual(['OverPermissive', 'InstanceProfile'])
    expect(lines.join('')).toBe('OverPermissiveInstanceProfile')
    expect(wrapIdentifier('DeploymentRole', 150, mono)).toEqual(['DeploymentRole'])
    expect(wrapIdentifier('Network.OpenGroup', 100, mono)).toEqual(['Network.', 'OpenGroup'])
  })

  it('cuts a single piece wider than a line', () => {
    const id = 'a'.repeat(40)
    const lines = wrapIdentifier(id, 150, mono)
    expect(lines.length).toBeGreaterThan(1)
    expect(lines.join('')).toBe(id)
    for (const line of lines) expect(mono(line)).toBeLessThanOrEqual(150)
  })

  it('wraps words and ellipsises what does not fit the line budget', () => {
    const measure = (s: string) => interWidth(s, 11)
    expect(wrapText('ElasticLoadBalancingV2 LoadBalancer', 150, measure, 2)).toEqual([
      'ElasticLoadBalancingV2',
      'LoadBalancer',
    ])
    const cut = wrapText('one two three four five six seven eight nine ten', 40, measure, 2)
    expect(cut).toHaveLength(2)
    expect(cut[1]?.endsWith('…')).toBe(true)
  })
})

describe('node sizes', () => {
  it('sizes a box from its wrapped lines, never past the header width', () => {
    const short = nodeLines(node({ key: 'Role' }))
    const long = nodeLines(node({ key: 'OverPermissiveInstanceProfile' }))
    const small = nodeSize('resource', short, null)
    const tall = nodeSize('resource', long, null)
    expect(long.title.join('')).toBe('OverPermissiveInstanceProfile')
    expect(long.title.length).toBeGreaterThan(1)
    expect(tall.height).toBe(small.height + (long.title.length - 1) * METRICS.titleLineHeight)
    expect(tall.width).toBeGreaterThan(small.width)
    expect(tall.width).toBeLessThanOrEqual(METRICS.headerMaxWidth + 2 * METRICS.nodePadX + 2)
    expect(small.width).toBeGreaterThanOrEqual(METRICS.minNodeWidth)
  })

  it('does not repeat the severity word or [entry] as text', () => {
    const lines = nodeLines(
      node({
        key: 'Bucket',
        label_lines: ['Bucket', 'AWS::S3::Bucket', 'high', '[entry]', 'note'],
      }),
    )
    expect(lines).toEqual({ title: ['Bucket'], type: ['S3 Bucket'], extra: ['note'] })
  })

  it('adds a row per gained fact and counts the carried-over ones after the last', () => {
    const lines = nodeLines(node({ key: 'Role' }))
    const header = nodeSize('state', lines, stateFacts([], []))
    const facts = stateFacts(
      ['credential(Role)', 'foothold(Box)', 'internet_reachable'],
      [['foothold(Box)', 'internet_reachable']],
    )
    expect(facts.gained.map((fact) => fact.raw)).toEqual(['credential(Role)'])
    expect(facts.carried).toBe(2)
    expect(factSummary(facts)).toBeNull()
    expect(factSuffix(facts)).toBe('+2')
    const withFacts = nodeSize('state', lines, facts)
    expect(withFacts.height).toBe(
      header.height + 2 * METRICS.factPadY + METRICS.factRowHeight + METRICS.border,
    )
  })

  it('gives the carried-over count a row of its own when nothing was gained', () => {
    const facts = stateFacts(['foothold(Box)'], [['foothold(Box)']])
    expect(facts.gained).toEqual([])
    expect(factSummary(facts)).toBe('1 carried over')
    expect(factSuffix(facts)).toBeNull()
  })

  it('names the kind, not the resource, for a fact about the box itself', () => {
    const facts = sortedFacts(['credential(Role)', 'foothold(Box)'])
    const own = facts.find((fact) => fact.subject === 'Role')
    const other = facts.find((fact) => fact.subject === 'Box')
    expect(own && factRowText(own, 'Role')).toEqual({ text: 'credentials', mono: false })
    expect(other && factRowText(other, 'Role')).toEqual({ text: 'Box', mono: true })
  })

  it('counts a fact as gained unless every way in already held it', () => {
    const facts = stateFacts(['a', 'b', 'c'], [['a', 'b'], ['a']])
    expect(facts.gained.map((fact) => fact.raw)).toEqual(['b', 'c'])
    expect(facts.carried).toBe(1)
  })
})

describe('layoutGraph: the state view sample', () => {
  const layout = layoutGraph(sampleState)

  it('places every node and edge, none overlapping', () => {
    expect(layout.nodes).toHaveLength(15)
    expect(layout.edges).toHaveLength(15)
    expect(layout.edges.filter((edge) => edge.edge?.reversed)).toHaveLength(2)
    expectNoOverlaps(layout)
  })

  it('runs left to right: forward edges leave a right side and enter a left side', () => {
    const forward = layout.edges.filter((edge) => edge.key !== 'DeploymentRole->AppServerRole')
    for (const edge of forward) {
      const source = layout.nodes.find((n) => n.key === edge.source)
      const target = layout.nodes.find((n) => n.key === edge.target)
      if (!source || !target) throw new Error(edge.key)
      expect(source.x + source.width, edge.key).toBeLessThan(target.x)
      expect(edge.points[0]).toEqual({
        x: source.x + source.width,
        y: source.y + source.height / 2,
      })
      expect(edge.points.at(-1)).toEqual({ x: target.x, y: target.y + target.height / 2 })
      expect(edge.startDir).toEqual({ x: 1, y: 0 })
      expect(edge.endDir).toEqual({ x: 1, y: 0 })
    }
  })

  it('gives every edge its own slot', () => {
    const slots = layout.edges.map((edge) => edge.label)
    for (const slot of slots) {
      expect(slot).not.toBeNull()
      for (const placed of layout.nodes) {
        if (slot) expect(overlaps(slot, placed), placed.key).toBe(false)
      }
    }
  })

  it('carries the edge text for hover', () => {
    const reversed = layout.edges.find(
      (edge) => edge.key === 'OpenSecurityGroup->PublicEC2Instance',
    )
    expect(reversed?.label?.lines).toEqual(['network control'])
    const merged = layout.edges.find((edge) => edge.key === 'AppServerRole->DeploymentRole')
    expect(merged?.label?.lines).toEqual(['escalation + identity'])
  })

  it('is deterministic', () => {
    expect(layoutGraph(sampleState)).toEqual(layout)
  })
})

describe('layoutGraph: the attack view sample', () => {
  const layout = layoutGraph(sampleAttack)
  const byKey = new Map(layout.nodes.map((n) => [n.key, n]))

  it('places all 22 states and 19 moves without overlaps', () => {
    expect(layout.nodes).toHaveLength(22)
    expect(layout.edges.filter((edge) => edge.kind === 'move')).toHaveLength(19)
    expectNoOverlaps(layout)
  })

  it('draws the attacker root small, leftmost, and joined to the entry states nothing else reaches', () => {
    const attacker = byKey.get('s0')
    expect(attacker?.kind).toBe('attacker')
    expect(attacker?.width).toBe(METRICS.attackerWidth)
    for (const placed of layout.nodes) {
      if (placed.key !== 's0') expect(placed.x).toBeGreaterThan(attacker?.x ?? Infinity)
    }
    const starts = layout.edges.filter((edge) => edge.kind === 'start').map((edge) => edge.target)
    // s3 and s7 are entry states too, but each is reached by a move from its security group.
    expect(starts.sort()).toEqual(['s1', 's2', 's4', 's5', 's6'])
  })

  it('draws parallel moves between one pair as separate curves with separate slots', () => {
    for (const [a, b] of [
      ['e9', 'e10'],
      ['e17', 'e18'],
    ] as const) {
      const first = layout.edges.find((edge) => edge.key === a)
      const second = layout.edges.find((edge) => edge.key === b)
      expect(first?.source).toBe(second?.source)
      expect(first?.target).toBe(second?.target)
      expect(first?.label?.y).not.toBe(second?.label?.y)
      expect(
        edgePath(
          first?.points ?? [],
          first?.startDir ?? { x: 1, y: 0 },
          first?.endDir ?? { x: 1, y: 0 },
        ),
      ).not.toBe(
        edgePath(
          second?.points ?? [],
          second?.startDir ?? { x: 1, y: 0 },
          second?.endDir ?? { x: 1, y: 0 },
        ),
      )
      expect(first?.label?.lines).not.toEqual(second?.label?.lines)
    }
  })

  it('shows what each move gained and counts what carried over', () => {
    const role = byKey.get('s10')?.facts
    expect(role?.gained.map((fact) => fact.raw)).toEqual(['credential(OverPermissiveRole)'])
    expect(role?.carried).toBe(3)
    const entry = byKey.get('s4')?.facts
    // The Entry tab says "reachable from the internet"; the rows do not repeat it.
    expect(entry?.gained.map((fact) => fact.raw)).toEqual([
      'foothold(PublicRDS)',
      'data_access(PublicRDS)',
    ])
    expect(entry?.all.map((fact) => fact.raw)).toContain('internet_reachable')
    expect(entry?.carried).toBe(0)
    expect(byKey.get('s0')?.facts).toBeNull()
  })

  it('labels moves with the action and its tactic and technique', () => {
    const move = layout.edges.find((edge) => edge.key === 'e1')
    expect(move?.label?.lines.join(' ')).toBe(
      'Read role credentials from the instance metadata service',
    )
    expect(move?.label?.meta).toBe('Credential access · T1552.005')
  })
})

describe('layoutGraph: nested stacks', () => {
  it('finds stacks that prefix other resources and no edge touches', () => {
    const { parents, groups } = stackParents(nestedState.nodes, nestedState.edges)
    expect([...groups].sort()).toEqual(['Data', 'Network', 'Web'])
    expect(parents.get('Web.WebRole')).toBe('Web')
    expect(parents.has('Web')).toBe(false)
  })

  it('draws each stack as a box around its resources, under them', () => {
    const layout = layoutGraph(nestedState)
    const groups = layout.nodes.filter((n) => n.kind === 'group')
    expect(groups.map((g) => g.key).sort()).toEqual(['Data', 'Network', 'Web'])
    expect(layout.nodes.slice(0, 3).every((n) => n.kind === 'group')).toBe(true)
    for (const child of layout.nodes.filter((n) => n.parent)) {
      const group = groups.find((g) => g.key === child.parent)
      if (!group) throw new Error(child.key)
      expect(child.x).toBeGreaterThan(group.x)
      expect(child.x + child.width).toBeLessThan(group.x + group.width)
      // Room above for the stack's title.
      expect(child.y - group.y).toBeGreaterThanOrEqual(METRICS.groupHeader + 8)
      expect(child.y + child.height).toBeLessThan(group.y + group.height)
    }
    expectNoOverlaps(layout)
  })

  it('leaves a stack that an edge touches as an ordinary box', () => {
    const view: GraphView = {
      ...nestedState,
      edges: [
        ...nestedState.edges,
        {
          key: 'Web->Data',
          source: 'Web',
          target: 'Data',
          label: 'connection',
          categories: ['connection'],
          reversed: false,
          path_ids: [],
          action_id: null,
          tactic: null,
          technique: null,
        },
      ],
    }
    const { groups } = stackParents(view.nodes, view.edges)
    expect([...groups]).toEqual(['Network'])
  })
})

describe('edge geometry', () => {
  it('anchors routes on facing sides, either direction', () => {
    const a = { x: 0, y: 0, width: 100, height: 40 }
    const b = { x: 300, y: 100, width: 100, height: 40 }
    const forward = anchorRoute(
      [
        { x: 100, y: 20 },
        { x: 200, y: 80 },
        { x: 300, y: 120 },
      ],
      a,
      b,
    )
    expect(forward.points[0]).toEqual({ x: 100, y: 20 })
    expect(forward.points.at(-1)).toEqual({ x: 300, y: 120 })
    const back = anchorRoute(
      [
        { x: 300, y: 120 },
        { x: 200, y: 80 },
        { x: 100, y: 20 },
      ],
      b,
      a,
    )
    expect(back.points[0]).toEqual({ x: 300, y: 120 })
    expect(back.startDir).toEqual({ x: -1, y: 0 })
    expect(back.endDir).toEqual({ x: -1, y: 0 })
  })

  it('draws level-tangent cubics and stops short of the arrowhead', () => {
    const d = edgePath(
      [
        { x: 0, y: 0 },
        { x: 100, y: 50 },
      ],
      { x: 1, y: 0 },
      { x: 1, y: 0 },
      10,
    )
    expect(d).toBe('M 0 0 C 45 0 45 50 90 50')
    expect(edgePath([], { x: 1, y: 0 }, { x: 1, y: 0 })).toBe('')
  })

  it('points the arrowhead along the arrival direction', () => {
    expect(arrowheadPath({ x: 10, y: 0 }, { x: 1, y: 0 }, 10, 4)).toBe('M 10 0 L 0 4 L 0 -4 Z')
  })
})
