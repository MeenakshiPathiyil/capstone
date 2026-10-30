import { describe, expect, it } from 'vitest'

import type { Finding, FixImpact, Path, ScoreBreakdown } from '@/api/types'

import { sampleRiskPaths } from './__fixtures__/sample-risk'
import { sampleScoredFindings, sampleScoredPaths } from './__fixtures__/sample-scoring'

import {
  alternativePreconditions,
  capabilityText,
  chainNodes,
  contextualFormula,
  contextualFormulaTemplate,
  contextualRankText,
  contextualTieText,
  effectiveFixes,
  evidenceChips,
  findingSearchText,
  fixAddedText,
  fixRemovedText,
  fixScopeText,
  FIX_REMOVED_LABEL,
  graphUrl,
  groupPathsByChain,
  hopsLabel,
  lengthFactorText,
  LENGTH_DECAY,
  lengthDecay,
  levelBandsText,
  parseTechniqueList,
  pathDetailUrl,
  pathsThroughResource,
  reachabilityDetail,
  reachabilityLabel,
  reportPath,
  RISK_EXPONENTS,
  riskMetadata,
  scoreFormula,
  scoreFormulaTemplate,
  SEVERITY_WEIGHTS,
  severityWeightsText,
  selectedPathsText,
  stepTechnique,
  techniqueNames,
  topScore,
  warningTitle,
  withResourceParam,
} from './analysis'

function path(overrides: Partial<Path> & Pick<Path, 'source_id' | 'rank' | 'chain_group'>): Path {
  return {
    exported: true,
    entry_id: 'A',
    target_id: 'C',
    hops: ['A', 'B', 'C'],
    length: 2,
    public_entry: true,
    objective: 'data_theft',
    objective_name: 'Data theft',
    objective_techniques: [],
    score: 40,
    attack_level: 'CRITICAL',
    breakdown: breakdown(),
    steps: [],
    finding_ids: [],
    export: null,
    risk: null,
    ...overrides,
  }
}

function breakdown(overrides: Partial<ScoreBreakdown> = {}): ScoreBreakdown {
  return {
    severity_total: 68,
    objective_weight: 5,
    hops: 4,
    length_factor: 0.85 ** 3,
    public_entry: true,
    boost: 1.25,
    score: 56.04,
    threshold_high: 30,
    threshold_critical: 40,
    ...overrides,
  }
}

function fix(overrides: Partial<FixImpact> = {}): FixImpact {
  return {
    finding_id: 'R::RULE',
    selected_paths_removed: 2,
    selected_paths_remaining: 17,
    selected_paths_added: 0,
    baseline_selected_paths: 19,
    removed_ids: ['AP-016', 'AP-017'],
    added_paths: [],
    scope_top: 5,
    ...overrides,
  }
}

describe('groupPathsByChain', () => {
  it('groups identical chains in order of their best rank, paths by rank', () => {
    const paths = [
      path({ source_id: 'AP-013', rank: 13, chain_group: 5 }),
      path({ source_id: 'AP-002', rank: 2, chain_group: 1, hops: ['X', 'Y'] }),
      path({ source_id: 'AP-009', rank: 9, chain_group: 5 }),
      path({ source_id: 'AP-001', rank: 1, chain_group: 1, hops: ['X', 'Y'] }),
      path({ source_id: 'AP-006', rank: 6, chain_group: 3 }),
    ]
    const groups = groupPathsByChain(paths)
    expect(groups.map((g) => g.group)).toEqual([1, 3, 5])
    expect(groups[0]?.hops).toEqual(['X', 'Y'])
    expect(groups[0]?.paths.map((p) => p.source_id)).toEqual(['AP-001', 'AP-002'])
    expect(groups[2]?.paths.map((p) => p.source_id)).toEqual(['AP-009', 'AP-013'])
  })

  it('returns no groups for no paths', () => {
    expect(groupPathsByChain([])).toEqual([])
  })
})

describe('path helpers', () => {
  it('finds the top score, 0 for none', () => {
    expect(topScore([{ score: 30 }, { score: 56.04 }, { score: 41 }])).toBe(56.04)
    expect(topScore([])).toBe(0)
  })

  it('lists the paths through a resource by rank', () => {
    const paths = [
      path({ source_id: 'AP-003', rank: 3, chain_group: 2, hops: ['A', 'Q'] }),
      path({ source_id: 'AP-001', rank: 1, chain_group: 1, hops: ['Q', 'B'] }),
      path({ source_id: 'AP-002', rank: 2, chain_group: 1, hops: ['A', 'B'] }),
    ]
    expect(pathsThroughResource(paths, 'Q').map((p) => p.source_id)).toEqual(['AP-001', 'AP-003'])
    expect(pathsThroughResource(paths, 'Z')).toEqual([])
  })

  it('draws a chain in severity colours with the first hop as the entry', () => {
    const resources = new Map([
      ['A', { type: 'AWS::EC2::SecurityGroup', max_severity: 'high' as const }],
      ['B', { type: 'AWS::IAM::InstanceProfile', max_severity: null }],
    ])
    expect(chainNodes(['A', 'B', 'Gone'], resources)).toEqual([
      { id: 'A', type: 'AWS::EC2::SecurityGroup', tone: 'high', isEntry: true },
      { id: 'B', type: 'AWS::IAM::InstanceProfile', tone: 'clean', isEntry: false },
      { id: 'Gone', type: undefined, tone: 'unknown', isEntry: false },
    ])
  })

  it('labels hops', () => {
    expect(hopsLabel(1)).toBe('1 hop')
    expect(hopsLabel(6)).toBe('6 hops')
  })
})

describe('score breakdown', () => {
  it('fills the formula with the real numbers', () => {
    expect(scoreFormula(breakdown())).toBe('(68 + 5) × 0.85^3 × 1.25 = 56.04')
  })

  it('leaves out the boost for a non-public entry and keeps two decimals on the score', () => {
    expect(
      scoreFormula(
        breakdown({
          public_entry: false,
          boost: 1,
          score: 30,
          severity_total: 26,
          hops: 1,
          length_factor: 1,
          objective_weight: 4,
        }),
      ),
    ).toBe('(26 + 4) × 0.85^0 = 30.00')
  })

  it('prints a length factor that does not match the decay as a number', () => {
    expect(lengthFactorText({ hops: 3, length_factor: 0.5 })).toBe('0.5')
    expect(lengthFactorText({ hops: 6, length_factor: 0.85 ** 5 })).toBe('0.85^5')
  })

  it('describes the level bands', () => {
    expect(levelBandsText(breakdown())).toBe(
      'Critical at 40 and above, High at 30 and above, Medium below.',
    )
  })
})

describe('fix impact wording', () => {
  it('keeps the plan wording for the removed count', () => {
    expect(FIX_REMOVED_LABEL).toBe(
      'Paths no longer at or above the selected risk level after suppressing this finding',
    )
  })

  it('formats removed and added counts', () => {
    expect(fixRemovedText(fix())).toBe('2 of 19')
    expect(fixAddedText(fix())).toBeNull()
    expect(fixAddedText(fix({ selected_paths_added: 1 }))).toBe('1 newly selected path')
    expect(fixAddedText(fix({ selected_paths_added: 3 }))).toBe('3 newly selected paths')
  })

  it('keeps only fixes that change the selected set, in order', () => {
    const results = [
      fix({ finding_id: 'a' }),
      fix({ finding_id: 'b', selected_paths_removed: 0 }),
      fix({ finding_id: 'c', selected_paths_removed: 0, selected_paths_added: 1 }),
    ]
    expect(effectiveFixes(results).map((f) => f.finding_id)).toEqual(['a', 'c'])
  })

  it('names the scope', () => {
    expect(fixScopeText(5)).toBe('the top 5 paths')
    expect(fixScopeText(1)).toBe('the top 1 path')
    expect(fixScopeText(null)).toBe('all selected paths')
  })
})

describe('techniques', () => {
  it('parses an export technique list, names with commas and colons included', () => {
    const names = parseTechniqueList(
      'T1190 - Exploit Public-Facing Application, T1552.005 - Unsecured Credentials: Cloud Instance Metadata API, T1078.004 - Valid Accounts: Cloud Accounts, T9999 - One, two and three',
    )
    expect(names.get('T1190')).toBe('Exploit Public-Facing Application')
    expect(names.get('T1552.005')).toBe('Unsecured Credentials: Cloud Instance Metadata API')
    expect(names.get('T1078.004')).toBe('Valid Accounts: Cloud Accounts')
    expect(names.get('T9999')).toBe('One, two and three')
    expect(parseTechniqueList('').size).toBe(0)
  })

  it('collects names from rules first, then exports', () => {
    const finding = {
      rule: { attack_techniques: [{ id: 'T1190', name: 'From rule' }] },
    } as unknown as Finding
    const exported = path({
      source_id: 'AP-001',
      rank: 1,
      chain_group: 1,
      export: {
        source_id: 'AP-001',
        source_name: 'A -> B',
        industry: 'x',
        attack_level: 'CRITICAL',
        techniques: 'T1190 - From export, T1530 - Data from Cloud Storage',
        surfaces: '',
        objective: 'Data theft',
      },
    })
    const names = techniqueNames({ findings: [finding], paths: [exported] })
    expect(names.get('T1190')).toBe('From rule')
    expect(names.get('T1530')).toBe('Data from Cloud Storage')
  })

  it('links a step technique only when it is a technique id', () => {
    const names = new Map([['T1552.005', 'Cloud Instance Metadata API']])
    expect(stepTechnique({ technique: 'T1552.005' }, names)).toEqual({
      id: 'T1552.005',
      name: 'Cloud Instance Metadata API',
      url: 'https://attack.mitre.org/techniques/T1552/005/',
    })
    expect(stepTechnique({ technique: 'T1530' }, names)).toEqual({
      id: 'T1530',
      name: null,
      url: 'https://attack.mitre.org/techniques/T1530/',
    })
    expect(stepTechnique({ technique: 'custom' }, names)?.url).toBeNull()
    expect(stepTechnique({ technique: null }, names)).toBeNull()
    expect(stepTechnique({ technique: '  ' }, names)).toBeNull()
  })
})

describe('steps', () => {
  const step = { source: 'OpenSecurityGroup', target: 'PublicEC2Instance' }
  const none = { end: null, source_id: null, source_id_prefix: null, state: null, semantic: null }

  it('describes a required capability and where it must be found', () => {
    expect(
      capabilityText({ ...none, end: 'source', source_id: ['INCOMING_SSH_DISABLED'] }, step),
    ).toBe('INCOMING_SSH_DISABLED on OpenSecurityGroup')
    expect(
      capabilityText(
        { ...none, end: 'target', state: ['a', 'b'], source_id_prefix: ['IAM_'] },
        step,
      ),
    ).toBe('IAM_* or a or b on PublicEC2Instance')
    expect(capabilityText({ ...none, semantic: ['exposure'] }, step)).toBe('any exposure finding')
    expect(capabilityText(none, step)).toBe('a finding')
  })

  it('lists unused precondition alternatives', () => {
    expect(
      alternativePreconditions({
        precondition: ['credential(X)'],
        precondition_options: ['foothold(X)', 'credential(X)'],
      }),
    ).toEqual(['foothold(X)'])
    expect(alternativePreconditions({ precondition: ['a'], precondition_options: ['a'] })).toEqual(
      [],
    )
  })

  it('turns any evidence value into chips', () => {
    expect(evidenceChips(['0.0.0.0/0'])).toEqual(['0.0.0.0/0'])
    expect(evidenceChips([22, 3389])).toEqual(['22', '3389'])
    expect(evidenceChips('v1')).toEqual(['v1'])
    expect(evidenceChips(false)).toEqual(['false'])
    expect(evidenceChips(null)).toEqual([])
    expect(evidenceChips('')).toEqual([])
    expect(evidenceChips([['a'], 'b'])).toEqual(['a', 'b'])
    expect(evidenceChips({ k: 1 })).toEqual(['{"k":1}'])
  })
})

describe('links', () => {
  it('builds report, detail and graph urls', () => {
    expect(reportPath('abc', 5)).toBe('/analyses/abc/report.pdf?top=5')
    expect(reportPath('abc', 'all')).toBe('/analyses/abc/report.pdf?top=all')
    expect(pathDetailUrl('abc', 'AP-001')).toBe('/analysis/abc/paths/AP-001')
    expect(graphUrl('abc', 'AP-001')).toBe('/analysis/abc?tab=graph&path=AP-001')
  })

  it('opens and closes the resource sheet without touching other params', () => {
    const params = new URLSearchParams('tab=findings')
    const opened = withResourceParam(params, 'OpenSecurityGroup')
    expect(opened.toString()).toBe('tab=findings&resource=OpenSecurityGroup')
    expect(params.toString()).toBe('tab=findings')
    expect(withResourceParam(opened, null).toString()).toBe('tab=findings')
  })
})

describe('labels', () => {
  it('counts selected paths against the minimum level', () => {
    expect(selectedPathsText(19, 'HIGH')).toBe('19 at or above High')
  })

  it('titles warnings and falls back for unknown kinds', () => {
    expect(warningTitle('orphan_finding')).toBe('Finding not used')
    expect(warningTitle('transform_unexpanded')).toBe('Transform not expanded')
    expect(warningTitle('something_new')).toBe('Notice')
  })

  it('searches every visible field of a finding', () => {
    const finding = {
      resource: 'OpenSecurityGroup',
      resource_type: 'AWS::EC2::SecurityGroup',
      rule_id: 'aws_config:INCOMING_SSH_DISABLED',
      source_id: 'INCOMING_SSH_DISABLED',
      semantic: null,
      rule: {
        display_name: 'Security group allows unrestricted SSH',
        attack_techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
      },
    } as unknown as Finding
    const text = findingSearchText(finding)
    expect(text).toContain('opensecuritygroup')
    expect(text).toContain('unrestricted ssh')
    expect(text).toContain('t1190')
    expect(text).toContain('exploit public-facing')
  })
})

describe('score breakdown against the API', () => {
  const weights = new Map<string, number>(SEVERITY_WEIGHTS)
  const findings = new Map(sampleScoredFindings.map((f) => [f.id, f]))

  /** attack_path/scoring.py path_severity_total: each (resource, state) weakness counted once. */
  function severityTotal(findingIds: readonly string[]): number {
    const counted = new Set<string>()
    let total = 0
    for (const id of findingIds) {
      const finding = findings.get(id)
      if (!finding) throw new Error(`the recording has no finding ${id}`)
      const weakness = `${finding.resource}\u0000${finding.state}`
      if (counted.has(weakness)) continue
      counted.add(weakness)
      total += weights.get(finding.severity) ?? weights.get('unknown') ?? 0
    }
    return total
  }

  it('has a recording to check', () => {
    // The loops below are vacuous on an empty recording.
    expect(sampleScoredPaths.length).toBeGreaterThan(0)
    expect(sampleScoredFindings.length).toBeGreaterThan(0)
  })

  it('shows weights that reproduce every recorded severity total', () => {
    for (const p of sampleScoredPaths) {
      expect(severityTotal(p.finding_ids), p.source_id).toBeCloseTo(p.breakdown.severity_total, 9)
    }
  })

  it('shows a formula that reproduces every recorded score', () => {
    for (const p of sampleScoredPaths) {
      const b = p.breakdown
      const shown =
        (severityTotal(p.finding_ids) + b.objective_weight) *
        lengthDecay(b) ** (b.hops - 1) *
        (b.public_entry ? b.boost : 1)
      expect(Number(shown.toFixed(2)), p.source_id).toBe(b.score)
      expect(b.score, p.source_id).toBe(p.score)
      expect(b.hops, p.source_id).toBe(p.length)
    }
  })

  it('reads the decay the API used, and it is the one the fallback names', () => {
    for (const p of sampleScoredPaths.filter((x) => x.breakdown.hops > 1)) {
      expect(lengthDecay(p.breakdown), p.source_id).toBe(LENGTH_DECAY)
      expect(p.breakdown.length_factor, p.source_id).toBeCloseTo(
        LENGTH_DECAY ** (p.breakdown.hops - 1),
        9,
      )
    }
  })

  it('prints the formula and its template from the breakdown', () => {
    for (const p of sampleScoredPaths) {
      const b = p.breakdown
      expect(scoreFormula(b), p.source_id).toContain(
        `${String(lengthDecay(b))}^${String(b.hops - 1)}`,
      )
      expect(scoreFormula(b), p.source_id).toMatch(new RegExp(`= ${b.score.toFixed(2)}$`))
      expect(scoreFormulaTemplate(b), p.source_id).toContain(`${String(lengthDecay(b))}^(hops - 1)`)
    }
  })

  it('writes the weights legend from the weights table', () => {
    expect(severityWeightsText()).toBe('critical 10, high 6, medium 3, low 1, unknown 0.5')
  })

  it('does not take a different decay for the one the API sent', () => {
    // A backend that retuned the decay shows up in the formula without a front-end change.
    expect(lengthDecay({ hops: 4, length_factor: 0.9 ** 3 })).toBe(0.9)
    expect(scoreFormulaTemplate({ hops: 4, length_factor: 0.9 ** 3 })).toContain('0.9^(hops - 1)')
  })
})

describe('contextual risk', () => {
  const byId = new Map(sampleRiskPaths.map((p) => [p.source_id, p.risk]))
  const risk = (id: string) => {
    const found = byId.get(id)
    if (!found) throw new Error(`the recording has no ${id}`)
    return found
  }

  it('has a recording to check', () => {
    expect(sampleRiskPaths.length).toBe(22)
  })

  it('names reachability in plain words', () => {
    expect(reachabilityLabel('direct')).toBe('Direct')
    expect(reachabilityLabel('via_path')).toBe('Via path')
    expect(reachabilityLabel('post_compromise')).toBe('After compromise')
    expect(reachabilityDetail('via_path')).toBe('through other resources')
  })

  it('shows untagged metadata as null and tagged metadata in words', () => {
    expect(riskMetadata(risk('AP-001'))).toEqual([
      { label: 'Environment', value: null },
      { label: 'Criticality', value: null },
      { label: 'Sensitive data', value: null },
    ])
    expect(
      riskMetadata({ environment: 'prod', asset_criticality: 'high', sensitive_data: false }),
    ).toEqual([
      { label: 'Environment', value: 'Production' },
      { label: 'Criticality', value: 'High' },
      { label: 'Sensitive data', value: 'No' },
    ])
  })

  it('counts dense ranks, not paths, and names ties', () => {
    expect(contextualRankText(risk('AP-019'), sampleRiskPaths)).toBe(
      'Rank 1 of 11 by contextual risk',
    )
    expect(contextualTieText(risk('AP-019'), sampleRiskPaths)).toBeNull()
    expect(contextualRankText(risk('AP-001'), sampleRiskPaths)).toBe(
      'Rank 3 of 11 by contextual risk',
    )
    expect(contextualTieText(risk('AP-001'), sampleRiskPaths)).toBe('tied with 4 other paths')
    expect(contextualTieText(risk('AP-021'), sampleRiskPaths)).toBe('tied with 1 other path')
    // paths saved before the model carry no risk and do not count
    expect(contextualRankText({ rank: 2 }, [{ risk: null }])).toBe('Rank 2 of 2 by contextual risk')
  })

  it('prints the formula with every number filled in', () => {
    expect(contextualFormula(risk('AP-001'))).toBe(
      '100 × 0.5^(0.45) × 0.9^(0.35) × 0.3012^(0.2) = 55.50',
    )
    expect(contextualFormulaTemplate()).toBe(
      '100 × (impact/100)^(0.45) × (exposure/100)^(0.35) × (path ease/100)^(0.2)',
    )
  })

  it('shows exponents that reproduce every recorded score', () => {
    for (const { source_id, risk: r } of sampleRiskPaths) {
      const shown =
        100 *
        (r.impact / 100) ** RISK_EXPONENTS.impact *
        (r.exposure / 100) ** RISK_EXPONENTS.exposure *
        (r.path_ease / 100) ** RISK_EXPONENTS.path_ease
      // the components are rounded to two places before they are sent
      expect(Math.abs(shown - r.score), source_id).toBeLessThan(0.02)
    }
  })
})
