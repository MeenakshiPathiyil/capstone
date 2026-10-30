/**
 * Pure helpers over the Analysis payload: grouping, lookups, the score formulas
 * and the wording of fix impact. No React, no fetching; every function here is
 * unit tested in analysis.test.ts.
 */

import type {
  Analysis,
  Finding,
  FixImpact,
  Path,
  PathRisk,
  Reachability,
  Resource,
  ScoreBreakdown,
  Step,
} from '@/api/types'

import type { ChainNode } from '@/components/ChainDiagram'

import { attackTechniqueUrl, formatCount, formatScore, pluralize, sentenceCase } from './format'
import { levelLabel, resourceTone, type AttackLevel } from './severity'

// -- Paths ------------------------------------------------------------------------------

export interface ChainGroup {
  /** The backend's chain_group id: identical hop chains share one. */
  group: number
  hops: string[]
  /** Ranked best first. */
  paths: Path[]
}

/**
 * Paths grouped by identical hop chain. Groups come in the order of their best
 * ranked path, and paths inside a group by rank, so reading top to bottom
 * still follows the overall ranking.
 */
export function groupPathsByChain(paths: readonly Path[]): ChainGroup[] {
  const sorted = [...paths].sort((a, b) => a.rank - b.rank)
  const groups = new Map<number, ChainGroup>()
  for (const path of sorted) {
    const existing = groups.get(path.chain_group)
    if (existing) existing.paths.push(path)
    else groups.set(path.chain_group, { group: path.chain_group, hops: path.hops, paths: [path] })
  }
  return [...groups.values()]
}

/** The highest score among paths, or 0 when there are none. The ScoreBar scale. */
export function topScore(paths: readonly Pick<Path, 'score'>[]): number {
  return paths.reduce((max, path) => Math.max(max, path.score), 0)
}

/** Paths whose hop chain passes through a resource, best rank first. */
export function pathsThroughResource(paths: readonly Path[], resourceId: string): Path[] {
  return paths.filter((path) => path.hops.includes(resourceId)).sort((a, b) => a.rank - b.rank)
}

/**
 * A hop chain as ChainDiagram boxes: each resource in its severity colour,
 * the first drawn as the path's entry. Ids missing from the analysis draw as
 * unknown rather than disappearing.
 */
export function chainNodes(
  hops: readonly string[],
  resources: ReadonlyMap<string, Pick<Resource, 'type' | 'max_severity'>>,
): ChainNode[] {
  return hops.map((id, index) => {
    const resource = resources.get(id)
    return {
      id,
      type: resource?.type,
      tone: resource ? resourceTone(resource.max_severity) : 'unknown',
      isEntry: index === 0,
    }
  })
}

/** "4 hops" for a path of length 4 (five resources). */
export function hopsLabel(length: number): string {
  return pluralize(length, 'hop')
}

// -- Lookups ------------------------------------------------------------------------------

export function indexById<T extends { id: string }>(items: readonly T[]): Map<string, T> {
  return new Map(items.map((item) => [item.id, item]))
}

export function resourceIndex(analysis: Pick<Analysis, 'resources'>): Map<string, Resource> {
  return indexById(analysis.resources)
}

export function findingIndex(analysis: Pick<Analysis, 'findings'>): Map<string, Finding> {
  return indexById(analysis.findings)
}

/**
 * "T1190 - Exploit Public-Facing Application, T1552.005 - Unsecured
 * Credentials: Cloud Instance Metadata API" -> a map from id to name. Names
 * may contain commas or colons; only "<id> - " starts a new entry.
 */
export function parseTechniqueList(text: string): Map<string, string> {
  const names = new Map<string, string>()
  const pattern = /(T\d{4}(?:\.\d{3})?) - (.*?)(?=,\s*T\d{4}(?:\.\d{3})? - |$)/g
  for (const match of text.matchAll(pattern)) {
    const [, id, name] = match
    if (id && name) names.set(id, name.trim())
  }
  return names
}

/**
 * Every ATT&CK technique name the analysis knows: from finding rules and from
 * the exported path records. Steps carry only the id, so this names them.
 */
export function techniqueNames(
  analysis: Pick<Analysis, 'findings' | 'paths'>,
): Map<string, string> {
  const names = new Map<string, string>()
  for (const finding of analysis.findings) {
    for (const technique of finding.rule.attack_techniques) {
      if (technique.name) names.set(technique.id, technique.name)
    }
  }
  for (const path of analysis.paths) {
    if (!path.export) continue
    for (const [id, name] of parseTechniqueList(path.export.techniques)) {
      if (!names.has(id)) names.set(id, name)
    }
  }
  return names
}

export interface TechniqueRef {
  id: string
  name: string | null
  /** Null when the id is not a technique id, so no broken link is drawn. */
  url: string | null
}

/** A step's technique with its name and MITRE link, or null when the step has none. */
export function stepTechnique(
  step: Pick<Step, 'technique'>,
  names: ReadonlyMap<string, string>,
): TechniqueRef | null {
  const id = step.technique?.trim()
  if (!id) return null
  return { id, name: names.get(id) ?? null, url: attackTechniqueUrl(id) }
}

// -- Score ------------------------------------------------------------------------------

/**
 * attack_path/scoring.py (LENGTH_DAMPING_PER_HOP): each hop after the first
 * multiplies the score by this. Only the fallback for a one-hop path, where
 * the API's length factor (1) cannot reveal it; otherwise `lengthDecay` reads
 * it back from the breakdown. analysis.test.ts checks it against a recorded
 * API response.
 */
export const LENGTH_DECAY = 0.85

/**
 * security_state_graph/semantics.py (SEVERITY_WEIGHTS, DEFAULT_SEVERITY_WEIGHT):
 * what one finding adds to a path's severity total, for the popover's legend.
 * The API sends only the total, so these cannot be read from the breakdown;
 * analysis.test.ts recomputes every recorded path's total from them and fails
 * when they drift from the API.
 */
export const SEVERITY_WEIGHTS = [
  ['critical', 10],
  ['high', 6],
  ['medium', 3],
  ['low', 1],
  ['unknown', 0.5],
] as const

/** "critical 10, high 6, medium 3, low 1, unknown 0.5" */
export function severityWeightsText(): string {
  return SEVERITY_WEIGHTS.map(([severity, weight]) => `${severity} ${String(weight)}`).join(', ')
}

/** The per-hop decay the API applied, read back from its length factor (the constant for a single hop). */
export function lengthDecay(breakdown: Pick<ScoreBreakdown, 'hops' | 'length_factor'>): number {
  if (breakdown.hops < 2) return LENGTH_DECAY
  return Number((breakdown.length_factor ** (1 / (breakdown.hops - 1))).toFixed(4))
}

/** 68 -> "68", 0.5 -> "0.5", 12.345 -> "12.35". Weights in the formula, without padding. */
function formatWeight(value: number): string {
  return Number(value.toFixed(2)).toString()
}

/**
 * The length factor as it is computed: "0.85^3" when it matches the decay
 * for this many hops, otherwise the number itself.
 */
export function lengthFactorText(
  breakdown: Pick<ScoreBreakdown, 'hops' | 'length_factor'>,
): string {
  const exponent = Math.max(0, breakdown.hops - 1)
  const decay = lengthDecay(breakdown)
  if (Math.abs(decay ** exponent - breakdown.length_factor) < 1e-9) {
    return `${String(decay)}^${String(exponent)}`
  }
  return Number(breakdown.length_factor.toFixed(3)).toString()
}

/**
 * The score with every number filled in, as the backend computes it:
 * "(68 + 5) × 0.85^3 × 1.25 = 56.04". The entry boost appears only for a
 * public entry.
 */
export function scoreFormula(breakdown: ScoreBreakdown): string {
  const sum = `(${formatWeight(breakdown.severity_total)} + ${formatWeight(breakdown.objective_weight)})`
  const boost = breakdown.public_entry ? ` × ${formatWeight(breakdown.boost)}` : ''
  return `${sum} × ${lengthFactorText(breakdown)}${boost} = ${formatScore(breakdown.score)}`
}

/** The general formula the numbers above fill in, with the decay this path's breakdown shows. */
export function scoreFormulaTemplate(
  breakdown: Pick<ScoreBreakdown, 'hops' | 'length_factor'>,
): string {
  return `(finding weights + objective weight) × ${String(lengthDecay(breakdown))}^(hops - 1) × boost`
}

/** "Critical at 40 and above, High at 30 and above, Medium below." */
export function levelBandsText(
  breakdown: Pick<ScoreBreakdown, 'threshold_high' | 'threshold_critical'>,
): string {
  return `Critical at ${formatWeight(breakdown.threshold_critical)} and above, High at ${formatWeight(breakdown.threshold_high)} and above, Medium below.`
}

// -- Contextual risk ----------------------------------------------------------------------

/**
 * risk_scoring/scoring/risk_scorer.py: how strongly each component counts in
 * the contextual score, 100 × (I/100)^0.45 × (E/100)^0.35 × (A/100)^0.2. The
 * API sends only the components, so these are for the formula shown;
 * analysis.test.ts recomputes every recorded score from them and fails when
 * they drift.
 */
export const RISK_EXPONENTS = { impact: 0.45, exposure: 0.35, path_ease: 0.2 } as const

const REACHABILITY: Record<Reachability, { label: string; detail: string }> = {
  direct: { label: 'Direct', detail: 'it is itself an entry point' },
  via_path: { label: 'Via path', detail: 'through other resources' },
  post_compromise: { label: 'After compromise', detail: 'only after a foothold' },
}

/** "direct" -> "Direct", "post_compromise" -> "After compromise". */
export function reachabilityLabel(reachability: Reachability): string {
  return REACHABILITY[reachability].label
}

/** How the target is reached, to follow "the target is reached ": "through other resources". */
export function reachabilityDetail(reachability: Reachability): string {
  return REACHABILITY[reachability].detail
}

/** The target's tag-derived metadata, "Not tagged" where no tag says. */
export function riskMetadata(
  risk: Pick<PathRisk, 'environment' | 'asset_criticality' | 'sensitive_data'>,
): { label: string; value: string | null }[] {
  const environments = { prod: 'Production', dev: 'Development', test: 'Test' } as const
  return [
    { label: 'Environment', value: risk.environment ? environments[risk.environment] : null },
    {
      label: 'Criticality',
      value: risk.asset_criticality ? sentenceCase(risk.asset_criticality) : null,
    },
    {
      label: 'Sensitive data',
      value: risk.sensitive_data === null ? null : risk.sensitive_data ? 'Yes' : 'No',
    },
  ]
}

/**
 * "Rank 3 of 11 by contextual risk". Ranks are dense (equal scores share one),
 * so the count is the number of distinct ranks, not of paths.
 */
export function contextualRankText(
  risk: Pick<PathRisk, 'rank'>,
  paths: readonly Pick<Path, 'risk'>[],
): string {
  const ranks = Math.max(risk.rank, ...paths.map((p) => p.risk?.rank ?? 0))
  return `Rank ${formatCount(risk.rank)} of ${formatCount(ranks)} by contextual risk`
}

/** "tied with 4 other paths", or null when no other path shares the rank. */
export function contextualTieText(
  risk: Pick<PathRisk, 'rank'>,
  paths: readonly Pick<Path, 'risk'>[],
): string | null {
  const others = paths.filter((p) => p.risk?.rank === risk.rank).length - 1
  return others > 0 ? `tied with ${pluralize(others, 'other path')}` : null
}

/** 0.5 -> "0.5", 0.3012 -> "0.3012": a component as the fraction the formula raises. */
function formatFraction(value: number): string {
  return Number((value / 100).toFixed(4)).toString()
}

/** The contextual score with every number filled in: "100 × 0.5^(0.45) × 0.9^(0.35) × 0.3012^(0.2) = 55.50". */
export function contextualFormula(
  risk: Pick<PathRisk, 'score' | 'impact' | 'exposure' | 'path_ease'>,
): string {
  const terms = (['impact', 'exposure', 'path_ease'] as const).map(
    (key) => `${formatFraction(risk[key])}^(${String(RISK_EXPONENTS[key])})`,
  )
  return `100 × ${terms.join(' × ')} = ${formatScore(risk.score)}`
}

/** The general formula the numbers above fill in. */
export function contextualFormulaTemplate(): string {
  const { impact, exposure, path_ease } = RISK_EXPONENTS
  return `100 × (impact/100)^(${String(impact)}) × (exposure/100)^(${String(exposure)}) × (path ease/100)^(${String(path_ease)})`
}

// -- Fix impact ---------------------------------------------------------------------------

/** Plan 5.4, word for word. Used by the UI and the PDF. */
export const FIX_REMOVED_LABEL =
  'Paths no longer at or above the selected risk level after suppressing this finding'

export const FIX_SUPPRESSION_NOTE =
  'Each estimate removes one finding from the evidence and re-runs the analysis. Suppression is not repair: changing the template may not have exactly this effect.'

/** Fixes that change the selected set at all, in the backend's ranking order. */
export function effectiveFixes(results: readonly FixImpact[]): FixImpact[] {
  return results.filter((fix) => fix.selected_paths_removed > 0 || fix.selected_paths_added > 0)
}

/** "2 of 19" selected paths. */
export function fixRemovedText(fix: FixImpact): string {
  return `${formatCount(fix.selected_paths_removed)} of ${formatCount(fix.baseline_selected_paths)}`
}

/** "1 newly selected path", or null when suppression selects nothing new. */
export function fixAddedText(fix: FixImpact): string | null {
  if (fix.selected_paths_added <= 0) return null
  return pluralize(fix.selected_paths_added, 'newly selected path')
}

/** "top 5 paths" or "all selected paths" for a fix-impact scope. */
export function fixScopeText(scopeTop: number | null): string {
  return scopeTop === null ? 'all selected paths' : `the top ${pluralize(scopeTop, 'path')}`
}

// -- Steps ------------------------------------------------------------------------------

export interface CapabilityLike {
  end: string | null
  source_id: string[] | null
  source_id_prefix: string[] | null
  state: string[] | null
  semantic: string[] | null
}

/**
 * A step's required capability as one line: what must be found, and on which
 * resource. "INCOMING_SSH_DISABLED on OpenSecurityGroup".
 */
export function capabilityText(
  capability: CapabilityLike,
  step: Pick<Step, 'source' | 'target'>,
): string {
  const needs = [
    ...(capability.source_id ?? []),
    ...(capability.source_id_prefix ?? []).map((prefix) => `${prefix}*`),
    ...(capability.state ?? []),
    ...(capability.semantic ?? []).map((semantic) => `any ${semantic} finding`),
  ]
  const what = needs.length > 0 ? needs.join(' or ') : 'a finding'
  const where =
    capability.end === 'source' ? step.source : capability.end === 'target' ? step.target : null
  return where ? `${what} on ${where}` : what
}

/** Precondition alternatives the step did not use, so the timeline can show them as "or". */
export function alternativePreconditions(
  step: Pick<Step, 'precondition' | 'precondition_options'>,
): string[] {
  const used = new Set(step.precondition)
  return step.precondition_options.filter((option) => !used.has(option))
}

/** An evidence value as chip texts: lists become one chip per item. */
export function evidenceChips(value: unknown): string[] {
  if (value === null || value === undefined) return []
  if (Array.isArray(value)) return value.flatMap((item) => evidenceChips(item))
  if (typeof value === 'string') return value === '' ? [] : [value]
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return [String(value)]
  }
  return [JSON.stringify(value)]
}

// -- Report and links ---------------------------------------------------------------------

export type ReportScope = number | 'all'

/** The report's API path, under API_BASE. */
export function reportPath(analysisId: string, top: ReportScope): string {
  return `/analyses/${encodeURIComponent(analysisId)}/report.pdf?top=${String(top)}`
}

export function pathDetailUrl(analysisId: string, sourceId: string): string {
  return `/analysis/${encodeURIComponent(analysisId)}/paths/${encodeURIComponent(sourceId)}`
}

export function graphUrl(analysisId: string, sourceId: string): string {
  const params = new URLSearchParams({ tab: 'graph', path: sourceId })
  return `/analysis/${encodeURIComponent(analysisId)}?${params.toString()}`
}

/** The search param that opens the resource sheet on the analysis and path pages. */
export const RESOURCE_PARAM = 'resource'

/** A copy of `params` with the resource sheet opened on `resourceId`, or closed for null. */
export function withResourceParam(params: URLSearchParams, resourceId: string | null) {
  const next = new URLSearchParams(params)
  if (resourceId) next.set(RESOURCE_PARAM, resourceId)
  else next.delete(RESOURCE_PARAM)
  return next
}

// -- Labels ------------------------------------------------------------------------------

/** "19 at or above High". */
export function selectedPathsText(count: number, minLevel: AttackLevel): string {
  return `${formatCount(count)} at or above ${levelLabel(minLevel)}`
}

/** Text the findings table's search box matches against. */
export function findingSearchText(finding: Finding): string {
  return [
    finding.resource,
    finding.resource_type,
    finding.rule.display_name,
    finding.rule_id,
    finding.source_id,
    finding.semantic ?? '',
    ...finding.rule.attack_techniques.flatMap((t) => [t.id, t.name]),
  ]
    .join(' ')
    .toLowerCase()
}

/** Short titles for the overview's notices, by warning kind. */
export const WARNING_TITLES: Record<string, string> = {
  orphan_finding: 'Finding not used',
  rule_error: 'Rule could not be evaluated',
  nested_skipped: 'Nested stack not analysed',
  transform_unexpanded: 'Transform not expanded',
  graph_truncated: 'Attack graph incomplete',
  graph_mapping: 'Graph mapping',
  depth_limit: 'Search depth limit',
}

export function warningTitle(kind: string): string {
  return WARNING_TITLES[kind] ?? 'Notice'
}
