export const ANALYSIS_TABS = ['overview', 'findings', 'paths', 'graph'] as const
export type AnalysisTab = (typeof ANALYSIS_TABS)[number]

export const DEFAULT_ANALYSIS_TAB: AnalysisTab = 'overview'

export const ANALYSIS_TAB_LABELS: Record<AnalysisTab, string> = {
  overview: 'Overview',
  findings: 'Findings',
  paths: 'Paths',
  graph: 'Graph',
}

export function isAnalysisTab(value: unknown): value is AnalysisTab {
  return typeof value === 'string' && (ANALYSIS_TABS as readonly string[]).includes(value)
}

/** The tab named by ?tab=, falling back to overview for a missing or unknown value. */
export function tabFromSearch(value: string | null): AnalysisTab {
  return isAnalysisTab(value) ? value : DEFAULT_ANALYSIS_TAB
}
