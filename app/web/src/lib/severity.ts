/**
 * Severity and attack level: ordering, labels, tones and the palette.
 *
 * The palette's source of truth is the backend's SEVERITY_STYLES, served by
 * /api/meta. index.css ships the same values as fallbacks so the first paint is
 * already correct; applySeverityPalette() overwrites them when meta arrives.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type AttackLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM'
/** Every key of SEVERITY_STYLES: the five severities plus "clean" (no findings). */
export type Tone = Severity | 'clean'

export interface SeverityStyle {
  fill: string
  stroke: string
}

/** Most severe first. */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']
export const TONES: readonly Tone[] = ['critical', 'high', 'medium', 'low', 'clean', 'unknown']
/** Most severe first. */
export const ATTACK_LEVELS: readonly AttackLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM']

/** Same values as attack_path/renderer.py SEVERITY_STYLES and the CSS fallbacks. */
export const DEFAULT_SEVERITY_STYLES: Readonly<Record<Tone, SeverityStyle>> = {
  critical: { fill: '#f8b4b4', stroke: '#7f1d1d' },
  high: { fill: '#fbcfa4', stroke: '#7c2d12' },
  medium: { fill: '#fde68a', stroke: '#78350f' },
  low: { fill: '#bfdbfe', stroke: '#1e3a8a' },
  clean: { fill: '#e5e7eb', stroke: '#374151' },
  unknown: { fill: '#ede9fe', stroke: '#4c1d95' },
}

const SEVERITY_LABELS: Record<Tone, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  clean: 'No findings',
  unknown: 'Unknown',
}

const LEVEL_LABELS: Record<AttackLevel, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
}

const LEVEL_TONES: Record<AttackLevel, Tone> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value)
}

export function isTone(value: unknown): value is Tone {
  return typeof value === 'string' && (TONES as readonly string[]).includes(value)
}

export function isAttackLevel(value: unknown): value is AttackLevel {
  return typeof value === 'string' && (ATTACK_LEVELS as readonly string[]).includes(value)
}

export function severityLabel(tone: Tone): string {
  return SEVERITY_LABELS[tone]
}

export function levelLabel(level: AttackLevel): string {
  return LEVEL_LABELS[level]
}

/** CRITICAL draws as critical, HIGH as high, MEDIUM as medium. */
export function levelTone(level: AttackLevel): Tone {
  return LEVEL_TONES[level]
}

/**
 * The tone a resource is drawn in. A resource with no findings has a null
 * max_severity and draws as "clean", like the renderer's style_key.
 */
export function resourceTone(maxSeverity: Severity | null | undefined): Tone {
  return maxSeverity ?? 'clean'
}

/** 0 for critical up to 4 for unknown; for sorting most severe first. */
export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity)
}

/** Comparator: most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b)
}

/** 0 for CRITICAL up to 2 for MEDIUM. */
export function levelRank(level: AttackLevel): number {
  return ATTACK_LEVELS.indexOf(level)
}

/** Comparator: most severe level first. */
export function compareLevel(a: AttackLevel, b: AttackLevel): number {
  return levelRank(a) - levelRank(b)
}

/** The most severe of a list, or null for an empty list. */
export function maxSeverity(severities: Iterable<Severity>): Severity | null {
  let best: Severity | null = null
  for (const severity of severities) {
    if (best === null || severityRank(severity) < severityRank(best)) best = severity
  }
  return best
}

/** Is `level` at or above `minimum`? The backend's "selected" rule. */
export function meetsLevel(level: AttackLevel, minimum: AttackLevel): boolean {
  return levelRank(level) <= levelRank(minimum)
}

/** Counts per severity in display order, including zeros. */
export function countBySeverity(
  severities: Iterable<Severity>,
): { severity: Severity; count: number }[] {
  const counts = new Map<Severity, number>(SEVERITIES.map((s) => [s, 0]))
  for (const severity of severities) counts.set(severity, (counts.get(severity) ?? 0) + 1)
  return SEVERITIES.map((severity) => ({ severity, count: counts.get(severity) ?? 0 }))
}

// -- Palette --------------------------------------------------------------------

/** The CSS custom property a tone's fill or stroke lives in. */
export function severityVar(tone: Tone, part: keyof SeverityStyle): string {
  return `--sev-${tone}-${part}`
}

const HEX = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i

/**
 * Write the served palette onto an element (by default :root) as
 * --sev-{tone}-fill / --sev-{tone}-stroke. Unknown keys and values that are
 * not hex colours are ignored, so a bad payload cannot blank the UI.
 * Returns the tones that were applied.
 */
export function applySeverityPalette(
  styles: Readonly<Record<string, SeverityStyle>>,
  target: HTMLElement = document.documentElement,
): Tone[] {
  const applied: Tone[] = []
  for (const [key, style] of Object.entries(styles)) {
    if (!isTone(key) || !HEX.test(style.fill) || !HEX.test(style.stroke)) continue
    target.style.setProperty(severityVar(key, 'fill'), style.fill)
    target.style.setProperty(severityVar(key, 'stroke'), style.stroke)
    applied.push(key)
  }
  return applied
}

// -- Contrast (WCAG 2.x) ------------------------------------------------------

function channels(hex: string): [number, number, number] {
  let h = hex.replace('#', '')
  if (h.length === 3) h = h.replace(/./g, (c) => c + c)
  const n = Number.parseInt(h, 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

/** Relative luminance of a hex colour, 0 (black) to 1 (white). */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = channels(hex).map((v) => {
    const c = v / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }) as [number, number, number]
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** WCAG contrast ratio between two hex colours, 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x) as [
    number,
    number,
  ]
  return (hi + 0.05) / (lo + 0.05)
}
