/**
 * Display formatting. Pure functions, en-GB conventions, no locale guessing:
 * the same analysis reads the same on every machine and in the PDF.
 */

const LOCALE = 'en-GB'

const integer = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 0 })

/** 1234 -> "1,234". */
export function formatCount(value: number): string {
  return integer.format(value)
}

/** Risk scores are rounded to two places by the backend; always show two. 56.04 -> "56.04". */
export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '-'
  return value.toFixed(2)
}

/** A multiplier such as the length damping or entry boost. 0.614125 -> "0.614", 1.25 -> "1.25". */
export function formatFactor(value: number): string {
  return Number(value.toFixed(3)).toString()
}

/** 0.4 -> "40%". */
export function formatPercent(fraction: number): string {
  return `${Math.round(fraction * 100)}%`
}

/** Binary units, like the upload limit. 2097152 -> "2 MB", 1536 -> "1.5 KB". */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '-'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  const rounded = value >= 10 ? Math.round(value) : Math.round(value * 10) / 10
  return `${rounded} ${units[unit]}`
}

/** 3 -> "3 findings", 1 -> "1 finding". */
export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${formatCount(count)} ${count === 1 ? singular : plural}`
}

/** Seconds as "0.4 s", "12 s", "2 min 5 s". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '-'
  }
  if (seconds < 10) return `${Math.round(seconds * 10) / 10} s`
  if (seconds < 60) return `${Math.round(seconds)} s`
  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds - minutes * 60)
  return rest === 0 ? `${minutes} min` : `${minutes} min ${rest} s`
}

const dateTime = new Intl.DateTimeFormat(LOCALE, {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
  timeZone: 'UTC',
})

/** A UTC ISO timestamp as "24 Oct 2026, 10:28 UTC". */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '-'
  return `${dateTime.format(date)} UTC`
}

/**
 * When to try again after a 503 or 429, from its Retry-After seconds.
 * 30 -> "Try again in 30 s." 600 -> "Try again in about 10 min."
 * 7200 -> "Try again after 24 Oct 2026, 14:00 UTC."
 */
export function retryAfterText(seconds: number, now: Date = new Date()): string {
  const s = Math.max(1, Math.round(seconds))
  if (s <= 90) return `Try again in ${s} s.`
  if (s < 3600) return `Try again in about ${Math.round(s / 60)} min.`
  // Servers floor the seconds, so a reset at 11:00 arrives as 10:59:58.
  const at = Math.round((now.getTime() + s * 1000) / 60_000) * 60_000
  return `Try again after ${formatDateTime(new Date(at).toISOString())}.`
}

/** First characters of a hash or commit. */
export function shortHash(hash: string, length = 7): string {
  return hash.slice(0, length)
}

/** Service names long enough to crowd a table cell, by the short names AWS's own CLI uses. */
const SHORT_SERVICES: Readonly<Record<string, string>> = {
  ElasticLoadBalancingV2: 'ELBv2',
  ElasticLoadBalancing: 'ELB',
}

/**
 * "AWS::EC2::SecurityGroup" -> "EC2 SecurityGroup", and
 * "AWS::ElasticLoadBalancingV2::LoadBalancer" -> "ELBv2 LoadBalancer".
 * Non-AWS types pass through.
 */
export function formatResourceType(type: string): string {
  const parts = type.split('::')
  if (parts.length === 3 && parts[0] === 'AWS' && parts[1] && parts[2]) {
    return `${SHORT_SERVICES[parts[1]] ?? parts[1]} ${parts[2]}`
  }
  return type
}

/** Hops as one readable line: "A → B → C". */
export function chainText(hops: readonly string[]): string {
  return hops.join(' → ')
}

/** "T1552.005" -> the MITRE ATT&CK page, or null when the id is not a technique id. */
export function attackTechniqueUrl(id: string | null | undefined): string | null {
  if (!id || !/^T\d{4}(?:\.\d{3})?$/.test(id)) return null
  return safeHttpUrl(`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`)
}

/** "privilege_escalation" or "initial access" -> "Privilege escalation" / "Initial access". */
export function sentenceCase(value: string): string {
  const spaced = value.replace(/[_-]+/g, ' ').trim()
  if (!spaced) return ''
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase()
}

/** The lower-cased extension of a file name including the dot, or "" when there is none. */
export function fileExtension(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot <= 0 ? '' : name.slice(dot).toLowerCase()
}

/**
 * An identifier cut into pieces where a line may break: before an upper-case
 * letter that follows a lower-case one or a digit, and after ::, _, -, / and dots.
 * "OverPermissiveRole" -> ["Over", "Permissive", "Role"]. Joining the pieces
 * gives back the input.
 */
export function identifierBreaks(id: string): string[] {
  return id.split(/(?<=[a-z0-9])(?=[A-Z])|(?<=::|[_\-/.])(?=[^:_\-/.])/).filter(Boolean)
}

/**
 * Sample descriptions from /api/meta lead with their file: "sample_yamls/x.yml: what it is".
 * Returns the file and the sentence apart, or a null file when there is no such prefix.
 */
export function splitSampleDescription(description: string): { file: string | null; text: string } {
  const match = /^(\S+\.(?:ya?ml|json|template)):\s+(.+)$/is.exec(description)
  if (!match?.[1] || !match[2]) return { file: null, text: description }
  const text = match[2]
  return { file: match[1], text: text.charAt(0).toUpperCase() + text.slice(1) }
}

/**
 * The one gate for every href built from data: the URL itself when it is an
 * absolute http or https URL, otherwise null (javascript:, data:, relative).
 * Render no link for null.
 */
export function safeHttpUrl(value: string | null | undefined): string | null {
  if (!value) return null
  try {
    const { protocol } = new URL(value)
    return protocol === 'http:' || protocol === 'https:' ? value : null
  } catch {
    return null
  }
}
