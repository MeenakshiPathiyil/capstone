/**
 * What the graph writes on nodes and edges, and how wide it is.
 *
 * Widths are estimated, not measured: the layout runs before the browser has
 * drawn anything (and in tests, where there is no canvas). Ids are set in
 * Geist Mono, whose advance is exactly 0.6em, so they are exact; Inter text
 * uses a per-character estimate that errs a little wide, so text never
 * overflows the box the layout reserved for it.
 */
import type { GraphEdge, GraphNode } from '@/api/types'
import { formatResourceType, identifierBreaks } from '@/lib/format'
import { isTone, type Tone } from '@/lib/severity'

/** Geist Mono advance: 0.6em for every glyph. */
export function monoWidth(text: string, px: number): number {
  return text.length * px * 0.6
}

const NARROW = 'iljtfrI.,:;\'"|!()[]/ '
const WIDE = 'mwMWQGOCDHNU@%'

/** Inter at `px` (medium weight or lighter), slightly generous. */
export function interWidth(text: string, px: number): number {
  let em = 0
  for (const char of text) {
    if (NARROW.includes(char)) em += 0.32
    else if (WIDE.includes(char)) em += 0.82
    else if (char >= 'A' && char <= 'Z') em += 0.68
    else if (char >= '0' && char <= '9') em += 0.6
    else em += 0.56
  }
  return em * px
}

/** Greedy word wrap to `maxWidth`, at most `maxLines`; the last line ends in an ellipsis if cut. */
export function wrapText(
  text: string,
  maxWidth: number,
  measure: (s: string) => number,
  maxLines: number,
): string[] {
  const words = text.split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let current = ''
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word
    if (!current || measure(candidate) <= maxWidth) {
      current = candidate
    } else {
      lines.push(current)
      current = word
    }
  }
  if (current) lines.push(current)
  if (lines.length <= maxLines) return lines
  const kept = lines.slice(0, maxLines)
  let last = `${kept[maxLines - 1] ?? ''} ${lines.slice(maxLines).join(' ')}`
  while (last.length > 1 && measure(`${last}…`) > maxWidth) last = last.slice(0, -1).trimEnd()
  kept[maxLines - 1] = `${last}…`
  return kept
}

/**
 * An identifier on as few lines as fit `maxWidth`, broken where identifierBreaks
 * allows ("OverPermissive" / "InstanceProfile"), and mid-piece only when a
 * single piece is wider than a line.
 */
export function wrapIdentifier(
  id: string,
  maxWidth: number,
  measure: (s: string) => number,
): string[] {
  // A nested stack's "Stack.Resource" that does not fit breaks after the
  // stack first, so the resource's own name stays in one piece.
  const dot = id.lastIndexOf('.')
  if (measure(id) > maxWidth && dot > 0 && dot < id.length - 1) {
    return [
      ...wrapPieces(id.slice(0, dot + 1), maxWidth, measure),
      ...wrapPieces(id.slice(dot + 1), maxWidth, measure),
    ]
  }
  return wrapPieces(id, maxWidth, measure)
}

function wrapPieces(id: string, maxWidth: number, measure: (s: string) => number): string[] {
  const pieces: string[] = []
  for (const piece of identifierBreaks(id)) {
    let rest = piece
    while (measure(rest) > maxWidth && rest.length > 1) {
      let cut = rest.length - 1
      while (cut > 1 && measure(rest.slice(0, cut)) > maxWidth) cut -= 1
      pieces.push(rest.slice(0, cut))
      rest = rest.slice(cut)
    }
    pieces.push(rest)
  }
  const lines: string[] = []
  for (const piece of pieces) {
    const last = lines[lines.length - 1]
    if (last !== undefined && measure(last + piece) <= maxWidth)
      lines[lines.length - 1] = last + piece
    else lines.push(piece)
  }
  return lines.length > 0 ? lines : [id]
}

// -- Nodes --------------------------------------------------------------------

/** The tone a node is drawn in; anything the client does not know draws as unknown. */
export function nodeTone(node: GraphNode): Tone {
  return isTone(node.style) ? node.style : 'unknown'
}

const SEVERITY_WORDS = new Set(['critical', 'high', 'medium', 'low', 'unknown', 'no findings'])

export interface NodeText {
  /** The resource id, or "Attacker" for the root. */
  title: string
  /** The CloudFormation type, shortened: "EC2 Instance". */
  type: string | null
  /** The raw type, for tooltips. */
  rawType: string | null
  /** Any further label line the backend sent that the drawing does not already say. */
  extra: string[]
}

/**
 * The backend's label_lines are [id, type, ...notes] as the static renderer
 * draws them. The severity word and "[entry]" are shown by colour and the entry
 * chip here, so they are not repeated as text.
 */
export function nodeText(node: GraphNode): NodeText {
  const [title = node.key, rawType = null, ...rest] = node.label_lines
  const extra = rest.filter((line) => {
    const lower = line.trim().toLowerCase()
    return lower !== '' && lower !== '[entry]' && !SEVERITY_WORDS.has(lower)
  })
  return {
    title,
    type: rawType ? formatResourceType(rawType) : null,
    rawType,
    extra,
  }
}

/** True for a CloudFormation stack resource: a nested stack's parent. */
export function isStackType(rawType: string | null): boolean {
  return rawType === 'AWS::CloudFormation::Stack'
}

// -- Facts --------------------------------------------------------------------

export type FactKind = 'foothold' | 'credential' | 'data_access' | 'internet_reachable' | 'other'

export interface Fact {
  kind: FactKind
  /** The resource the fact is about, or null for a bare fact. */
  subject: string | null
  /** The fact as the backend wrote it. */
  raw: string
}

const KNOWN_KINDS: readonly FactKind[] = [
  'foothold',
  'credential',
  'data_access',
  'internet_reachable',
]

export const FACT_KIND_LABELS: Record<FactKind, string> = {
  foothold: 'Foothold on',
  credential: 'Credentials for',
  data_access: 'Data access to',
  internet_reachable: 'Reachable from the internet',
  other: 'Fact',
}

/** "credential(OverPermissiveRole)" -> credential about OverPermissiveRole. */
export function parseFact(raw: string): Fact {
  const match = /^([a-z_]+)\((.*)\)$/i.exec(raw.trim())
  const name = match?.[1] ?? raw.trim()
  const kind = (KNOWN_KINDS as readonly string[]).includes(name) ? (name as FactKind) : 'other'
  return { kind, subject: match ? (match[2] ?? null) : null, raw }
}

/** Display order: where the attacker stands, what they hold, what they can read, then the rest. */
export function sortedFacts(facts: readonly string[]): Fact[] {
  const order = (fact: Fact) => {
    const index = KNOWN_KINDS.indexOf(fact.kind)
    return index === -1 ? KNOWN_KINDS.length : index
  }
  return facts.map(parseFact).sort((a, b) => order(a) - order(b) || a.raw.localeCompare(b.raw))
}

/** The text on a fact row: the subject, or a sentence for a bare fact. */
export function factText(fact: Fact): string {
  if (fact.subject) return fact.subject
  if (fact.kind === 'internet_reachable') return 'internet reachable'
  return fact.raw.replace(/_/g, ' ')
}

/** A fact kind in a word or two, for legends and rows. */
export const FACT_SHORT_LABELS: Record<FactKind, string> = {
  foothold: 'foothold',
  credential: 'credentials',
  data_access: 'data access',
  internet_reachable: 'internet reachable',
  other: 'fact',
}

/**
 * A fact row in a state box. A fact about the box's own resource says only
 * what kind it is ("credentials"): the title already names the resource, and
 * repeating it made every box as wide as its longest id. A fact about another
 * resource names that resource, in mono like every id.
 */
export function factRowText(fact: Fact, resource: string | null): { text: string; mono: boolean } {
  if (fact.subject && fact.subject === resource && fact.kind !== 'other') {
    return { text: FACT_SHORT_LABELS[fact.kind], mono: false }
  }
  if (!fact.subject) return { text: factText(fact), mono: fact.kind === 'other' }
  return { text: fact.subject, mono: true }
}

/** Full sentence, for the tooltip and screen readers. */
export function factDescription(fact: Fact): string {
  if (fact.kind === 'other') return fact.raw
  if (!fact.subject) return FACT_KIND_LABELS[fact.kind]
  return `${FACT_KIND_LABELS[fact.kind]} ${fact.subject}`
}

// -- Edges --------------------------------------------------------------------

/** "network_control" -> "network control". */
export function formatCategory(category: string): string {
  return category.replace(/_/g, ' ')
}

/** The state view's edge text: its categories. The reversed note is drawn separately. */
export function categoryText(edge: GraphEdge): string {
  if (edge.categories.length === 0) return edge.label
  return edge.categories.map(formatCategory).join(' + ')
}
