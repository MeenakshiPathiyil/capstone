import { ArrowRight } from 'lucide-react'
import { Fragment } from 'react'

import { cn } from '@/lib/utils'
import { formatResourceType, identifierBreaks } from '@/lib/format'
import { severityLabel, type Tone } from '@/lib/severity'

export interface ChainNode {
  /** Resource id (logical id in the template). */
  id: string
  /** CloudFormation type, for example AWS::EC2::Instance. */
  type?: string
  /** The resource's max severity, or "clean" when it has no findings. */
  tone: Tone
  /** Where the attacker starts. Drawn with a dashed border, as in the graph and PDF. */
  isEntry?: boolean
}

interface ChainDiagramProps {
  nodes: readonly ChainNode[]
  /** Optional text on each arrow; index i sits between nodes i and i + 1. */
  edgeLabels?: readonly (string | null | undefined)[]
  /** Makes each box a button, for example to open the resource sheet. */
  onNodeSelect?: (id: string) => void
  /** compact: ids only, for path cards and list rows. */
  size?: 'default' | 'compact'
  className?: string
  'aria-label'?: string
}

/**
 * A path as a row of resource boxes joined by arrows, coloured by severity.
 * Wraps onto further lines when it runs out of width; an arrow always stays
 * attached to the box before it, so a line never starts with an arrow.
 */
export function ChainDiagram({
  nodes,
  edgeLabels,
  onNodeSelect,
  size = 'default',
  className,
  'aria-label': ariaLabel = 'Attack path',
}: ChainDiagramProps) {
  const compact = size === 'compact'
  return (
    <ol
      aria-label={ariaLabel}
      className={cn('flex flex-wrap items-center', compact ? 'gap-y-1.5' : 'gap-y-2.5', className)}
    >
      {nodes.map((node, index) => {
        const last = index === nodes.length - 1
        const edgeLabel = edgeLabels?.[index]
        return (
          <li key={`${node.id}-${String(index)}`} className="flex min-w-0 items-center">
            <ChainBox node={node} compact={compact} onSelect={onNodeSelect} />
            {!last && <ChainArrow label={edgeLabel ?? undefined} compact={compact} />}
          </li>
        )
      })}
    </ol>
  )
}

function ChainBox({
  node,
  compact,
  onSelect,
}: {
  node: ChainNode
  compact: boolean
  onSelect?: (id: string) => void
}) {
  const description = `${node.isEntry ? 'Entry point, ' : ''}${severityLabel(node.tone)}`
  const className = cn(
    'flex min-w-0 flex-col items-start rounded-md border bg-tone-fill text-left',
    node.isEntry ? 'border-dashed border-tone-stroke' : 'border-tone-line/60',
    compact ? 'max-w-56 px-1.5 py-0.5' : 'max-w-60 px-2.5 py-1.5',
    onSelect && 'cursor-pointer transition-[filter] hover:brightness-[0.97]',
  )
  const content = (
    <>
      <span
        className={cn(
          'max-w-full font-mono font-medium text-(--label-text)',
          // Compact rows stay on one line and truncate; full boxes wrap at
          // word boundaries inside the id, then anywhere as a last resort.
          compact ? 'truncate text-2xs leading-4' : 'text-xs leading-4 [overflow-wrap:anywhere]',
        )}
        title={compact ? node.id : undefined}
      >
        {compact ? node.id : <BreakableId id={node.id} />}
      </span>
      {!compact && (node.type !== undefined || node.isEntry === true) && (
        <span className="mt-0.5 max-w-full text-2xs leading-4 [overflow-wrap:anywhere] text-tone-stroke">
          {node.type ? formatResourceType(node.type) : null}
          {node.type && node.isEntry ? ' · ' : null}
          {node.isEntry ? 'entry' : null}
        </span>
      )}
      <span className="sr-only">{`(${description})`}</span>
    </>
  )
  if (onSelect) {
    return (
      <button
        type="button"
        data-tone={node.tone}
        className={className}
        title={node.type}
        onClick={() => onSelect(node.id)}
      >
        {content}
      </button>
    )
  }
  return (
    <div data-tone={node.tone} className={className} title={node.type}>
      {content}
    </div>
  )
}

function BreakableId({ id }: { id: string }) {
  const pieces = identifierBreaks(id)
  return pieces.map((piece, index) => (
    <Fragment key={index}>
      {index > 0 && <wbr />}
      {piece}
    </Fragment>
  ))
}

function ChainArrow({ label, compact }: { label?: string; compact: boolean }) {
  if (label) {
    return (
      <span
        className={cn(
          'flex shrink-0 flex-col items-center text-muted-foreground',
          compact ? 'mx-1' : 'mx-1.5',
        )}
      >
        <span className="font-mono text-2xs leading-3 text-muted-foreground">{label}</span>
        <ArrowRight aria-hidden="true" className="size-3.5" />
      </span>
    )
  }
  return (
    <ArrowRight
      aria-hidden="true"
      className={cn('shrink-0 text-muted-foreground', compact ? 'mx-1 size-3' : 'mx-1.5 size-3.5')}
    />
  )
}
