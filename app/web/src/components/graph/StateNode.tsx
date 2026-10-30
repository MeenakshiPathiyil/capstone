import type { NodeProps } from '@xyflow/react'
import { Crosshair } from 'lucide-react'

import { cn } from '@/lib/utils'

import { nodeFrameClass, type GraphFlowNode } from './flow'
import { FACT_ICONS } from './icons'
import { factDescription, factRowText, nodeTone } from './labels'
import { factSuffix, factSummary, METRICS, unlistedFacts } from './layout'
import { EntryTab, NodeHandles, NodeHeading } from './ResourceNode'

/**
 * An attacker state in the attack view: the resource they stand on (header in
 * its severity colour), then what the move here gained them, one fact a row.
 * Facts carried over from earlier states are counted; the tooltip lists all.
 */
export function StateNode({ data }: NodeProps<GraphFlowNode>) {
  const { node, facts } = data.placed
  const summary = facts ? factSummary(facts) : null
  const suffix = facts ? factSuffix(facts) : null
  const hasRows = facts !== null && (facts.gained.length > 0 || summary !== null)
  return (
    <div
      data-tone={nodeTone(node)}
      className={nodeFrameClass(data, 'flex flex-col bg-surface')}
      title={facts ? `Attacker holds:\n${facts.all.map(factDescription).join('\n')}` : undefined}
    >
      <NodeHandles />
      {node.is_entry && <EntryTab />}
      <div className={cn('bg-tone-fill', hasRows ? 'rounded-t-[5px]' : 'rounded-[5px]')}>
        <NodeHeading data={data} />
      </div>
      {facts && hasRows && (
        <ul
          aria-label="Gained here"
          className="flex flex-1 flex-col justify-center border-t border-tone-line/30"
          style={{ padding: `${String(METRICS.factPadY)}px ${String(METRICS.nodePadX)}px` }}
        >
          {facts.gained.map((fact, index) => {
            const Icon = FACT_ICONS[fact.kind]
            const row = factRowText(fact, node.resource)
            const last = index === facts.gained.length - 1
            return (
              <li
                key={fact.raw}
                className="flex min-w-0 items-center text-zinc-700"
                style={{ height: METRICS.factRowHeight, gap: METRICS.factGap }}
              >
                <Icon
                  aria-hidden="true"
                  className="shrink-0 text-zinc-500"
                  style={{ width: METRICS.factIcon, height: METRICS.factIcon }}
                  strokeWidth={1.75}
                />
                <span className="sr-only">{factDescription(fact)}</span>
                <span
                  aria-hidden="true"
                  className={cn('truncate text-[10.5px] leading-4', row.mono && 'font-mono')}
                >
                  {row.text}
                </span>
                {last && suffix && (
                  <span
                    className="ml-auto shrink-0 text-[11px] leading-4 text-muted-foreground tabular-nums"
                    title={`Also holds ${String(unlistedFacts(facts))} more: see the box's tooltip`}
                  >
                    {suffix}
                  </span>
                )}
              </li>
            )
          })}
          {summary && (
            <li
              className="flex items-center text-[11px] whitespace-nowrap text-muted-foreground"
              style={{
                height: METRICS.factRowHeight,
                paddingLeft: METRICS.factIcon + METRICS.factGap,
              }}
            >
              {summary}
            </li>
          )}
        </ul>
      )}
    </div>
  )
}

/** The attacker before any move: a small dark pill every path starts from. */
export function AttackerNode({ data }: NodeProps<GraphFlowNode>) {
  return (
    <div
      className={cn(
        'flex size-full items-center justify-center gap-2 rounded-full bg-zinc-900 text-[12px] font-medium text-white shadow-[0_1px_2px_rgb(0_0_0/0.12)] transition-opacity duration-200',
        data.dimmed && 'opacity-40',
      )}
    >
      <NodeHandles />
      <Crosshair aria-hidden="true" className="size-3.5 text-zinc-300" strokeWidth={2} />
      {data.placed.node.label_lines[0] ?? 'Attacker'}
    </div>
  )
}
