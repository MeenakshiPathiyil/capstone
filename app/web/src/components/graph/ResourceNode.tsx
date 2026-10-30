import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Layers } from 'lucide-react'

import { nodeFrameClass, type GraphFlowNode } from './flow'
import { nodeText, nodeTone } from './labels'
import { METRICS } from './layout'

/** Invisible anchors. React Flow wants them; the edges follow the layout's own routes. */
export function NodeHandles() {
  return (
    <>
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
        style={{ opacity: 0, pointerEvents: 'none' }}
      />
      <Handle
        type="source"
        position={Position.Right}
        isConnectable={false}
        style={{ opacity: 0, pointerEvents: 'none' }}
      />
    </>
  )
}

/** A small tab on the top edge of an entry point's box. Takes no room in the layout. */
export function EntryTab() {
  return (
    <span
      aria-hidden="true"
      className="absolute -top-[7px] right-2 z-10 flex h-3.5 items-center rounded-[3px] border border-dashed border-tone-stroke/70 bg-tone-fill px-1 text-[8.5px] leading-none font-semibold tracking-[0.08em] text-tone-stroke uppercase"
    >
      Entry
    </span>
  )
}

/** The title and type lines shared by resource and state boxes, wrapped as the layout decided. */
export function NodeHeading({ data }: { data: GraphFlowNode['data'] }) {
  const { lines, node } = data.placed
  const text = nodeText(node)
  return (
    <div
      className="flex flex-col justify-center whitespace-nowrap"
      style={{ padding: `${String(METRICS.nodePadY)}px ${String(METRICS.nodePadX)}px` }}
    >
      <span
        className="font-mono text-[12px] leading-4 font-medium text-(--label-text)"
        title={text.title}
      >
        {lines.title.map((line, index) => (
          <span key={index} className="block">
            {line}
          </span>
        ))}
      </span>
      {lines.type.length > 0 && (
        <span
          className="text-[11px] leading-[15px] text-tone-stroke"
          title={text.rawType ?? undefined}
        >
          {lines.type.map((line, index) => (
            <span key={index} className="block">
              {line}
            </span>
          ))}
        </span>
      )}
      {lines.extra.map((line, index) => (
        <span key={index} className="block text-[11px] leading-[15px] text-tone-stroke">
          {line}
        </span>
      ))}
    </div>
  )
}

/** A resource in the state view: one box per resource, coloured by its worst finding. */
export function ResourceNode({ data }: NodeProps<GraphFlowNode>) {
  return (
    <div data-tone={nodeTone(data.placed.node)} className={nodeFrameClass(data, 'bg-tone-fill')}>
      <NodeHandles />
      {data.placed.node.is_entry && <EntryTab />}
      <NodeHeading data={data} />
    </div>
  )
}

/** A nested stack, drawn as a quiet box around the resources it declares. */
export function StackGroupNode({ data }: NodeProps<GraphFlowNode>) {
  const text = nodeText(data.placed.node)
  return (
    <div className="pointer-events-none size-full rounded-lg border border-dashed border-border-strong bg-zinc-500/[0.035]">
      <NodeHandles />
      {/*
        One line, clipped to the header: the name comes first and truncates only when it alone is
        too long. "nested stack" wraps to the clipped second line when it does not fit beside it.
      */}
      <div
        className="pointer-events-auto absolute top-1 left-2.5 flex max-w-[calc(100%-20px)] cursor-pointer flex-wrap content-start items-center gap-x-1.5 overflow-hidden text-[11px] leading-4 text-muted-foreground hover:text-foreground"
        style={{ height: METRICS.groupHeader }}
      >
        <Layers aria-hidden="true" className="size-3 shrink-0" />
        <span className="max-w-[calc(100%-18px)] truncate font-mono font-medium" title={text.title}>
          {text.title}
        </span>
        <span className="text-faint">nested stack</span>
      </div>
    </div>
  )
}
