import { BaseEdge, EdgeLabelRenderer, useStore, type EdgeProps } from '@xyflow/react'
import { ArrowLeftRight } from 'lucide-react'

import type { EdgeTone, GraphFlowEdge } from './flow'
import { arrowheadPath, edgePath, type PlacedLabel } from './layout'

/** Line widths and arrowheads in screen pixels: they stay the same at any zoom. */
const STROKE_PX: Record<EdgeTone, number> = { path: 2.75, hover: 1.75, default: 1.25, dim: 1.25 }
const ARROW_PX: Record<EdgeTone, number> = { path: 10, hover: 8, default: 7, dim: 7 }
const COLOUR: Record<EdgeTone, string> = {
  path: 'var(--emphasis)',
  hover: 'var(--label-text)',
  default: 'var(--faint)',
  dim: 'var(--faint)',
}

const zoomSelector = (state: { transform: [number, number, number] }) => state.transform[2]

/**
 * One edge along the route the layout computed. Reversed hops are dashed,
 * the attacker's start connectors dotted. A path edge is drawn in the
 * emphasis colour with its step number on the label.
 */
export function GraphEdgeView({ id, data }: EdgeProps<GraphFlowEdge>) {
  const zoom = useStore(zoomSelector)
  if (!data) return null
  const { placed, tone, steps, showText, onHoverChange } = data
  const end = placed.points[placed.points.length - 1]
  if (!end) return null

  const unit = 1 / zoom
  const arrowLength = ARROW_PX[tone] * unit
  const path = edgePath(placed.points, placed.startDir, placed.endDir, arrowLength * 0.75)
  const reversed = placed.edge?.reversed === true
  const start = placed.kind === 'start'
  const dash = start
    ? `${0.01 * unit} ${4.5 * unit}`
    : reversed
      ? `${5 * unit} ${3.5 * unit}`
      : undefined
  const opacity = tone === 'dim' ? 0.22 : start && tone === 'default' ? 0.8 : 1
  const colour = COLOUR[tone]

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        interactionWidth={start ? 0 : 14 * unit}
        style={{
          stroke: colour,
          strokeWidth: (start ? 1.5 : STROKE_PX[tone]) * unit,
          strokeDasharray: dash,
          strokeLinecap: start ? 'round' : 'butt',
          opacity,
          transition: 'opacity 200ms, stroke 200ms',
        }}
      />
      {!start && (
        <path
          d={arrowheadPath(end, placed.endDir, arrowLength, arrowLength * 0.42)}
          fill={colour}
          opacity={opacity}
          style={{ transition: 'opacity 200ms, fill 200ms' }}
        />
      )}
      {placed.label && (
        <EdgeSlot
          edgeKey={placed.key}
          label={placed.label}
          steps={steps}
          reversed={reversed}
          showText={showText}
          zoom={zoom}
          onHoverChange={onHoverChange}
        />
      )}
    </>
  )
}

function StepBadges({ steps }: { steps: readonly number[] }) {
  return (
    <span className="flex items-center gap-0.5">
      {steps.map((step) => (
        <span
          key={step}
          className="flex size-[18px] items-center justify-center rounded-full bg-(--emphasis) font-mono text-[10.5px] leading-none font-medium text-white tabular-nums shadow-[0_0_0_2px_var(--surface)]"
        >
          {step}
        </span>
      ))}
    </span>
  )
}

interface EdgeSlotProps {
  edgeKey: string
  label: PlacedLabel
  steps: readonly number[]
  reversed: boolean
  showText: boolean
  zoom: number
  onHoverChange: (key: string | null) => void
}

/**
 * What sits in the edge's slot: the step numbers of a selected path, and on
 * hover a card with the edge's text. Both are drawn at screen size, so they
 * read the same at any zoom; the card floats above the slot.
 */
function EdgeSlot({
  edgeKey,
  label,
  steps,
  reversed,
  showText,
  zoom,
  onHoverChange,
}: EdgeSlotProps) {
  if (steps.length === 0 && !showText) return null
  const x = label.x + label.width / 2
  const y = label.y + label.height / 2
  const scale = 1 / zoom
  const hover = {
    onPointerEnter: () => onHoverChange(edgeKey),
    onPointerLeave: () => onHoverChange(null),
  }
  return (
    <EdgeLabelRenderer>
      {steps.length > 0 && (
        <div
          className="nodrag nopan absolute top-0 left-0"
          style={{
            transform: `translate(${String(x)}px, ${String(y)}px) translate(-50%, -50%) scale(${String(scale)})`,
            zIndex: 4,
            pointerEvents: 'all',
          }}
          {...hover}
        >
          <StepBadges steps={steps} />
        </div>
      )}
      {showText && (
        <div
          role="tooltip"
          className="pointer-events-none absolute top-0 left-0"
          style={{
            transform: `translate(${String(x)}px, ${String(y)}px) scale(${String(scale)}) translate(-50%, calc(-100% - 14px))`,
            transformOrigin: '0 0',
            zIndex: 5,
          }}
        >
          <div className="flex max-w-[260px] flex-col gap-0.5 rounded-md border bg-surface px-2.5 py-1.5 text-left shadow-overlay">
            {label.lines.map((line, index) => (
              <span
                key={`${String(index)}-${line}`}
                className="text-[12px] leading-4 font-medium whitespace-nowrap text-foreground"
              >
                {line}
              </span>
            ))}
            {reversed && (
              <span className="flex items-center gap-1 text-[11px] leading-4 whitespace-nowrap text-muted-foreground">
                <ArrowLeftRight aria-hidden="true" className="size-3" strokeWidth={2} />
                Reversed: declared the other way in the template
              </span>
            )}
            {label.meta && !reversed && (
              <span className="text-[11px] leading-4 whitespace-nowrap text-muted-foreground">
                {label.meta}
              </span>
            )}
          </div>
        </div>
      )}
    </EdgeLabelRenderer>
  )
}
