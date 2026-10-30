import { Crosshair } from 'lucide-react'
import type { ReactNode } from 'react'

import type { GraphViewKind } from '@/api/graph'
import { severityLabel, type Tone } from '@/lib/severity'

import { FACT_ICONS } from './icons'
import { FACT_KIND_LABELS, FACT_SHORT_LABELS, type FactKind } from './labels'

function Item({ swatch, children }: { swatch: ReactNode; children: ReactNode }) {
  return (
    <li className="flex items-center gap-1.5 whitespace-nowrap">
      {swatch}
      {children}
    </li>
  )
}

function Swatch({ tone }: { tone: Tone }) {
  return (
    <span
      data-tone={tone}
      aria-hidden="true"
      className="inline-block h-2.5 w-3.5 rounded-[3px] border border-tone-line/60 bg-tone-fill"
    />
  )
}

function Line({ dash, colour, width = 1.5 }: { dash?: string; colour: string; width?: number }) {
  return (
    <svg aria-hidden="true" width="22" height="8" viewBox="0 0 22 8" className="shrink-0">
      <line
        x1="1"
        y1="4"
        x2="21"
        y2="4"
        stroke={colour}
        strokeWidth={width}
        strokeDasharray={dash}
        strokeLinecap={dash === '0.01 4' ? 'round' : 'butt'}
      />
    </svg>
  )
}

function Divider() {
  return <li aria-hidden="true" className="h-3 w-px bg-border" />
}

const LEGEND_FACTS: readonly FactKind[] = [
  'foothold',
  'credential',
  'data_access',
  'internet_reachable',
]
/** The key under the canvas: colours, shapes and line styles in this view. */
export function GraphLegend({ view, tones }: { view: GraphViewKind; tones: readonly Tone[] }) {
  return (
    <div className="flex min-h-9 items-center gap-x-4 border-t bg-surface px-3 py-1.5">
      <ul
        aria-label="Legend"
        className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground"
      >
        {tones.map((tone) => (
          <Item key={tone} swatch={<Swatch tone={tone} />}>
            {severityLabel(tone)}
          </Item>
        ))}
        {tones.length > 0 && <Divider />}
        <Item
          swatch={
            <span
              aria-hidden="true"
              className="inline-block h-2.5 w-3.5 rounded-[3px] border border-dashed border-zinc-500 bg-surface"
            />
          }
        >
          Entry point
        </Item>
        {view === 'attack' && (
          <Item
            swatch={
              <span className="flex h-3.5 items-center gap-1 rounded-full bg-zinc-900 px-1.5 text-[9px] font-medium text-white">
                <Crosshair aria-hidden="true" className="size-2.5" />
              </span>
            }
          >
            Attacker start
          </Item>
        )}
        <Divider />
        <Item swatch={<Line colour="var(--faint)" dash="4 3" />}>Reversed link</Item>
        <Item swatch={<Line colour="var(--emphasis)" width={2.5} />}>Selected path</Item>
        {view === 'attack' && (
          <>
            <Divider />
            {LEGEND_FACTS.map((kind) => {
              const Icon = FACT_ICONS[kind]
              return (
                <Item
                  key={kind}
                  swatch={
                    <Icon aria-hidden="true" className="size-3 text-faint" strokeWidth={1.75} />
                  }
                >
                  <span title={FACT_KIND_LABELS[kind]}>{FACT_SHORT_LABELS[kind]}</span>
                </Item>
              )
            })}
          </>
        )}
      </ul>
      <p className="ml-auto hidden shrink-0 text-2xs text-faint 2xl:block">
        Scroll to zoom · drag to pan · Enter opens a resource
      </p>
    </div>
  )
}
