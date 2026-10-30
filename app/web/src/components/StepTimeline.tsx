import { ArrowRight, ArrowUpRight } from 'lucide-react'
import type { ReactNode } from 'react'

import type { Step } from '@/api/types'
import {
  alternativePreconditions,
  capabilityText,
  evidenceChips,
  stepTechnique,
  type TechniqueRef,
} from '@/lib/analysis'
import { safeHttpUrl, sentenceCase } from '@/lib/format'
import { cn } from '@/lib/utils'

interface StepTimelineProps {
  steps: readonly Step[]
  /** ATT&CK technique names by id; steps carry only the id. */
  techniqueNames: ReadonlyMap<string, string>
  /** Opens the resource sheet for a step's source or target. */
  onResourceSelect?: (id: string) => void
}

/** A path's steps, top to bottom, on a numbered rail. */
export function StepTimeline({ steps, techniqueNames, onResourceSelect }: StepTimelineProps) {
  return (
    <ol className="flex flex-col">
      {steps.map((step, index) => (
        <li
          key={`${step.source}-${step.target}-${String(index)}`}
          className="group/step flex gap-4"
        >
          <div className="flex flex-col items-center">
            <span className="flex size-6 shrink-0 items-center justify-center rounded-full border bg-surface text-xs font-medium text-foreground tabular-nums">
              {index + 1}
            </span>
            <span aria-hidden="true" className="w-px flex-1 bg-border group-last/step:hidden" />
          </div>
          <div className="min-w-0 flex-1 pb-7 group-last/step:pb-0">
            <StepBody
              step={step}
              technique={stepTechnique(step, techniqueNames)}
              onResourceSelect={onResourceSelect}
            />
          </div>
        </li>
      ))}
    </ol>
  )
}

function StepBody({
  step,
  technique,
  onResourceSelect,
}: {
  step: Step
  technique: TechniqueRef | null
  onResourceSelect?: (id: string) => void
}) {
  const alternatives = alternativePreconditions(step)
  const evidence = step.evidence
    .map((item) => ({ key: item.key, chips: evidenceChips(item.value) }))
    .filter((item) => item.chips.length > 0)

  return (
    <article className="flex flex-col gap-2.5">
      <header className="flex flex-col gap-1.5">
        <div className="flex min-h-6 flex-wrap items-center gap-x-2 gap-y-1">
          {step.tactic && (
            <span className="inline-flex h-5 items-center rounded-full border bg-zinc-50 px-2 text-2xs font-medium text-foreground">
              {sentenceCase(step.tactic)}
            </span>
          )}
          {technique && <TechniqueLink technique={technique} />}
          {!step.tactic && !technique && (
            <span className="text-xs text-muted-foreground">No ATT&amp;CK mapping</span>
          )}
          {step.fallback && (
            <span
              className="inline-flex h-5 items-center rounded-sm border border-dashed px-1.5 text-2xs text-muted-foreground"
              title="No specific action matched this edge; the generic fallback table supplied it."
            >
              Fallback
            </span>
          )}
        </div>
        <h3 className="text-sm leading-5 font-medium text-pretty text-foreground">{step.action}</h3>
        <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-muted-foreground">
          <ResourceRef id={step.source} onSelect={onResourceSelect} />
          <ArrowRight aria-label="to" className="size-3 shrink-0" />
          <ResourceRef id={step.target} onSelect={onResourceSelect} />
          {step.category && (
            <span>
              · {sentenceCase(step.category)}
              {step.relation && step.relation !== step.category
                ? `, ${sentenceCase(step.relation)}`
                : ''}
            </span>
          )}
        </div>
      </header>

      <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 rounded-md border bg-zinc-50/50 px-3 py-2.5 text-xs">
        <Row label="Requires">
          <span className="flex flex-wrap items-center gap-1.5">
            {step.precondition.length > 0 ? (
              step.precondition.map((p, index) => <Fact key={`${String(index)}-${p}`}>{p}</Fact>)
            ) : (
              <span className="text-muted-foreground">Nothing</span>
            )}
            {alternatives.length > 0 && (
              <span className="text-muted-foreground">
                or{' '}
                {alternatives.map((a, i) => (
                  <span key={`${String(i)}-${a}`}>
                    {i > 0 && ', '}
                    <span className="font-mono text-2xs">{a}</span>
                  </span>
                ))}
              </span>
            )}
          </span>
        </Row>
        <Row label="Grants">
          <span className="flex flex-wrap items-center gap-1.5">
            {step.postcondition.length > 0 ? (
              step.postcondition.map((p, index) => (
                <Fact key={`${String(index)}-${p}`} strong>
                  {p}
                </Fact>
              ))
            ) : (
              <span className="text-muted-foreground">Nothing new</span>
            )}
          </span>
        </Row>
        {step.required_capabilities.length > 0 && (
          <Row label="Needs findings">
            <ul className="flex flex-col gap-0.5">
              {step.required_capabilities.map((capability, index) => (
                <li
                  key={index}
                  className="font-mono text-2xs leading-5 [overflow-wrap:anywhere] text-foreground"
                >
                  {capabilityText(capability, step)}
                </li>
              ))}
            </ul>
          </Row>
        )}
        {step.required_permissions.length > 0 && (
          <Row label="Permissions">
            <span className="flex flex-wrap gap-1">
              {step.required_permissions.map((permission, index) => (
                <Chip key={`${String(index)}-${permission}`}>{permission}</Chip>
              ))}
            </span>
          </Row>
        )}
        {evidence.length > 0 && (
          <Row label="Evidence">
            <span className="flex flex-col gap-1">
              {evidence.map((item) => (
                <span key={item.key} className="flex flex-wrap items-center gap-1">
                  <span className="mr-0.5 font-mono text-2xs text-muted-foreground">
                    {item.key}
                  </span>
                  {item.chips.map((chip, index) => (
                    <Chip key={`${chip}-${String(index)}`}>{chip}</Chip>
                  ))}
                </span>
              ))}
            </span>
          </Row>
        )}
      </dl>
    </article>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="leading-5 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 leading-5">{children}</dd>
    </>
  )
}

function Fact({ children, strong = false }: { children: string; strong?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex min-h-5 items-center rounded-sm px-1.5 font-mono text-2xs [overflow-wrap:anywhere]',
        strong ? 'bg-zinc-900 text-white' : 'border bg-surface text-foreground',
      )}
    >
      {children}
    </span>
  )
}

function Chip({ children }: { children: string }) {
  return (
    <span className="inline-flex min-h-5 items-center rounded-sm border bg-surface px-1.5 font-mono text-2xs [overflow-wrap:anywhere] text-foreground">
      {children}
    </span>
  )
}

function ResourceRef({ id, onSelect }: { id: string; onSelect?: (id: string) => void }) {
  if (!onSelect) return <span className="font-mono text-foreground">{id}</span>
  return (
    <button
      type="button"
      onClick={() => onSelect(id)}
      className="cursor-pointer rounded-sm font-mono text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground"
    >
      {id}
    </button>
  )
}

function TechniqueLink({ technique }: { technique: TechniqueRef }) {
  const content = (
    <>
      <span className="font-mono font-medium">{technique.id}</span>
      {technique.name && <span className="text-muted-foreground">{technique.name}</span>}
    </>
  )
  const url = safeHttpUrl(technique.url)
  if (!url) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-foreground">{content}</span>
    )
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="group/tech inline-flex items-center gap-1.5 rounded-sm text-xs text-foreground hover:underline hover:decoration-border-strong hover:underline-offset-4"
    >
      {content}
      <ArrowUpRight
        aria-hidden="true"
        className="size-3 text-muted-foreground group-hover/tech:text-foreground"
      />
      <span className="sr-only">(MITRE ATT&amp;CK, opens in a new tab)</span>
    </a>
  )
}
