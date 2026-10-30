import { ArrowRight, CircleDashed } from 'lucide-react'
import { Fragment, type ReactNode } from 'react'

import type { Scenario } from '@/api/types'
import {
  missingSectionCopy,
  parseAttackGraph,
  sectionTitle,
  splitArrows,
  splitLines,
  splitParagraphs,
  splitTechniqueIds,
  truncationNote,
  type AttackStage,
  type SectionField,
} from '@/lib/scenario'

/**
 * The three sections of a generated scenario, laid out as narrative on the
 * left and the formal parts on the right. Every string here is model output
 * and is rendered as React text, never as HTML.
 */
export function ScenarioContent({ scenario }: { scenario: Scenario }) {
  const { sections } = scenario
  const note = truncationNote(scenario)

  return (
    <div className="flex flex-col">
      {sections.preamble !== null && (
        <div className="border-b px-4 py-3">
          <SectionHeading>Preamble</SectionHeading>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Text the model wrote before the first section.
          </p>
          <p className="mt-1.5 text-dense whitespace-pre-line text-foreground">
            {sections.preamble}
          </p>
        </div>
      )}
      <div className="grid lg:grid-cols-2 lg:divide-x">
        <Section field="natural_language" scenario={scenario}>
          {(text) => <Narrative text={text} />}
        </Section>
        <div className="flex min-w-0 flex-col divide-y border-t lg:border-t-0">
          <Section field="mathematical" scenario={scenario}>
            {(text) => <Mathematical text={text} />}
          </Section>
          <Section field="attack_graph" scenario={scenario}>
            {(text) => <AttackGraph text={text} />}
          </Section>
        </div>
      </div>
      {note && (
        <p className="border-t px-4 py-2.5 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Stopped at the token limit.</span> {note}
        </p>
      )}
    </div>
  )
}

function SectionHeading({ children }: { children: ReactNode }) {
  return <h3 className="text-dense font-semibold text-foreground">{children}</h3>
}

function Section({
  field,
  scenario,
  children,
}: {
  field: SectionField
  scenario: Scenario
  children: (text: string) => ReactNode
}) {
  const text = scenario.sections[field]
  if (text === null) {
    const copy = missingSectionCopy(field, scenario)
    return (
      <section aria-label={copy.title} className="min-w-0 p-4">
        <div className="flex items-start gap-2.5 rounded-md border border-dashed bg-zinc-50/60 px-3 py-2.5">
          <CircleDashed aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-faint" />
          <div className="min-w-0 text-dense">
            <p className="font-medium text-muted-foreground">{copy.title}</p>
            <p className="mt-0.5 text-xs text-pretty text-muted-foreground">{copy.description}</p>
          </div>
        </div>
      </section>
    )
  }
  const title = sectionTitle(field)
  const headingId = `scenario-section-${field}`
  return (
    <section aria-labelledby={headingId} className="min-w-0 p-4">
      <h3 id={headingId} className="text-dense font-semibold text-foreground">
        {title}
      </h3>
      <div className="mt-2.5">
        {text.trim() === '' ? (
          <p className="text-dense text-muted-foreground">
            The model wrote this heading with no text under it.
          </p>
        ) : (
          children(text)
        )}
      </div>
    </section>
  )
}

/** Text with ATT&CK technique ids set in mono. */
function WithTechniques({ text }: { text: string }) {
  return splitTechniqueIds(text).map((part, index) =>
    part.technique ? (
      <span key={index} className="font-mono text-[0.9em] text-foreground">
        {part.text}
      </span>
    ) : (
      <Fragment key={index}>{part.text}</Fragment>
    ),
  )
}

function Narrative({ text }: { text: string }) {
  return (
    <div className="flex max-w-[72ch] flex-col gap-3 text-sm leading-6 text-pretty text-foreground">
      {splitParagraphs(text).map((paragraph, index) => (
        <p key={index} className="whitespace-pre-line">
          <WithTechniques text={paragraph} />
        </p>
      ))}
    </div>
  )
}

function Mathematical({ text }: { text: string }) {
  return (
    <div className="rounded-md border bg-zinc-50/60 px-3 py-2.5 font-mono text-xs leading-5 text-foreground">
      {splitLines(text).map((line, index) => (
        // A hanging indent: a wrapped set reads as one line.
        <div key={index} className="pl-4 -indent-4 [overflow-wrap:anywhere]">
          {line}
        </div>
      ))}
    </div>
  )
}

function AttackGraph({ text }: { text: string }) {
  const graph = parseAttackGraph(text)
  if (graph.kind === 'text') {
    return (
      <div className="flex flex-col gap-1 text-dense text-foreground">
        {graph.lines.map((line, index) => (
          <p key={index} className="[overflow-wrap:anywhere]">
            <WithTechniques text={line} />
          </p>
        ))}
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-3">
      {graph.intro.length > 0 && (
        <p className="text-dense whitespace-pre-line text-muted-foreground">
          {graph.intro.join('\n')}
        </p>
      )}
      <ol className="flex flex-col">
        {graph.stages.map((stage, index) => (
          <StageItem key={`${String(stage.number)}-${String(index)}`} stage={stage} />
        ))}
      </ol>
      {graph.finalImpact !== null && (
        <div className="rounded-md border bg-zinc-50/60 px-3 py-2 text-dense">
          <span className="font-medium text-foreground">Final impact </span>
          <span className="text-muted-foreground">{graph.finalImpact}</span>
        </div>
      )}
      {graph.after.length > 0 && (
        <p className="text-dense whitespace-pre-line text-muted-foreground">
          {graph.after.join('\n')}
        </p>
      )}
    </div>
  )
}

function StageItem({ stage }: { stage: AttackStage }) {
  const [first = '', ...continuation] = stage.text.split('\n')
  const hops = splitArrows(first)
  return (
    <li className="group/stage flex gap-3">
      <div className="flex flex-col items-center">
        <span className="flex size-5 shrink-0 items-center justify-center rounded-full border bg-surface text-2xs font-medium text-foreground tabular-nums">
          {stage.number}
        </span>
        <span aria-hidden="true" className="w-px flex-1 bg-border group-last/stage:hidden" />
      </div>
      <div className="min-w-0 flex-1 pb-3 group-last/stage:pb-0">
        {stage.label && (
          <p className="text-xs leading-5 font-medium text-muted-foreground">{stage.label}</p>
        )}
        <p className="text-dense leading-5 [overflow-wrap:anywhere] text-foreground">
          {hops.length > 1
            ? hops.map((hop, index) => (
                <Fragment key={index}>
                  {index > 0 && (
                    <ArrowRight
                      aria-label="to"
                      className="mx-1 inline size-3.5 -translate-y-px text-muted-foreground"
                    />
                  )}
                  <WithTechniques text={hop} />
                </Fragment>
              ))
            : (first && <WithTechniques text={first} />) || (
                <span className="text-muted-foreground">No description</span>
              )}
        </p>
        {continuation.length > 0 && (
          <p className="mt-0.5 text-xs whitespace-pre-line text-muted-foreground">
            {continuation.join('\n')}
          </p>
        )}
      </div>
    </li>
  )
}
