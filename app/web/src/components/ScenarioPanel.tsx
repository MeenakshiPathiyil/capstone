import { Check, CircleAlert, Copy, Info, Lock, Sparkles } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'

import { ApiError } from '@/api/client'
import { useHealth, useScenario } from '@/api/scenario'
import type { Health, Scenario, ScenarioState } from '@/api/types'
import { ErrorState } from '@/components/ErrorState'
import { ScenarioContent } from '@/components/ScenarioContent'
import { SectionCard } from '@/components/SectionCard'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { formatDateTime, formatDuration, pluralize, shortHash } from '@/lib/format'
import {
  humanizeTimestamps,
  isActiveStatus,
  isResultStatus,
  progressCopy,
  repoName,
  retryAfterSuffix,
  sourceLabel,
  statusAnnouncement,
  type ScenarioStatus,
} from '@/lib/scenario'
import { cn } from '@/lib/utils'

export interface ScenarioPanelProps {
  analysisId: string
  /** The path's AP id, for example AP-001. */
  sourceId: string
  /** Only exported paths (at or above the minimum level) can have a scenario. */
  exported: boolean
}

const NOT_EXPORTED = 'Scenarios are generated only for paths at or above the minimum level'

/**
 * The model-written attack scenario for one path (plan 10.4): generate it,
 * follow its job while it is queued, warming up or running, then read the
 * three sections with their provenance. Generated text is rendered as text.
 */
export function ScenarioPanel({ analysisId, sourceId, exported }: ScenarioPanelProps) {
  const { state, generate } = useScenario(analysisId, sourceId, exported)
  const health = useHealth({ enabled: exported })
  const data = exported ? state.data : undefined
  const status = data?.status

  const panelRef = useRef<HTMLDivElement>(null)
  const resultRef = useRef<HTMLDivElement>(null)
  const failedRef = useRef<HTMLDivElement>(null)
  const { announcement, finished } = useStatusTransitions(status, data?.queue_position ?? null)

  // A job that finishes while the user waits gets focus moved to its outcome,
  // unless the user has moved on to something else on the page.
  useEffect(() => {
    if (finished === 0) return
    const panel = panelRef.current
    const active = document.activeElement
    if (!panel || (active && active !== document.body && !panel.contains(active))) return
    const target = failedRef.current ?? resultRef.current
    target?.focus({ preventScroll: true })
    target?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [finished])

  const scenario = data?.scenario ?? null
  const showResult = scenario !== null && (isResultStatus(status) || status === 'failed')
  const startError = generate.error
  const onGenerate = () => {
    if (!generate.isPending) generate.mutate()
  }

  let body: ReactNode
  if (!exported) {
    body = (
      <ActionRow
        icon={Lock}
        title="Not available for this path"
        detail={`${NOT_EXPORTED}.`}
        action={<NotExportedButton />}
      />
    )
  } else if (state.isPending) {
    body = <ScenarioLoading />
  } else if (state.isError) {
    body = (
      <div className="p-4">
        <ErrorState
          variant="inline"
          title="Could not load the scenario"
          message={state.error.message}
          onRetry={() => void state.refetch()}
          retrying={state.isFetching}
        />
      </div>
    )
  } else if (status === 'idle' || isActiveStatus(status)) {
    body = (
      <IdleOrProgress
        state={state.data}
        health={health.data}
        updatedAt={state.dataUpdatedAt}
        onGenerate={onGenerate}
        requesting={generate.isPending}
        startError={startError}
      />
    )
  } else if (status === 'failed') {
    body = (
      <div className="flex flex-col gap-3 p-4">
        <div ref={failedRef} tabIndex={-1} className="rounded-lg outline-none">
          <ErrorState
            variant="inline"
            title="Scenario generation failed"
            message={state.data.error ?? 'The generation stopped without a message.'}
            onRetry={onGenerate}
            retrying={generate.isPending}
            retryLabel="Retry"
          />
        </div>
        {startError && <StartErrorNotice error={startError} />}
        {scenario && (
          <p className="text-xs text-muted-foreground">
            The last saved scenario for this path is shown below.
          </p>
        )}
      </div>
    )
  } else if (!scenario) {
    body = (
      <div className="p-4">
        <ErrorState
          variant="inline"
          title="Could not load the scenario"
          message="The API reported a finished scenario but sent no text."
          onRetry={() => void state.refetch()}
          retrying={state.isFetching}
        />
      </div>
    )
  }

  return (
    <div ref={panelRef}>
      <SectionCard
        title={
          <span className="flex items-center gap-2">
            <Sparkles aria-hidden="true" className="size-3.5 text-muted-foreground" />
            Attack scenario
          </span>
        }
        titleId="scenario-heading"
        meta={
          showResult ? (
            <Badge variant="outline" title="Written by a fine-tuned language model">
              AI-generated
            </Badge>
          ) : null
        }
        action={showResult ? <CopyButton text={scenario.text} /> : null}
        flush
      >
        <p role="status" aria-live="polite" className="sr-only">
          {announcement}
        </p>
        {body}
        {showResult && (
          <>
            <div
              ref={resultRef}
              tabIndex={-1}
              aria-label={`Generated scenario for ${sourceId}`}
              className={cn('outline-none', status === 'failed' && 'border-t')}
            >
              <ScenarioContent scenario={scenario} />
            </div>
            <ProvenanceFooter scenario={scenario} />
          </>
        )}
      </SectionCard>
    </div>
  )
}

// -- Status transitions -------------------------------------------------------------

/**
 * The live-region text and a counter that ticks when a job ends. Both change
 * only on a change of status (never on the first load, never per second).
 */
function useStatusTransitions(status: ScenarioStatus | undefined, queuePosition: number | null) {
  const [previous, setPrevious] = useState(status)
  const [announcement, setAnnouncement] = useState('')
  const [finished, setFinished] = useState(0)

  if (status !== previous) {
    setPrevious(status)
    if (previous !== undefined && status !== undefined) {
      setAnnouncement(statusAnnouncement(status, queuePosition))
      if (isActiveStatus(previous) && !isActiveStatus(status)) setFinished((n) => n + 1)
    }
  }

  return { announcement, finished }
}

/** Wall-clock seconds since `anchor` (ms), ticking once a second while `active`. */
function useTicker(active: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [active])
  return now
}

/**
 * The job's elapsed seconds, counted locally between two-second polls. The
 * start time is pinned from the first answer, so the count never steps
 * backwards when a poll lands; a new job (a jump of more than two seconds)
 * re-pins it.
 */
function useElapsed(serverElapsedS: number | null, updatedAt: number, active: boolean): number {
  const now = useTicker(active)
  const candidate = updatedAt - (serverElapsedS ?? 0) * 1000
  const [start, setStart] = useState(candidate)
  if (Math.abs(candidate - start) > 2000) setStart(candidate)
  return Math.max(serverElapsedS ?? 0, (Math.max(now, updatedAt) - start) / 1000)
}

// -- Idle and in progress -----------------------------------------------------------

function IdleOrProgress({
  state,
  health,
  updatedAt,
  onGenerate,
  requesting,
  startError,
}: {
  state: ScenarioState
  health: Health | undefined
  updatedAt: number
  onGenerate: () => void
  requesting: boolean
  startError: Error | null
}) {
  const active = isActiveStatus(state.status)
  const elapsed = useElapsed(state.elapsed_s, updatedAt, state.status === 'running')
  const unavailable = !active ? (health?.model_unavailable_reason ?? null) : null

  let title: string
  let detail: ReactNode
  let action: ReactNode

  if (active) {
    const copy = progressCopy(state.status, state.queue_position, elapsed)
    title = 'Writing the scenario'
    detail = copy.detail
    action = (
      <StatusButton label={copy.button} pulse={state.status !== 'queued'} onClick={undefined} />
    )
  } else {
    title = 'Write this path up as an attack scenario'
    detail =
      'A fine-tuned Mistral-7B model drafts a narrative, a mathematical expression and an attack graph from this path. Live generation runs on a shared GPU and can take a few minutes.'
    action = (
      <StatusButton
        label="Generate scenario"
        primary
        disabled={unavailable !== null}
        busy={requesting}
        onClick={onGenerate}
      />
    )
  }

  return (
    <>
      {active && <IndeterminateBar />}
      <ActionRow icon={Sparkles} title={title} detail={detail} action={action} />
      {unavailable && (
        <div className="px-4 pb-4">
          <Notice icon={Info} title="Live generation is unavailable">
            {humanizeTimestamps(unavailable)}
          </Notice>
        </div>
      )}
      {startError && !active && (
        <div className="px-4 pb-4">
          <StartErrorNotice error={startError} />
        </div>
      )}
    </>
  )
}

function ActionRow({
  icon: Icon,
  title,
  detail,
  action,
}: {
  icon: typeof Sparkles
  title: string
  detail: ReactNode
  action: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-4">
      <div className="flex size-8 shrink-0 items-center justify-center rounded-md border bg-zinc-50 text-muted-foreground">
        <Icon aria-hidden="true" className="size-4" />
      </div>
      <div className="min-w-0 flex-1 basis-80">
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="mt-0.5 max-w-[80ch] text-dense text-pretty text-muted-foreground">{detail}</p>
      </div>
      <div className="shrink-0">{action}</div>
    </div>
  )
}

/**
 * The panel's one button. It stays the same element from "Generate scenario"
 * through queued and running, so keyboard focus is not lost when it turns
 * into a status; while busy it is aria-disabled rather than disabled for the
 * same reason.
 */
function StatusButton({
  label,
  primary = false,
  disabled = false,
  busy = false,
  pulse = false,
  onClick,
}: {
  label: string
  primary?: boolean
  disabled?: boolean
  busy?: boolean
  pulse?: boolean
  onClick: (() => void) | undefined
}) {
  const inert = onClick === undefined || busy
  return (
    <Button
      variant={primary ? 'default' : 'outline'}
      disabled={disabled}
      aria-disabled={inert && !disabled ? true : undefined}
      onClick={inert ? undefined : onClick}
      className={cn(
        'min-w-44 tabular-nums',
        onClick === undefined &&
          'cursor-default text-muted-foreground hover:bg-surface aria-disabled:pointer-events-auto aria-disabled:opacity-100',
      )}
    >
      {onClick === undefined ? (
        <span
          aria-hidden="true"
          className={cn(
            'size-1.5 rounded-full bg-zinc-400',
            pulse && 'animate-pulse motion-reduce:animate-none',
          )}
        />
      ) : (
        <Sparkles aria-hidden="true" />
      )}
      {label}
    </Button>
  )
}

function IndeterminateBar() {
  return (
    <div aria-hidden="true" className="relative -mt-px h-0.5 overflow-hidden bg-zinc-100">
      <div className="absolute inset-y-0 left-0 w-1/4 animate-indeterminate rounded-full bg-zinc-400 motion-reduce:w-full motion-reduce:animate-none motion-reduce:bg-zinc-300" />
    </div>
  )
}

function NotExportedButton() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* A disabled button gets no pointer or focus events; the wrapper does. */}
        <span tabIndex={0} className="inline-flex rounded-md">
          <Button variant="outline" disabled className="min-w-44">
            <Sparkles aria-hidden="true" />
            Generate scenario
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{NOT_EXPORTED}</TooltipContent>
    </Tooltip>
  )
}

// -- Notices -----------------------------------------------------------------------

function Notice({
  icon: Icon,
  title,
  children,
  alert = false,
}: {
  icon: typeof Info
  title: string
  children: ReactNode
  alert?: boolean
}) {
  return (
    <div
      role={alert ? 'alert' : undefined}
      className="flex items-start gap-3 rounded-lg border bg-zinc-50/70 px-3 py-2.5"
    >
      <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1 text-dense">
        <p className="font-medium text-foreground">{title}</p>
        <p className="mt-0.5 text-pretty [overflow-wrap:anywhere] text-muted-foreground">
          {children}
        </p>
      </div>
    </div>
  )
}

/**
 * Why a POST did not start a generation: the server's detail, and when to try
 * again. A 429's message already says when (see rateLimitMessage).
 */
function StartErrorNotice({ error }: { error: Error }) {
  if (error instanceof ApiError && (error.status === 503 || error.status === 429)) {
    const retry =
      error.status === 503 && error.retryAfterS !== null
        ? retryAfterSuffix(error.message, error.retryAfterS)
        : null
    return (
      <Notice icon={CircleAlert} title="Could not start a generation" alert>
        {humanizeTimestamps(error.message)}
        {retry && <> {retry}</>}
      </Notice>
    )
  }
  return (
    <ErrorState variant="inline" title="Could not start a generation" message={error.message} />
  )
}

// -- Loading -----------------------------------------------------------------------

function ScenarioLoading() {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-4 px-4 py-4">
      <span className="sr-only">Loading the scenario</span>
      <Skeleton className="size-8 rounded-md" />
      <div className="flex flex-1 flex-col gap-2">
        <Skeleton className="h-3.5 w-64" />
        <Skeleton className="h-3 w-full max-w-xl" />
      </div>
      <Skeleton className="h-8 w-44" />
    </div>
  )
}

// -- Result chrome -----------------------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState<'idle' | 'copied' | 'failed'>('idle')
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])

  const copy = async () => {
    window.clearTimeout(timer.current)
    try {
      await navigator.clipboard.writeText(text)
      setCopied('copied')
    } catch {
      setCopied('failed')
    }
    timer.current = window.setTimeout(() => setCopied('idle'), 2000)
  }

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={() => void copy()}
        title="Copy the model's raw output"
      >
        {copied === 'copied' ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        {copied === 'copied' ? 'Copied' : copied === 'failed' ? 'Copy failed' : 'Copy'}
      </Button>
      <span role="status" className="sr-only">
        {copied === 'copied'
          ? 'Scenario text copied.'
          : copied === 'failed'
            ? 'Could not copy.'
            : ''}
      </span>
    </>
  )
}

function ProvenanceFooter({ scenario }: { scenario: Scenario }) {
  const items: { key: string; node: ReactNode; title?: string }[] = [
    {
      key: 'model',
      node: repoName(scenario.model_id),
      title: `${scenario.model_id} @ ${scenario.model_revision}, ${scenario.loading_recipe}`,
    },
    {
      key: 'adapter',
      node: (
        <>
          {repoName(scenario.adapter_repo)}{' '}
          <span className="font-mono">{shortHash(scenario.adapter_revision)}</span>
        </>
      ),
      title: `Adapter ${scenario.adapter_repo} @ ${scenario.adapter_revision}`,
    },
    {
      key: 'prompt',
      node: `prompt ${scenario.prompt_version}`,
      title: 'The prompt format this scenario was generated with',
    },
    {
      key: 'time',
      node: `${formatDuration(scenario.seconds)}, ${pluralize(scenario.new_tokens, 'token')}`,
    },
    { key: 'at', node: formatDateTime(scenario.generated_at) },
  ]
  return (
    <footer className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-b-lg border-t bg-zinc-50/60 px-4 py-2.5 text-xs text-muted-foreground">
      <Badge variant={scenario.source === 'live' ? 'secondary' : 'outline'}>
        {sourceLabel(scenario.source)}
      </Badge>
      <ul className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {items.map((item, index) => (
          <li key={item.key} className="flex items-center gap-2" title={item.title}>
            {index > 0 && (
              <span aria-hidden="true" className="text-faint">
                ·
              </span>
            )}
            <span>{item.node}</span>
          </li>
        ))}
      </ul>
      <p className="ml-auto text-pretty">
        Written by a language model. Check it against the analysed steps above.
      </p>
    </footer>
  )
}
