import { ArrowRight, FileCode2, Upload, X } from 'lucide-react'
import { useEffect, useId, useRef, useState, type DragEvent, type SubmitEvent } from 'react'
import { useNavigate } from 'react-router'

import { busyKeys, RETRYING_TEXT, useRetrying } from '@/api/busy'
import { useCreateAnalysis, useCreateSampleAnalysis, useMeta } from '@/api/hooks'
import type { Limits, Sample } from '@/api/types'
import { AppShell, Container } from '@/components/AppShell'
import { ErrorState } from '@/components/ErrorState'
import { Spinner } from '@/components/Spinner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { fileExtension, formatBytes, formatCount, splitSampleDescription } from '@/lib/format'
import { ATTACK_LEVELS, isAttackLevel, type AttackLevel } from '@/lib/severity'
import { cn } from '@/lib/utils'

/** Used until /api/meta answers, and if it never does. Same values as app/api (config.py, analysis.py). */
const FALLBACK_LIMITS: Limits = {
  max_upload_bytes: 2 * 1024 * 1024,
  max_resources: 500,
  accepted_extensions: ['.yaml', '.yml', '.json', '.template'],
}

const DEFAULT_MIN_LEVEL: AttackLevel = 'HIGH'

const LEVEL_OPTION_LABELS: Record<AttackLevel, string> = {
  CRITICAL: 'Critical only',
  HIGH: 'High and above',
  MEDIUM: 'All paths',
}

/** Client-side check so an obviously wrong file fails before it is sent. */
function rejectFile(file: File, limits: Limits): string | null {
  const extension = fileExtension(file.name)
  if (!limits.accepted_extensions.includes(extension)) {
    return `${file.name} is not a template file. Use ${listExtensions(limits.accepted_extensions)}.`
  }
  if (file.size > limits.max_upload_bytes) {
    return `${file.name} is ${formatBytes(file.size)}. The limit is ${formatBytes(limits.max_upload_bytes)}.`
  }
  if (file.size === 0) return `${file.name} is empty.`
  return null
}

function listExtensions(extensions: readonly string[]): string {
  if (extensions.length <= 1) return extensions.join('')
  return `${extensions.slice(0, -1).join(', ')} or ${extensions.at(-1) ?? ''}`
}

export function UploadPage() {
  const navigate = useNavigate()
  const meta = useMeta()
  const upload = useCreateAnalysis()
  const sample = useCreateSampleAnalysis()

  const limits = meta.data?.limits ?? FALLBACK_LIMITS
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [industry, setIndustry] = useState<string | null>(null)
  const [minLevel, setMinLevel] = useState<AttackLevel>(DEFAULT_MIN_LEVEL)
  const [pendingSample, setPendingSample] = useState<string | null>(null)
  const uploadRetrying = useRetrying(busyKeys.upload)
  const sampleRetrying = useRetrying(busyKeys.sample)
  // `busy` only turns true after a render; two Enter presses (or clicks) can land before it.
  const inFlight = useRef(false)

  // The industry field starts with the backend's default once meta arrives;
  // after that it is the user's.
  const industryValue = industry ?? meta.data?.default_industry ?? ''
  const busy = upload.isPending || sample.isPending
  const trimmedIndustry = industryValue.trim()

  const chooseFile = (next: File | null) => {
    upload.reset()
    if (!next) {
      setFile(null)
      setFileError(null)
      return
    }
    const problem = rejectFile(next, limits)
    setFileError(problem)
    setFile(problem ? null : next)
  }

  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!file || !trimmedIndustry || busy || inFlight.current) return
    inFlight.current = true
    sample.reset()
    upload.mutate(
      { file, industry: trimmedIndustry, minLevel },
      {
        onSuccess: (analysis) => void navigate(`/analysis/${analysis.id}`),
        onSettled: () => {
          inFlight.current = false
        },
      },
    )
  }

  const runSample = (sampleId: string) => {
    if (!trimmedIndustry || busy || inFlight.current) return
    inFlight.current = true
    upload.reset()
    setPendingSample(sampleId)
    sample.mutate(
      { sample_id: sampleId, industry: trimmedIndustry, min_level: minLevel },
      {
        onSuccess: (analysis) => void navigate(`/analysis/${analysis.id}`),
        onSettled: () => {
          inFlight.current = false
          setPendingSample(null)
        },
      },
    )
  }

  const uploadError = fileError ?? (upload.error ? upload.error.message : null)

  return (
    <AppShell>
      <Container className="max-w-[46rem] pt-14 pb-20">
        <h1 className="text-2xl font-semibold text-foreground">
          Analyse a CloudFormation template
        </h1>
        <p className="mt-2 max-w-xl text-sm text-pretty text-muted-foreground">
          Finds misconfigurations and IAM privilege escalations, ranks the routes an attacker could
          take through the infrastructure, and prepares the riskiest for attack scenarios.
        </p>

        {meta.isError && (
          <ErrorState
            variant="inline"
            className="mt-6"
            title="Could not load samples and limits"
            message={meta.error.message}
            onRetry={() => void meta.refetch()}
            retrying={meta.isFetching}
          />
        )}

        <form onSubmit={submit} className="mt-8 rounded-lg border bg-surface" noValidate>
          <div className="p-5">
            <Dropzone
              file={file}
              limits={limits}
              invalid={uploadError !== null}
              disabled={busy}
              onFile={chooseFile}
              errorId="upload-error"
            />
            {uploadError && (
              <p
                id="upload-error"
                role="alert"
                data-tone="critical"
                className="mt-2.5 flex items-start gap-1.5 text-dense [overflow-wrap:anywhere] text-tone-stroke"
              >
                {uploadError}
              </p>
            )}
          </div>

          <div className="grid gap-4 border-t p-5 sm:grid-cols-[minmax(0,1fr)_12rem]">
            <IndustryField
              value={industryValue}
              onChange={setIndustry}
              suggestions={meta.data?.industries ?? []}
              disabled={busy}
              touched={industry !== null}
            />
            <MinLevelField
              value={minLevel}
              onChange={setMinLevel}
              levels={meta.data?.attack_levels ?? ATTACK_LEVELS}
              disabled={busy}
            />
          </div>

          <div className="flex items-center justify-between gap-4 rounded-b-lg border-t bg-zinc-50/70 px-5 py-3">
            <p className="text-xs text-muted-foreground">
              Runs on this machine. Nested stack URLs are never fetched.
            </p>
            <Button type="submit" disabled={!file || !trimmedIndustry || busy}>
              {upload.isPending ? (
                <>
                  <Spinner />
                  {uploadRetrying ? RETRYING_TEXT : 'Analysing'}
                </>
              ) : (
                'Analyse template'
              )}
            </Button>
          </div>
        </form>

        <section aria-labelledby="samples-heading" className="mt-10">
          <div className="flex items-baseline justify-between gap-4">
            <h2 id="samples-heading" className="text-sm font-semibold text-foreground">
              Or try a sample
            </h2>
            <p role="status" className="text-xs text-muted-foreground">
              {sampleRetrying ? RETRYING_TEXT : 'Uses the industry and level above'}
            </p>
          </div>
          <SampleGrid
            samples={meta.data?.samples}
            loading={meta.isPending}
            failed={meta.isError}
            pendingId={pendingSample}
            disabled={busy || !trimmedIndustry}
            onRun={runSample}
          />
          {sample.error && (
            <ErrorState
              variant="inline"
              className="mt-3"
              title="The sample could not be analysed"
              message={sample.error.message}
            />
          )}
        </section>
      </Container>
    </AppShell>
  )
}

// -- Dropzone -------------------------------------------------------------------------

interface DropzoneProps {
  file: File | null
  limits: Limits
  invalid: boolean
  disabled: boolean
  onFile: (file: File | null) => void
  errorId: string
}

function Dropzone({ file, limits, invalid, disabled, onFile, errorId }: DropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const inputId = useId()
  const hintId = useId()
  const [dragging, setDragging] = useState(false)
  const depth = useRef(0)

  // A file dropped just outside the zone would otherwise make the browser
  // navigate away to display it.
  useEffect(() => {
    const block = (event: globalThis.DragEvent) => {
      if (event.dataTransfer?.types.includes('Files')) event.preventDefault()
    }
    window.addEventListener('dragover', block)
    window.addEventListener('drop', block)
    return () => {
      window.removeEventListener('dragover', block)
      window.removeEventListener('drop', block)
    }
  }, [])

  const hasFiles = (event: DragEvent) => event.dataTransfer.types.includes('Files')

  const onDragEnter = (event: DragEvent) => {
    if (disabled || !hasFiles(event)) return
    event.preventDefault()
    depth.current += 1
    setDragging(true)
  }
  const onDragOver = (event: DragEvent) => {
    if (disabled || !hasFiles(event)) return
    event.preventDefault()
    event.dataTransfer.dropEffect = 'copy'
  }
  const onDragLeave = () => {
    depth.current = Math.max(0, depth.current - 1)
    if (depth.current === 0) setDragging(false)
  }
  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    depth.current = 0
    setDragging(false)
    if (disabled) return
    const dropped = event.dataTransfer.files[0]
    if (dropped) onFile(dropped)
  }

  const browse = () => inputRef.current?.click()
  const describedBy = invalid ? `${hintId} ${errorId}` : hintId

  return (
    <div
      onDragEnter={onDragEnter}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={(event) => {
        // The whole zone is a click target for the mouse; keyboard users get the button.
        if (!disabled && !(event.target as HTMLElement).closest('button')) browse()
      }}
      data-dragging={dragging || undefined}
      className={cn(
        'flex min-h-40 flex-col items-center justify-center rounded-lg border border-dashed px-6 py-8 text-center transition-colors',
        disabled ? 'cursor-default opacity-60' : 'cursor-pointer',
        dragging
          ? 'border-foreground bg-zinc-100'
          : invalid
            ? 'border-destructive/50 bg-zinc-50/60'
            : 'border-border-strong bg-zinc-50/60 hover:border-zinc-400 hover:bg-zinc-50',
      )}
    >
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        className="sr-only"
        tabIndex={-1}
        accept={limits.accepted_extensions.join(',')}
        disabled={disabled}
        aria-hidden="true"
        onChange={(event) => {
          onFile(event.target.files?.[0] ?? null)
          // Choosing the same file again should still fire change.
          event.target.value = ''
        }}
      />
      {file ? (
        <div className="flex w-full max-w-md items-center gap-3 rounded-lg border bg-surface p-3 text-left">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-md border bg-zinc-50 text-muted-foreground">
            <FileCode2 aria-hidden="true" className="size-4" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-foreground" title={file.name}>
              {file.name}
            </p>
            <p className="text-xs text-muted-foreground tabular-nums">{formatBytes(file.size)}</p>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={browse} disabled={disabled}>
            Replace
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={() => onFile(null)}
            disabled={disabled}
            aria-label={`Remove ${file.name}`}
          >
            <X />
          </Button>
        </div>
      ) : (
        <>
          <div className="mb-3 flex size-9 items-center justify-center rounded-lg border bg-surface text-muted-foreground">
            <Upload aria-hidden="true" className="size-4" />
          </div>
          <p className="text-sm text-foreground">
            {dragging ? (
              'Drop to select this file'
            ) : (
              <>
                Drop a template here, or{' '}
                <button
                  type="button"
                  onClick={browse}
                  disabled={disabled}
                  aria-describedby={describedBy}
                  className="cursor-pointer rounded-sm font-medium underline decoration-border-strong underline-offset-4 hover:decoration-foreground"
                >
                  browse files
                </button>
              </>
            )}
          </p>
          <p id={hintId} className="mt-1 text-xs text-muted-foreground">
            {listExtensions(limits.accepted_extensions)} up to{' '}
            <span className="tabular-nums">{formatBytes(limits.max_upload_bytes)}</span> and{' '}
            <span className="tabular-nums">{formatCount(limits.max_resources)}</span> resources
          </p>
        </>
      )}
    </div>
  )
}

// -- Options --------------------------------------------------------------------------

function IndustryField({
  value,
  onChange,
  suggestions,
  disabled,
  touched,
}: {
  value: string
  onChange: (value: string) => void
  suggestions: readonly string[]
  disabled: boolean
  /** Only flag an empty field once the user has edited it. */
  touched: boolean
}) {
  const id = useId()
  const listId = useId()
  const hintId = useId()
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <Label htmlFor={id}>Industry</Label>
      <Input
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        list={suggestions.length > 0 ? listId : undefined}
        maxLength={200}
        required
        disabled={disabled}
        aria-invalid={(touched && value.trim() === '') || undefined}
        aria-describedby={hintId}
        autoComplete="off"
        spellCheck={false}
      />
      {suggestions.length > 0 && (
        <datalist id={listId}>
          {suggestions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      )}
      <p id={hintId} className="text-xs text-muted-foreground">
        Sets the scene for generated scenarios. Pick a suggestion or type your own.
      </p>
    </div>
  )
}

function MinLevelField({
  value,
  onChange,
  levels,
  disabled,
}: {
  value: AttackLevel
  onChange: (value: AttackLevel) => void
  levels: readonly AttackLevel[]
  disabled: boolean
}) {
  const id = useId()
  const hintId = useId()
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <Label htmlFor={id}>Minimum level</Label>
      <Select
        value={value}
        onValueChange={(next) => {
          if (isAttackLevel(next)) onChange(next)
        }}
        disabled={disabled}
      >
        <SelectTrigger id={id} className="w-full" aria-describedby={hintId}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {levels.map((level) => (
            <SelectItem key={level} value={level}>
              {LEVEL_OPTION_LABELS[level]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p id={hintId} className="text-xs text-muted-foreground">
        Paths that qualify for scenarios.
      </p>
    </div>
  )
}

// -- Samples --------------------------------------------------------------------------

function SampleGrid({
  samples,
  loading,
  failed,
  pendingId,
  disabled,
  onRun,
}: {
  samples: readonly Sample[] | undefined
  loading: boolean
  failed: boolean
  pendingId: string | null
  disabled: boolean
  onRun: (id: string) => void
}) {
  if (loading) {
    return (
      <div role="status" className="mt-3 grid gap-3 sm:grid-cols-2">
        <span className="sr-only">Loading samples</span>
        {[0, 1].map((i) => (
          <div key={i} className="rounded-lg border bg-surface p-4">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="mt-2.5 h-3 w-full" />
            <Skeleton className="mt-1.5 h-3 w-2/3" />
            <Skeleton className="mt-4 h-3 w-24" />
          </div>
        ))}
      </div>
    )
  }
  if (!samples || samples.length === 0) {
    return (
      <p className="mt-3 rounded-lg border border-dashed px-4 py-6 text-center text-dense text-muted-foreground">
        {failed
          ? 'Samples appear once the analysis service is reachable.'
          : 'No samples are available.'}
      </p>
    )
  }
  return (
    <ul className="mt-3 grid gap-3 sm:grid-cols-2">
      {samples.map((s) => {
        const pending = pendingId === s.id
        const { file, text } = splitSampleDescription(s.description)
        return (
          <li key={s.id} className="flex">
            <button
              type="button"
              onClick={() => onRun(s.id)}
              disabled={disabled}
              aria-busy={pending || undefined}
              className="group flex w-full cursor-pointer flex-col rounded-lg border bg-surface p-4 text-left transition-colors hover:border-border-strong hover:bg-zinc-50/60 disabled:cursor-default disabled:opacity-60 disabled:hover:border-border disabled:hover:bg-surface aria-busy:opacity-100"
            >
              <span className="flex w-full items-center gap-2">
                <span className="truncate text-sm font-medium text-foreground">{s.name}</span>
                {s.kind === 'nested' && s.name.toLowerCase() !== 'nested stacks' && (
                  <span className="rounded-sm border px-1.5 text-2xs leading-4 text-muted-foreground">
                    Nested
                  </span>
                )}
                <span className="ml-auto flex size-4 shrink-0 items-center justify-center text-muted-foreground">
                  {pending ? (
                    <Spinner className="size-3.5" />
                  ) : (
                    <ArrowRight
                      aria-hidden="true"
                      className="size-3.5 transition-transform group-hover:translate-x-0.5 group-disabled:translate-x-0"
                    />
                  )}
                </span>
              </span>
              <span className="mt-1 text-dense text-pretty text-muted-foreground">{text}</span>
              {file && (
                <span className="mt-auto flex items-center gap-1.5 pt-3 text-muted-foreground">
                  <FileCode2 aria-hidden="true" className="size-3.5 shrink-0" />
                  <span className="truncate font-mono text-2xs">{file}</span>
                </span>
              )}
            </button>
          </li>
        )
      })}
    </ul>
  )
}
