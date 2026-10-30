import { useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Download, TriangleAlert } from 'lucide-react'
import { useId, useRef, useState } from 'react'

import { ApiError, fetchFile } from '@/api/client'
import { busyKeys, useRetrying } from '@/api/busy'
import { fixImpactQuery, type FixScope } from '@/api/hooks'
import { useHealth } from '@/api/scenario'
import { Spinner } from '@/components/Spinner'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Popover, PopoverAnchor, PopoverContent } from '@/components/ui/popover'
import { reportPath } from '@/lib/analysis'
import { formatCount, pluralize } from '@/lib/format'

/** Most paths one report details (the server's MAX_REPORT_PATHS); a larger scope is cut to it. */
const REPORT_PATH_CAP = 50

interface DownloadReportMenuProps {
  analysisId: string
  /** Selected (exported) paths in the analysis, for the "all" option's count. */
  exportedPaths: number
}

interface DownloadError {
  scope: FixScope
  /** Whether the failed download was asked to include fix-impact estimates. */
  estimates: boolean
  /** Which step failed: computing the estimates, or fetching the PDF itself. */
  step: 'estimates' | 'report'
  message: string
}

/** What to tell the user when fix impact for the report could not be computed. */
function prepareErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 503) {
    const wait =
      error.retryAfterS !== null && error.retryAfterS > 0
        ? `in ${pluralize(error.retryAfterS, 'second')}`
        : 'in a moment'
    return `The analysis service is busy. Try again ${wait}.`
  }
  return error instanceof Error ? error.message : 'Something went wrong.'
}

/** Used when the response names no file; the server always sends one. */
const FALLBACK_FILENAME = 'attack-path-assessment.pdf'

/** Save `blob` as `filename` the way a link with a download attribute would. */
function saveFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  // Revoking at once can cancel the download in some browsers.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

/**
 * Split button: the main half downloads the default report (top five paths);
 * the chevron offers the scope. The report includes fix-impact estimates only
 * when they were computed for the same scope, so a download first makes sure
 * they are (instant when the overview already did), then fetches the PDF and
 * saves it. Fetching it here, rather than letting the browser follow a link,
 * means a refusal (render busy, rate limit) is shown, not a failed download.
 * When the server cannot render PDFs (/api/health) both halves are inert and
 * say why.
 *
 * Inert buttons are aria-disabled, not disabled, so keyboard focus stays on
 * them while the report is prepared; when the menu or the error popover
 * closes, focus goes to the main button rather than to nowhere.
 */
export function DownloadReportMenu({ analysisId, exportedPaths }: DownloadReportMenuProps) {
  const queryClient = useQueryClient()
  const [preparing, setPreparing] = useState<FixScope | null>(null)
  const [error, setError] = useState<DownloadError | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const mainRef = useRef<HTMLButtonElement>(null)
  const reasonId = useId()
  // Set when a menu item starts the download, so closing the menu moves focus to the main button.
  const chosenFromMenu = useRef(false)

  const health = useHealth()
  // Until /api/health answers, assume PDFs work: the download itself reports a 503.
  const pdfUnavailable =
    health.data && !health.data.weasyprint
      ? (health.data.pdf_unavailable_reason ?? 'PDF reports are unavailable on this server.')
      : null

  const download = async (scope: FixScope, estimates = true) => {
    if (pdfUnavailable !== null) return
    setError(null)
    setPreparing(scope)
    try {
      // No exported paths: there is nothing to estimate, and the report says so.
      if (estimates && exportedPaths > 0) {
        try {
          await queryClient.query(fixImpactQuery(analysisId, scope))
        } catch (caught) {
          setError({ scope, estimates, step: 'estimates', message: prepareErrorMessage(caught) })
          return
        }
      }
      try {
        const file = await fetchFile(reportPath(analysisId, scope))
        saveFile(file.blob, file.filename ?? FALLBACK_FILENAME)
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : 'Something went wrong.'
        setError({ scope, estimates, step: 'report', message })
      }
    } finally {
      setPreparing(null)
    }
  }

  const busy = preparing !== null
  const inert = busy || pdfUnavailable !== null
  const retrying = useRetrying(busyKeys.fixes(analysisId, preparing ?? 5))
  return (
    <Popover open={error !== null} onOpenChange={(open) => !open && setError(null)}>
      <PopoverAnchor asChild>
        <div className="flex items-center" aria-busy={busy} title={pdfUnavailable ?? undefined}>
          <Button
            ref={mainRef}
            variant="outline"
            className="rounded-r-none border-r-0"
            aria-disabled={inert || undefined}
            aria-describedby={pdfUnavailable ? reasonId : undefined}
            onClick={inert ? undefined : () => void download(5)}
          >
            {busy ? <Spinner /> : <Download />}
            {/* Both labels share one cell, so the button keeps its width. */}
            <span className="grid">
              <span
                aria-hidden={!busy}
                className={busy ? 'col-start-1 row-start-1' : 'invisible col-start-1 row-start-1'}
              >
                {busy && retrying ? 'Busy, retrying…' : 'Preparing report…'}
              </span>
              <span
                aria-hidden={busy}
                className={busy ? 'invisible col-start-1 row-start-1' : 'col-start-1 row-start-1'}
              >
                Download report
              </span>
            </span>
          </Button>
          {pdfUnavailable && (
            <span id={reasonId} className="sr-only">
              {pdfUnavailable}
            </span>
          )}
          <DropdownMenu open={menuOpen} onOpenChange={(open) => setMenuOpen(open && !inert)}>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                className="w-7 rounded-l-none"
                aria-label="Report options"
                aria-disabled={inert || undefined}
              >
                <ChevronDown className="size-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-60"
              onCloseAutoFocus={(event) => {
                if (!chosenFromMenu.current) return
                chosenFromMenu.current = false
                event.preventDefault()
                mainRef.current?.focus()
              }}
            >
              <DropdownMenuLabel>Paths in the report</DropdownMenuLabel>
              <DropdownMenuItem
                onSelect={() => {
                  chosenFromMenu.current = true
                  void download(5)
                }}
              >
                <span className="flex-1">Top 5 paths</span>
                <span className="text-xs text-muted-foreground">Default</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={() => {
                  chosenFromMenu.current = true
                  void download('all')
                }}
              >
                <span className="flex-1">
                  {exportedPaths > REPORT_PATH_CAP
                    ? `Top ${REPORT_PATH_CAP} exported paths`
                    : 'All exported paths'}
                </span>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {exportedPaths > REPORT_PATH_CAP
                    ? `of ${formatCount(exportedPaths)}`
                    : formatCount(exportedPaths)}
                </span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </PopoverAnchor>
      <PopoverContent
        align="end"
        className="w-80"
        role="alert"
        onCloseAutoFocus={(event) => {
          // There is no trigger for Radix to return to. Focus the main button unless
          // the user already clicked on something else.
          event.preventDefault()
          if (document.activeElement === null || document.activeElement === document.body) {
            mainRef.current?.focus()
          }
        }}
      >
        <div className="flex gap-2.5">
          <TriangleAlert
            aria-hidden="true"
            data-tone="medium"
            className="mt-0.5 size-4 shrink-0 text-tone-stroke"
          />
          <div className="min-w-0 flex-1">
            <p className="font-medium text-foreground">
              {error?.step === 'report'
                ? 'The report could not be downloaded'
                : 'Fix-impact estimates are not ready'}
            </p>
            <p className="mt-0.5 text-dense text-muted-foreground">{error?.message}</p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          {error?.step === 'estimates' && (
            <Button variant="ghost" size="sm" onClick={() => void download(error.scope, false)}>
              Download without estimates
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (error) void download(error.scope, error.estimates)
            }}
          >
            Try again
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  )
}
