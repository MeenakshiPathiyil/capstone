import type { ReactNode } from 'react'

import { Container } from '@/components/AppShell'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatCount } from '@/lib/format'
import { ANALYSIS_TAB_LABELS, ANALYSIS_TABS, isAnalysisTab, type AnalysisTab } from '@/lib/tabs'

interface AnalysisLayoutProps {
  /** The uploaded file name or sample name. */
  title: ReactNode
  /** One muted line under the title: industry, threshold, time, hash. */
  meta?: ReactNode
  /** Right of the title. The "Download report" button goes here. */
  actions?: ReactNode
  /** A strip under the header for warnings or notices. */
  notice?: ReactNode
  tab: AnalysisTab
  onTabChange: (tab: AnalysisTab) => void
  /** Shown as a quiet count next to the tab label. */
  tabCounts?: Partial<Record<AnalysisTab, number>>
  children: ReactNode
}

export function AnalysisLayout({
  title,
  meta,
  actions,
  notice,
  tab,
  onTabChange,
  tabCounts,
  children,
}: AnalysisLayoutProps) {
  return (
    <Tabs
      value={tab}
      onValueChange={(value) => {
        if (isAnalysisTab(value)) onTabChange(value)
      }}
      className="flex flex-1 flex-col"
    >
      <div className="border-b bg-surface">
        <Container>
          <div className="flex flex-wrap items-start gap-x-6 gap-y-3 pt-6 pb-4">
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-xl font-semibold text-foreground">{title}</h1>
              {meta && (
                <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-dense text-muted-foreground">
                  {meta}
                </div>
              )}
            </div>
            {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
          </div>
          <TabsList variant="line" aria-label="Analysis sections" className="-mb-px">
            {ANALYSIS_TABS.map((value) => {
              const count = tabCounts?.[value]
              return (
                <TabsTrigger key={value} value={value}>
                  {ANALYSIS_TAB_LABELS[value]}
                  {count !== undefined && (
                    <span className="rounded-sm bg-subtle px-1.5 text-xs leading-5 font-medium text-muted-foreground tabular-nums">
                      {formatCount(count)}
                    </span>
                  )}
                </TabsTrigger>
              )
            })}
          </TabsList>
        </Container>
      </div>
      {notice}
      <TabsContent value={tab} className="flex-1">
        <Container className="py-6">{children}</Container>
      </TabsContent>
    </Tabs>
  )
}

/** A "·" between items of the meta line. */
export function MetaDot() {
  return (
    <span aria-hidden="true" className="text-faint">
      ·
    </span>
  )
}
