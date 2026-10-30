import type { ReactNode } from 'react'
import { Link } from 'react-router'

import { cn } from '@/lib/utils'

/** The one page width: 1280px content, 24px gutters. */
export function Container({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn('mx-auto w-full max-w-[1280px] px-6', className)}>{children}</div>
}

function BrandMark() {
  // Three nodes and two edges: a path. Drawn, not decorative; it is the logo.
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true" className="size-5 shrink-0">
      <rect width="20" height="20" rx="5" className="fill-zinc-900" />
      <path d="M5.5 14.5 10 10l4.5-4.5" className="stroke-white" strokeWidth="1.5" fill="none" />
      <circle cx="5.5" cy="14.5" r="1.75" className="fill-white" />
      <circle cx="10" cy="10" r="1.75" className="fill-white" />
      <circle cx="14.5" cy="5.5" r="1.75" className="fill-white" />
    </svg>
  )
}

interface AppHeaderProps {
  /** Right-hand side: page-level actions such as "New analysis". */
  actions?: ReactNode
}

export function AppHeader({ actions }: AppHeaderProps) {
  return (
    <header className="sticky top-0 z-40 border-b bg-surface/95 backdrop-blur-sm">
      <Container className="flex h-12 items-center gap-4">
        <Link
          to="/"
          className="-mx-1 flex items-center gap-2.5 rounded-md px-1 py-1 text-sm font-semibold text-foreground"
        >
          <BrandMark />
          Capstone
        </Link>
        <span aria-hidden="true" className="h-4 w-px bg-border" />
        <span className="hidden truncate text-dense text-muted-foreground sm:block">
          Cloud attack path analysis
        </span>
        {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
      </Container>
    </header>
  )
}

interface AppShellProps {
  headerActions?: ReactNode
  children: ReactNode
}

export function AppShell({ headerActions, children }: AppShellProps) {
  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-surface px-3 py-2 text-sm font-medium focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Skip to content
      </a>
      <AppHeader actions={headerActions} />
      <main id="main" className="flex flex-1 flex-col">
        {children}
      </main>
    </div>
  )
}
