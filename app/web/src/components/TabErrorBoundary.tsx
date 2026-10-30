import { Component, type ErrorInfo, type ReactNode } from 'react'

import { ErrorState } from '@/components/ErrorState'

interface TabErrorBoundaryProps {
  /** What failed, for the title: "Could not show the graph". */
  label: string
  children: ReactNode
}

interface TabErrorBoundaryState {
  error: Error | null
}

/**
 * Keeps a failing tab (a chunk that did not load, a render error) inside the
 * tab, so the header, the other tabs and the resource sheet keep working.
 */
export class TabErrorBoundary extends Component<TabErrorBoundaryProps, TabErrorBoundaryState> {
  override state: TabErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: unknown): TabErrorBoundaryState {
    return { error: error instanceof Error ? error : new Error(String(error)) }
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(error, info.componentStack)
  }

  override render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <ErrorState
        title={`Could not show the ${this.props.label}`}
        message={error.message}
        // A chunk that failed to load needs a fresh page, not just a re-render.
        onRetry={() => window.location.reload()}
      />
    )
  }
}
