import { FileQuestion } from 'lucide-react'
import { isRouteErrorResponse, Link, useRouteError } from 'react-router'

import { AppShell, Container } from '@/components/AppShell'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { Button } from '@/components/ui/button'

export function NotFoundPage() {
  return (
    <AppShell>
      <Container className="py-16">
        <EmptyState
          bordered
          icon={FileQuestion}
          title="Page not found"
          description="The address does not match any page. Analyses open from the upload page or a saved link."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/">New analysis</Link>
            </Button>
          }
        />
      </Container>
    </AppShell>
  )
}

export function RouteErrorPage() {
  const error = useRouteError()
  const message = isRouteErrorResponse(error)
    ? `${String(error.status)} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : 'An unexpected error stopped this page from rendering.'
  return (
    <AppShell>
      <Container className="py-16">
        <ErrorState
          title="This page failed to render"
          message={message}
          onRetry={() => window.location.reload()}
        />
      </Container>
    </AppShell>
  )
}
