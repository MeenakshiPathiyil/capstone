import { useLayoutEffect } from 'react'
import { useLocation } from 'react-router'

/**
 * Scrolls to the top when the page changes. Keyed on the pathname, so a tab,
 * resource or graph change (search params only) leaves the scroll alone.
 */
export function ScrollToTop() {
  const { pathname } = useLocation()
  useLayoutEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])
  return null
}
