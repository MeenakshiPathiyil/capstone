import { useReactFlow, useStoreApi, type Viewport } from '@xyflow/react'
import { useCallback, useMemo } from 'react'

import { boundsOf, METRICS, type Box, type GraphLayout } from './layout'

/**
 * The smallest zoom an automatic move uses: node titles still draw at 10.5px
 * on screen. A graph that does not fit at this zoom keeps its focus (the
 * path ends) in view, and the rest is a pan away, rather than shrinking
 * until it is unreadable. The layout's metrics are sized so that the sample
 * templates fit a 1440 by 900 window whole, and path by path beside the panel.
 */
export const READABLE_ZOOM = 10.5 / METRICS.titlePx
/** Never magnify past 100% to fit a small graph or path. */
export const HOME_MAX_ZOOM = 1
/** A search result or a step: a touch of magnification for one or two boxes. */
export const FOCUS_MAX_ZOOM = 1.1

/** The path panel, laid over the right of the canvas. */
export const PANEL_WIDTH = 272
/** The minimap, in the bottom right corner of what the panel leaves visible. */
export const MINIMAP = { width: 152, height: 96 } as const
/** React Flow's margin around its corner panels (controls, minimap). */
export const CORNER_MARGIN = 15
/** Air between the fitted drawing and the canvas edges or the minimap. */
const AIR = 16
/** Less above and below: these graphs run out of height before width on short windows. */
const AIR_Y = 10

export interface Size {
  width: number
  height: number
}

export interface Insets {
  top: number
  right: number
  bottom: number
  left: number
}

export interface FitOptions {
  /** Canvas edges the drawing keeps clear of, such as an overlaid panel. */
  insets: Insets
  minZoom: number
  maxZoom: number
  /** A rectangle in canvas pixels to keep the drawing out of, such as the minimap. */
  avoid?: Box | null
  /**
   * The whole graph. When the fit shows all of it, the minimap is hidden
   * (see showsWhole), so there is nothing to avoid.
   */
  whole?: Box | null
  /** What must stay in view when the boxes do not fit, such as where paths end. */
  focus?: readonly Box[]
  /** The path panel is open, over the right of the canvas. */
  panelOpen?: boolean
}

/** The canvas edges a fit keeps clear: some air, plus the path panel when it is open. */
export function canvasInsets(panelOpen: boolean): Insets {
  return { top: AIR_Y, right: AIR + (panelOpen ? PANEL_WIDTH : 0), bottom: AIR_Y, left: AIR }
}

/** Where the minimap sits on a canvas of this size, in canvas pixels. */
export function minimapRect(size: Size, panelOpen: boolean): Box {
  const right = CORNER_MARGIN + (panelOpen ? PANEL_WIDTH : 0)
  return {
    x: size.width - right - MINIMAP.width,
    y: size.height - CORNER_MARGIN - MINIMAP.height,
    width: MINIMAP.width,
    height: MINIMAP.height,
  }
}

function intersects(a: Box, b: Box): boolean {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height
}

function drawnBox(box: Box, viewport: Viewport): Box {
  return {
    x: box.x * viewport.zoom + viewport.x,
    y: box.y * viewport.zoom + viewport.y,
    width: box.width * viewport.zoom,
    height: box.height * viewport.zoom,
  }
}

/**
 * Does the viewport show all of `whole`, clear of the panel? The canvas hides
 * its minimap then: there is nowhere to navigate to.
 */
export function showsWhole(whole: Box, viewport: Viewport, size: Size, panelOpen: boolean) {
  const drawn = drawnBox(whole, viewport)
  const right = size.width - (panelOpen ? PANEL_WIDTH : 0)
  const slack = 0.5
  return (
    drawn.x >= -slack &&
    drawn.y >= -slack &&
    drawn.x + drawn.width <= right + slack &&
    drawn.y + drawn.height <= size.height + slack
  )
}

function place(bounds: Box, size: Size, insets: Insets, options: FitOptions, focus: Box | null) {
  const width = Math.max(1, size.width - insets.left - insets.right)
  const height = Math.max(1, size.height - insets.top - insets.bottom)
  const fit = Math.min(width / Math.max(1, bounds.width), height / Math.max(1, bounds.height))
  const zoom = Math.min(options.maxZoom, Math.max(options.minZoom, fit))
  // Centred along an axis where the drawing fits. Where it does not: the
  // focus centred, without pulling either end of the drawing into the room;
  // with no focus, from the start, as these graphs read left to right.
  const axis = (
    start: number,
    length: number,
    room: number,
    inset: number,
    f?: [number, number],
  ) => {
    const drawn = length * zoom
    if (drawn <= room) return inset + (room - drawn) / 2 - start * zoom
    if (!f) return inset - start * zoom
    const centred = inset + (room - f[1] * zoom) / 2 - f[0] * zoom
    const lowest = inset + room - (start + length) * zoom
    const highest = inset - start * zoom
    return Math.min(highest, Math.max(lowest, centred))
  }
  return {
    x: axis(bounds.x, bounds.width, width, insets.left, focus ? [focus.x, focus.width] : undefined),
    y: axis(
      bounds.y,
      bounds.height,
      height,
      insets.top,
      focus ? [focus.y, focus.height] : undefined,
    ),
    zoom,
  }
}

/** place(), moved above `avoid` when it would draw under it. */
function placeClear(bounds: Box, size: Size, options: FitOptions, focus: Box | null) {
  const { insets, avoid, whole } = options
  const first = place(bounds, size, insets, options, focus)
  if (!avoid || !intersects(drawnBox(bounds, first), avoid)) return first
  if (whole && showsWhole(whole, first, size, options.panelOpen ?? false)) return first
  const bottom = Math.max(insets.bottom, size.height - avoid.y + AIR / 2)
  return place(bounds, size, { ...insets, bottom }, options, focus)
}

/**
 * The viewport that shows `boxes` (graph coordinates) as large as fits in the
 * canvas between the insets, at a zoom within [minZoom, maxZoom], clear of
 * `avoid`. A drawing too large to show whole keeps `focus` in view; without
 * one, a run too long starts at its left end and the part in view is centred
 * vertically rather than the whole run. Null for no boxes.
 */
export function fitViewport(
  boxes: readonly Box[],
  size: Size,
  options: FitOptions,
): Viewport | null {
  const bounds = boundsOf(boxes)
  if (!bounds) return null
  const focus = options.focus ? boundsOf(options.focus) : null
  const viewport = placeClear(bounds, size, options, focus)
  const left = options.insets.left
  const right = size.width - options.insets.right
  if (focus || bounds.width * viewport.zoom <= right - left) return viewport

  const shown = boundsOf(
    boxes.filter((box) => {
      const drawn = drawnBox(box, viewport)
      return drawn.x < right && drawn.x + drawn.width > left
    }),
  )
  if (!shown) return viewport
  const rows = placeClear({ ...bounds, y: shown.y, height: shown.height }, size, options, null)
  return { ...viewport, y: rows.y }
}

/** The boxes of some of the layout's nodes. */
export function nodeBoxes(layout: GraphLayout, keys: Iterable<string>): Box[] {
  const wanted = new Set(keys)
  return layout.nodes.filter((node) => wanted.has(node.key))
}

/**
 * What the canvas opens on: the selected path's boxes when one is drawn,
 * otherwise the whole graph.
 */
export function homeBoxes(layout: GraphLayout, pathNodes: ReadonlySet<string> | null): Box[] {
  const path = pathNodes ? nodeBoxes(layout, pathNodes) : []
  return path.length > 0 ? path : layout.nodes
}

export function prefersReducedMotion() {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

/** Animation length for viewport moves, or none for people who asked for less motion. */
export function motion(ms: number) {
  return prefersReducedMotion() ? 0 : ms
}

/**
 * Viewport moves that keep text readable and stay clear of the path panel and
 * the minimap. Must be used inside a ReactFlowProvider.
 */
export function useGraphViewport(panelOpen: boolean, layout: GraphLayout | null) {
  const { setViewport } = useReactFlow()
  const store = useStoreApi()
  const whole = useMemo(() => (layout ? boundsOf(layout.nodes) : null), [layout])

  const fitBoxes = useCallback(
    (
      boxes: readonly Box[],
      {
        duration = 0,
        maxZoom = HOME_MAX_ZOOM,
        focus,
        extra = [],
      }: {
        duration?: number
        maxZoom?: number
        focus?: readonly Box[]
        /** Boxes to show too, but only if they fit without dropping below READABLE_ZOOM. */
        extra?: readonly Box[]
      } = {},
    ) => {
      const { width, height } = store.getState()
      if (width === 0 || height === 0) return Promise.resolve(false)
      const size = { width, height }
      const options: FitOptions = {
        insets: canvasInsets(panelOpen),
        minZoom: READABLE_ZOOM,
        maxZoom,
        avoid: minimapRect(size, panelOpen),
        whole,
        focus,
        panelOpen,
      }
      const withExtra = extra.length > 0 ? fitViewport([...boxes, ...extra], size, options) : null
      const all = boundsOf([...boxes, ...extra])
      const fits = withExtra !== null && all !== null && showsWhole(all, withExtra, size, panelOpen)
      const viewport = fits ? withExtra : fitViewport(boxes, size, options)
      return viewport ? setViewport(viewport, { duration }) : Promise.resolve(false)
    },
    [store, setViewport, panelOpen, whole],
  )

  return { fitBoxes, whole }
}
