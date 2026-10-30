import { describe, expect, it } from 'vitest'

import { sampleAttack } from './__fixtures__/sample-attack'
import { samplePaths } from './__fixtures__/sample-paths'
import { sampleState } from './__fixtures__/sample-state'
import { pathHighlight } from './highlight'
import {
  boundsOf,
  layoutGraph,
  METRICS,
  type Box,
  type GraphLayout,
  type PlacedNode,
} from './layout'
import {
  canvasInsets,
  fitViewport,
  homeBoxes,
  minimapRect,
  PANEL_WIDTH,
  READABLE_ZOOM,
  showsWhole,
  type FitOptions,
} from './viewport'

const size = { width: 1200, height: 600 }
const box0: Box = { x: 0, y: 0, width: 0, height: 0 }
const options = (panelOpen = false): FitOptions => ({
  insets: canvasInsets(panelOpen),
  minZoom: READABLE_ZOOM,
  maxZoom: 1,
  avoid: minimapRect(size, panelOpen),
})

/** Where a box lands on screen under a viewport. */
function onScreen(box: Box, viewport: { x: number; y: number; zoom: number }): Box {
  return {
    x: box.x * viewport.zoom + viewport.x,
    y: box.y * viewport.zoom + viewport.y,
    width: box.width * viewport.zoom,
    height: box.height * viewport.zoom,
  }
}

/** fitViewport for boxes that are never empty. */
function fit(boxes: readonly Box[], fitOptions: FitOptions) {
  const viewport = fitViewport(boxes, size, fitOptions)
  if (!viewport) throw new Error('expected a viewport')
  return viewport
}

const overlaps = (a: Box, b: Box) =>
  a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height

describe('fitViewport', () => {
  it('returns null for nothing to fit', () => {
    expect(fitViewport([], size, options())).toBeNull()
  })

  it('centres a small drawing at no more than 100%', () => {
    const box = { x: 0, y: 0, width: 200, height: 100 }
    const viewport = fit([box], options())
    expect(viewport.zoom).toBe(1)
    const drawn = onScreen(box, viewport)
    expect(drawn.x + drawn.width / 2).toBeCloseTo(600)
    expect(drawn.y + drawn.height / 2).toBeCloseTo(300)
  })

  it('never shrinks a long run below the readable zoom; it starts at the left instead', () => {
    const boxes: Box[] = [
      { x: 0, y: 0, width: 150, height: 40 },
      { x: 2850, y: 0, width: 150, height: 40 },
    ]
    const viewport = fit(boxes, options())
    expect(viewport.zoom).toBe(READABLE_ZOOM)
    expect(onScreen(boxes[0] ?? box0, viewport).x).toBeCloseTo(canvasInsets(false).left)
  })

  it('keeps a fitted path clear of the panel', () => {
    const boxes: Box[] = [
      { x: 0, y: 0, width: 150, height: 40 },
      { x: 600, y: 0, width: 150, height: 40 },
    ]
    const viewport = fit(boxes, options(true))
    const right = size.width - PANEL_WIDTH
    for (const box of boxes) expect(onScreen(box, viewport).x + box.width).toBeLessThan(right)
  })

  it('moves a drawing that would sit under the minimap above it', () => {
    // A wide, low strip whose right end would land on the minimap when centred.
    const boxes: Box[] = [
      { x: 0, y: 0, width: 150, height: 40 },
      { x: 1000, y: 380, width: 150, height: 40 },
    ]
    const minimap = minimapRect(size, false)
    const viewport = fit(boxes, options())
    for (const box of boxes) expect(overlaps(onScreen(box, viewport), minimap)).toBe(false)
  })

  it('centres the part of an overflowing run that is in view, not the whole run', () => {
    // The start of the run is low, its far end high and off screen.
    const boxes: Box[] = [
      { x: 0, y: 400, width: 150, height: 40 },
      { x: 300, y: 400, width: 150, height: 40 },
      { x: 2850, y: 0, width: 150, height: 40 },
    ]
    const viewport = fit(boxes, options())
    const first = onScreen(boxes[0] ?? box0, viewport)
    expect(first.y + first.height / 2).toBeCloseTo(size.height / 2, 0)
  })
})

describe('homeBoxes', () => {
  const node = (key: string, x: number): PlacedNode =>
    ({ key, x, y: 0, width: 100, height: 40 }) as PlacedNode
  const layout = { nodes: [node('a', 0), node('b', 200), node('c', 400)] } as GraphLayout

  it('is the whole graph without a path', () => {
    expect(homeBoxes(layout, null).map((box) => box.x)).toEqual([0, 200, 400])
  })

  it('is the path when one is drawn', () => {
    expect(homeBoxes(layout, new Set(['b', 'c'])).map((box) => box.x)).toEqual([200, 400])
  })

  it('falls back to the whole graph when none of the path is drawn', () => {
    expect(homeBoxes(layout, new Set(['z']))).toHaveLength(3)
  })
})

describe('the cloudformation5 sample in a 1440 by 900 window', () => {
  // The canvas the graph tab gets at 1440 by 900.
  const canvas = { width: 1230, height: 597 }
  const fitOptions = (panelOpen: boolean): FitOptions => ({
    insets: canvasInsets(panelOpen),
    minZoom: READABLE_ZOOM,
    maxZoom: 1,
    avoid: minimapRect(canvas, panelOpen),
    panelOpen,
  })
  const exported = samplePaths.filter((path) => path.exported)

  for (const view of [sampleState, sampleAttack]) {
    const layout = layoutGraph(view)
    const whole = boundsOf(layout.nodes) ?? box0

    it(`shows the whole ${view.view} graph, readable`, () => {
      const viewport = fitViewport(layout.nodes, canvas, fitOptions(false))
      expect(viewport && viewport.zoom * METRICS.titlePx).toBeGreaterThanOrEqual(10.5)
      expect(viewport && showsWhole(whole, viewport, canvas, false)).toBe(true)
    })

    it(`fits every exported path beside the panel in the ${view.view} view`, () => {
      let checked = 0
      for (const path of exported) {
        const highlight = pathHighlight(view.nodes, view.edges, path)
        if (!highlight?.mapped) continue
        const boxes = homeBoxes(layout, highlight.nodeKeys)
        const viewport = fitViewport(boxes, canvas, fitOptions(true))
        expect(viewport, `${path.source_id} has a viewport`).not.toBeNull()
        if (!viewport) continue
        const right = canvas.width - PANEL_WIDTH
        expect(boxes.length, path.source_id).toBeGreaterThan(0)
        for (const box of boxes) {
          const drawn = onScreen(box, viewport)
          expect(drawn.x, `${path.source_id} ${box.x}`).toBeGreaterThanOrEqual(0)
          expect(drawn.x + drawn.width, path.source_id).toBeLessThanOrEqual(right)
        }
        checked += 1
      }
      // Without this the loop passes when no path is drawn at all.
      expect(checked).toBeGreaterThan(0)
    })
  }
})
