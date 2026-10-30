import { afterEach, describe, expect, it } from 'vitest'

import { keyModality, trackInputModality } from './inputModality'

describe('keyModality', () => {
  it('counts keys that move focus or type', () => {
    expect(keyModality({ key: 'Tab', metaKey: false, ctrlKey: false })).toBe('keyboard')
    expect(keyModality({ key: 'ArrowLeft', metaKey: false, ctrlKey: false })).toBe('keyboard')
  })

  it('ignores modifiers and shortcuts', () => {
    expect(keyModality({ key: 'Shift', metaKey: false, ctrlKey: false })).toBeNull()
    expect(keyModality({ key: 'c', metaKey: true, ctrlKey: false })).toBeNull()
    expect(keyModality({ key: 'c', metaKey: false, ctrlKey: true })).toBeNull()
  })
})

describe('trackInputModality', () => {
  let stop: (() => void) | undefined
  afterEach(() => {
    stop?.()
    delete document.documentElement.dataset.modality
  })

  it('marks the last input on <html>', () => {
    stop = trackInputModality()
    window.dispatchEvent(new Event('pointerdown'))
    expect(document.documentElement.dataset.modality).toBe('pointer')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab' }))
    expect(document.documentElement.dataset.modality).toBe('keyboard')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Shift' }))
    expect(document.documentElement.dataset.modality).toBe('keyboard')
  })

  it('stops when asked', () => {
    stop = trackInputModality()
    stop()
    window.dispatchEvent(new Event('pointerdown'))
    expect(document.documentElement.dataset.modality).toBeUndefined()
  })
})
