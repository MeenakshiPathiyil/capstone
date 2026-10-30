/**
 * Which input the user last used, kept on <html data-modality="keyboard|pointer">.
 *
 * :focus-visible alone is not enough: Radix moves focus with element.focus()
 * on mouse down (tabs) and when an overlay closes (select, menu, sheet), and
 * browsers may treat such script focus as visible. index.css hides focus
 * rings while the last input was a pointer, except on text fields, where the
 * ring shows where typing goes.
 */

/** Keys that do not move focus or type: holding one should not bring rings back. */
const IGNORED_KEYS = new Set(['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Fn'])

export type InputModality = 'keyboard' | 'pointer'

/** The modality a keydown implies, or null when it implies none (a modifier or a shortcut). */
export function keyModality(
  event: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey'>,
): InputModality | null {
  if (IGNORED_KEYS.has(event.key) || event.metaKey || event.ctrlKey) return null
  return 'keyboard'
}

/** Start tracking. Returns a function that stops it. */
export function trackInputModality(root: HTMLElement = document.documentElement): () => void {
  const set = (modality: InputModality) => {
    if (root.dataset.modality !== modality) root.dataset.modality = modality
  }
  const onKeyDown = (event: KeyboardEvent) => {
    const modality = keyModality(event)
    if (modality) set(modality)
  }
  const onPointerDown = () => set('pointer')
  // Capture phase: before any handler moves focus in response.
  window.addEventListener('keydown', onKeyDown, true)
  window.addEventListener('pointerdown', onPointerDown, true)
  return () => {
    window.removeEventListener('keydown', onKeyDown, true)
    window.removeEventListener('pointerdown', onPointerDown, true)
  }
}
