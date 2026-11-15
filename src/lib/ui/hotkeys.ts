import { onBeforeUnmount, onMounted } from 'vue'
import { isEditableElement } from './focus'

export interface HotkeyCombo {
  key: string
  mod?: boolean
  ctrl?: boolean
  meta?: boolean
  shift?: boolean
  alt?: boolean
}

export interface HotkeyBinding {
  /** `'mod+k'`, `'/'`, `'?'` or `'Escape'`; `mod` matches Ctrl on Windows/Linux and ⌘ on macOS. */
  combo: string | HotkeyCombo
  handler: (event: KeyboardEvent) => void
  /** Skip the default input guard, e.g. Escape that intentionally clears a search box. */
  allowInInput?: boolean
  /** Optional extra guard; the shortcut only runs when it returns true. */
  when?: () => boolean
  /** Defaults to true so browser defaults (quick find, `/` insertion) do not fire. */
  preventDefault?: boolean
}

export interface UseHotkeysOptions {
  target?: EventTarget | null
  enabled?: () => boolean
}

export function parseCombo(combo: string): HotkeyCombo {
  const parts = combo
    .split('+')
    .map((part) => part.trim())
    .filter(Boolean)
  const key = parts.pop() ?? ''
  const spec: HotkeyCombo = { key }
  for (const part of parts) {
    switch (part.toLowerCase()) {
      case 'mod':
        spec.mod = true
        break
      case 'ctrl':
      case 'control':
        spec.ctrl = true
        break
      case 'meta':
      case 'cmd':
      case 'command':
        spec.meta = true
        break
      case 'shift':
        spec.shift = true
        break
      case 'alt':
      case 'option':
        spec.alt = true
        break
    }
  }
  return spec
}

function normalizeKey(key: string): string {
  return key.length === 1 ? key.toLowerCase() : key
}

export function matchesCombo(event: KeyboardEvent, combo: string | HotkeyCombo): boolean {
  const spec = typeof combo === 'string' ? parseCombo(combo) : combo
  if (normalizeKey(event.key) !== normalizeKey(spec.key)) return false
  const wantsMod = Boolean(spec.mod)
  const wantsCtrl = Boolean(spec.ctrl || wantsMod)
  const wantsMeta = Boolean(spec.meta || wantsMod)
  const hasCtrl = event.ctrlKey
  const hasMeta = event.metaKey
  if (wantsCtrl || wantsMeta) {
    if (!hasCtrl && !hasMeta) return false
    if (spec.ctrl && !hasCtrl) return false
    if (spec.meta && !hasMeta) return false
  } else if (hasCtrl || hasMeta) {
    return false
  }
  if (Boolean(spec.alt) !== event.altKey) return false
  if (spec.shift && !event.shiftKey) return false
  return true
}

/**
 * Bind keyboard shortcuts on the document. Text fields own their input: `/`, `?`
 * and Escape do not fire there unless a binding opts in with `allowInInput` (R30).
 */
export function useHotkeys(bindings: readonly HotkeyBinding[], options: UseHotkeysOptions = {}) {
  const enabled = options.enabled ?? (() => true)
  const target = options.target ?? (typeof document === 'undefined' ? null : document)

  function onKeydown(event: KeyboardEvent): void {
    if (event.defaultPrevented || event.isComposing || event.repeat) return
    if (!enabled()) return
    const fromInput = isEditableElement(event.target)
    for (const binding of bindings) {
      if (fromInput && !binding.allowInInput) continue
      if (binding.when && !binding.when()) continue
      if (!matchesCombo(event, binding.combo)) continue
      if (binding.preventDefault !== false) event.preventDefault()
      binding.handler(event)
      return
    }
  }

  onMounted(() => target?.addEventListener('keydown', onKeydown as EventListener))
  onBeforeUnmount(() => target?.removeEventListener('keydown', onKeydown as EventListener))

  return { onKeydown }
}
