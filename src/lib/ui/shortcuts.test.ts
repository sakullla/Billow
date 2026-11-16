import { describe, expect, it } from 'vitest'
import { getShortcut, SHORTCUTS, shortcutBindings, shortcutKeyLabel } from './shortcuts'

describe('shortcut registry', () => {
  it('exports one entry per in-app shortcut without duplicates', () => {
    const ids = SHORTCUTS.map((shortcut) => shortcut.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toEqual(['palette', 'sidebar', 'search', 'escape', 'zoom-in', 'zoom-out', 'zoom-reset', 'help'])
    expect(getShortcut('palette').combo).toBe('mod+k')
    expect(getShortcut('sidebar').combo).toBe('mod+b')
    expect(getShortcut('palette').allowInInput).toBe(true)
    expect(getShortcut('search').allowInInput).toBeUndefined()
    expect(() => getShortcut('missing' as never)).toThrow()
  })

  it('formats keycaps for mac and other platforms', () => {
    expect(shortcutKeyLabel('mod+k', true)).toBe('⌘K')
    expect(shortcutKeyLabel('mod+k', false)).toBe('Ctrl + K')
    expect(shortcutKeyLabel('Escape', false)).toBe('Escape')
  })

  it('builds guarded hotkey bindings from the registry', () => {
    const bindings = shortcutBindings({ search: () => undefined, escape: () => undefined })
    expect(bindings.map((binding) => binding.combo)).toEqual(['/', 'Escape'])
    expect(bindings.every((binding) => binding.allowInInput === false)).toBe(true)
    const optIn = shortcutBindings({ escape: () => undefined }, { allowInInput: ['escape'] })
    expect(optIn[0]?.allowInInput).toBe(true)
  })
})
