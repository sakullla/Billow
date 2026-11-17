import { describe, expect, it } from 'vitest'
import { getShortcut, pageShortcutCombo, SHORTCUTS, shortcutBindings, shortcutKeyLabel } from './shortcuts'

describe('shortcut registry', () => {
  it('exports one entry per in-app shortcut without duplicates', () => {
    const ids = SHORTCUTS.map((shortcut) => shortcut.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toEqual(['palette', 'sidebar', 'pages', 'settings', 'search', 'escape', 'help'])
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
    expect(shortcutKeyLabel(getShortcut('pages').combo, true)).toBe('⌘1…7')
    expect(shortcutKeyLabel(getShortcut('settings').combo, false)).toBe('Ctrl + ,')
  })

  it('numbers the sidebar pages and stops after the listed range', () => {
    expect(pageShortcutCombo(0)).toBe('mod+1')
    expect(pageShortcutCombo(6)).toBe('mod+7')
    expect(pageShortcutCombo(7)).toBeNull()
    expect(pageShortcutCombo(-1)).toBeNull()
  })

  it('builds guarded hotkey bindings from the registry', () => {
    const bindings = shortcutBindings({ search: () => undefined, escape: () => undefined })
    expect(bindings.map((binding) => binding.combo)).toEqual(['/', 'Escape'])
    expect(bindings.every((binding) => binding.allowInInput === false)).toBe(true)
    const optIn = shortcutBindings({ escape: () => undefined }, { allowInInput: ['escape'] })
    expect(optIn[0]?.allowInInput).toBe(true)
  })
})
