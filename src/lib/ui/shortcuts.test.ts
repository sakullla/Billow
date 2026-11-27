import { describe, expect, it } from 'vitest'
import {
  comboFromEvent,
  comboSignature,
  getShortcut,
  inWindowShortcut,
  pageShortcutCombo,
  SHORTCUTS,
  shortcutBindings,
  shortcutKeyLabel,
} from './shortcuts'

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
    expect(shortcutKeyLabel('Ctrl+Alt+Super+P', false)).toBe('Ctrl + Alt + Win + P')
    expect(shortcutKeyLabel('Ctrl+Alt+Super+P', true)).toBe('⌃⌥⌘P')
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

describe('global shortcut combinations (R39)', () => {
  it('gives one combination one spelling so mod and Ctrl compare the same', () => {
    expect(comboSignature('Ctrl+Alt+P', false)).toBe('ctrl+alt+p')
    expect(comboSignature('Hyper+K', false)).toBeNull()
    expect(comboSignature('mod+K', false)).toBe('ctrl+k')
    expect(comboSignature('mod+K', true)).toBe('meta+k')
    expect(comboSignature('Super+K', true)).toBe('meta+k')
    expect(comboSignature('Shift+F5', false)).toBe('shift+f5')
    expect(comboSignature(getShortcut('pages').combo, false)).toBeNull()
    expect(comboSignature('', false)).toBeNull()
    expect(comboSignature('Ctrl+Nope+P', false)).toBeNull()
  })

  it('names the window shortcut a global combination would shadow', () => {
    expect(inWindowShortcut('Ctrl+K', false)?.label).toBe('命令面板')
    // Cmd on macOS is the same in-window shortcut as Ctrl elsewhere.
    expect(inWindowShortcut('Super+K', true)?.label).toBe('命令面板')
    expect(inWindowShortcut('Ctrl+3', false)?.label).toBe('切换页面')
    expect(inWindowShortcut('Ctrl+,', false)?.label).toBe('打开设置')
    expect(inWindowShortcut('Ctrl+S', false)?.label).toBe('保存设置')
    // A combination nothing in the window uses is free.
    expect(inWindowShortcut('Ctrl+Alt+P', false)).toBeNull()
  })

  it('turns a keydown into the accelerator the backend stores', () => {
    const combo = (init: KeyboardEventInit & { key?: string }) =>
      comboFromEvent(new KeyboardEvent('keydown', init))
    expect(combo({ code: 'KeyP', key: 'p', ctrlKey: true, altKey: true })).toEqual({
      kind: 'combo',
      combo: 'Ctrl+Alt+P',
    })
    expect(combo({ code: 'F5', key: 'F5', shiftKey: true })).toEqual({ kind: 'combo', combo: 'Shift+F5' })
    expect(combo({ code: 'Digit1', key: '1', metaKey: true })).toEqual({ kind: 'combo', combo: 'Super+1' })
    expect(combo({ code: 'ControlLeft', key: 'Control', ctrlKey: true })).toEqual({ kind: 'modifier' })
    expect(combo({ code: 'KeyP', key: 'p' })).toEqual({ kind: 'plain' })
    expect(combo({ code: 'IntlRo', key: 'ろ', ctrlKey: true })).toEqual({ kind: 'unsupported' })
  })
})
