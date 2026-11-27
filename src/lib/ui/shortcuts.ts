import type { HotkeyBinding } from './hotkeys'
import { t, tr } from '../i18n'

export type ShortcutId =
  | 'palette'
  | 'sidebar'
  | 'pages'
  | 'settings'
  | 'search'
  | 'escape'
  | 'help'

/** `mod+1` … `mod+N` follow the sidebar order; the registry lists them as one row. */
export const PAGE_SHORTCUT_COUNT = 7

/** Combo for the Nth sidebar page (0-based), or null past the numbered range. */
export function pageShortcutCombo(index: number): string | null {
  return index >= 0 && index < PAGE_SHORTCUT_COUNT ? `mod+${index + 1}` : null
}

export interface ShortcutSpec {
  id: ShortcutId
  label: string
  description: string
  combo: string
  scope: 'global' | 'page' | 'overlay'
  /** Shortcuts that intentionally run while a text field is focused. */
  allowInInput?: boolean
}

/**
 * The single source of truth for in-app shortcuts. The command palette, the `?`
 * sheet and `useHotkeys` all read from here so labels never drift (D2).
 */
export const SHORTCUTS: readonly ShortcutSpec[] = [
  {
    id: 'palette',
    get label() { return tr('命令面板') },
    get description() { return tr('搜索页面、设置分类与常用动作') },
    combo: 'mod+k',
    scope: 'global',
    // The palette opens from a search field too; `/` and `?` stay guarded.
    allowInInput: true,
  },
  {
    id: 'sidebar',
    get label() { return tr('切换侧边栏') },
    get description() { return tr('展开或收起桌面侧边栏') },
    combo: 'mod+b',
    scope: 'global',
    allowInInput: true,
  },
  {
    id: 'pages',
    get label() { return tr('切换页面') },
    get description() { return tr('按侧边栏顺序：首页、代理、配置、连接、规则、资源、日志') },
    // Display form of the range; App binds mod+1 … mod+7 individually.
    combo: `mod+1…${PAGE_SHORTCUT_COUNT}`,
    scope: 'global',
    allowInInput: true,
  },
  {
    id: 'settings',
    get label() { return tr('打开设置') },
    get description() { return tr('跳转到设置页') },
    combo: 'mod+,',
    scope: 'global',
    allowInInput: true,
  },
  {
    id: 'search',
    get label() { return tr('聚焦搜索') },
    get description() { return tr('把焦点移到当前页搜索框') },
    combo: '/',
    scope: 'page',
  },
  {
    id: 'escape',
    get label() { return tr('关闭或清空') },
    get description() { return tr('关闭最上层弹层，或清空当前搜索') },
    combo: 'Escape',
    scope: 'overlay',
  },
  {
    id: 'help',
    get label() { return tr('快捷键说明') },
    get description() { return tr('查看全部快捷键') },
    combo: '?',
    scope: 'global',
  },
]

export function getShortcut(id: ShortcutId): ShortcutSpec {
  const shortcut = SHORTCUTS.find((item) => item.id === id)
  if (!shortcut) throw new Error(`Unknown shortcut: ${id}`)
  return shortcut
}

/**
 * One spelling per combination so `mod+k`, `Ctrl+K` and `⌘K` compare the same.
 * `mod` follows the platform, mirroring how `useHotkeys` matches it (R39).
 */
export function comboSignature(combo: string, mac = isMacPlatform()): string | null {
  const parts = combo
    .split('+')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean)
  if (!parts.length) return null
  const key = parts.pop() ?? ''
  // The pages row is a display range, not a single binding.
  if (!key || key.includes('…') || key === '...') return null
  let ctrl = false
  let alt = false
  let shift = false
  let meta = false
  for (const part of parts) {
    if (part === 'mod') {
      if (mac) meta = true
      else ctrl = true
    } else if (part === 'ctrl' || part === 'control') ctrl = true
    else if (part === 'alt' || part === 'option') alt = true
    else if (part === 'shift') shift = true
    else if (part === 'meta' || part === 'cmd' || part === 'command' || part === 'super') meta = true
    else return null
  }
  const name = key === 'esc' ? 'escape' : key
  return [ctrl ? 'ctrl' : '', alt ? 'alt' : '', shift ? 'shift' : '', meta ? 'meta' : '', name]
    .filter(Boolean)
    .join('+')
}

/** In-window shortcuts that a global binding must not shadow, with the row that owns them. */
function inWindowEntries(): { combo: string; label: string }[] {
  const entries = SHORTCUTS.map((spec) => ({ combo: spec.combo, label: spec.label }))
  const pages = getShortcut('pages')
  for (let index = 0; index < PAGE_SHORTCUT_COUNT; index += 1) {
    entries.push({ combo: `mod+${index + 1}`, label: pages.label })
  }
  // The settings page saves the open tab with this combination.
  entries.push({ combo: 'mod+s', label: t('hotkey.inWindow.save') })
  return entries
}

/**
 * The in-window shortcut a global combination would collide with (R39). The
 * window owns these combos while it is focused, so a global binding for the same
 * keys would fire both actions at once.
 */
export function inWindowShortcut(
  combo: string,
  mac = isMacPlatform(),
): { combo: string; label: string } | null {
  const signature = comboSignature(combo, mac)
  if (!signature) return null
  return inWindowEntries().find((entry) => comboSignature(entry.combo, mac) === signature) ?? null
}

/** `event.code` values that can become a global shortcut, named how the backend parses them. */
const NAMED_KEYS: Record<string, string> = {
  Space: 'Space',
  Enter: 'Enter',
  Tab: 'Tab',
  Backspace: 'Backspace',
  Delete: 'Delete',
  Insert: 'Insert',
  Home: 'Home',
  End: 'End',
  PageUp: 'PageUp',
  PageDown: 'PageDown',
  ArrowUp: 'ArrowUp',
  ArrowDown: 'ArrowDown',
  ArrowLeft: 'ArrowLeft',
  ArrowRight: 'ArrowRight',
  Comma: ',',
  Period: '.',
  Slash: '/',
  Backquote: '`',
  Minus: '-',
  Equal: '=',
  BracketLeft: '[',
  BracketRight: ']',
  Backslash: '\\',
  Semicolon: ';',
  Quote: "'",
}

const MODIFIER_CODES = new Set([
  'ControlLeft',
  'ControlRight',
  'AltLeft',
  'AltRight',
  'ShiftLeft',
  'ShiftRight',
  'MetaLeft',
  'MetaRight',
])

/** What one keydown means while recording a global shortcut (R39). */
export type ComboCapture =
  | { kind: 'combo'; combo: string }
  /** Only modifiers were held down; keep waiting for the main key. */
  | { kind: 'modifier' }
  /** A printable key without a modifier would hijack ordinary typing. */
  | { kind: 'plain' }
  | { kind: 'unsupported' }

/** Turn a keydown into the accelerator string the Rust side stores. */
export function comboFromEvent(event: KeyboardEvent): ComboCapture {
  const code = event.code || ''
  if (MODIFIER_CODES.has(code)) return { kind: 'modifier' }
  let key: string | null = null
  if (/^Key[A-Z]$/.test(code)) key = code.slice(3)
  else if (/^Digit[0-9]$/.test(code)) key = code.slice(5)
  else if (/^F([1-9]|1[0-9]|2[0-4])$/.test(code)) key = code
  else if (/^Numpad[0-9]$/.test(code)) key = code
  else if (code in NAMED_KEYS) key = NAMED_KEYS[code] ?? null
  if (!key) return { kind: 'unsupported' }
  const parts: string[] = []
  if (event.ctrlKey) parts.push('Ctrl')
  if (event.altKey) parts.push('Alt')
  if (event.shiftKey) parts.push('Shift')
  if (event.metaKey) parts.push('Super')
  if (!parts.length) return { kind: 'plain' }
  return { kind: 'combo', combo: [...parts, key].join('+') }
}

export function isMacPlatform(): boolean {
  if (typeof navigator === 'undefined') return false
  return /mac|iphone|ipad|ipod/i.test(navigator.platform || navigator.userAgent)
}

/** Human-readable keycaps: `mod+k` becomes `Ctrl + K` or `⌘K`. */
export function shortcutKeyLabel(combo: string, mac = isMacPlatform()): string {
  return combo
    .split('+')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const token = part.toLowerCase()
      if (token === 'mod') return mac ? '⌘' : 'Ctrl'
      if (token === 'ctrl' || token === 'control') return mac ? '⌃' : 'Ctrl'
      if (token === 'meta' || token === 'cmd' || token === 'command') return mac ? '⌘' : 'Meta'
      if (token === 'super') return mac ? '⌘' : 'Win'
      if (token === 'shift') return mac ? '⇧' : 'Shift'
      if (token === 'alt' || token === 'option') return mac ? '⌥' : 'Alt'
      if (part.length === 1) return part.toUpperCase()
      return part
    })
    .join(mac ? '' : ' + ')
}

/** Build `useHotkeys` bindings from the registry, keeping guards in one place. */
export function shortcutBindings(
  handlers: Partial<Record<ShortcutId, (event: KeyboardEvent) => void>>,
  options: { allowInInput?: readonly ShortcutId[] } = {},
): HotkeyBinding[] {
  return SHORTCUTS.flatMap((spec) => {
    const handler = handlers[spec.id]
    if (!handler) return []
    return [
      {
        combo: spec.combo,
        handler,
        allowInInput: Boolean(spec.allowInInput) || Boolean(options.allowInInput?.includes(spec.id)),
      },
    ]
  })
}
