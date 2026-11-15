import type { HotkeyBinding } from './hotkeys'

export type ShortcutId = 'palette' | 'search' | 'escape' | 'help'

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
    label: '命令面板',
    description: '搜索页面、设置分类与常用动作',
    combo: 'mod+k',
    scope: 'global',
    // The palette opens from a search field too; `/` and `?` stay guarded.
    allowInInput: true,
  },
  {
    id: 'search',
    label: '聚焦搜索',
    description: '把焦点移到当前页搜索框',
    combo: '/',
    scope: 'page',
  },
  {
    id: 'escape',
    label: '关闭或清空',
    description: '关闭最上层弹层，或清空当前搜索',
    combo: 'Escape',
    scope: 'overlay',
  },
  {
    id: 'help',
    label: '快捷键说明',
    description: '查看全部快捷键',
    combo: '?',
    scope: 'global',
  },
]

export function getShortcut(id: ShortcutId): ShortcutSpec {
  const shortcut = SHORTCUTS.find((item) => item.id === id)
  if (!shortcut) throw new Error(`Unknown shortcut: ${id}`)
  return shortcut
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
