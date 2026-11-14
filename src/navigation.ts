import { NAV_ITEMS, type EntryId } from './copy'

export { NAV_ITEMS }
export type { EntryId }

export const SIDEBAR_WIDTH = 200
export const CONTENT_MIN_WIDTH = 420
/** Sidebar and content column can sit side by side only at or above this width. */
export const SIDE_BY_SIDE_MIN = SIDEBAR_WIDTH + CONTENT_MIN_WIDTH

export type LayoutMode = 'sidebar' | 'bottom'

const ENTRY_IDS: readonly EntryId[] = ['home', 'nodes', 'settings']

export function layoutForWidth(width: number): LayoutMode {
  if (!Number.isFinite(width) || width < SIDE_BY_SIDE_MIN) return 'bottom'
  return 'sidebar'
}

export function resolveEntry(value: string | null | undefined): EntryId {
  if (value === 'home' || value === 'nodes' || value === 'settings') return value
  return 'home'
}

export function isEntryId(value: string): value is EntryId {
  return ENTRY_IDS.some((id) => id === value)
}
