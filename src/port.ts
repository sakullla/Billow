import type { EntryId, ThemePreference } from './copy'
import { resolveEntry } from './navigation'
import { resolveTheme } from './theme'

export interface ShellSnapshot {
  theme: string
  entry: string
}

export interface ShellPort {
  load(): Promise<ShellSnapshot>
  saveTheme(theme: ThemePreference): Promise<void>
  saveEntry(entry: EntryId): Promise<void>
}

const LOCAL_KEY = 'billow-shell'

export function createMemoryPort(initial?: Partial<ShellSnapshot>): ShellPort {
  const state: ShellSnapshot = {
    theme: initial?.theme ?? 'system',
    entry: initial?.entry ?? 'home',
  }
  return {
    async load() {
      return { theme: state.theme, entry: state.entry }
    },
    async saveTheme(theme) {
      state.theme = theme
    },
    async saveEntry(entry) {
      state.entry = entry
    },
  }
}

export function createLocalPort(storage: Storage): ShellPort {
  async function load(): Promise<ShellSnapshot> {
    try {
      const raw = JSON.parse(storage.getItem(LOCAL_KEY) || '') as Partial<ShellSnapshot>
      return {
        theme: typeof raw.theme === 'string' ? raw.theme : 'system',
        entry: typeof raw.entry === 'string' ? raw.entry : 'home',
      }
    } catch {
      return { theme: 'system', entry: 'home' }
    }
  }
  return {
    load,
    async saveTheme(theme) {
      const current = await load()
      storage.setItem(LOCAL_KEY, JSON.stringify({ ...current, theme }))
    },
    async saveEntry(entry) {
      const current = await load()
      storage.setItem(LOCAL_KEY, JSON.stringify({ ...current, entry }))
    },
  }
}

function inTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function createShellPort(): ShellPort {
  if (inTauri()) return createTauriPort()
  return createLocalPort(localStorage)
}

function createTauriPort(): ShellPort {
  return {
    async load() {
      const { invoke } = await import('@tauri-apps/api/core')
      const raw = await invoke<{ theme: string; last_entry: string }>('shell_state')
      return { theme: raw.theme, entry: raw.last_entry }
    },
    async saveTheme(theme) {
      const { invoke } = await import('@tauri-apps/api/core')
      await invoke('set_theme', { theme: resolveTheme(theme) })
    },
    async saveEntry(entry) {
      const { invoke } = await import('@tauri-apps/api/core')
      await invoke('set_last_entry', { entry: resolveEntry(entry) })
    },
  }
}
