import { THEME_OPTIONS, type ThemePreference } from './copy'

export { THEME_OPTIONS }
export type { ThemePreference }

export const DEFAULT_THEME: ThemePreference = 'system'
export const ACCENT = '#1d6fdb'
export const RADIUS = '10px'

export const SURFACES = {
  light: {
    page: '#e7edf2',
    content: '#ffffff',
    text: '#17202a',
    muted: '#5d6b78',
    line: '#d5dee6',
  },
  dark: {
    page: '#0f1318',
    content: '#1c242d',
    text: '#e8eef4',
    muted: '#a7b3bf',
    line: '#2e3a46',
  },
} as const

export function resolveTheme(value: string | null | undefined): ThemePreference {
  if (value === 'system' || value === 'light' || value === 'dark') return value
  return DEFAULT_THEME
}

export function resolveAppearance(
  preference: ThemePreference,
  systemDark: boolean,
): 'light' | 'dark' {
  if (preference === 'light') return 'light'
  if (preference === 'dark') return 'dark'
  return systemDark ? 'dark' : 'light'
}

export function applyTheme(preference: ThemePreference): void {
  const root = document.documentElement
  root.dataset.theme = preference
  if (preference === 'system') root.removeAttribute('data-appearance')
  else root.setAttribute('data-appearance', preference)
}
