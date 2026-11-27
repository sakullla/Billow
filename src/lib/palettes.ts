import { PALETTES, normalizePalette, type PalettePreference } from './types'

export interface PaletteToneMeta {
  /** Page canvas background (`--bg`), also used for `<meta name="theme-color">`. */
  bg: string
  /** Outer shell / sidebar frame (`--chrome`). */
  chrome: string
  /** Primary card surface (`--surface`). */
  surface: string
  /** Primary brand accent (`--accent`). */
  accent: string
  /** Foreground text/icon color rendered on top of `--accent` (`--on-accent`). */
  onAccent: string
  /** Primary ink color (`--text`). */
  text: string
}

export interface PaletteMeta {
  id: PalettePreference
  /** Simplified Chinese display name passed through `tr()` in the UI. */
  name: string
  light: PaletteToneMeta
  dark: PaletteToneMeta
}

/**
 * Single source of truth for all 6 Billow palettes across light and dark modes.
 * Values mirror `--bg`, `--chrome`, `--surface`, `--accent`, `--on-accent`, and
 * `--text` in `src/styles/redesign.css` (teal) and `src/styles/palettes.css`.
 */
export const PALETTE_META: Record<PalettePreference, PaletteMeta> = {
  teal: {
    id: 'teal',
    name: '碧潮',
    light: {
      bg: '#f4f6f7',
      chrome: '#eaeeef',
      surface: '#fcfdfd',
      accent: '#1f7a73',
      onAccent: '#ffffff',
      text: '#181d1f',
    },
    dark: {
      bg: '#151819',
      chrome: '#101314',
      surface: '#1c2022',
      accent: '#4fb3a9',
      onAccent: '#0c2220',
      text: '#e3e7e8',
    },
  },
  sapphire: {
    id: 'sapphire',
    name: '晴空蓝',
    light: {
      bg: '#f4f6f9',
      chrome: '#eaedf2',
      surface: '#fcfcfe',
      accent: '#2d62c8',
      onAccent: '#ffffff',
      text: '#181b20',
    },
    dark: {
      bg: '#15171b',
      chrome: '#101215',
      surface: '#1c1f24',
      accent: '#6d9be0',
      onAccent: '#0d1a2e',
      text: '#e3e6ea',
    },
  },
  indigo: {
    id: 'indigo',
    name: '星夜靛',
    light: {
      bg: '#f5f5f8',
      chrome: '#ebebf0',
      surface: '#fcfcfd',
      accent: '#5258b8',
      onAccent: '#ffffff',
      text: '#191920',
    },
    dark: {
      bg: '#16171b',
      chrome: '#111215',
      surface: '#1d1f24',
      accent: '#8c93d6',
      onAccent: '#13152b',
      text: '#e4e5ea',
    },
  },
  terracotta: {
    id: 'terracotta',
    name: '暖砂陶',
    light: {
      bg: '#f6f4f1',
      chrome: '#ece9e4',
      surface: '#fdfcfb',
      accent: '#a85734',
      onAccent: '#ffffff',
      text: '#1f1c19',
    },
    dark: {
      bg: '#171615',
      chrome: '#121110',
      surface: '#1f1e1d',
      accent: '#d48c6a',
      onAccent: '#24130b',
      text: '#e6e3df',
    },
  },
  berry: {
    id: 'berry',
    name: '绯莓',
    light: {
      bg: '#f6f4f5',
      chrome: '#ece9eb',
      surface: '#fdfcfd',
      accent: '#a33b64',
      onAccent: '#ffffff',
      text: '#1f1a1c',
    },
    dark: {
      bg: '#171617',
      chrome: '#121112',
      surface: '#1f1e20',
      accent: '#d182a1',
      onAccent: '#260f19',
      text: '#e6e2e5',
    },
  },
  graphite: {
    id: 'graphite',
    name: '墨韵',
    light: {
      bg: '#f5f5f6',
      chrome: '#ebebee',
      surface: '#fcfcfd',
      accent: '#2f3137',
      onAccent: '#ffffff',
      text: '#18181b',
    },
    dark: {
      bg: '#161718',
      chrome: '#111213',
      surface: '#1e1f21',
      accent: '#c8cbd2',
      onAccent: '#141518',
      text: '#e4e5e7',
    },
  },
}

export const PALETTE_LIST: readonly PaletteMeta[] = PALETTES.map((id) => PALETTE_META[id])

export function getPaletteMeta(palette: unknown): PaletteMeta {
  return PALETTE_META[normalizePalette(palette)]
}
