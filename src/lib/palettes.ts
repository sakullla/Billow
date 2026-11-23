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
      bg: '#f3f7f7',
      chrome: '#e5eded',
      surface: '#ffffff',
      accent: '#0c7f75',
      onAccent: '#ffffff',
      text: '#0e1d20',
    },
    dark: {
      bg: '#0b1215',
      chrome: '#070c0e',
      surface: '#131c20',
      accent: '#2dd4bf',
      onAccent: '#05201d',
      text: '#edf4f5',
    },
  },
  sapphire: {
    id: 'sapphire',
    name: '晴空蓝',
    light: {
      bg: '#f4f7fc',
      chrome: '#e6ebf4',
      surface: '#ffffff',
      accent: '#2563eb',
      onAccent: '#ffffff',
      text: '#0f172a',
    },
    dark: {
      bg: '#0c1119',
      chrome: '#080b11',
      surface: '#141b26',
      accent: '#60a5fa',
      onAccent: '#081426',
      text: '#f1f5f9',
    },
  },
  indigo: {
    id: 'indigo',
    name: '星夜靛',
    light: {
      bg: '#f5f5fb',
      chrome: '#e9e9f4',
      surface: '#ffffff',
      accent: '#4f46e5',
      onAccent: '#ffffff',
      text: '#15142b',
    },
    dark: {
      bg: '#0d0d18',
      chrome: '#080811',
      surface: '#151525',
      accent: '#818cf8',
      onAccent: '#0c0b24',
      text: '#f0f0fa',
    },
  },
  terracotta: {
    id: 'terracotta',
    name: '暖砂陶',
    light: {
      bg: '#faf6f0',
      chrome: '#eee6dc',
      surface: '#fffdfa',
      accent: '#b85020',
      onAccent: '#ffffff',
      text: '#231710',
    },
    dark: {
      bg: '#130f0c',
      chrome: '#0d0a08',
      surface: '#1c1713',
      accent: '#f0905e',
      onAccent: '#220f06',
      text: '#f6efe8',
    },
  },
  berry: {
    id: 'berry',
    name: '绯莓',
    light: {
      bg: '#faf5f8',
      chrome: '#efe6ec',
      surface: '#ffffff',
      accent: '#b8185a',
      onAccent: '#ffffff',
      text: '#23111c',
    },
    dark: {
      bg: '#140d13',
      chrome: '#0d080c',
      surface: '#1d141c',
      accent: '#f472b6',
      onAccent: '#240817',
      text: '#f7eef4',
    },
  },
  graphite: {
    id: 'graphite',
    name: '墨韵',
    light: {
      bg: '#f5f5f7',
      chrome: '#e9e9ed',
      surface: '#ffffff',
      accent: '#18181b',
      onAccent: '#ffffff',
      text: '#111114',
    },
    dark: {
      bg: '#0d0d10',
      chrome: '#08080a',
      surface: '#151519',
      accent: '#e4e4e7',
      onAccent: '#09090b',
      text: '#f4f4f6',
    },
  },
}

export const PALETTE_LIST: readonly PaletteMeta[] = PALETTES.map((id) => PALETTE_META[id])

export function getPaletteMeta(palette: unknown): PaletteMeta {
  return PALETTE_META[normalizePalette(palette)]
}
