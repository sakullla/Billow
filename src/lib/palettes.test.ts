import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { getPaletteMeta, PALETTE_LIST, PALETTE_META, type PaletteToneMeta } from './palettes'
import { PALETTES, type PalettePreference } from './types'

const HEX_COLOR = /^#[0-9a-f]{6}$/i

function relativeLuminance(hex: string): number {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)!
    .map((pair) => parseInt(pair, 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
  return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!
}

function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a)
  const lb = relativeLuminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

function extractBlockTokens(css: string, selector: string): Record<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = css.match(new RegExp(`${escaped}\\s*\\{([^}]+)\\}`))
  if (!match) {
    throw new Error(`Missing CSS selector block: ${selector}`)
  }
  const tokens: Record<string, string> = {}
  for (const line of match[1]!.split('\n')) {
    const tokenMatch = line.match(/^\s*(--[a-z0-9-]+)\s*:\s*([^;]+);/i)
    if (tokenMatch) {
      tokens[tokenMatch[1]!] = tokenMatch[2]!.trim().toLowerCase()
    }
  }
  return tokens
}

function assertTokensMatchMeta(tokens: Record<string, string>, meta: PaletteToneMeta, label: string) {
  expect(tokens['--bg'], `${label} --bg`).toBe(meta.bg.toLowerCase())
  expect(tokens['--chrome'], `${label} --chrome`).toBe(meta.chrome.toLowerCase())
  expect(tokens['--surface'], `${label} --surface`).toBe(meta.surface.toLowerCase())
  expect(tokens['--accent'], `${label} --accent`).toBe(meta.accent.toLowerCase())
  expect(tokens['--on-accent'], `${label} --on-accent`).toBe(meta.onAccent.toLowerCase())
  expect(tokens['--text'], `${label} --text`).toBe(meta.text.toLowerCase())
}

describe('palette metadata single source of truth', () => {
  it('defines complete light and dark metadata for all 6 palettes in canonical order', () => {
    expect(Object.keys(PALETTE_META)).toEqual([...PALETTES])
    expect(PALETTE_LIST.map((item) => item.id)).toEqual([...PALETTES])

    for (const id of PALETTES) {
      const meta = PALETTE_META[id]
      expect(meta.id).toBe(id)
      expect(meta.name.trim().length).toBeGreaterThan(0)
      for (const mode of ['light', 'dark'] as const) {
        const tone = meta[mode]
        for (const key of ['bg', 'chrome', 'surface', 'accent', 'onAccent', 'text'] as const) {
          expect(tone[key], `${id}.${mode}.${key}`).toMatch(HEX_COLOR)
        }
      }
    }

    expect(getPaletteMeta('indigo')).toBe(PALETTE_META.indigo)
    expect(getPaletteMeta('unknown')).toBe(PALETTE_META.teal)
    expect(getPaletteMeta(null)).toBe(PALETTE_META.teal)
  })

  it('satisfies contrast and surface luminance hierarchy constraints across all 12 light/dark combinations', () => {
    for (const id of PALETTES) {
      const meta = PALETTE_META[id]

      // Light mode: chrome < bg < surface
      const lightChrome = relativeLuminance(meta.light.chrome)
      const lightBg = relativeLuminance(meta.light.bg)
      const lightSurface = relativeLuminance(meta.light.surface)
      expect(lightChrome, `${id}.light chrome < bg`).toBeLessThan(lightBg)
      expect(lightBg, `${id}.light bg < surface`).toBeLessThan(lightSurface)
      expect(lightBg, `${id}.light bg luminance`).toBeGreaterThan(0.8)

      // Dark mode: chrome < bg < surface, lifted above pitch-black void to avoid halation
      const darkChrome = relativeLuminance(meta.dark.chrome)
      const darkBg = relativeLuminance(meta.dark.bg)
      const darkSurface = relativeLuminance(meta.dark.surface)
      expect(darkChrome, `${id}.dark chrome < bg`).toBeLessThan(darkBg)
      expect(darkBg, `${id}.dark bg < surface`).toBeLessThan(darkSurface)
      expect(darkBg, `${id}.dark bg luminance`).toBeGreaterThan(0.007)
      expect(darkBg, `${id}.dark bg luminance`).toBeLessThan(0.05)

      // Neutral/low-cast surface ergonomics: prevent heavy chromatic cast across backgrounds & cards
      for (const mode of ['light', 'dark'] as const) {
        const tone = meta[mode]
        for (const surfaceKey of ['bg', 'chrome', 'surface'] as const) {
          const rgb = tone[surfaceKey]
            .slice(1)
            .match(/.{2}/g)!
            .map((pair) => parseInt(pair, 16))
          const spread = Math.max(...rgb) - Math.min(...rgb)
          expect(spread, `${id}.${mode}.${surfaceKey} RGB cast spread`).toBeLessThanOrEqual(10)
        }
        expect(contrastRatio(tone.accent, tone.onAccent), `${id}.${mode} accent/onAccent`).toBeGreaterThanOrEqual(4.5)
        expect(contrastRatio(tone.accent, tone.surface), `${id}.${mode} accent/surface`).toBeGreaterThanOrEqual(3.0)
        expect(contrastRatio(tone.text, tone.bg), `${id}.${mode} text/bg`).toBeGreaterThanOrEqual(10.0)
        expect(contrastRatio(tone.text, tone.surface), `${id}.${mode} text/surface`).toBeGreaterThanOrEqual(10.0)
      }
    }
  })

  it('stays strictly synchronized with CSS tokens in redesign.css and palettes.css', () => {
    const redesignCss = readFileSync(resolve(process.cwd(), 'src/styles/redesign.css'), 'utf8')
    const palettesCss = readFileSync(resolve(process.cwd(), 'src/styles/palettes.css'), 'utf8')

    // Default palette (teal) lives in redesign.css
    assertTokensMatchMeta(extractBlockTokens(redesignCss, ':root'), PALETTE_META.teal.light, 'teal.light')
    assertTokensMatchMeta(extractBlockTokens(redesignCss, ":root:not([data-theme='light'])"), PALETTE_META.teal.dark, 'teal.dark (media)')
    assertTokensMatchMeta(extractBlockTokens(redesignCss, ":root[data-theme='dark']"), PALETTE_META.teal.dark, 'teal.dark (explicit)')

    // Alternate 5 palettes live in palettes.css
    const alternatePalettes: Exclude<PalettePreference, 'teal'>[] = ['sapphire', 'indigo', 'terracotta', 'berry', 'graphite']
    for (const id of alternatePalettes) {
      assertTokensMatchMeta(extractBlockTokens(palettesCss, `:root[data-palette='${id}']`), PALETTE_META[id].light, `${id}.light`)
      assertTokensMatchMeta(
        extractBlockTokens(palettesCss, `:root:not([data-theme='light'])[data-palette='${id}']`),
        PALETTE_META[id].dark,
        `${id}.dark (media)`,
      )
      assertTokensMatchMeta(
        extractBlockTokens(palettesCss, `:root[data-theme='dark'][data-palette='${id}']`),
        PALETTE_META[id].dark,
        `${id}.dark (explicit)`,
      )
    }
  })
})
