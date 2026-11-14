import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it } from 'vitest'
import App from './App.vue'
import { THEME_OPTIONS } from './copy'
import { createMemoryPort } from './port'
import { ACCENT, DEFAULT_THEME, RADIUS, SURFACES, applyTheme, resolveAppearance, resolveTheme } from './theme'

const css = readFileSync('src/styles.css', 'utf8')

afterEach(() => {
  document.documentElement.removeAttribute('data-appearance')
  delete document.documentElement.dataset.theme
})

async function mountApp(port = createMemoryPort()) {
  const wrapper = mount(App, { props: { initialWidth: 800, port } })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  return wrapper
}

describe('主题', () => {
  it('默认跟随系统，可以改为始终浅色或始终深色', async () => {
    expect(DEFAULT_THEME).toBe('system')
    expect(THEME_OPTIONS.map((option) => option.label)).toEqual(['跟随系统', '始终浅色', '始终深色'])
    expect(resolveTheme(null)).toBe('system')
    expect(resolveTheme('blue')).toBe('system')
    expect(resolveAppearance('system', true)).toBe('dark')
    expect(resolveAppearance('system', false)).toBe('light')
    expect(resolveAppearance('light', true)).toBe('light')
    expect(resolveAppearance('dark', false)).toBe('dark')

    const port = createMemoryPort()
    const wrapper = await mountApp(port)
    expect(document.documentElement.dataset.theme).toBe('system')
    expect(document.documentElement.hasAttribute('data-appearance')).toBe(false)

    await wrapper.get('[data-entry="settings"]').trigger('click')
    const radios = wrapper.findAll('input[name="theme"]')
    expect(radios.map((radio) => (radio.element as HTMLInputElement).value)).toEqual([
      'system',
      'light',
      'dark',
    ])
    await radios[1]!.trigger('change')
    expect(document.documentElement.getAttribute('data-appearance')).toBe('light')
    expect((await port.load()).theme).toBe('light')

    await radios[2]!.trigger('change')
    expect(document.documentElement.getAttribute('data-appearance')).toBe('dark')

    await radios[0]!.trigger('change')
    expect(document.documentElement.hasAttribute('data-appearance')).toBe(false)
    expect((await port.load()).theme).toBe('system')
  })

  it('浅色和深色的页面底与内容底不同，强调色和圆角只有一套', () => {
    expect(SURFACES.light.page).not.toBe(SURFACES.light.content)
    expect(SURFACES.dark.page).not.toBe(SURFACES.dark.content)
    expect(css).toContain(`--page: ${SURFACES.light.page}`)
    expect(css).toContain(`--content: ${SURFACES.light.content}`)
    expect(css).toContain(`--page: ${SURFACES.dark.page}`)
    expect(css).toContain(`--content: ${SURFACES.dark.content}`)
    expect(css).toContain(`--accent: ${ACCENT}`)
    expect(css).toContain(`--radius: ${RADIUS}`)
    expect(css).toContain('font-family: system-ui,')
    expect(css).toContain(':focus-visible')
    expect(css).not.toMatch(/gradient|backdrop-filter|@keyframes/i)

    const allowed = new Set<string>([
      SURFACES.light.page,
      SURFACES.light.content,
      SURFACES.light.text,
      SURFACES.light.muted,
      SURFACES.light.line,
      SURFACES.dark.page,
      SURFACES.dark.content,
      SURFACES.dark.text,
      SURFACES.dark.muted,
      SURFACES.dark.line,
      ACCENT,
      '#ffffff',
    ])
    const used = css.match(/#[0-9a-fA-F]{6}/g) ?? []
    expect(used.length).toBeGreaterThan(0)
    for (const color of used) expect(allowed.has(color.toLowerCase())).toBe(true)

    applyTheme('light')
    expect(document.documentElement.getAttribute('data-appearance')).toBe('light')
    applyTheme('system')
    expect(document.documentElement.hasAttribute('data-appearance')).toBe(false)
  })

  it('每屏最多一个实心主按钮，首页状态词更大', async () => {
    expect(css).toMatch(/\.status-word\s*\{[^}]*font-size:\s*3rem/)
    expect(css).toMatch(/\.page-title[\s\S]*font-size:\s*1\.25rem/)
    const wrapper = await mountApp()
    expect(wrapper.get('.status-word').text()).toBe('未连接')
    expect(wrapper.findAll('.btn-primary')).toHaveLength(0)
    await wrapper.get('[data-entry="settings"]').trigger('click')
    expect(wrapper.findAll('.btn-primary')).toHaveLength(0)
    await wrapper.get('[data-entry="nodes"]').trigger('click')
    expect(wrapper.findAll('.btn-primary')).toHaveLength(0)
  })
})
