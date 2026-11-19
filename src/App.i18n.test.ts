import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import { applyLocale } from './lib/i18n'

const mounted: { unmount: () => void }[] = []

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

async function mountApp(backend: ReturnType<typeof createDemoBackend>) {
  vi.useFakeTimers()
  const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return wrapper
}

async function openSettings(wrapper: Awaited<ReturnType<typeof mountApp>>) {
  await wrapper.find('.sidebar [data-page="settings"]').trigger('click')
  await flushPromises()
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  applyLocale('zh-CN')
})

vi.setConfig({ testTimeout: 20_000 })

describe('R42 language setting', () => {
  it('switches the dictionary and document lang immediately, and remembers it', async () => {
    const backend = createDemoBackend()
    const wrapper = await mountApp(backend)
    await openSettings(wrapper)

    const row = () => wrapper.find('[data-testid="language-setting"]')
    expect(row().text()).toContain('界面语言')
    expect(document.documentElement.lang).toBe('zh-CN')
    expect(wrapper.find('[data-testid="language-select"] [data-value="system"]').text()).toBe('跟随系统')

    await wrapper.find('[data-testid="language-select"] [data-value="en"]').trigger('click')
    await settle(0)

    expect(document.documentElement.lang).toBe('en')
    expect(row().text()).toContain('Language')
    expect(wrapper.find('[data-testid="language-select"] [data-value="system"]').text()).toBe('Follow system')

    // A restart reads the stored preference back from the same persisted state.
    wrapper.unmount()
    mounted.splice(0, mounted.length)
    const restarted = await mountApp(backend)
    await openSettings(restarted)
    expect(document.documentElement.lang).toBe('en')
    expect(restarted.find('[data-testid="language-setting"]').text()).toContain('Language')
  })

  it('starts in English on an English system and in Chinese on a Chinese one', async () => {
    const english = await mountApp(createDemoBackend({ systemLocale: 'en' }))
    await openSettings(english)
    expect(document.documentElement.lang).toBe('en')
    expect(english.find('[data-testid="language-setting"]').text()).toContain('Language')
    english.unmount()
    mounted.splice(0, mounted.length)

    // A Traditional Chinese system (zh-TW) is Simplified Chinese too (R46).
    const chinese = await mountApp(createDemoBackend({ systemLocale: 'zh-CN' }))
    await openSettings(chinese)
    expect(document.documentElement.lang).toBe('zh-CN')
    expect(chinese.find('[data-testid="language-setting"]').text()).toContain('界面语言')
  })
})
