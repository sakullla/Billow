import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import { SETTINGS_CATEGORIES, SETTINGS_INDEX, SETTINGS_PANES, searchSettings } from './lib/settings/catalog'
import type { Store } from './lib/store'

// Settings 3.0: categories by task, a searchable index, and rows that apply at once.

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountApp>>['wrapper']
const storeOf = (wrapper: Wrapper) => (wrapper.vm as unknown as { store: Store }).store
const body = () => new DOMWrapper(document.body)

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
  document.documentElement.removeAttribute('data-palette')
  document.body.innerHTML = ''
  vi.useRealTimers()
})

describe('settings catalog', () => {
  const desktop = { android: false, windows: true, linux: false, mac: false }
  const android = { android: true, windows: false, linux: false, mac: false }

  it('indexes every row under a pane that exists, and shows every pane on some page', () => {
    const ids = new Set(SETTINGS_PANES.map((pane) => pane.id))
    expect(SETTINGS_CATEGORIES.map((category) => category.id)).toEqual(['general', 'proxy', 'network', 'behavior', 'dns', 'kernel', 'backup'])
    expect(new Set(SETTINGS_CATEGORIES.flatMap((category) => category.panes))).toEqual(ids)
    for (const entry of SETTINGS_INDEX) expect(ids.has(entry.tab)).toBe(true)
    expect(new Set(SETTINGS_INDEX.map((entry) => entry.id)).size).toBe(SETTINGS_INDEX.length)
  })

  it('matches titles, mihomo keys and English words, and hides rows the platform lacks', () => {
    expect(searchSettings('mtu', desktop).map((entry) => entry.id)).toContain('tun-mtu')
    expect(searchSettings('enhanced-mode', desktop).map((entry) => entry.id)).toEqual(['dns-mode'])
    expect(searchSettings('端口', desktop).map((entry) => entry.id)).toContain('mixed-port')
    expect(searchSettings('配色', desktop).map((entry) => entry.id)).toContain('palette')
    expect(searchSettings('bypass', android)).toEqual([])
    expect(searchSettings('uwp', { ...desktop, windows: false })).toEqual([])
  })
})

describe('settings page', () => {
  it('opens on 通用 with top category tabs, and switches 系统代理 / TUN via sub-tabs without accordions', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).go('settings')
    await flushPromises()
    const tabs = wrapper.find('[data-testid="settings-tabs"]')
    expect(tabs.findAll('.settings-tab').map((item) => item.text())).toEqual(['通用', '系统与 TUN', '端口与网络', '代理与测速', 'DNS', '内核', '备份与关于'])
    expect(tabs.find('[aria-current="page"]').attributes('data-value')).toBe('general')
    await tabs.find('[data-value="proxy"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="subtab-proxy"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.find('[data-testid="proxy-settings"]').exists()).toBe(true)
    await wrapper.find('[data-testid="subtab-tun"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="subtab-tun"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.find('[data-testid="tun-settings"]').exists()).toBe(true)
    await tabs.find('[data-value="network"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-pane="network"] [data-testid="mixed-port-input"]').exists()).toBe(true)
  })

  it('finds a folded row by search and opens its group to show it', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).go('settings')
    await flushPromises()
    const search = wrapper.find('[data-testid="settings-search"]')
    await search.setValue('mtu')
    expect(wrapper.find('[data-testid="settings-results"] [data-result="tun-mtu"]').exists()).toBe(true)

    await search.trigger('keydown', { key: 'Enter' })
    await settle(100)
    const store = storeOf(wrapper)
    expect(store.settingsTab.value).toBe('tun')
    expect((search.element as HTMLInputElement).value).toBe('')
    const row = wrapper.find('[data-setting="tun-mtu"]')
    expect(row.classes()).toContain('srow-flash')
    expect((row.element.closest('details') as HTMLDetailsElement).open).toBe(true)
    expect(store.settingsFocus.value).toBeNull()
  })

  it('says so when nothing matches, and Escape clears the query', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).go('settings')
    await flushPromises()
    const search = wrapper.find('[data-testid="settings-search"]')
    await search.setValue('zzzz')
    expect(wrapper.find('.settings-pane-head').text()).toContain('没有找到“zzzz”相关的设置')
    expect(wrapper.find('[data-testid="clear-settings-search"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="reset-settings-search"]').exists()).toBe(true)
    await search.trigger('keydown', { key: 'Escape' })
    expect((search.element as HTMLInputElement).value).toBe('')
    expect(wrapper.find('[data-testid="settings-results"]').exists()).toBe(false)
  })

  it('highlights search matches and shows live status badges on System Proxy / TUN sub-tabs', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.go('settings')
    await flushPromises()

    const search = wrapper.find('[data-testid="settings-search"]')
    await search.setValue('端口')
    await flushPromises()
    expect(wrapper.find('[data-testid="settings-results"] mark').text()).toBe('端口')
    await wrapper.find('[data-testid="clear-settings-search"]').trigger('click')
    await flushPromises()
    expect((search.element as HTMLInputElement).value).toBe('')

    await wrapper.find('[data-value="proxy"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="pane-status-proxy"]').text()).toBe('已关闭')
    expect(wrapper.find('[data-testid="pane-status-tun"]').text()).toBe('已关闭')
  })

  it('jumps from the effective config straight to the row that changes a value', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.openConfig('overview')
    await settle(300)
    await body().find('[data-testid="config-search"]').setValue('tcp-concurrent')
    await body().find('.cfg-row[data-path="tcp-concurrent"]').trigger('click')
    await settle(100)
    expect(store.settingsTab.value).toBe('network')
    expect(wrapper.find('[data-setting="tcp-concurrent"]').classes()).toContain('srow-flash')
  })

  it('sends a port conflict to the mixed port row in 网络与端口', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.openSettings('network', 'mixed-port')
    await settle(100)
    expect(wrapper.find('[data-setting="mixed-port"]').classes()).toContain('srow-flash')
  })

  it('keeps proxy and TUN out of the Android list, with per-app access in their place', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    storeOf(wrapper).go('settings')
    await flushPromises()
    expect(wrapper.find('[data-testid="open-proxy"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-tun"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-apps"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="open-dns"]').exists()).toBe(true)
    expect(wrapper.findAll('.srow-cat')).toHaveLength(7)
    await wrapper.find('[data-testid="open-network"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-pane="network"]').exists()).toBe(true)
  })

  it('switches color palettes immediately, persists them across restarts, and resets to default teal', async () => {
    const { wrapper, backend } = await mountApp()
    storeOf(wrapper).go('settings')
    await flushPromises()

    const picker = wrapper.find('[data-testid="palette-picker"]')
    expect(picker.exists()).toBe(true)
    expect(picker.findAll('.palette-chip').map((chip) => chip.attributes('data-value'))).toEqual([
      'teal',
      'sapphire',
      'indigo',
      'terracotta',
      'berry',
      'graphite',
    ])
    expect(document.documentElement.getAttribute('data-palette')).toBeNull()

    await picker.find('[data-value="indigo"]').trigger('click')
    await flushPromises()
    expect(document.documentElement.getAttribute('data-palette')).toBe('indigo')
    expect(picker.find('[data-value="indigo"]').attributes('aria-checked')).toBe('true')

    // Persists through backend shell state on restart
    wrapper.unmount()
    mounted.splice(0, mounted.length)
    document.documentElement.removeAttribute('data-palette')
    const restarted = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
    mounted.push(restarted)
    await settle(50)
    expect(document.documentElement.getAttribute('data-palette')).toBe('indigo')

    // Cycling palettes via store helper advances through the list and back to default teal
    const store = storeOf(restarted)
    expect(store.cyclePalette()).toBe('terracotta')
    expect(document.documentElement.getAttribute('data-palette')).toBe('terracotta')
    store.setPalette('teal')
    expect(document.documentElement.getAttribute('data-palette')).toBeNull()
  })
})
