import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'

// Phone layout regressions: grouped settings, one-row tool headers and readable fact lines.

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

async function mountPhone(options: Parameters<typeof createDemoBackend>[0] = {}) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width: 390 }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountPhone>>['wrapper']

function storeOf(wrapper: Wrapper) {
  return (wrapper.vm as unknown as { store: Store }).store
}

function body() {
  return new DOMWrapper(document.body)
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  vi.useRealTimers()
})

describe('phone layout', () => {
  it('keeps list ends reachable above the dock and inside the picker sheet (R8)', () => {
    // Layout is absent in happy-dom, so guard the rules that create the clearance.
    const css = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')
    expect(css.length, 'raw stylesheet').toBeGreaterThan(1000)
    const rule = (selector: string) => {
      const at = css.lastIndexOf(`${selector} {`)
      expect(at, selector).toBeGreaterThan(-1)
      return css.slice(at, css.indexOf('}', at))
    }
    expect(rule('.compact .page')).toMatch(/padding-bottom:\s*calc\(var\(--tabbar-h\) \+ var\(--safe-bottom\)/)
    // The picker list scrolls with the sheet body, never in a nested box that could clip its last row.
    expect(rule('.node-picker-list')).not.toMatch(/max-height|overflow/)
    expect(css).not.toMatch(/\.compact \.node-picker-list\s*\{[^}]*max-height/)
  })

  it('keeps a quiet, tappable latency slot on untested proxy rows', async () => {
    const { wrapper, backend } = await mountPhone({ platform: 'android' })
    await connect(wrapper)
    const testNode = vi.spyOn(backend, 'testNode')
    storeOf(wrapper).go('proxies')
    await settle(100)
    const slot = wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .delay')
    expect(slot.classes()).toContain('untested')
    // The zap glyph is kept for desktop hover; phones hide it and draw a dash in its place.
    expect(slot.find('.delay-zap').exists()).toBe(true)
    expect(slot.text()).toBe('')
    await slot.trigger('click')
    await settle(50)
    expect(testNode).toHaveBeenCalledWith('日本 02')
  })

  it('lists categories with their state, and keeps each category in grouped list rows', async () => {
    const { wrapper, backend } = await mountPhone()
    storeOf(wrapper).go('settings')
    await flushPromises()

    // The root is a grouped list of categories; each says what is on without opening it.
    expect(wrapper.find('[data-testid="open-network"] .srow-value').text()).toBe(':7890')
    expect(wrapper.find('[data-testid="open-dns"] .srow-value').text()).toBe('跟随配置')
    expect(wrapper.findAll('.page.settings > section.card')).toHaveLength(0)

    await wrapper.find('[data-testid="open-behavior"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.settings-subhead h1').text()).toBe('代理与测速')
    // The subscription User-Agent is a row in the same grouped list, marked once customised.
    const row = wrapper.find('[data-testid="subscription-settings"]')
    expect(row.classes()).toContain('srow')
    expect(row.find('.srow-badge').exists()).toBe(false)

    const save = vi.spyOn(backend, 'saveSettings')
    const input = row.find('[data-testid="global-subscription-user-agent"]')
    await input.trigger('focus')
    await input.setValue('phone-client/1')
    await input.trigger('blur')
    await settle(300)
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ subscription_user_agent: 'phone-client/1' }))
    expect(wrapper.find('[data-testid="subscription-settings"] .srow-badge').text()).toBe('已自定义')

    // Update status sits in the about page as a row under the version hero.
    await wrapper.find('[data-testid="settings-back"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="open-backup"]').trigger('click')
    await flushPromises()
    const about = wrapper.find('[data-testid="settings-about"]')
    expect(about.exists()).toBe(true)
    expect(wrapper.find('[data-testid="app-update"]').classes()).toContain('update-row')
  })

  it('folds rarer log actions into one menu so the header stays on one row', async () => {
    const { wrapper } = await mountPhone()
    await connect(wrapper)
    storeOf(wrapper).go('logs')
    await settle(1200)

    expect(wrapper.find('[data-testid="pause-logs"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="copy-logs"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="clear-logs"]').exists()).toBe(false)

    const openMenu = async () => {
      await wrapper.find('[data-testid="log-more"]').trigger('click')
      await flushPromises()
    }
    await openMenu()
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).not.toContain('no-wrap')
    await wrapper.find('[data-menu-item="wrap"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).toContain('no-wrap')

    await openMenu()
    expect(wrapper.find('[data-menu-item="wrap"]').text()).toContain('开启自动换行')
    await wrapper.find('[data-menu-item="clear"]').trigger('click')
    await flushPromises()
    expect(body().find('[data-testid="confirm-clear-logs"]').exists()).toBe(true)
  })

  it('pairs the connection scope with a sort sheet and keeps summary facts whole', async () => {
    const { wrapper } = await mountPhone()
    await connect(wrapper)
    storeOf(wrapper).go('connections')
    await settle(1100)

    const summary = wrapper.find('[data-testid="connection-summary"]')
    expect(summary.classes()).toContain('meta-line')
    // Separators are drawn by CSS after each fact, never typed as text that could start a line.
    expect(summary.text()).not.toContain('·')
    expect(summary.findAll(':scope > span').length).toBeGreaterThanOrEqual(3)

    const sort = wrapper.find('[data-testid="connection-sort"]')
    expect(sort.text()).toContain('按时间')
    await sort.trigger('click')
    await flushPromises()
    await body().find('.option-row[data-option-value="download"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="connection-sort"]').text()).toContain('按下载')
  })

  it('gives immediate feedback and updates status when checking kernel updates on Android', async () => {
    const { wrapper } = await mountPhone({ platform: 'android' })
    const store = storeOf(wrapper)
    const checkSpy = vi.spyOn(store.appUpdate, 'check').mockImplementation(async () => {
      store.appUpdate.status.value = 'current'
    })
    store.openSettings('kernel')
    await flushPromises()

    const checkBtn = wrapper.find('[data-testid="kernel-check-update"]')
    expect(checkBtn.exists()).toBe(true)
    await checkBtn.trigger('click')
    await flushPromises()

    expect(checkSpy).toHaveBeenCalledWith(false)
    expect(wrapper.find('[data-testid="kernel-update-subtitle"]').text()).toContain('最新版本')
    expect(wrapper.find('.toasts').text()).toContain('最新版本')
  })

  it('keeps the compact proxies top bar uncluttered and reveals quick filters and group jump inside options', async () => {
    const { wrapper } = await mountPhone()
    storeOf(wrapper).go('proxies')
    await settle(100)

    // Default compact proxies view stays a single row: no mode bar, filter chips, or group jump strip.
    expect(wrapper.find('[data-testid="proxies-mobile-mode"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="proxy-quick-filters"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="group-jump-bar"]').exists()).toBe(false)

    await wrapper.find('[data-testid="toggle-options"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="proxy-quick-filters"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="group-jump-bar"]').exists()).toBe(true)

    // Selecting a filter and folding options back keeps a removable active pill in the single-row bar.
    await wrapper.find('[data-testid="quick-filter-tag:udp"]').trigger('click')
    await wrapper.find('[data-testid="toggle-options"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="proxy-quick-filters"]').exists()).toBe(false)
    const activePill = wrapper.find('[data-testid="active-quick-filter-pill"]')
    expect(activePill.exists()).toBe(true)
    await activePill.trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="active-quick-filter-pill"]').exists()).toBe(false)
  })

  it('keeps compact mobile layout free of floating command-palette search button', async () => {
    const { wrapper } = await mountPhone()
    expect(wrapper.find('[data-testid="mobile-open-palette"]').exists()).toBe(false)
  })

  it('keeps home, proxies, profiles and dock free of distracting status and badge dots', async () => {
    localStorage.setItem('billow:proxy-sort', JSON.stringify('delay'))
    localStorage.setItem('billow:proxy-view', JSON.stringify('dense'))
    const { wrapper } = await mountPhone()
    void storeOf(wrapper).importCustomNodes('ss://YWVzLTI1Ni1nY206cGFzc0AxLjEuMS4xOjg4ODg=#TestNode')
    await settle(300)
    await connect(wrapper)

    // Home & dock: no live dot on tabbar, no hero dot, no collecting dot, directional legend icons instead of dots
    expect(wrapper.find('.tabbar .tab-live-dot').exists()).toBe(false)
    expect(wrapper.find('.tabbar .update-dot').exists()).toBe(false)
    expect(wrapper.find('.hero-dot').exists()).toBe(false)
    expect(wrapper.find('.chart-collecting-dot').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="chart-legend"] .legend-item .icon')).toHaveLength(2)

    // Proxies: options button never renders a marked corner dot even when sort/view are non-default
    storeOf(wrapper).go('proxies')
    await settle(100)
    const optionsBtn = wrapper.find('[data-testid="toggle-options"]')
    expect(optionsBtn.exists()).toBe(true)
    expect(optionsBtn.classes()).not.toContain('marked')

    // Profiles: custom nodes tab and active profile badge render without status dots
    storeOf(wrapper).go('profiles')
    await settle(100)
    expect(wrapper.find('.profiles-tab-dot').exists()).toBe(false)
    expect(wrapper.find('.profile-live-dot').exists()).toBe(false)
    expect(wrapper.find('.profile-active-tag').text()).toBe('使用中')
  })
})
