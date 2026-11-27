import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'
import { applyInsets } from './lib/ui/insets'

// Regression coverage for docs/requirements/2026-11-19-competitor-parity.md R40/R47.

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
  await settle(80)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountApp>>['wrapper']

function storeOf(wrapper: Wrapper) {
  return (wrapper.vm as unknown as { store: Store }).store
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  applyInsets({ top: 0, right: 0, bottom: 0, left: 0, ime: 0 })
  document.body.innerHTML = ''
  localStorage.clear()
  vi.useRealTimers()
})

describe('Exit IP lookup (R40)', () => {
  it('shows no card and makes no request while auto-query is off, even after connecting and switching', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    const exitSpy = vi.spyOn(backend, 'exitIp')

    expect(store.app.value?.auto_exit_ip).toBe(false)
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(false)

    await connect(wrapper)
    expect(exitSpy).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(false)

    // An off switch also means switches must not sneak in an automatic request.
    void store.selectNode('节点选择', '日本 01')
    await settle(800)
    void store.setMode('global')
    await settle(500)
    expect(exitSpy).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(false)
  })

  it('shows the entry once enabled and automatically queries on connect', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    const exitSpy = vi.spyOn(backend, 'exitIp')

    await store.setAutoExitIp(true)
    await flushPromises()
    const card = () => wrapper.find('[data-testid="exit-ip-card"]')
    expect(card().exists()).toBe(true)
    expect(card().find('[data-testid="exit-ip-offline"]').text()).toContain('连接后才能查询')
    expect(exitSpy).not.toHaveBeenCalled()

    await connect(wrapper)
    await settle(600)

    expect(exitSpy).toHaveBeenCalledTimes(1)
    expect(card().find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
    expect(card().find('[data-testid="exit-ip-region"]').text()).toBe('Hong Kong')
    expect(card().find('[data-testid="exit-ip-region"]').attributes('title')).toContain('地区')
    expect(card().find('[data-testid="exit-ip-isp"]').text()).toContain('AS15169 Google LLC')
    const meta = card().find('[data-testid="exit-ip-meta"]').text()
    expect(meta).toContain('ip.sb')
    expect(meta).toMatch(/\d{2}:\d{2}:\d{2}/)
    expect(card().find('[data-testid="exit-ip-stale"]').exists()).toBe(false)
    expect(card().find('[data-testid="exit-ip-query"]').exists()).toBe(false)
    await wrapper.find('[data-testid="exit-ip-refresh"]').trigger('click')
    await settle(600)
    expect(exitSpy).toHaveBeenCalledTimes(2)
  })

  it('queries once when the window opens on a live connection with auto-query on', async () => {
    vi.useFakeTimers()
    const backend = createDemoBackend()
    // A released window reopening from the tray (R44) or a launch auto-connect
    // can both finish before the first snapshot: the connection already exists
    // and auto-query is already on when the store initializes.
    const connecting = backend.connect()
    await vi.advanceTimersByTimeAsync(700)
    await connecting
    const info = await backend.appInfo()
    vi.spyOn(backend, 'appInfo').mockResolvedValue({ ...info, auto_exit_ip: true })
    const exitSpy = vi.spyOn(backend, 'exitIp')

    const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
    mounted.push(wrapper)
    await settle(1200)

    // Exactly one automatic query, and the result is on screen without a click.
    expect(exitSpy).toHaveBeenCalledTimes(1)
    const card = wrapper.find('[data-testid="exit-ip-card"]')
    expect(card.find('[data-testid="exit-ip-query"]').exists()).toBe(false)
    expect(card.find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
    expect(card.find('[data-testid="exit-ip-stale"]').exists()).toBe(false)
  })

  it('explains why nothing can be queried while enabled but disconnected', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    await store.setAutoExitIp(true)
    await flushPromises()
    const exitSpy = vi.spyOn(backend, 'exitIp')
    const card = wrapper.find('[data-testid="exit-ip-card"]')
    expect(card.exists()).toBe(true)
    expect(card.find('[data-testid="exit-ip-offline"]').text()).toContain('连接后才能查询')
    const button = card.find('[data-testid="exit-ip-query"]')
    expect(button.attributes('disabled')).toBeDefined()
    await button.trigger('click')
    await settle(500)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('marks a stale result after a switch and clears it on refresh, keeping the old answer on failure', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    await store.setAutoExitIp(true)
    await flushPromises()
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await connect(wrapper)
    await settle(600)
    expect(store.exitIp.value?.ip).toBe('203.0.113.42')

    const switchAndFail = async (switchAway: () => void) => {
      exitSpy.mockRejectedValueOnce(new Error('出口 IP 查询超时'))
      switchAway()
      await settle(800)
      expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
      expect(wrapper.find('[data-testid="exit-ip-error"]').text()).toContain('出口 IP 查询超时')
      await wrapper.find('[data-testid="exit-ip-refresh"]').trigger('click')
      await settle(600)
      expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="exit-ip-error"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
    }

    await switchAndFail(() => void store.selectNode('节点选择', '日本 01'))
    await switchAndFail(() => void store.setMode('global'))
    await switchAndFail(() => void store.enable('p2'))
  })

  it('hides the card and stops automatic requests once the option is turned off', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    await store.setAutoExitIp(true)
    await flushPromises()
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await connect(wrapper)
    await settle(600)
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(true)
    expect(store.exitIp.value?.ip).toBe('203.0.113.42')

    await store.setAutoExitIp(false)
    await flushPromises()
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(false)
    expect(store.exitIp.value).toBeNull()

    exitSpy.mockClear()
    void store.selectNode('节点选择', '美国 01')
    await settle(800)
    void store.setMode('global')
    await settle(500)
    void store.disconnect()
    await settle(400)
    await connect(wrapper)
    await settle(800)
    expect(exitSpy).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="exit-ip-card"]').exists()).toBe(false)
  })

  it('puts exit IP and traffic history together under 通用 → 首页与统计 on desktop', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.openSettings('general')
    await flushPromises()

    const network = wrapper.find('[data-testid="settings-network"]')
    expect(network.exists()).toBe(true)
    expect(network.text()).toContain('首页与统计')
    const setting = network.find('[data-testid="auto-exit-ip-setting"]')
    expect(setting.text()).toContain('ip.sb')
    expect(setting.text()).toContain('ipinfo.io')
    expect(setting.find('[data-testid="auto-exit-ip-toggle"]').attributes('aria-checked')).toBe('false')
    expect(wrapper.find('[data-testid="node-switch-settings"] [data-testid="auto-exit-ip-setting"]').exists()).toBe(false)

    // Traffic history lives under Home & Stats too (R43): off by default, stats entry reachable, no duplicate row.
    const traffic = network.find('[data-testid="traffic-history-setting"]')
    expect(traffic.exists()).toBe(true)
    expect(traffic.find('[data-testid="traffic-history-toggle"]').attributes('aria-checked')).toBe('false')
    expect(traffic.find('[data-testid="open-traffic-stats"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="node-switch-settings"] [data-testid="traffic-history-setting"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="traffic-history-setting"]')).toHaveLength(1)
  })

  it('reaches the same group on the phone through the 通用 category', async () => {
    const { wrapper } = await mountApp({}, 390)
    const store = storeOf(wrapper)
    store.go('settings')
    await flushPromises()
    expect(wrapper.find('[data-testid="settings-network"]').exists()).toBe(false)
    await wrapper.find('[data-testid="open-general"]').trigger('click')
    await flushPromises()

    const network = wrapper.find('[data-testid="settings-network"]')
    expect(network.exists()).toBe(true)
    const setting = network.find('[data-testid="auto-exit-ip-setting"]')
    expect(setting.exists()).toBe(true)
    expect(setting.text()).toContain('ip.sb')
    expect(setting.text()).toContain('ipinfo.io')
    expect(setting.find('[data-testid="auto-exit-ip-toggle"]').attributes('aria-checked')).toBe('false')
    expect(wrapper.find('[data-testid="node-switch-settings"] [data-testid="auto-exit-ip-setting"]').exists()).toBe(false)

    // Traffic history sits beside it (R43), still off by default and reachable.
    const traffic = network.find('[data-testid="traffic-history-setting"]')
    expect(traffic.exists()).toBe(true)
    expect(traffic.find('[data-testid="traffic-history-toggle"]').attributes('aria-checked')).toBe('false')
    expect(traffic.find('[data-testid="open-traffic-stats"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="node-switch-settings"] [data-testid="traffic-history-setting"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="traffic-history-setting"]')).toHaveLength(1)
  })
})
