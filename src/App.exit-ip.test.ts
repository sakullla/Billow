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
  it('stays idle after connecting until clicked, then shows IP, region, ISP and time', async () => {
    const { wrapper, backend } = await mountApp()
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await connect(wrapper)
    expect(exitSpy).not.toHaveBeenCalled()

    const card = () => wrapper.find('[data-testid="exit-ip-card"]')
    expect(card().exists()).toBe(true)
    const button = card().find('[data-testid="exit-ip-query"]')
    expect(button.text()).toContain('查询出口 IP')
    expect(button.attributes('disabled')).toBeUndefined()

    await button.trigger('click')
    await settle(600)
    expect(exitSpy).toHaveBeenCalledTimes(1)
    expect(card().find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
    expect(card().find('[data-testid="exit-ip-region"]').text()).toContain('地区')
    expect(card().find('[data-testid="exit-ip-isp"]').text()).toContain('AS15169 Google LLC')
    const meta = card().find('[data-testid="exit-ip-meta"]').text()
    expect(meta).toContain('ip.sb')
    expect(meta).toMatch(/\d{2}:\d{2}:\d{2}/)
    expect(card().find('[data-testid="exit-ip-stale"]').exists()).toBe(false)
    expect(card().find('[data-testid="exit-ip-query"]').exists()).toBe(false)
  })

  it('shows the entry but explains why nothing can be queried while disconnected', async () => {
    const { wrapper, backend } = await mountApp()
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

  it('marks the result after a node, mode or profile switch and clears it on refresh', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await connect(wrapper)
    await wrapper.find('[data-testid="exit-ip-query"]').trigger('click')
    await settle(600)

    void store.selectNode('节点选择', '日本 01')
    await settle(300)
    expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(true)
    await wrapper.find('[data-testid="exit-ip-refresh"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(false)

    void store.setMode('global')
    await settle(300)
    expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(true)
    await wrapper.find('[data-testid="exit-ip-refresh"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(false)

    void store.enable('p2')
    await settle(700)
    expect(wrapper.find('[data-testid="exit-ip-stale"]').exists()).toBe(true)

    // A failed refresh reports the reason and keeps the previous answer.
    exitSpy.mockRejectedValueOnce(new Error('出口 IP 查询超时'))
    await wrapper.find('[data-testid="exit-ip-refresh"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-testid="exit-ip-value"]').text()).toBe('203.0.113.42')
    expect(wrapper.find('[data-testid="exit-ip-error"]').text()).toContain('出口 IP 查询超时')
  })

  it('keeps automatic queries off by default and names the services used', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await connect(wrapper)
    // Off by default: connecting must not send a request.
    expect(exitSpy).not.toHaveBeenCalled()
    expect(store.app.value?.auto_exit_ip).toBe(false)

    store.openSettings('general')
    await flushPromises()
    const setting = wrapper.find('[data-testid="auto-exit-ip-setting"]')
    expect(setting.exists()).toBe(true)
    expect(setting.text()).toContain('ip.sb')
    expect(setting.text()).toContain('ipinfo.io')
    expect(setting.find('[data-testid="auto-exit-ip-toggle"]').attributes('aria-checked')).toBe('false')
  })

  it('queries automatically after reconnecting while on and stays quiet while off', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    const exitSpy = vi.spyOn(backend, 'exitIp')
    await store.setAutoExitIp(true)
    await flushPromises()
    expect(store.app.value?.auto_exit_ip).toBe(true)

    await connect(wrapper)
    await settle(600)
    expect(exitSpy).toHaveBeenCalledTimes(1)
    expect(store.exitIp.value?.ip).toBe('203.0.113.42')

    // A node switch queries again without a click.
    void store.selectNode('节点选择', '美国 01')
    await settle(800)
    expect(exitSpy.mock.calls.length).toBeGreaterThanOrEqual(2)

    // Turning it off stops every automatic request.
    await store.setAutoExitIp(false)
    await flushPromises()
    exitSpy.mockClear()
    void store.disconnect()
    await settle(400)
    await connect(wrapper)
    await settle(800)
    expect(exitSpy).not.toHaveBeenCalled()
  })
})
