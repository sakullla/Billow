import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  await settle(50)
  return { wrapper, backend }
}

afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
})

describe('App', () => {
  it('shows the sidebar with every page on desktop and a tab bar on narrow screens', async () => {
    const { wrapper } = await mountApp()
    const pages = wrapper.findAll('.sidebar [data-page]').map((item) => item.attributes('data-page'))
    expect(pages).toEqual(['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs', 'settings'])
    expect(wrapper.find('.tabbar').exists()).toBe(false)
    wrapper.unmount()

    const narrow = await mountApp({}, 390)
    expect(narrow.wrapper.find('.sidebar').exists()).toBe(false)
    expect(narrow.wrapper.findAll('.tabbar [data-page]')).toHaveLength(5)
  })

  it('connects from the power button and shows live rates', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')
    expect(wrapper.find('[data-testid="rates"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="toggle-proxy"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="toggle-tun"]').attributes('aria-checked')).toBe('false')
  })

  it('opens the add dialog straight from home when no profile exists', async () => {
    const { wrapper } = await mountApp({ profiles: false })
    expect(wrapper.find('[data-testid="status"]').text()).toBe('欢迎使用 Billow')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="add-url"]')).not.toBeNull()
  })

  it('switches outbound mode', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-mode="global"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-mode="global"]').attributes('aria-checked')).toBe('true')
  })

  it('selects a node in a manual group and filters by name', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-group-card="节点选择"] .group-head').trigger('click')
    await flushPromises()
    await wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"]').trigger('click')
    await settle(200)
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"]').classes()).toContain('selected')

    await wrapper.find('[data-testid="node-search"]').setValue('新加坡')
    const visible = wrapper.findAll('[data-group-card="节点选择"] [data-node]').map((node) => node.attributes('data-node'))
    expect(visible.length).toBeGreaterThan(0)
    expect(visible.every((name) => name?.includes('新加坡'))).toBe(true)
  })

  it('lists profiles with the active one first and switches on click', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
    const cards = wrapper.findAll('[data-profile]')
    expect(cards[0].attributes('data-profile')).toBe('p1')
    expect(cards[0].classes()).toContain('current')
    await cards[1].trigger('click')
    await settle(800)
    expect(wrapper.find('[data-profile="p2"]').classes()).toContain('current')
    expect(wrapper.findAll('[data-profile]')[0].attributes('data-profile')).toBe('p2')
  })

  it('shows connections after connecting and filters them', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="connections"]').trigger('click')
    await settle(1100)
    expect(wrapper.findAll('[data-testid="connection-row"]').length).toBeGreaterThan(0)
    await wrapper.find('[data-testid="connection-search"]').setValue('zzz-no-such-host')
    expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(0)
    expect(wrapper.text()).toContain('没有匹配的连接')
  })

  it('offers per-app exclusion on Android instead of system proxy and TUN', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    expect(wrapper.find('[data-testid="toggle-proxy"]').exists()).toBe(false)
    await wrapper.find('[data-testid="open-apps"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('微信')
    expect(document.body.textContent).toContain('com.tencent.mm')
  })
  it('opens TUN settings from home and saves a changed stack', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="tun-settings-link"]').trigger('click')
    await flushPromises()
    const tunCard = wrapper.find('[data-testid="tun-settings"]')
    expect(tunCard.exists()).toBe(true)
    expect(tunCard.find('[data-value="mixed"]').attributes('aria-checked')).toBe('true')
    await tunCard.find('[data-value="gvisor"]').trigger('click')
    await wrapper.find('[data-testid="save-tun"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="save-tun"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="tun-settings"] [data-value="gvisor"]').attributes('aria-checked')).toBe('true')
  })

  it('turns on DNS override and edits fake-ip settings', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="settings"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="settings-tabs"] [data-value="dns"]').trigger('click')
    await flushPromises()
    const toggle = wrapper.find('[data-testid="dns-override"]')
    expect(toggle.attributes('aria-checked')).toBe('false')
    await toggle.trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="dns-override"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.text()).toContain('Fake-IP 过滤')
    await wrapper.find('[data-testid="dns-settings"] [data-value="redir-host"]').trigger('click')
    expect(wrapper.text()).not.toContain('Fake-IP 过滤')
    await wrapper.find('[data-testid="save-dns"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="save-dns"]').exists()).toBe(false)
  })

  it('lists proxy and rule providers once connected', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="resources"]').trigger('click')
    await settle(500)
    expect(wrapper.find('[data-provider="机场订阅"]').exists()).toBe(true)
    expect(wrapper.find('[data-provider="cn-domains"]').text()).toContain('112,480 条规则')
    expect(wrapper.find('[data-testid="upgrade-geo"]').attributes('disabled')).toBeUndefined()
  })
})
