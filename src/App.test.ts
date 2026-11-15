import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'

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

function press(target: EventTarget, key: string, init: KeyboardEventInit = {}) {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init })
  target.dispatchEvent(event)
  return event
}

async function openPalette() {
  press(document, 'k', { ctrlKey: true })
  await flushPromises()
  await nextTick()
  await flushPromises()
}

function paletteOption(key: string) {
  return document.body.querySelector<HTMLElement>(`[data-command="${key}"]`)
}

function paletteInput() {
  return document.body.querySelector<HTMLInputElement>('.palette-search input')
}

async function searchPalette(value: string) {
  const input = paletteInput()
  if (!input) throw new Error('palette input missing')
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
  await flushPromises()
  return input
}

afterEach(() => {
  while (mounted.length) {
    try {
      mounted.pop()?.unmount()
    } catch {
      /* already unmounted */
    }
  }
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

  it('groups the desktop sidebar into core and tools with settings pinned last', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.findAll('.sidebar .nav-group-label').map((label) => label.text())).toEqual(['核心', '工具'])
    expect(wrapper.findAll('.nav-group').map((group) => group.findAll('[data-page]').length)).toEqual([4, 3])
    expect(wrapper.find('.side-foot [data-page="settings"]').exists()).toBe(true)
    expect(wrapper.find('.nav [data-page="settings"]').exists()).toBe(false)
    const order = wrapper.findAll('.sidebar [data-page]').map((item) => item.attributes('data-page'))
    expect(order).toEqual(['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs', 'settings'])
    expect(order[order.length - 1]).toBe('settings')
  })

  it('marks the mobile settings tab current while a tools page is open', async () => {
    const { wrapper } = await mountApp({}, 390)
    const settingsTab = () => wrapper.find('.tabbar [data-page="settings"]')
    expect(settingsTab().attributes('aria-current')).toBeUndefined()
    await settingsTab().trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    await wrapper.findAll('.shortcut-card .setting-row')[1].trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('rules')
    expect(settingsTab().attributes('aria-current')).toBe('page')
    expect(wrapper.find('.main .page').exists()).toBe(true)
  })

  it('opens the command palette with Ctrl+K, filters and executes a page', async () => {
    const { wrapper } = await mountApp()
    await openPalette()
    expect(paletteInput()).not.toBeNull()
    expect(paletteOption('action:test-all')?.textContent).toContain('连接后可测速')
    expect(document.body.textContent).not.toContain('删除配置')

    const input = await searchPalette('代理')
    expect(paletteOption('page:proxies')).not.toBeNull()
    expect(paletteOption('page:home')).toBeNull()
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(document.body.querySelector('.palette')).toBeNull()
  })

  it('lists page, settings and non-destructive actions and hides TUN on Android', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 1200)
    await openPalette()
    expect(paletteOption('page:logs')).not.toBeNull()
    expect(paletteOption('setting:dns')).not.toBeNull()
    expect(paletteOption('setting:tun')).toBeNull()
    for (const id of ['connect', 'disconnect', 'test-all', 'refresh-profiles', 'add-profile', 'toggle-theme', 'open-logs']) {
      expect(paletteOption(`action:${id}`)).not.toBeNull()
    }
    expect(paletteOption('action:remove')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('executes palette actions and opens a settings category', async () => {
    const { wrapper } = await mountApp()
    await openPalette()
    let input = await searchPalette('打开日志')
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('logs')

    await openPalette()
    input = await searchPalette('Fake-IP')
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    expect(wrapper.find('[data-testid="dns-settings"]').exists()).toBe(true)
  })

  it('closes the palette with Escape and returns focus to the opener', async () => {
    const { wrapper } = await mountApp()
    const trigger = wrapper.find('.sidebar [data-page="home"]').element as HTMLElement
    trigger.focus()
    await openPalette()
    expect(document.activeElement).toBe(paletteInput())
    press(document.activeElement ?? document, 'Escape')
    await flushPromises()
    await nextTick()
    await flushPromises()
    expect(document.body.querySelector('.palette')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('focuses the page search with / but leaves the key alone inside inputs', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    const search = wrapper.find('[data-page-search]').element as HTMLInputElement
    search.focus()
    const inside = press(search, '/')
    expect(inside.defaultPrevented).toBe(false)
    expect(document.activeElement).toBe(search)

    search.blur()
    press(document.body, '/')
    expect(document.activeElement).toBe(search)
  })

  it('opens the shortcut sheet with ? outside inputs and clears search with Escape', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    const search = wrapper.find('[data-page-search]').element as HTMLInputElement
    search.focus()
    press(search, '?')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).toBeNull()

    search.value = 'error'
    search.dispatchEvent(new Event('input', { bubbles: true }))
    await nextTick()
    press(search, 'Escape')
    await flushPromises()
    expect(search.value).toBe('')

    search.blur()
    press(document.body, '?')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).not.toBeNull()
    press(document.activeElement ?? document, 'Escape')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).toBeNull()
  })

  it('restores per-page scroll but lets a proxy group target win', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const main = wrapper.find('.main').element as HTMLElement
    main.scrollTop = 260
    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()
    expect(main.scrollTop).toBe(0)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(main.scrollTop).toBe(260)

    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="groups-card"] [data-group="节点选择"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(main.scrollTop).toBe(0)

    window.dispatchEvent(new Event('resize'))
    expect(main.scrollTop).toBe(0)
    expect(wrapper.find('.sidebar').exists()).toBe(true)
  })

  it('closes an open menu on back before leaving the page', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
    await wrapper.find('[aria-label="更多操作"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(true)

    window.dispatchEvent(new PopStateEvent('popstate', { state: { billow: 'overlay' } }))
    await flushPromises()
    await nextTick()
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(wrapper.find('.main').attributes('data-page')).toBe('profiles')
  })

  it('closes the topmost layer before navigating back on popstate', async () => {
    const { wrapper } = await mountApp()
    await openPalette()
    expect(document.body.querySelector('.palette')).not.toBeNull()

    window.dispatchEvent(new PopStateEvent('popstate', { state: { billow: 'overlay' } }))
    await flushPromises()
    await nextTick()
    await flushPromises()
    expect(document.body.querySelector('.palette')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')

    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    window.dispatchEvent(new PopStateEvent('popstate', { state: { billow: 'page', page: 'home' } }))
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')

    window.dispatchEvent(new PopStateEvent('popstate', { state: null }))
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })
})
