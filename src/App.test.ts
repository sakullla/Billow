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

/** Drive the real WebView history the way a back button does. */
async function goBack() {
  window.history.back()
  await settle(20)
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
  })

  it('top-scrolls when the requested proxy group cannot be found', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const main = wrapper.find('.main').element as HTMLElement
    main.scrollTop = 240
    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()

    const store = (wrapper.vm as unknown as { store: { go: (page: string, group?: string) => void } }).store
    store.go('proxies', '不存在的组')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(main.scrollTop).toBe(0)
  })

  it('resets scroll on width changes but keeps it on height-only resizes', async () => {
    const original = window.innerWidth
    try {
      vi.useFakeTimers()
      const backend = createDemoBackend()
      const wrapper = mount(App, { props: { backend }, attachTo: document.body })
      mounted.push(wrapper)
      await settle(50)
      await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
      await flushPromises()
      const main = wrapper.find('.main').element as HTMLElement
      main.scrollTop = 180
      window.dispatchEvent(new Event('resize'))
      expect(main.scrollTop).toBe(180)

      window.innerWidth = original - 400
      window.dispatchEvent(new Event('resize'))
      expect(main.scrollTop).toBe(0)
    } finally {
      window.innerWidth = original
    }
  })

  it('closes an open menu on back, then returns to the previous page on the next back', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
    const more = wrapper.find('[aria-label="更多操作"]')
    await more.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(true)
    press(document, 'k', { ctrlKey: true })
    await flushPromises()
    expect(document.body.querySelector('.palette')).toBeNull()

    const moreEl = more.element as HTMLElement
    moreEl.focus()
    press(moreEl, 'Escape')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(document.activeElement).toBe(moreEl)

    await more.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(true)
    await goBack()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(wrapper.find('.main').attributes('data-page')).toBe('profiles')

    await goBack()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('closes a dialog on back and keeps the page history for the next back', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    await openPalette()
    expect(document.body.querySelector('.palette')).not.toBeNull()

    await goBack()
    expect(document.body.querySelector('.palette')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('logs')

    await goBack()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('keeps one control for connect, disconnect and add-config', async () => {
    const { wrapper } = await mountApp()
    const power = wrapper.find('[data-testid="power"]')
    expect(power.element.tagName).toBe('BUTTON')
    expect(power.find('.connect-glyph .icon').exists()).toBe(true)
    expect(power.text()).toBe('连接')
    // The glyph and the label live in the same button; no second connect entry exists.
    const duplicate = wrapper
      .findAll('.home button')
      .filter((button) => button.element !== power.element && ['连接', '断开'].includes(button.text().trim()))
    expect(duplicate).toHaveLength(0)

    await power.trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="power"]').text()).toBe('断开')
    expect(wrapper.find('[data-testid="rates"]').exists()).toBe(true)

    wrapper.unmount()
    const welcome = await mountApp({ profiles: false }, 390)
    expect(welcome.wrapper.find('[data-testid="power"]').text()).toBe('添加配置')
  })

  it('keeps the Android VPN switch as takeover state, not a second connect entry', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    const vpn = wrapper.find('[data-testid="toggle-vpn"]')
    expect(vpn.attributes('role')).toBe('switch')
    expect(vpn.attributes('aria-checked')).toBe('false')
    expect(vpn.attributes('disabled')).not.toBeUndefined()
    expect(wrapper.find('[data-testid="takeover-card"]').text()).toContain('开启 VPN 需连接')
    expect(wrapper.findAll('[data-testid="power"]')).toHaveLength(1)
  })

  it('shows the mode row with one live sentence on phones and keeps desktop cards', async () => {
    const { wrapper } = await mountApp({}, 390)
    const segments = wrapper.findAll('[data-testid="mode-segmented"] .segment')
    expect(segments.map((segment) => segment.text())).toEqual(['规则', '全局', '直连'])
    expect(wrapper.find('[data-testid="mode-card"] .mode-cards').exists()).toBe(false)
    const hint = wrapper.find('[data-testid="mode-hint"]')
    expect(hint.attributes('aria-live')).toBe('polite')
    expect(hint.text()).toBe('按配置中的规则分流')

    await wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-testid="mode-hint"]').text()).toBe('新连接都不经过代理')
    expect(wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').attributes('aria-checked')).toBe('true')

    wrapper.unmount()
    const desktop = await mountApp({}, 1200)
    expect(desktop.wrapper.findAll('[data-mode]')).toHaveLength(3)
    expect(desktop.wrapper.find('[data-testid="mode-card"]').text()).toContain('全部流量走当前节点')
    expect(desktop.wrapper.find('[data-testid="mode-hint"]').exists()).toBe(false)
  })

  it('shows only the welcome, add-config and import hint without a profile', async () => {
    const { wrapper } = await mountApp({ profiles: false }, 390)
    expect(wrapper.find('[data-testid="welcome"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('欢迎使用 Billow')
    expect(wrapper.find('[data-testid="power"]').text()).toBe('添加配置')
    expect(wrapper.find('[data-testid="import-hint"]').text()).toContain('YAML')
    for (const id of ['mode-card', 'takeover-card', 'traffic-card', 'groups-card', 'profile-card', 'runtime']) {
      expect(wrapper.find(`[data-testid="${id}"]`).exists()).toBe(false)
    }
  })

  it('shows the connect failure with retry and clears it after the retry succeeds', async () => {
    const { wrapper, backend } = await mountApp()
    const original = backend.connect
    let calls = 0
    backend.connect = vi.fn(async () => {
      calls += 1
      if (calls === 1) throw new Error('内核没有启动')
      return original()
    })

    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    const banner = wrapper.find('[data-testid="home-failure"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain('内核没有启动')
    expect(banner.text()).toContain('重试')
    expect(banner.text()).toContain('查看日志')
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(1500)
    expect(backend.connect).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')
  })

  it('retries the failed mode switch with the same mode', async () => {
    const { wrapper, backend } = await mountApp()
    const original = backend.setMode
    let calls = 0
    backend.setMode = vi.fn(async (mode: Parameters<typeof original>[0]) => {
      calls += 1
      if (calls === 1) throw new Error('模式没有切换')
      return original(mode)
    })

    await wrapper.find('[data-mode="direct"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('模式没有切换')
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('重试')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(300)
    expect(backend.setMode).toHaveBeenCalledTimes(2)
    expect(backend.setMode).toHaveBeenLastCalledWith('direct')
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-mode="direct"]').attributes('aria-checked')).toBe('true')
  })

  it('hides runtime rows the kernel does not report and never shows a dash', async () => {
    const demo = createDemoBackend()
    const readState = demo.state
    demo.state = async () => ({ ...(await readState.call(demo)), kernel_memory: null, kernel_uptime_secs: null })
    vi.useFakeTimers()
    const wrapper = mount(App, { props: { backend: demo, width: 1200 }, attachTo: document.body })
    mounted.push(wrapper)
    await settle(50)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    expect(wrapper.find('[data-testid="runtime-kernel"]').text()).toContain('v1.19.17')
    expect(wrapper.find('[data-testid="runtime-connections"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="runtime-memory"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="runtime-uptime"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="runtime"]').text()).not.toContain('—')
    wrapper.unmount()

    const full = await mountApp()
    await full.wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(full.wrapper.find('[data-testid="runtime-memory"]').text()).toContain('128 MB')
    expect(full.wrapper.find('[data-testid="runtime-uptime"]').text()).toBeTruthy()
  })

  it('orders the phone first screen before the mode switch', async () => {
    const { wrapper } = await mountApp({}, 390)
    const order = wrapper.findAll('.home-grid > *').map((element) => element.attributes('data-testid'))
    expect(order.slice(0, 4)).toEqual(['home-status', 'home-action', 'takeover-card', 'mode-card'])
    expect(wrapper.find('[data-testid="home-status"]').text()).toContain('星河云')
    expect(order.slice(-3)).toEqual(['traffic-card', 'groups-card', 'profile-card'])
  })

  it('replaces the spinning refresh glyph with update progress text', async () => {
    const { wrapper } = await mountApp()
    const button = () => wrapper.find('[data-testid="update-subscription"]')
    expect(button().text()).toBe('更新')
    await button().trigger('click')
    await settle(100)
    expect(button().text()).toContain('更新中')
    expect(button().attributes('aria-busy')).toBe('true')
    expect(button().find('.spin').exists()).toBe(false)
    await settle(1200)
    expect(button().text()).toBe('更新')
    expect(button().attributes('aria-busy')).toBeUndefined()
  })
})
