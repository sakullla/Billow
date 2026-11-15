import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import App from './App.vue'
import GroupIcon from './components/GroupIcon.vue'
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
  localStorage.clear()
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
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).toContain('open')
    await wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .node-select').trigger('click')
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
    const main = wrapper.findAll('.home-main > *').map((element) => element.attributes('data-testid'))
    const side = wrapper.findAll('.home-side > *').map((element) => element.attributes('data-testid'))
    expect(main).toEqual(['home-status', 'home-action', 'takeover-card', 'mode-card'])
    expect(side).toEqual(['traffic-card', 'groups-card', 'profile-card'])
    expect(wrapper.find('[data-testid="home-status"]').text()).toContain('星河云')
    expect(wrapper.find('[data-testid="groups-card"]').text()).toContain('查看全部')
  })

  it('offers a retry when disconnecting fails', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')

    const original = backend.disconnect
    let calls = 0
    backend.disconnect = vi.fn(async () => {
      calls += 1
      if (calls === 1) throw new Error('系统代理没有关闭')
      return original()
    })

    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('系统代理没有关闭')
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(1500)
    expect(backend.disconnect).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')
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

  it('opens the current manual group on the first proxy visit and restores the saved set', async () => {
    localStorage.clear()
    const card = (wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper'], name: string) =>
      wrapper.find(`[data-group-card="${name}"]`).classes()

    const first = await mountApp()
    await first.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(first.wrapper, '节点选择')).toContain('open')
    expect(card(first.wrapper, '流媒体')).not.toContain('open')

    await first.wrapper.find('[data-group-card="节点选择"] .group-toggle').trigger('click')
    await first.wrapper.find('[data-group-card="流媒体"] .group-toggle').trigger('click')
    await flushPromises()
    expect(card(first.wrapper, '节点选择')).not.toContain('open')
    expect(card(first.wrapper, '流媒体')).toContain('open')
    first.wrapper.unmount()

    const second = await mountApp()
    await second.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(second.wrapper, '流媒体')).toContain('open')
    expect(card(second.wrapper, '节点选择')).not.toContain('open')
    second.wrapper.unmount()

    localStorage.setItem('billow:proxy-open', '{ this is not json')
    const third = await mountApp()
    await third.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(third.wrapper, '节点选择')).toContain('open')
    third.wrapper.unmount()

    localStorage.setItem('billow:proxy-open', JSON.stringify(['已删除的组']))
    const fourth = await mountApp()
    await fourth.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(fourth.wrapper, '节点选择')).toContain('open')
  })

  it('locates the group requested from home and drops a filter that hides it', async () => {
    const { wrapper } = await mountApp()
    const proto = Element.prototype as unknown as { scrollIntoView?: (options?: ScrollIntoViewOptions) => void }
    const original = proto.scrollIntoView
    const scrolled: string[] = []
    proto.scrollIntoView = function (this: Element) {
      scrolled.push(this.getAttribute('data-group-card') ?? '')
    }
    try {
      await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
      await flushPromises()
      await wrapper.find('[data-testid="toggle-hide-auto"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-group-card="自动选择"]').exists()).toBe(false)

      const store = (wrapper.vm as unknown as { store: { go: (page: string, group?: string) => void } }).store
      store.go('home')
      await flushPromises()
      store.go('proxies', '自动选择')
      await flushPromises()

      expect(wrapper.find('[data-group-card="自动选择"]').classes()).toContain('open')
      expect(wrapper.find('[data-testid="toggle-hide-auto"]').attributes('aria-pressed')).toBe('false')
      expect(scrolled).toContain('自动选择')
    } finally {
      proto.scrollIntoView = original
    }
  })

  it('highlights search matches and reports how many nodes match', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="node-search"]').setValue('新加坡')
    await flushPromises()

    expect(wrapper.find('[data-testid="match-count"]').text()).toBe('匹配 10 个节点')
    const marks = wrapper.findAll('[data-group-card] mark')
    expect(marks).toHaveLength(10)
    expect(marks.every((mark) => mark.text() === '新加坡')).toBe(true)

    await wrapper.find('[data-testid="clear-search"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="match-count"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-group-card] mark')).toHaveLength(0)
    expect(wrapper.findAll('[data-group-card="节点选择"] [data-node]')).toHaveLength(22)
  })

  it('selects a manual node with Space while auto-group rows stay inert', async () => {
    const { wrapper, backend } = await mountApp()
    const select = vi.spyOn(backend, 'selectNode')
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()

    const manual = wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .node-select')
    expect(manual.element.tagName).toBe('BUTTON')
    press(manual.element, ' ')
    await settle(200)
    expect(select).toHaveBeenCalledWith('节点选择', '日本 02')
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"]').classes()).toContain('selected')

    await wrapper.find('[data-group-card="自动选择"] .group-toggle').trigger('click')
    await flushPromises()
    const auto = wrapper.find('[data-group-card="自动选择"] [data-node="香港 01"] .node-select')
    expect(auto.attributes('aria-disabled')).toBe('true')
    expect(auto.attributes('tabindex')).toBe('-1')
    await auto.trigger('click')
    await settle(100)
    expect(select).toHaveBeenCalledTimes(1)
  })

  it('shows test-all progress and marks only failed nodes as timed out', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="test-hint"]').exists()).toBe(false)
    expect(wrapper.find('[data-group-card="节点选择"] .group-tested').exists()).toBe(false)

    await wrapper.find('[data-testid="test-all"]').trigger('click')
    await settle(400)
    const progress = wrapper.find('[data-testid="test-progress"]')
    expect(progress.exists()).toBe(true)
    expect(progress.text()).toMatch(/^已测 \d+\/23$/)
    expect(progress.text()).not.toBe('已测 23/23')

    await settle(1600)
    expect(wrapper.find('[data-testid="test-progress"]').text()).toBe('已测 23/23')
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="新加坡 01"] .delay').text()).toBe('超时')
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="香港 01"] .delay').text()).toMatch(/^\d+ ms$/)
    expect(wrapper.find('[data-group-card="节点选择"] .group-tested').text()).toContain('测速')
  })

  it('tests one group without toggling it and stamps the header result time', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const groupTest = vi.spyOn(backend, 'testGroup')

    await wrapper.find('[data-testid="test-group-节点选择"]').trigger('click')
    await settle(900)
    expect(groupTest).toHaveBeenCalledWith('节点选择')
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).toContain('open')
    const tested = wrapper.find('[data-group-card="节点选择"] .group-tested')
    expect(tested.exists()).toBe(true)
    expect(tested.text()).toContain('测速')
  })

  it('renders configured group icons and falls back to the type glyph', async () => {
    const { wrapper } = await mountApp()
    const homeIcon = wrapper.find('[data-testid="groups-card"] [data-group="流媒体"] .group-icon img')
    expect(homeIcon.exists()).toBe(true)
    expect(homeIcon.attributes('src')).toBe('https://icons.example.com/media.png')
    expect(homeIcon.attributes('alt')).toBe('')
    expect(homeIcon.attributes('aria-hidden')).toBe('true')
    expect(homeIcon.attributes('tabindex')).toBeUndefined()
    expect(wrapper.find('[data-testid="groups-card"] [data-group="流媒体"] .group-icon').attributes('style')).toContain('width: 20px')

    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const media = wrapper.find('[data-group-card="流媒体"] .group-toggle img')
    expect(media.exists()).toBe(true)
    expect(media.attributes('src')).toBe('https://icons.example.com/media.png')
    expect(media.attributes('loading')).toBe('lazy')
    expect(media.attributes('decoding')).toBe('async')
    expect(wrapper.find('[data-group-card="流媒体"] .group-toggle .group-icon').attributes('style')).toContain('width: 24px')

    const unreachable = wrapper.find('[data-group-card="国内网站"] .group-toggle img')
    expect(unreachable.attributes('src')).toBe('https://unreachable.invalid/cn.png')
    await unreachable.trigger('error')
    await nextTick()
    const fallback = wrapper.find('[data-group-card="国内网站"] .group-toggle .group-icon svg path')
    expect(fallback.exists()).toBe(true)
    expect(fallback.attributes('d')).toContain('M6 19a2 2')
  })

  it('swaps a group icon with the config URL and picks a fallback glyph per group type', async () => {
    const view = mount(GroupIcon, { props: { icon: 'https://a.example.com/a.png', type: 'relay', size: 24 } })
    expect(view.find('img').attributes('src')).toBe('https://a.example.com/a.png')
    await view.find('img').trigger('error')
    expect(view.find('svg path').attributes('d')).toContain('m12 3 9 5')
    await view.setProps({ icon: 'data:image/png;base64,AAAA' })
    expect(view.find('img').attributes('src')).toBe('data:image/png;base64,AAAA')
    view.unmount()

    for (const [type, shape] of [
      ['select', 'M6 19a2 2'],
      ['selector', 'M6 19a2 2'],
      ['url-test', 'M9 3h6v5'],
      ['urltest', 'M9 3h6v5'],
      ['fallback', 'M9 3h6v5'],
      ['load-balance', 'M9 3h6v5'],
      ['relay', 'm12 3 9 5'],
      ['unknown', 'M12 21a9 9'],
    ] as const) {
      const icon = mount(GroupIcon, { props: { type, size: 20 } })
      expect(icon.attributes('style')).toContain('width: 20px')
      expect(icon.find('svg path').attributes('d')).toContain(shape)
      icon.unmount()
    }
  })

  it('keeps every proxy toolbar control reachable on a 390px screen', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('.tabbar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const toolbar = wrapper.find('[data-testid="proxy-toolbar"]')
    expect(toolbar.exists()).toBe(true)
    expect(toolbar.find('[data-testid="node-search"]').exists()).toBe(true)
    expect(toolbar.findAll('.segment')).toHaveLength(3)
    for (const id of ['toggle-hide-auto', 'toggle-dense', 'toggle-all']) {
      const button = toolbar.find(`[data-testid="${id}"]`)
      expect(button.exists()).toBe(true)
      expect(button.attributes('aria-label') ?? button.text()).toBeTruthy()
    }

    const head = wrapper.find('[data-group-card="节点选择"] .group-head')
    const buttons = head.findAll('button')
    expect(buttons).toHaveLength(2)
    for (const button of buttons) expect(button.findAll('button')).toHaveLength(0)
    expect(head.find('.group-toggle .group-icon').exists()).toBe(true)
    expect(head.find('.group-toggle .group-name strong').exists()).toBe(true)
  })
})
