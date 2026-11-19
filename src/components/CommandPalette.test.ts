import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'
import { getShortcut, shortcutKeyLabel } from '../lib/ui/shortcuts'
import CommandPalette from './CommandPalette.vue'

async function settle() {
  await flushPromises()
  await nextTick()
  await flushPromises()
}

function press(target: EventTarget, key: string) {
  target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }))
}

function mountPalette(props: Record<string, unknown> = {}) {
  const trigger = document.createElement('button')
  trigger.textContent = '命令'
  document.body.appendChild(trigger)
  trigger.focus()
  const wrapper = mount(CommandPalette, { attachTo: document.body, props })
  return { wrapper, trigger }
}

function option(key: string) {
  return document.body.querySelector<HTMLElement>(`[data-command="${key}"]`)
}

function search(value: string) {
  const input = document.body.querySelector<HTMLInputElement>('.palette-search input')
  if (!input) throw new Error('palette input missing')
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  return input
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('CommandPalette', () => {
  it('is a labelled dialog that focuses the search field and lists pages, settings and actions', async () => {
    const { wrapper } = mountPalette()
    await settle()
    const dialog = document.body.querySelector<HTMLElement>('[role="dialog"]')
    const labelledBy = dialog?.getAttribute('aria-labelledby')
    expect(document.getElementById(labelledBy ?? '')?.textContent).toBe('命令面板')
    expect(document.activeElement).toBe(document.body.querySelector('.palette-search input'))
    expect(option('page:home')).not.toBeNull()
    expect(option('setting:dns')).not.toBeNull()
    expect(option('action:test-all')).not.toBeNull()
    expect(document.body.querySelector('.palette-kbd')?.textContent).toBe(
      shortcutKeyLabel(getShortcut('palette').combo),
    )
    expect(document.body.textContent).not.toContain('删除配置')
    expect(option('action:remove')).toBeNull()
    wrapper.unmount()
  })

  it('skips the TUN settings category on Android', async () => {
    const android = mountPalette({ platform: 'android' })
    await settle()
    expect(option('setting:tun')).toBeNull()
    expect(option('setting:dns')).not.toBeNull()
    android.wrapper.unmount()

    const desktop = mountPalette({ platform: 'desktop' })
    await settle()
    expect(option('setting:tun')).not.toBeNull()
    desktop.wrapper.unmount()
  })

  it('never lists irreversible actions, even when a caller supplies one', async () => {
    const { wrapper } = mountPalette({
      actions: [
        { id: 'refresh', label: '刷新订阅', icon: 'refresh' },
        { id: 'remove', label: '删除配置', icon: 'trash' },
        { id: 'clear-logs', label: '清空日志', icon: 'trash' },
      ],
    })
    await settle()
    expect(option('action:refresh')).not.toBeNull()
    expect(option('action:remove')).toBeNull()
    expect(option('action:clear-logs')).toBeNull()
    expect(document.body.textContent).not.toContain('删除配置')
    expect(document.body.textContent).not.toContain('清空日志')
    wrapper.unmount()
  })

  it('filters, moves with arrows and executes the active command with Enter', async () => {
    const { wrapper } = mountPalette()
    await settle()
    const input = search('代理')
    await nextTick()
    expect(option('page:proxies')).not.toBeNull()
    expect(option('page:home')).toBeNull()
    expect(input.getAttribute('aria-activedescendant')).toBe('page:proxies')

    search('')
    await nextTick()
    expect(input.getAttribute('aria-activedescendant')).toBe('page:home')
    press(input, 'ArrowDown')
    await nextTick()
    expect(input.getAttribute('aria-activedescendant')).toBe('page:proxies')
    press(input, 'ArrowUp')
    await nextTick()
    expect(input.getAttribute('aria-activedescendant')).toBe('page:home')

    search('代理')
    await nextTick()
    press(input, 'Enter')
    expect(wrapper.emitted('navigate')).toEqual([['proxies']])
    expect(wrapper.emitted('close')).toHaveLength(1)
  })

  it('shows why an action cannot run and does not execute it', async () => {
    const { wrapper } = mountPalette({ connected: false })
    await settle()
    const disabled = option('action:test-all')
    expect(disabled?.getAttribute('aria-disabled')).toBe('true')
    expect(disabled?.textContent).toContain('连接后可测速')
    const describedBy = disabled?.getAttribute('aria-describedby')
    expect(document.getElementById(describedBy ?? '')?.textContent).toContain('连接后可测速')
    disabled?.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    expect(wrapper.emitted('action')).toBeUndefined()
    wrapper.unmount()
  })

  it('offers DNS 查询 while disconnected so the dialog can explain itself', async () => {
    const { wrapper } = mountPalette({ connected: false })
    await settle()
    const input = search('DNS 查询')
    await settle()
    const action = option('action:dns-query')
    expect(action?.textContent).toContain('DNS 查询')
    expect(action?.getAttribute('aria-disabled')).not.toBe('true')
    press(input, 'Enter')
    expect(wrapper.emitted('action')).toEqual([['dns-query']])
    wrapper.unmount()
  })

  it('closes with Escape and returns focus to the previous element on unmount', async () => {
    const { wrapper, trigger } = mountPalette()
    await settle()
    press(document.activeElement ?? document, 'Escape')
    expect(wrapper.emitted('close')).toHaveLength(1)
    wrapper.unmount()
    expect(document.activeElement).toBe(trigger)
  })

  it('opens a settings category through its own event', async () => {
    const { wrapper } = mountPalette()
    await settle()
    search('Fake-IP')
    await nextTick()
    press(document.body.querySelector('.palette-search input') ?? document, 'Enter')
    expect(wrapper.emitted('open-settings')).toEqual([['dns']])
    wrapper.unmount()
  })

  it('marks the current page, clears search inline and lists desktop-aware quick actions', async () => {
    const { wrapper } = mountPalette({
      platform: 'desktop',
      currentPage: 'proxies',
      mode: 'rule',
    })
    await settle()
    expect(option('page:proxies')?.textContent).toContain('当前')
    expect(option('action:mode-rule')?.textContent).toContain('当前')
    expect(option('action:mode-global')?.textContent).toContain('Global')
    expect(option('action:copy-proxy-env')).not.toBeNull()
    expect(option('action:open-shortcuts')).not.toBeNull()

    const input = search('全局')
    await nextTick()
    const clearBtn = document.body.querySelector<HTMLButtonElement>('[data-testid="palette-clear"]')
    expect(clearBtn).not.toBeNull()
    clearBtn?.click()
    await nextTick()
    expect(input.value).toBe('')
    expect(document.activeElement).toBe(input)
    wrapper.unmount()

    const android = mountPalette({ platform: 'android' })
    await settle()
    expect(option('action:copy-proxy-env')).toBeNull()
    expect(option('action:open-shortcuts')).toBeNull()
    expect(option('action:toggle-system-proxy')).toBeNull()
    expect(option('action:toggle-tun')).toBeNull()
    android.wrapper.unmount()
  })

  it('searches profiles, proxy groups and manual nodes only when a query is entered', async () => {
    const { wrapper } = mountPalette({
      platform: 'desktop',
      connected: true,
      systemProxy: true,
      tun: false,
      profiles: [
        {
          id: 'p1',
          name: '星河云',
          kind: 'subscription',
          source: 'https://example.com',
          current: true,
          failure: null,
          override_text: '',
          override_error: null,
          used: null,
          total: null,
          expire: null,
          last_success_ms: null,
          interval_hours: 0,
          updated_ms: null,
          proxy_count: 10,
          age_recipients: [],
          user_agent: '',
        },
        {
          id: 'p2',
          name: '备用机场',
          kind: 'subscription',
          source: 'https://backup.example.com',
          current: false,
          failure: null,
          override_text: '',
          override_error: null,
          used: null,
          total: null,
          expire: null,
          last_success_ms: null,
          interval_hours: 0,
          updated_ms: null,
          proxy_count: 8,
          age_recipients: [],
          user_agent: '',
        },
      ],
      nodeCatalog: [
        {
          name: '节点选择',
          kind: 'manual',
          now: '香港 01',
          sort: 'default',
          group_type: 'select',
          icon: null,
          nodes: [
            { name: '香港 01', delay_ms: 42, failed: false, selected: true, node_type: 'vless', tags: ['UDP', 'Reality'] },
            { name: '日本 02', delay_ms: 68, failed: false, selected: false, node_type: 'trojan', tags: ['UDP'] },
          ],
        },
      ],
    })
    await settle()
    // Empty query stays concise: no profile or node spam.
    expect(option('profile:p2')).toBeNull()
    expect(option('node:节点选择:日本 02')).toBeNull()
    expect(option('action:toggle-system-proxy')?.textContent).toContain('关闭系统代理')
    expect(option('action:toggle-tun')?.textContent).toContain('开启 TUN 模式')

    const input = search('备用')
    await nextTick()
    expect(option('profile:p2')).not.toBeNull()
    press(input, 'Enter')
    expect(wrapper.emitted('select-profile')).toEqual([['p2']])

    search('日本 02')
    await nextTick()
    const nodeOpt = option('node:节点选择:日本 02')
    expect(nodeOpt).not.toBeNull()
    expect(nodeOpt?.textContent).toContain('68 ms')
    nodeOpt?.click()
    expect(wrapper.emitted('select-node')).toEqual([['节点选择', '日本 02']])
    wrapper.unmount()
  })

  it('skips hidden groups and offers url-test nodes for fixing, but not load-balance ones', async () => {
    const node = (name: string, selected = false) => ({ name, delay_ms: null, failed: false, selected, node_type: 'vless', tags: [] })
    const catalog = [
      { name: '隐藏组', kind: 'manual', now: '香港 01', sort: 'default', group_type: 'select', icon: null, hidden: true, nodes: [node('香港 01', true), node('隐藏节点')] },
      { name: '节点选择', kind: 'manual', now: '香港 01', sort: 'default', group_type: 'select', icon: null, nodes: [node('香港 01', true)] },
      { name: '自动选择', kind: 'auto', now: '日本 01', sort: 'default', group_type: 'url-test', icon: null, pinnable: true, fixed: '日本 01', nodes: [node('日本 01', true), node('日本 02')] },
      { name: '负载均衡', kind: 'auto', now: '日本 01', sort: 'default', group_type: 'load-balance', icon: null, pinnable: false, fixed: null, nodes: [node('日本 01', true), node('日本 02')] },
    ]
    // Kernel running without takeover: pinning still works, it only needs the controller.
    const { wrapper } = mountPalette({ connected: false, kernelRunning: true, nodeCatalog: catalog })
    await settle()
    search('隐藏')
    await nextTick()
    expect(option('group:隐藏组')).toBeNull()
    expect(option('node:隐藏组:隐藏节点')).toBeNull()

    search('自动选择')
    await nextTick()
    expect(option('group:自动选择')?.textContent).toContain('已固定')

    search('日本')
    await nextTick()
    expect(option('node:自动选择:日本 01')?.textContent).toContain('已固定')
    expect(option('node:负载均衡:日本 02')).toBeNull()
    option('node:自动选择:日本 02')?.click()
    expect(wrapper.emitted('select-node')).toEqual([['自动选择', '日本 02']])
    wrapper.unmount()

    const offline = mountPalette({ connected: false, kernelRunning: false, nodeCatalog: catalog })
    await settle()
    search('日本 02')
    await nextTick()
    const pin = option('node:自动选择:日本 02')
    expect(pin?.getAttribute('aria-disabled')).toBe('true')
    expect(pin?.textContent).toContain('内核没有运行')
    pin?.click()
    expect(offline.wrapper.emitted('select-node')).toBeUndefined()
    offline.wrapper.unmount()
  })
})
