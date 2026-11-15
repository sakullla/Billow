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
    android.wrapper.unmount()
  })
})
