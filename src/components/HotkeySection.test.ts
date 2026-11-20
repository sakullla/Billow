import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, provide } from 'vue'
import App from '../App.vue'
import HotkeySection from './HotkeySection.vue'
import { createDemoBackend } from '../lib/demo'
import { createStore, STORE } from '../lib/store'
import type { Backend } from '../lib/backend'
import type { Store } from '../lib/store'
import type { HotkeySettings } from '../lib/types'

const cleanups: (() => void)[] = []
afterEach(() => {
  cleanups.splice(0).forEach((stop) => stop())
  document.body.innerHTML = ''
  vi.useRealTimers()
})

async function setup(backend: Backend = createDemoBackend()) {
  const store = createStore(backend)
  const Harness = defineComponent({
    setup() {
      provide(STORE, store)
      return () => h(HotkeySection)
    },
  })
  const wrapper = mount(Harness, { attachTo: document.body })
  await flushPromises()
  cleanups.push(() => {
    wrapper.unmount()
    store.stop()
  })
  return { store, backend }
}

function find<T extends HTMLElement = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector)
  if (!element) throw new Error(`missing ${selector}`)
  return element
}

async function click(testid: string) {
  find(`[data-testid="${testid}"]`).click()
  await flushPromises()
}

/** Press a combination while a row is recording; `window` owns the capture listener. */
async function press(init: KeyboardEventInit & { key?: string }) {
  window.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init }))
  await flushPromises()
}

const CTRL_ALT_P = { key: 'p', code: 'KeyP', ctrlKey: true, altKey: true }

describe('HotkeySection', () => {
  it('binds nothing until the user records a combination', async () => {
    await setup()
    for (const action of ['connect', 'proxy', 'tun', 'mode-rule', 'mode-global', 'mode-direct', 'window']) {
      expect(find(`[data-testid="hotkey-combo-${action}"]`).textContent).toBe('未绑定')
      expect(document.querySelector(`[data-testid="hotkey-clear-${action}"]`)).toBeNull()
    }
    expect(find('[data-testid="hotkey-hint"]').textContent).toContain('Ctrl、Alt 或 Shift')
  })

  it('records Ctrl+Alt+P for system proxy and shows it in the row', async () => {
    const { backend } = await setup()
    await click('hotkey-record-proxy')
    expect(find('[data-testid="hotkey-record-proxy"]').textContent).toContain('请按下组合键')

    await press(CTRL_ALT_P)
    expect(find('[data-testid="hotkey-combo-proxy"]').textContent).toBe('Ctrl + Alt + P')
    expect(document.querySelector('[data-testid="hotkey-clear-proxy"]')).not.toBeNull()
    expect(document.querySelector('[data-testid="hotkey-error"]')).toBeNull()

    const saved = await backend.hotkeySettings()
    expect(saved.bindings).toEqual([
      expect.objectContaining({ action: 'proxy', combo: 'Ctrl+Alt+P' }),
    ])
  })

  it('ignores a modifier on its own and waits for the main key', async () => {
    await setup()
    await click('hotkey-record-connect')
    await press({ key: 'Control', code: 'ControlLeft', ctrlKey: true })
    // Still waiting: the key cap keeps prompting and nothing is bound yet.
    expect(find('[data-testid="hotkey-record-connect"]').textContent).toContain('请按下组合键')
    expect(document.querySelector('[data-testid="hotkey-clear-connect"]')).toBeNull()

    // A printable key on its own would hijack ordinary typing.
    await press({ key: 'p', code: 'KeyP' })
    expect(find('[data-testid="hotkey-error"]').textContent).toContain('请先按住')
    expect(document.querySelector('[data-testid="hotkey-clear-connect"]')).toBeNull()
    // Esc leaves recording without binding anything.
    await press({ key: 'Escape', code: 'Escape' })
    expect(find('[data-testid="hotkey-combo-connect"]').textContent).toBe('未绑定')
  })

  it('refuses a combination another action already uses and keeps both rows unchanged', async () => {
    await setup()
    await click('hotkey-record-proxy')
    await press(CTRL_ALT_P)

    await click('hotkey-record-connect')
    await press(CTRL_ALT_P)

    const error = find('[data-testid="hotkey-error"]').textContent ?? ''
    expect(error).toContain('已绑定给')
    expect(error).toContain('系统代理')
    expect(find('[data-testid="hotkey-combo-connect"]').textContent).toBe('未绑定')
    expect(find('[data-testid="hotkey-combo-proxy"]').textContent).toBe('Ctrl + Alt + P')
  })

  it('refuses a combination the window itself answers', async () => {
    await setup()
    await click('hotkey-record-tun')
    await press({ key: 'k', code: 'KeyK', ctrlKey: true })

    const error = find('[data-testid="hotkey-error"]').textContent ?? ''
    expect(error).toContain('窗口内快捷键')
    expect(error).toContain('命令面板')
    expect(find('[data-testid="hotkey-combo-tun"]').textContent).toBe('未绑定')
  })

  it('keeps the old binding when the system refuses to register the new one', async () => {
    const demo = createDemoBackend()
    const backend: Backend = {
      ...demo,
      async setHotkey(action, combo) {
        if (combo.includes('F12')) throw new Error(`系统不允许注册 ${combo}，可能已被其他应用占用`)
        return demo.setHotkey(action, combo)
      },
    }
    await setup(backend)
    await click('hotkey-record-proxy')
    await press(CTRL_ALT_P)

    await click('hotkey-record-tun')
    await press({ key: 'F12', code: 'F12', ctrlKey: true, altKey: true })

    expect(find('[data-testid="hotkey-error"]').textContent).toContain('不允许注册')
    expect(find('[data-testid="hotkey-combo-tun"]').textContent).toBe('未绑定')
    expect(find('[data-testid="hotkey-combo-proxy"]').textContent).toBe('Ctrl + Alt + P')
  })

  it('disables the whole section with the platform reason where shortcuts are unsupported', async () => {
    const demo = createDemoBackend()
    const unavailable: HotkeySettings = {
      available: false,
      reason: '当前 Wayland 会话不支持全局快捷键，请改用 X11 会话',
      platform: 'linux',
      bindings: [],
    }
    await setup({
      ...demo,
      hotkeySettings: async () => unavailable,
      setHotkey: async () => unavailable,
    })

    expect(find('[data-testid="hotkey-unavailable"]').textContent).toContain('Wayland')
    expect((find('[data-testid="hotkey-record-connect"]') as HTMLButtonElement).disabled).toBe(true)
    await click('hotkey-record-connect')
    // Clicking a disabled key cap never starts recording.
    expect(find('[data-testid="hotkey-record-connect"]').textContent).not.toContain('请按下组合键')
    expect(find('[data-testid="hotkey-combo-connect"]').textContent).toBe('未绑定')
  })

  it('shows a stored binding that the system refused at startup as inactive', async () => {
    const demo = createDemoBackend()
    await setup({
      ...demo,
      hotkeySettings: async () => ({
        available: true,
        reason: null,
        platform: 'windows',
        bindings: [
          { action: 'window', combo: 'Alt+Shift+D', active: false, error: '启动时未能注册，可能已被其他应用占用' },
        ],
      }),
    })
    expect(find('[data-testid="hotkey-combo-window"]').textContent).toBe('Alt + Shift + D')
    expect(find('[data-testid="hotkey-inactive-window"]').textContent).toContain('未生效')
  })

  it('clears a binding and stops listening once the component is gone', async () => {
    const { backend } = await setup()
    await click('hotkey-record-proxy')
    await press(CTRL_ALT_P)
    await click('hotkey-clear-proxy')

    expect(find('[data-testid="hotkey-combo-proxy"]').textContent).toBe('未绑定')
    expect((await backend.hotkeySettings()).bindings).toEqual([])

    await click('hotkey-record-proxy')
    const remove = vi.spyOn(window, 'removeEventListener')
    cleanups.splice(0).forEach((stop) => stop())
    expect(remove).toHaveBeenCalledWith('keydown', expect.any(Function), true)
  })
})

/** The whole app has to be mounted to check where the settings page puts the section. */
async function mountAppShell(platform: 'desktop' | 'android', width: number) {
  vi.useFakeTimers()
  const backend = createDemoBackend({ platform })
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  await vi.advanceTimersByTimeAsync(50)
  await flushPromises()
  cleanups.push(() => wrapper.unmount())
  const store = (wrapper.vm as unknown as { store: Store }).store
  store.go('settings')
  await flushPromises()
  return wrapper
}

describe('hotkey settings placement (R39)', () => {
  it('keeps the bindings in the secondary shortcut sheet, not on the settings page', async () => {
    const wrapper = await mountAppShell('desktop', 1200)
    expect(document.querySelector('[data-testid="hotkey-settings"]')).toBeNull()
    await wrapper.find('[data-testid="settings-shortcuts"]').trigger('click')
    await flushPromises()
    const section = document.querySelector('[data-testid="hotkey-settings"]') as HTMLElement | null
    expect(section).not.toBeNull()
    expect(section!.textContent).toContain('全局快捷键')
    expect(document.querySelector('[data-testid="hotkey-combo-proxy"]')!.textContent).toBe('未绑定')
    expect(document.querySelectorAll('[data-testid^="hotkey-row-"]')).toHaveLength(7)
  })

  it('hides the secondary hotkey section on Android', async () => {
    await mountAppShell('android', 390)
    expect(document.querySelector('[data-testid="hotkey-settings"]')).toBeNull()
    expect(document.body.textContent).not.toContain('全局快捷键')
  })
})
