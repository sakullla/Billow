import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'
import Menu, { type MenuItem } from './Menu.vue'

const items: MenuItem[] = [
  { id: 'edit', label: '编辑信息', icon: 'edit' },
  { id: 'copy', label: '复制链接', icon: 'copy' },
  { id: 'test', label: '测试', icon: 'zap', disabled: true, reason: '连接后可测速' },
  { id: 'delete', label: '删除', icon: 'trash', danger: true },
]

async function settle() {
  await flushPromises()
  await nextTick()
  await flushPromises()
}

function press(target: EventTarget, key: string, shiftKey = false) {
  target.dispatchEvent(new KeyboardEvent('keydown', { key, shiftKey, bubbles: true, cancelable: true }))
}

function mountMenu() {
  const trigger = document.createElement('button')
  trigger.textContent = '更多操作'
  document.body.appendChild(trigger)
  trigger.focus()
  const wrapper = mount(Menu, { attachTo: document.body, props: { items, label: '配置操作' } })
  return { wrapper, trigger }
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('Menu', () => {
  it('renders menuitem roles with a single roving tab stop', async () => {
    const { wrapper } = mountMenu()
    await settle()
    const menu = document.body.querySelector('[role="menu"]')
    expect(menu?.getAttribute('aria-label')).toBe('配置操作')
    const entries = Array.from(document.body.querySelectorAll<HTMLElement>('[role="menuitem"]'))
    expect(entries).toHaveLength(4)
    expect(entries.map((entry) => entry.getAttribute('tabindex'))).toEqual(['0', '-1', '-1', '-1'])
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('edit')
    wrapper.unmount()
  })

  it('moves with ArrowUp/Down and Home/End', async () => {
    const { wrapper } = mountMenu()
    await settle()
    press(document.activeElement ?? document, 'ArrowDown')
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('copy')
    press(document.activeElement ?? document, 'End')
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('delete')
    press(document.activeElement ?? document, 'ArrowDown')
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('edit')
    press(document.activeElement ?? document, 'ArrowUp')
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('delete')
    press(document.activeElement ?? document, 'Home')
    expect(document.activeElement?.getAttribute('data-menu-item')).toBe('edit')
    wrapper.unmount()
  })

  it('closes on Escape and returns focus to the trigger', async () => {
    const { wrapper, trigger } = mountMenu()
    await settle()
    press(document.activeElement ?? document, 'Escape')
    expect(wrapper.emitted('close')).toHaveLength(1)
    expect(document.activeElement).toBe(trigger)
    wrapper.unmount()
  })

  it('closes and returns focus to the trigger after selecting an item', async () => {
    const { wrapper, trigger } = mountMenu()
    await settle()
    document.body.querySelector<HTMLElement>('[data-menu-item="edit"]')?.click()
    expect(wrapper.emitted('select')?.[0]?.[0]).toMatchObject({ id: 'edit' })
    expect(wrapper.emitted('close')).toHaveLength(1)
    expect(document.activeElement).toBe(trigger)
    wrapper.unmount()
  })

  it('closes on an outside click but not on the trigger', async () => {
    const { wrapper, trigger } = mountMenu()
    await settle()
    trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    expect(wrapper.emitted('close')).toBeUndefined()
    document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    expect(wrapper.emitted('close')).toHaveLength(1)
    wrapper.unmount()
  })

  it('shows a visible reason and ignores disabled items', async () => {
    const { wrapper } = mountMenu()
    await settle()
    const disabled = document.body.querySelector<HTMLElement>('[data-menu-item="test"]')
    expect(disabled?.getAttribute('aria-disabled')).toBe('true')
    expect(disabled?.textContent).toContain('连接后可测速')
    const describedBy = disabled?.getAttribute('aria-describedby')
    expect(document.getElementById(describedBy ?? '')?.textContent).toBe('连接后可测速')
    disabled?.click()
    expect(wrapper.emitted('select')).toBeUndefined()
    wrapper.unmount()
  })

  it('opens upward when a clipping scroll container would cut it off below', async () => {
    const rect = (top: number, height: number) =>
      ({ top, bottom: top + height, height, left: 0, right: 200, width: 200, x: 0, y: top, toJSON() {} }) as DOMRect
    const scroller = document.createElement('div')
    scroller.style.overflowY = 'auto'
    scroller.getBoundingClientRect = () => rect(100, 400)
    const anchor = document.createElement('div')
    anchor.className = 'menu-anchor'
    const trigger = document.createElement('button')
    trigger.getBoundingClientRect = () => rect(470, 24)
    anchor.appendChild(trigger)
    scroller.appendChild(anchor)
    document.body.appendChild(scroller)
    trigger.focus()
    const original = HTMLElement.prototype.getBoundingClientRect
    HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
      return this.getAttribute('role') === 'menu' ? rect(498, 180) : original.call(this)
    }
    try {
      const wrapper = mount(Menu, { attachTo: anchor, props: { items, label: '行操作' } })
      await settle()
      // The viewport (768px) has room below, but the scroller ends at 500px.
      expect(document.body.querySelector('[role="menu"]')?.classList.contains('above')).toBe(true)
      wrapper.unmount()
    } finally {
      HTMLElement.prototype.getBoundingClientRect = original
    }
  })
})
