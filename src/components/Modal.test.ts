import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'
import Modal from './Modal.vue'

async function settle() {
  await flushPromises()
  await nextTick()
  await flushPromises()
}

function press(target: EventTarget, key: string, shiftKey = false) {
  target.dispatchEvent(new KeyboardEvent('keydown', { key, shiftKey, bubbles: true, cancelable: true }))
}

afterEach(() => {
  document.body.innerHTML = ''
})

function mountModal() {
  const main = document.createElement('div')
  main.className = 'main'
  document.body.appendChild(main)
  const trigger = document.createElement('button')
  trigger.textContent = '打开'
  document.body.appendChild(trigger)
  trigger.focus()
  const wrapper = mount(Modal, {
    attachTo: document.body,
    props: { title: '测试弹层', subtitle: '说明文字' },
    slots: {
      default: '<button id="first" autofocus>第一个</button><button id="last">最后一个</button>',
      footer: '<button id="foot">确定</button>',
    },
  })
  return { wrapper, trigger, main }
}

describe('Modal', () => {
  it('moves focus in, labels the dialog from the title and makes the background inert', async () => {
    const { wrapper, main } = mountModal()
    await settle()
    const dialog = document.body.querySelector<HTMLElement>('[role="dialog"]')
    expect(dialog).not.toBeNull()
    const labelledBy = dialog?.getAttribute('aria-labelledby')
    expect(labelledBy).toBeTruthy()
    expect(document.getElementById(labelledBy ?? '')?.textContent).toBe('测试弹层')
    expect(dialog?.getAttribute('aria-modal')).toBe('true')
    expect(document.activeElement?.id).toBe('first')
    expect(main.hasAttribute('inert')).toBe(true)
    expect(main.style.overflow).toBe('hidden')
    const outside = document.createElement('button')
    outside.id = 'outside'
    main.appendChild(outside)
    outside.focus()
    expect(document.activeElement?.id).toBe('first')
    wrapper.unmount()
    expect(main.hasAttribute('inert')).toBe(false)
    expect(main.style.overflow).toBe('')
  })

  it('loops Tab inside the dialog and restores focus to the trigger on close', async () => {
    const { wrapper, trigger } = mountModal()
    await settle()
    const foot = document.getElementById('foot')
    foot?.focus()
    press(foot ?? document, 'Tab')
    expect(document.activeElement?.getAttribute('aria-label')).toBe('关闭')

    const close = document.querySelector<HTMLElement>('.modal-head .icon-btn')
    close?.focus()
    press(close ?? document, 'Tab', true)
    expect(document.activeElement?.id).toBe('foot')

    press(document.activeElement ?? document, 'Escape')
    expect(wrapper.emitted('close')).toHaveLength(1)
    wrapper.unmount()
    expect(document.activeElement).toBe(trigger)
  })

  it('only closes the topmost dialog on Escape', async () => {
    const first = mount(Modal, { attachTo: document.body, props: { title: '第一层' } })
    const second = mount(Modal, { attachTo: document.body, props: { title: '第二层' } })
    await settle()
    press(document.activeElement ?? document, 'Escape')
    expect(second.emitted('close')).toHaveLength(1)
    expect(first.emitted('close')).toBeUndefined()
    second.unmount()
    first.unmount()
  })

  it('keeps the dialog open when beforeClose declines', async () => {
    const wrapper = mount(Modal, {
      attachTo: document.body,
      props: { title: '编辑', beforeClose: () => false },
    })
    await settle()
    press(document.activeElement ?? document, 'Escape')
    await settle()
    expect(wrapper.emitted('close')).toBeUndefined()
    wrapper.unmount()
  })
})
