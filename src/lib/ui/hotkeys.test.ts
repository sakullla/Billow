import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h, nextTick } from 'vue'
import { afterEach, describe, expect, it } from 'vitest'
import Modal from '../../components/Modal.vue'
import { matchesCombo, parseCombo, useHotkeys } from './hotkeys'

afterEach(() => {
  document.body.innerHTML = ''
})

function host(bindings: Parameters<typeof useHotkeys>[0]) {
  return defineComponent({
    setup() {
      useHotkeys(bindings)
      return () => h('div')
    },
  })
}

function press(target: EventTarget, init: KeyboardEventInit) {
  target.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init }))
}

describe('hotkeys', () => {
  it('parses combos and matches modifiers', () => {
    expect(parseCombo('mod+k')).toMatchObject({ key: 'k', mod: true })
    expect(parseCombo('Escape')).toMatchObject({ key: 'Escape' })
    expect(matchesCombo(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }), 'mod+k')).toBe(true)
    expect(matchesCombo(new KeyboardEvent('keydown', { key: 'k' }), 'mod+k')).toBe(false)
    expect(matchesCombo(new KeyboardEvent('keydown', { key: '?' , shiftKey: true }), '?')).toBe(true)
    expect(matchesCombo(new KeyboardEvent('keydown', { key: 'Escape' }), 'Escape')).toBe(true)
  })

  it('does not steal input typing for slash, question mark or Escape', () => {
    const calls: string[] = []
    const wrapper = mount(
      host([
        { combo: '/', handler: () => calls.push('search') },
        { combo: '?', handler: () => calls.push('help') },
        { combo: 'Escape', handler: () => calls.push('escape') },
      ]),
      { attachTo: document.body },
    )
    const input = document.createElement('input')
    document.body.appendChild(input)
    input.focus()
    press(input, { key: '/' })
    press(input, { key: '?' , shiftKey: true })
    press(input, { key: 'Escape' })
    expect(calls).toEqual([])

    press(document.body, { key: '/' })
    press(document.body, { key: '?', shiftKey: true })
    press(document.body, { key: 'Escape' })
    expect(calls).toEqual(['search', 'help', 'escape'])
    wrapper.unmount()
  })

  it('runs explicit opt-in shortcuts inside inputs', () => {
    const calls: string[] = []
    const wrapper = mount(
      host([{ combo: 'Escape', allowInInput: true, handler: () => calls.push('clear') }]),
      { attachTo: document.body },
    )
    const input = document.createElement('input')
    document.body.appendChild(input)
    press(input, { key: 'Escape' })
    expect(calls).toEqual(['clear'])
    wrapper.unmount()
  })

  it('skips global shortcuts while a focus-trapped overlay is open', async () => {
    const calls: string[] = []
    const wrapper = mount(
      host([
        { combo: '/', handler: () => calls.push('search') },
        { combo: '?', handler: () => calls.push('help') },
        { combo: 'mod+k', handler: () => calls.push('palette') },
        { combo: 'Escape', handler: () => calls.push('escape') },
      ]),
      { attachTo: document.body },
    )
    const overlay = mount(Modal, {
      attachTo: document.body,
      props: { title: '弹层' },
      slots: { default: '<button>确定</button>' },
    })
    await flushPromises()
    await nextTick()

    press(document.body, { key: '/' })
    press(document.body, { key: '?', shiftKey: true })
    press(document.body, { key: 'k', ctrlKey: true })
    press(document.body, { key: 'Escape' })
    expect(calls).toEqual([])

    overlay.unmount()
    press(document.body, { key: '/' })
    expect(calls).toEqual(['search'])
    wrapper.unmount()
  })

  it('lets a shortcut opt into running while an overlay is open', async () => {
    const calls: string[] = []
    const wrapper = mount(
      host([{ combo: '/', allowInOverlay: true, handler: () => calls.push('search') }]),
      { attachTo: document.body },
    )
    const overlay = mount(Modal, {
      attachTo: document.body,
      props: { title: '弹层' },
      slots: { default: '<button>确定</button>' },
    })
    await flushPromises()
    await nextTick()
    press(document.body, { key: '/' })
    expect(calls).toEqual(['search'])
    overlay.unmount()
    wrapper.unmount()
  })
})
