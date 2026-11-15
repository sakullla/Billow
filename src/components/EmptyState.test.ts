import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import EmptyState from './EmptyState.vue'

describe('EmptyState', () => {
  it('distinguishes loading, no data, no match and error with different copy', () => {
    const titles = new Set<string>()
    for (const variant of ['loading', 'no-data', 'no-match', 'error'] as const) {
      const wrapper = mount(EmptyState, { props: { variant } })
      titles.add(wrapper.find('h3').text())
      if (variant === 'loading') expect(wrapper.find('.spinner').exists()).toBe(true)
      wrapper.unmount()
    }
    expect(titles.size).toBe(4)
  })

  it('announces failures and renders a next-step action slot', () => {
    const wrapper = mount(EmptyState, {
      props: { variant: 'error', title: '规则读取失败' },
      slots: { action: '<button id="retry">重试</button>' },
    })
    expect(wrapper.attributes('role')).toBe('alert')
    expect(wrapper.find('h3').text()).toBe('规则读取失败')
    expect(wrapper.find('#retry').text()).toBe('重试')
    wrapper.unmount()
  })

  it('gives loading a polite status role', () => {
    const wrapper = mount(EmptyState, { props: { variant: 'loading' } })
    expect(wrapper.attributes('role')).toBe('status')
    expect(wrapper.attributes('aria-busy')).toBe('true')
    wrapper.unmount()
  })
})
