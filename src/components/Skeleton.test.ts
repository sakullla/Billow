import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Skeleton from './Skeleton.vue'

describe('Skeleton', () => {
  it('renders the requested number of list rows with a spoken loading label', () => {
    const wrapper = mount(Skeleton, { props: { variant: 'list', rows: 3 } })
    expect(wrapper.findAll('.sk-row')).toHaveLength(3)
    expect(wrapper.find('.sr-only').text()).toBe('加载中')
    expect(wrapper.attributes('aria-busy')).toBe('true')
    wrapper.unmount()
  })

  it('has card and detail shapes', () => {
    const cards = mount(Skeleton, { props: { variant: 'card', cards: 2 } })
    expect(cards.findAll('.sk-card')).toHaveLength(2)
    cards.unmount()
    const detail = mount(Skeleton, { props: { variant: 'detail', rows: 4 } })
    expect(detail.findAll('.sk-detail-row')).toHaveLength(4)
    detail.unmount()
  })
})
