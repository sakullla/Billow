import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { h, nextTick } from 'vue'
import ProxyNodeGrid from './ProxyNodeGrid.vue'
import type { NodeItem } from '../lib/types'

const cleanups: (() => void)[] = []
afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => cleanup())
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function setup(count: number, withHeader = false) {
  const nodes: NodeItem[] = Array.from({ length: count }, (_, i) => ({
    name: `node ${i}`, node_type: 'ss', tags: [], selected: false, delay_ms: null, failed: false,
  }))
  const host = document.createElement('main')
  host.className = 'main'
  document.body.append(host)
  Object.defineProperty(host, 'clientHeight', { value: 600 })
  const wrapper = mount(ProxyNodeGrid, {
    attachTo: host,
    props: { nodes, dense: false },
    slots: {
      default: ({ nodes }: { nodes: NodeItem[] }) => nodes.map((node) => h('div', { class: 'node', 'data-node': node.name }, [h('button', node.name)])),
      ...(withHeader ? { header: h('p', '自动选择延迟最低的节点') } : {}),
    },
  })
  // Layout is absent in happy-dom: simulate the document position as the parent scrolls.
  vi.spyOn(wrapper.element, 'getBoundingClientRect').mockImplementation(() => ({ top: -host.scrollTop } as DOMRect))
  cleanups.push(() => { wrapper.unmount(); host.remove() })
  return { wrapper, host, nodes }
}

describe('proxy grid windowing', () => {
  it('renders a small group without layout reads or scroll observers', async () => {
    const measure = vi.spyOn(window, 'getComputedStyle')
    const observer = vi.fn()
    vi.stubGlobal('ResizeObserver', observer)
    const { wrapper } = setup(12)
    await nextTick()
    expect(wrapper.findAll('.node')).toHaveLength(12)
    expect(measure).not.toHaveBeenCalled()
    expect(observer).not.toHaveBeenCalled()
  })

  it('bounds DOM size and reveals the last node without truncating the data', async () => {
    const { wrapper, nodes } = setup(2000)
    expect(wrapper.findAll('.node').length).toBeLessThan(30)
    expect(wrapper.text()).not.toContain('node 1999')
    await wrapper.vm.reveal('node 1999')
    expect(wrapper.find('[data-node="node 1999"]').exists()).toBe(true)
    expect(wrapper.findAll('.node').length).toBeLessThan(30)
    expect(nodes).toHaveLength(2000)
    await wrapper.setProps({ nodes: [nodes[1999]!] })
    expect(wrapper.findAll('.node')).toHaveLength(1)
    expect(wrapper.findAll('.node-spacer')).toHaveLength(0)
  })

  it('keeps group explanations above the spacer when scrolling to a distant node', async () => {
    const { wrapper } = setup(2000, true)
    await wrapper.vm.reveal('node 1999')
    expect(wrapper.element.firstElementChild?.className).toBe('node-grid-header')
    expect(wrapper.find('.node-grid-header').text()).toBe('自动选择延迟最低的节点')
  })

  it('tabs into the next window and back instead of skipping unmounted nodes', async () => {
    const { wrapper } = setup(2000)
    const buttons = wrapper.findAll('button')
    const nextIndex = buttons.length
    await buttons[buttons.length - 1]!.trigger('keydown', { key: 'Tab' })
    await nextTick()
    expect(document.activeElement?.textContent).toBe(`node ${nextIndex}`)
    const first = wrapper.find('button')
    const previous = Number(first.text().split(' ')[1]) - 1
    await first.trigger('keydown', { key: 'Tab', shiftKey: true })
    await nextTick()
    expect(document.activeElement?.textContent).toBe(`node ${previous}`)
  })

  it('releases its observers and pending animation frame on page departure', async () => {
    const disconnect = vi.fn()
    vi.stubGlobal('ResizeObserver', class { observe() {} disconnect = disconnect })
    const cancel = vi.spyOn(window, 'cancelAnimationFrame')
    const { wrapper, host } = setup(2000)
    host.dispatchEvent(new Event('scroll'))
    wrapper.unmount()
    expect(disconnect).toHaveBeenCalledOnce()
    expect(cancel).toHaveBeenCalled()
    // No leftover handler should schedule more work.
    const request = vi.spyOn(window, 'requestAnimationFrame')
    host.dispatchEvent(new Event('scroll'))
    expect(request).not.toHaveBeenCalled()
  })
})
