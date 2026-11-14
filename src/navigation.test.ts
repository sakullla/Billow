import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import { NAV_ITEMS } from './copy'
import {
  CONTENT_MIN_WIDTH,
  SIDEBAR_WIDTH,
  SIDE_BY_SIDE_MIN,
  layoutForWidth,
  resolveEntry,
} from './navigation'
import { createMemoryPort, type ShellPort } from './port'

async function mountApp(width: number, port: ShellPort = createMemoryPort()) {
  const wrapper = mount(App, { props: { initialWidth: width, port } })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  return wrapper
}

describe('导航', () => {
  it('只有首页、节点、配置，并且按这个顺序', () => {
    expect(NAV_ITEMS.map((item) => item.label)).toEqual(['首页', '节点', '配置'])
    expect(NAV_ITEMS.map((item) => item.id)).toEqual(['home', 'nodes', 'settings'])
  })

  it('上次入口不是这三项时回到首页', async () => {
    expect(resolveEntry('nodes')).toBe('nodes')
    expect(resolveEntry('logs')).toBe('home')
    expect(resolveEntry('theme')).toBe('home')
    expect(resolveEntry('')).toBe('home')
    expect(resolveEntry(null)).toBe('home')

    const port = createMemoryPort({ entry: 'diagnostics' })
    const wrapper = await mountApp(SIDE_BY_SIDE_MIN, port)
    expect(wrapper.get('[data-entry="home"]').attributes('aria-current')).toBe('page')
    expect((await port.load()).entry).toBe('home')
  })

  it('能并列时用侧栏，不能并列时用底部这三项', async () => {
    expect(SIDE_BY_SIDE_MIN).toBe(SIDEBAR_WIDTH + CONTENT_MIN_WIDTH)
    expect(layoutForWidth(SIDE_BY_SIDE_MIN)).toBe('sidebar')
    expect(layoutForWidth(SIDE_BY_SIDE_MIN - 1)).toBe('bottom')
    expect(layoutForWidth(Number.NaN)).toBe('bottom')

    const wide = await mountApp(SIDE_BY_SIDE_MIN)
    expect(wide.get('.app').attributes('data-layout')).toBe('sidebar')
    expect(wide.find('.sidebar').exists()).toBe(true)
    expect(wide.find('.bottom-nav').exists()).toBe(false)
    expect(wide.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])

    const narrow = await mountApp(SIDE_BY_SIDE_MIN - 1)
    expect(narrow.get('.app').attributes('data-layout')).toBe('bottom')
    expect(narrow.find('.sidebar').exists()).toBe(false)
    expect(narrow.find('.bottom-nav').exists()).toBe(true)
    expect(narrow.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])
  })

  it('当前项有标记，主导航不包含连接、日志或主题', async () => {
    const port = createMemoryPort()
    const wrapper = await mountApp(800, port)
    await wrapper.get('[data-entry="nodes"]').trigger('click')
    expect(wrapper.get('[data-entry="nodes"]').attributes('aria-current')).toBe('page')
    expect(wrapper.get('[data-screen="nodes"]').text()).toContain('节点')
    expect((await port.load()).entry).toBe('nodes')

    const labels = wrapper.findAll('.nav-button').map((button) => button.text())
    expect(labels.join(' ')).not.toMatch(/连接|日志|主题|内核|请求|DNS|Sub-Store/)
    expect(wrapper.findAll('nav')).toHaveLength(1)
  })
})
