import { readFileSync } from 'node:fs'
import { flushPromises, mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createMemoryPort } from './port'
import { createMemoryProfilePort, type ProfilePort } from './profile-port'
import DiagnosticsView from './views/DiagnosticsView.vue'
import { DIAGNOSTICS_SAMPLE_MS, type LogLine, type ProfileSnapshot } from './profile'

const mounted: Array<{ unmount: () => void }> = []

afterEach(() => {
  for (const wrapper of mounted.splice(0)) wrapper.unmount()
  vi.useRealTimers()
})

async function mountApp(profilePort = createMemoryProfilePort()) {
  const wrapper = mount(App, {
    props: { initialWidth: 900, port: createMemoryPort(), profilePort },
  })
  mounted.push(wrapper)
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  await flushPromises()
  return wrapper
}

describe('连接与日志', () => {
  it('首页两个入口打开同一诊断页，配置页和主导航没有这个入口', async () => {
    const wrapper = await mountApp(createMemoryProfilePort({ failure: '订阅没有取回' }))
    expect(wrapper.get('[data-testid="open-diagnostics"]').text()).toBe('连接与日志')
    expect(wrapper.get('[data-testid="open-diagnostics-failure"]').text()).toBe('查看诊断')
    expect(wrapper.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])

    await wrapper.get('[data-testid="open-diagnostics"]').trigger('click')
    expect(wrapper.get('[data-screen="diagnostics"]').text()).toContain('诊断')
    expect(wrapper.get('[data-testid="diagnostic-tab-connections"]').text()).toBe('连接')
    expect(wrapper.get('[data-testid="diagnostic-tab-logs"]').text()).toBe('日志')
    expect(wrapper.find('[data-screen="home"]').exists()).toBe(false)
    expect(wrapper.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])

    await wrapper.get('[data-testid="diagnostics-back"]').trigger('click')
    await wrapper.get('[data-testid="open-diagnostics-failure"]').trigger('click')
    expect(wrapper.get('[data-screen="diagnostics"]').text()).toContain('连接')
    await wrapper.get('[data-testid="diagnostic-tab-logs"]').trigger('click')
    expect(wrapper.get('[data-testid="log-panel"]').exists()).toBe(true)
    await wrapper.get('[data-testid="diagnostic-tab-connections"]').trigger('click')
    expect(wrapper.get('[data-testid="connection-panel"]').exists()).toBe(true)

    await wrapper.get('[data-entry="settings"]').trigger('click')
    const settings = wrapper.get('[data-screen="settings"]')
    expect(settings.text()).not.toContain('连接与日志')
    expect(settings.text()).not.toContain('查看诊断')
    expect(wrapper.find('[data-testid="open-diagnostics"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-diagnostics-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-screen="diagnostics"]').exists()).toBe(false)
  })

  it('连接行能看出目标主机和出站，并按目标文字筛选', async () => {
    const wrapper = await mountApp(
      createMemoryProfilePort({
        connected: true,
        kernel_running: true,
        connections: [
          { host: 'example.com', outbound: '香港节点' },
          { host: 'other.test', outbound: '直连' },
        ],
      }),
    )
    await wrapper.get('[data-testid="open-diagnostics"]').trigger('click')
    expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(2)
    await wrapper.get('[data-testid="connection-query"]').setValue('example')
    await flushPromises()
    const row = wrapper.get('[data-testid="connection-row"]')
    expect(row.attributes('data-host')).toBe('example.com')
    expect(row.attributes('data-outbound')).toBe('香港节点')
    expect(row.text()).toContain('example.com')
    expect(row.text()).toContain('香港节点')
    expect(row.text()).not.toMatch(/dns|请求|正文/i)
    expect(wrapper.find('[data-testid="connection-detail"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="dns-panel"]').exists()).toBe(false)
  })

  it('内核停止后列表为空，并且不显示已连接', async () => {
    const wrapper = await mountApp(
      createMemoryProfilePort({
        connected: true,
        kernel_running: true,
        system_proxy: true,
        connections: [{ host: 'example.com', outbound: '香港节点' }],
      }),
    )
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('已连接')
    await wrapper.get('[data-testid="session-connect"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
    await wrapper.get('[data-testid="open-diagnostics"]').trigger('click')
    expect(wrapper.find('[data-testid="connection-row"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="connection-empty"]').text()).toBe('未连接')
  })

  it('一次启动失败能在日志里看到，并且可以按级别留下失败行', async () => {
    const wrapper = await mountApp()
    await wrapper.get('[data-testid="session-connect"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="open-diagnostics-failure"]').trigger('click')
    await wrapper.get('[data-testid="diagnostic-tab-logs"]').trigger('click')
    expect(wrapper.text()).toContain('没有生效配置')
    const failure = wrapper.get('[data-testid="log-line"]')
    expect(failure.attributes('data-level')).toBe('error')
    expect(failure.classes()).toContain('log-line')
    expect(wrapper.get('[data-testid="log-filter"]').classes()).not.toContain('log-line')

    const filtered = await mountApp(
      createMemoryProfilePort({
        logs: [
          { level: 'info', message: '普通记录' },
          { level: 'warning', message: '注意一下' },
          { level: 'error', message: '内核没有启动' },
        ] satisfies LogLine[],
      }),
    )
    await filtered.get('[data-testid="open-diagnostics"]').trigger('click')
    await filtered.get('[data-testid="diagnostic-tab-logs"]').trigger('click')
    await filtered.get('[data-testid="log-filter"][data-level="error"]').trigger('click')
    await flushPromises()
    expect(filtered.text()).toContain('内核没有启动')
    expect(filtered.text()).not.toContain('普通记录')
    expect(filtered.text()).not.toContain('注意一下')
    const css = readFileSync('src/styles.css', 'utf8')
    expect(css).toMatch(/\.log-line\s*\{[^}]*monospace/)
    expect(css).not.toMatch(/\.choice\s*\{[^}]*monospace/)
  })

  it('日志停在底部时跟随最新一条，离开底部后不被拉回', async () => {
    const wrapper = mount(DiagnosticsView, {
      props: {
        connected: true,
        connections: [],
        connectionQuery: '',
        logs: [{ level: 'info', message: '旧记录' }],
        logFilter: 'all',
      },
    })
    await wrapper.get('[data-testid="diagnostic-tab-logs"]').trigger('click')
    const scroller = wrapper.get('[data-testid="log-scroller"]')
    const el = scroller.element as HTMLElement
    Object.defineProperty(el, 'scrollHeight', { configurable: true, value: 500 })
    Object.defineProperty(el, 'clientHeight', { configurable: true, value: 100 })
    await wrapper.setProps({
      logs: [
        { level: 'info', message: '旧记录' },
        { level: 'info', message: '最新一条' },
      ],
    })
    await flushPromises()
    await nextTick()
    expect(wrapper.text()).toContain('最新一条')
    expect(el.scrollTop).toBe(500)
    el.scrollTop = 12
    await scroller.trigger('scroll')
    await nextTick()
    expect(scroller.attributes('data-follow')).toBe('false')
    await wrapper.setProps({
      logs: [
        { level: 'info', message: '旧记录' },
        { level: 'info', message: '最新一条' },
        { level: 'error', message: '又一条' },
      ],
    })
    await flushPromises()
    await nextTick()
    expect(wrapper.text()).toContain('又一条')
    expect(el.scrollTop).toBe(12)
  })

  it('诊断页打开后能看到新连接和新日志，内核自己退出后不再显示已连接', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    let injected = false
    let exited = false
    let loads = 0
    let filterCalls = 0
    const memory = createMemoryProfilePort({
      connected: true,
      kernel_running: true,
      system_proxy: true,
      tun: true,
      connections: [{ host: 'example.com', outbound: '香港节点' }],
      logs: [{ level: 'info', message: '旧记录' }],
    })
    function project(snapshot: ProfileSnapshot): ProfileSnapshot {
      if (exited) {
        return {
          ...snapshot,
          connected: false,
          kernel_running: false,
          tun: false,
          connections: [],
        }
      }
      return {
        ...snapshot,
        connected: true,
        kernel_running: true,
        connections: injected
          ? [...snapshot.connections, { host: 'fresh.example', outbound: '日本节点' }]
          : snapshot.connections,
        logs: injected ? [...snapshot.logs, { level: 'info', message: '新的流量' }] : snapshot.logs,
      }
    }
    const port: ProfilePort = {
      ...memory,
      async load() {
        loads += 1
        return project(await memory.load())
      },
      async setLogFilter(level) {
        filterCalls += 1
        return project(await memory.setLogFilter(level))
      },
    }
    const wrapper = await mountApp(port)
    const beforeOpen = loads
    await wrapper.get('[data-testid="open-diagnostics"]').trigger('click')
    await flushPromises()
    expect(loads).toBeGreaterThan(beforeOpen)
    expect(wrapper.text()).toContain('example.com')
    expect(wrapper.text()).not.toContain('fresh.example')

    injected = true
    await vi.advanceTimersByTimeAsync(DIAGNOSTICS_SAMPLE_MS)
    await flushPromises()
    expect(wrapper.text()).toContain('fresh.example')
    await wrapper.get('[data-testid="diagnostic-tab-logs"]').trigger('click')
    expect(wrapper.text()).toContain('新的流量')
    expect(wrapper.text()).toContain('旧记录')
    await wrapper.get('[data-testid="log-filter"][data-level="info"]').trigger('click')
    await flushPromises()
    expect(filterCalls).toBe(1)
    expect(wrapper.text()).toContain('新的流量')

    exited = true
    await vi.advanceTimersByTimeAsync(DIAGNOSTICS_SAMPLE_MS)
    await flushPromises()
    await wrapper.get('[data-testid="diagnostic-tab-connections"]').trigger('click')
    expect(wrapper.find('[data-testid="connection-row"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="connection-empty"]').text()).toBe('未连接')
    await wrapper.get('[data-testid="diagnostics-back"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
  })
})
