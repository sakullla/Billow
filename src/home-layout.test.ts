import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { flushPromises, mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, describe, expect, it } from 'vitest'
import App from './App.vue'
import { MODE_DIRECT_HINT, MODE_GLOBAL_HINT, MODE_RULE_HINT } from './copy'
import { createMemoryProfilePort, type ProfilePort } from './profile-port'
import { createMemoryPort } from './port'
import type { ProfileItem } from './profile'

function item(partial: Partial<ProfileItem> & Pick<ProfileItem, 'id' | 'name'>): ProfileItem {
  return {
    kind: 'local',
    source: '',
    current: false,
    failure: null,
    override_text: '',
    override_error: null,
    used: null,
    total: null,
    expire: null,
    last_success_ms: null,
    ...partial,
  }
}

const mounted: Array<{ unmount: () => void }> = []

async function mountApp(profilePort: ProfilePort = createMemoryProfilePort(), width = 900) {
  const wrapper = mount(App, {
    props: { initialWidth: width, port: createMemoryPort(), profilePort },
  })
  mounted.push(wrapper)
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  await flushPromises()
  return wrapper
}

afterEach(() => {
  for (const wrapper of mounted.splice(0)) wrapper.unmount()
})

function follows(earlier: Element, later: Element) {
  return (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
}

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path))
    else if (!name.endsWith('.test.ts')) out.push(path)
  }
  return out
}

describe('首页结构', () => {
  it('没有配置时主操作直接打开添加层，状态是未连接', async () => {
    const wrapper = await mountApp()
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
    expect(wrapper.get('[data-testid="home-add"]').text()).toBe('添加配置')
    expect(wrapper.find('[data-testid="mode-switch"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="desktop-controls"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="home-rates"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-diagnostics"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('连接与日志')
    expect(wrapper.findAll('.btn-primary')).toHaveLength(1)
    await wrapper.get('[data-testid="home-add"]').trigger('click')
    expect(wrapper.get('[data-screen="home"]').exists()).toBe(true)
    expect(wrapper.get('[data-entry="home"]').attributes('aria-current')).toBe('page')
    expect(wrapper.get('[data-testid="add-subscription"]').text()).toContain('订阅链接')
    expect(wrapper.get('[data-testid="add-local"]').text()).toContain('本地文件')
  })

  it('桌面连接经过连接中后显示速率，断开后接管和速率都关闭', async () => {
    let calls = 0
    let release: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const port = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      profiles: [item({ id: 'p1', name: '甲', current: true, source: 'mixed-port: 7890' })],
    })
    const connect = port.connect.bind(port)
    port.connect = async () => {
      calls += 1
      await gate
      return connect()
    }
    const wrapper = await mountApp(port)
    await wrapper.get('[data-testid="session-connect"]').trigger('click')
    await nextTick()
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('连接中')
    await wrapper.get('[data-testid="session-connect"]').trigger('click')
    expect(calls).toBe(1)
    release()
    await flushPromises()
    expect(calls).toBe(1)
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('已连接')
    expect(wrapper.get('[data-testid="home-profile"]').text()).toBe('甲')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-tun')).toBe('off')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-vpn')).toBe('off')
    expect(wrapper.get('[data-testid="home-rates"]').text()).toContain('上行')
    expect(wrapper.get('[data-testid="home-rates"]').text()).toContain('下行')
    await wrapper.get('[data-testid="session-connect"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('off')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-tun')).toBe('off')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-vpn')).toBe('off')
    expect(wrapper.find('[data-testid="home-rates"]').exists()).toBe(false)
  })

  it('模式切换失败时保持原模式，直连不改系统代理', async () => {
    const failed = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      system_proxy: true,
      connected: true,
      upload: 3,
      download: 4,
      profiles: [item({ id: 'p1', name: '甲', current: true })],
    })
    failed.setMode = async () => {
      const current = await failed.load()
      return { ...current, failure: '模式没有切换' }
    }
    const blocked = await mountApp(failed)
    expect(blocked.get('[data-testid="mode-hint"]').text()).toBe(MODE_RULE_HINT)
    await blocked.get('[data-mode="direct"]').trigger('click')
    await flushPromises()
    expect(blocked.get('[data-testid="mode-switch"]').attributes('data-mode')).toBe('rule')
    expect(blocked.get('[data-testid="mode-hint"]').text()).toBe(MODE_RULE_HINT)
    expect(blocked.get('[data-testid="home-failure"]').text()).toContain('模式没有切换')
    expect(blocked.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')

    const kept = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      system_proxy: true,
      connected: false,
      failure: '内核没有启动',
      profiles: [item({ id: 'p1', name: '甲', current: true })],
    })
    const keptView = await mountApp(kept)
    await keptView.get('[data-mode="direct"]').trigger('click')
    await flushPromises()
    expect(keptView.get('[data-testid="mode-switch"]').attributes('data-mode')).toBe('direct')
    expect(keptView.get('[data-testid="mode-hint"]').text()).toBe(MODE_DIRECT_HINT)
    expect(keptView.get('[data-testid="home-failure"]').text()).toContain('内核没有启动')
    expect(keptView.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')
    await keptView.get('[data-testid="session-connect"]').trigger('click')
    await flushPromises()
    expect(keptView.get('[data-testid="link-status"]').text()).toBe('已连接')
    expect(keptView.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(keptView.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')

    const port = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      system_proxy: true,
      tun: false,
      connected: true,
      upload: 3,
      download: 4,
      profiles: [item({ id: 'p1', name: '甲', current: true })],
    })
    const wrapper = await mountApp(port)
    await wrapper.get('[data-mode="global"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="mode-switch"]').attributes('data-mode')).toBe('global')
    expect(wrapper.get('[data-testid="mode-hint"]').text()).toBe(MODE_GLOBAL_HINT)
    await wrapper.get('[data-mode="direct"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="mode-switch"]').attributes('data-mode')).toBe('direct')
    expect(wrapper.get('[data-testid="mode-hint"]').text()).toBe(MODE_DIRECT_HINT)
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-tun')).toBe('off')
    await wrapper.get('[data-mode="rule"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="mode-switch"]').attributes('data-mode')).toBe('rule')
    expect(wrapper.get('[data-testid="mode-hint"]').text()).toBe(MODE_RULE_HINT)
    expect((await port.load()).system_proxy).toBe(true)
  })

  it('宽屏左列是状态到开关，右列的手动组能定位到节点页', async () => {
    const port = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      connected: true,
      system_proxy: true,
      upload: 8,
      download: 9,
      profiles: [
        item({ id: 'p1', name: '甲', current: true, used: 1, total: 2 }),
        item({ id: 'p2', name: '乙' }),
      ],
      node_groups: [
        {
          name: '手动组',
          kind: 'manual',
          now: '甲',
          sort: 'default',
          nodes: [{ name: '甲', delay_ms: null, failed: false, selected: true }],
        },
        {
          name: '自动组',
          kind: 'auto',
          now: '乙',
          sort: 'default',
          nodes: [{ name: '乙', delay_ms: null, failed: false, selected: false }],
        },
      ],
    })
    const wrapper = await mountApp(port, 900)
    expect(wrapper.get('[data-testid="home-board"]').attributes('data-arrangement')).toBe('columns')
    const main = wrapper.get('[data-testid="home-column-main"]').element
    const side = wrapper.get('[data-testid="home-column-groups"]').element
    expect(main.contains(side)).toBe(false)
    const order = [
      'link-status',
      'home-profile',
      'home-usage',
      'mode-switch',
      'system-proxy-toggle',
      'tun-toggle',
    ]
    for (let index = 1; index < order.length; index += 1) {
      expect(follows(wrapper.get(`[data-testid="${order[index - 1]}"]`).element, wrapper.get(`[data-testid="${order[index]}"]`).element)).toBe(true)
    }
    expect(main.contains(wrapper.get('[data-testid="mode-switch"]').element)).toBe(true)
    expect(main.contains(wrapper.get('[data-testid="tun-toggle"]').element)).toBe(true)
    expect(main.contains(wrapper.get('[data-testid="home-rates"]').element)).toBe(false)
    expect(side.contains(wrapper.get('[data-testid="home-rates"]').element)).toBe(true)
    expect(wrapper.get('[data-testid="home-rates"]').text()).toContain('上行')
    expect(wrapper.get('[data-testid="home-rates"]').text()).toContain('下行')
    expect(
      follows(wrapper.get('[data-testid="home-group"]').element, wrapper.get('[data-testid="home-rates"]').element),
    ).toBe(true)
    expect(wrapper.get('[data-testid="open-diagnostics"]').text()).toBe('连接与日志')
    expect(follows(wrapper.get('[data-testid="home-board"]').element, wrapper.get('[data-testid="open-diagnostics"]').element)).toBe(true)
    expect(side.textContent).toContain('手动组')
    expect(side.textContent).not.toContain('自动组')
    expect(wrapper.findAll('.btn-primary')).toHaveLength(1)
    await wrapper.get('[data-testid="home-group"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-screen="nodes"]').exists()).toBe(true)
    expect(wrapper.get('[data-group="手动组"]').attributes('data-located')).toBe('true')

    const narrow = await mountApp(port, 500)
    expect(narrow.get('.app').attributes('data-layout')).toBe('bottom')
    expect(narrow.get('[data-testid="home-board"]').attributes('data-arrangement')).toBe('stack')
    expect(narrow.find('.bottom-nav').exists()).toBe(true)
    expect(
      follows(
        narrow.get('[data-testid="tun-toggle"]').element,
        narrow.get('[data-testid="home-column-groups"]').element,
      ),
    ).toBe(true)
    expect(narrow.get('[data-testid="home-column-main"]').element.contains(narrow.get('[data-testid="home-rates"]').element)).toBe(false)
    expect(
      follows(
        narrow.get('[data-testid="home-group"]').element,
        narrow.get('[data-testid="home-rates"]').element,
      ),
    ).toBe(true)
    expect(
      follows(
        narrow.get('[data-testid="home-rates"]').element,
        narrow.get('[data-testid="open-diagnostics"]').element,
      ),
    ).toBe(true)
  })

  it('搜索滤掉手动组后从首页进入仍能定位，无搜索时也能定位', async () => {
    const port = createMemoryProfilePort({
      active_id: 'p1',
      mode: 'rule',
      profiles: [item({ id: 'p1', name: '甲', current: true })],
      node_groups: [
        {
          name: '手动组',
          kind: 'manual',
          now: '甲',
          sort: 'default',
          nodes: [{ name: '甲', delay_ms: null, failed: false, selected: true }],
        },
      ],
    })
    const wrapper = await mountApp(port)
    await wrapper.get('[data-entry="nodes"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="node-query"]').setValue('不会匹配')
    await flushPromises()
    expect(wrapper.find('[data-group="手动组"]').exists()).toBe(false)
    await wrapper.get('[data-entry="home"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="home-group"]').attributes('data-group')).toBe('手动组')
    await wrapper.get('[data-testid="home-group"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-screen="nodes"]').exists()).toBe(true)
    expect(wrapper.get('[data-group="手动组"]').attributes('data-located')).toBe('true')
    expect((wrapper.get('[data-testid="node-query"]').element as HTMLInputElement).value).toBe('')

    await wrapper.get('[data-testid="node-query"]').setValue('甲')
    await flushPromises()
    await wrapper.get('[data-entry="home"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="home-group"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-group="手动组"]').attributes('data-located')).toBe('true')
    expect((wrapper.get('[data-testid="node-query"]').element as HTMLInputElement).value).toBe('甲')
  })

  it('配置页列表之后是主题和内核渠道，并且没有排除项入口', async () => {
    const port = createMemoryProfilePort({
      active_id: 'p2',
      profiles: [
        item({ id: 'p1', name: '甲' }),
        item({ id: 'p2', name: '乙', current: true, kind: 'subscription' }),
      ],
    })
    const wrapper = await mountApp(port)
    await wrapper.get('[data-entry="settings"]').trigger('click')
    const settings = wrapper.get('[data-screen="settings"]')
    const profiles = settings.get('[data-testid="profiles"]').element
    const theme = settings.get('input[name="theme"]').element
    const kernel = settings.get('[data-testid="kernel-channel"]').element
    expect(follows(profiles, theme)).toBe(true)
    expect(follows(theme, kernel)).toBe(true)
    expect(settings.text()).not.toContain('连接与日志')
    expect(wrapper.find('[data-testid="open-diagnostics"]').exists()).toBe(false)
    expect(settings.get('[data-testid="profile-row"]').attributes('data-profile-id')).toBe('p2')
    expect(settings.get('[data-profile-id="p2"] [data-testid="profile-kind"]').text()).toBe('订阅')
    expect(settings.get('[data-profile-id="p1"] [data-testid="profile-kind"]').text()).toBe('本地')
    expect(settings.get('[data-profile-id="p2"] [data-testid="profile-actions"]').text()).toContain('更新')
    expect(settings.get('[data-profile-id="p2"] [data-testid="profile-actions"]').text()).not.toContain('启用')
    expect(settings.get('[data-profile-id="p1"] [data-testid="profile-actions"]').text()).toContain('启用')

    const banned = [/磁贴/, /热键/, /webdav/i, /sub-store/i, /请求明细/, /dns/i, /连接正文/]
    const joined = sourceFiles('src')
      .filter((file) => file.endsWith('.vue') || file.endsWith('.css') || file.endsWith('.ts'))
      .map((file) => readFileSync(file, 'utf8'))
      .join('\n')
    for (const pattern of banned) expect(joined).not.toMatch(pattern)
    expect(wrapper.text()).not.toMatch(/磁贴|热键|WebDAV|Sub-Store|请求明细|连接正文/)
  })
})
