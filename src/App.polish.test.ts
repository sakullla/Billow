import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { DEMO_LONG_NAMES, createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'

// Regression coverage for docs/requirements/2026-11-08-ui-ux-polish.md (R1–R8, R10–R24).

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountApp>>['wrapper']

function storeOf(wrapper: Wrapper) {
  return (wrapper.vm as unknown as { store: Store }).store
}

async function openPage(wrapper: Wrapper, page: string) {
  await wrapper.find(`.sidebar [data-page="${page}"]`).trigger('click')
  await flushPromises()
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  vi.useRealTimers()
})

describe('UI/UX polish', () => {
  it('R1: home group cards badge only automatic strategies and keep a delay slot that never fakes a value', async () => {
    const { wrapper } = await mountApp()
    const card = () => wrapper.find('[data-testid="groups-card"] [data-group="节点选择"]')
    // Plain select groups are the norm and carry no “手选” badge; automatic strategies are named.
    expect(card().find('[data-testid="home-group-type"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="groups-card"] [data-group="自动选择"] [data-testid="home-group-type"]').text()).toBe('自动')
    expect(wrapper.find('[data-testid="groups-card"]').text()).not.toContain('手选')
    // Disconnected: the slot reads "—", never 0 ms or 超时.
    expect(card().find('[data-testid="home-group-delay"]').text()).toBe('—')

    await connect(wrapper)
    const store = storeOf(wrapper)
    void store.testAll()
    await settle(3000)

    const now = store.snapshot.value.node_catalog.find((group) => group.name === '节点选择')!.now
    const node = store.snapshot.value.node_catalog.find((group) => group.name === '节点选择')!.nodes.find((item) => item.name === now)!
    const result = store.testResults.value[now]
    const delay = result ? result.delay : node.delay_ms
    const failed = result ? result.failed : node.failed
    const text = card().find('[data-testid="home-group-delay"]').text()
    expect(text).toBe(failed ? '超时' : `${delay} ms`)

    // DIRECT targets have no latency to show.
    expect(wrapper.find('[data-testid="groups-card"] [data-group="国内网站"] [data-testid="home-group-delay"]').text()).toBe('—')

    await card().trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="home-node-picker"]')).not.toBeNull()
    document.body.querySelector<HTMLElement>('[data-testid="node-picker-open-proxies"]')?.click()
    await flushPromises()
    expect(store.page.value).toBe('proxies')
  })

  it('R2: the traffic chart waits for samples and orders its legend like the rate cards', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1200)
    expect(wrapper.find('[data-testid="chart-collecting"]').exists()).toBe(true)
    expect(wrapper.find('.chart-line').exists()).toBe(false)

    await settle(6000)
    expect(wrapper.find('[data-testid="chart-collecting"]').exists()).toBe(false)
    expect(wrapper.findAll('.chart-line')).toHaveLength(2)
    const legend = wrapper.findAll('[data-testid="chart-legend"] .legend-item').map((item) => item.text())
    expect(legend).toEqual(['下载', '上传'])

    // A new session starts collecting again instead of reusing the old curve.
    const store = storeOf(wrapper)
    void store.disconnect()
    await settle(1200)
    void store.connect()
    await settle(1200)
    expect(wrapper.find('[data-testid="chart-collecting"]').exists()).toBe(true)
  })

  it('R3: desktop proxy view controls are labelled icon buttons with a pressed state', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'proxies')
    const locate = wrapper.find('[data-testid="locate-active-node"]')
    expect(locate.text()).toContain('定位')
    expect(locate.attributes('aria-label')).toBe('定位当前选中节点')

    // A two-way switch: 卡片 and 列表, each an icon with an accessible name.
    const view = () => wrapper.find('[data-testid="node-view"]')
    const card = () => wrapper.find('[data-testid="node-view-card"]')
    const list = () => wrapper.find('[data-testid="node-view-list"]')
    expect(view().attributes('data-value')).toBe('card')
    expect(card().attributes('aria-label')).toBe('卡片视图')
    expect(card().attributes('aria-pressed')).toBe('true')
    expect(list().attributes('aria-pressed')).toBe('false')
    await list().trigger('click')
    expect(view().attributes('data-value')).toBe('list')
    expect(list().attributes('aria-pressed')).toBe('true')
    expect(wrapper.find('.nodes').classes()).toContain('list')
    await card().trigger('click')
    expect(wrapper.find('.nodes').classes()).not.toContain('list')

    const all = wrapper.find('[data-testid="toggle-all"]')
    if (all.text() === '展开全部') await all.trigger('click')
    expect(wrapper.find('[data-testid="toggle-all"]').text()).toBe('收起全部')
    await wrapper.find('[data-testid="toggle-all"]').trigger('click')
    expect(wrapper.find('[data-testid="toggle-all"]').text()).toBe('展开全部')
  })

  it('R12: phones label every view control inside the options panel', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('.tabbar [data-page="proxies"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="toggle-options"]').trigger('click')
    const labels = ['locate-active-node', 'toggle-dense', 'toggle-all'].map((id) =>
      wrapper.find(`[data-testid="${id}"] .tool-btn-label`).text(),
    )
    expect(labels).toEqual(['定位', '双列', expect.stringMatching(/^(展开|收起)全部$/)])
  })

  it('R13: automatic groups are not listed and no hide toggle is offered', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'proxies')
    expect(wrapper.find('[data-testid="toggle-hide-auto"]').exists()).toBe(false)
    expect(wrapper.find('[data-group-card="自动选择"]').exists()).toBe(false)
    expect(wrapper.find('[data-group-card="故障转移"]').exists()).toBe(false)
    expect(wrapper.find('[data-group-card="节点选择"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="jump-group-自动选择"]').exists()).toBe(false)
  })

  it('R14: auto entries show their strategy and target, and open a strategy view', async () => {
    const { wrapper } = await mountApp()
    await connect(wrapper)
    await openPage(wrapper, 'proxies')
    const store = storeOf(wrapper)
    const fallback = store.snapshot.value.node_catalog.find((group) => group.name === '故障转移')!

    const entry = wrapper.find('[data-group-card="节点选择"] [data-node="故障转移"]')
    const via = entry.find('[data-testid="node-via"]')
    expect(via.text()).toContain('故障转移')
    expect(via.text()).toContain(`→ ${fallback.now}`)

    await entry.find('[data-testid="open-auto-故障转移"]').trigger('click')
    await flushPromises()
    const card = wrapper.find('[data-group-card="故障转移"]')
    expect(card.exists()).toBe(true)
    expect(card.classes()).toContain('open')
    expect(card.find('[data-testid="group-strategy"]').text()).toContain('按顺序使用第一个可用的节点')
    // Fallback members carry their priority in config order.
    const ranks = card.findAll('[data-testid="node-rank"]').map((rank) => rank.text())
    expect(ranks).toEqual(fallback.nodes.map((_, index) => String(index + 1)))

    // Manual groups explain nothing; url-test explains its latency rule.
    expect(wrapper.find('[data-group-card="节点选择"] [data-testid="group-strategy"]').exists()).toBe(false)
    await wrapper.find('[data-group-card="节点选择"] [data-testid="open-auto-自动选择"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-group-card="自动选择"] [data-testid="group-strategy"]').text()).toContain('延迟最低')
    expect(wrapper.find('[data-group-card="自动选择"] [data-testid="node-rank"]').exists()).toBe(false)

    // Choosing an auto entry makes home name the real server behind it.
    await wrapper.find('[data-group-card="节点选择"] [data-testid="node-select-自动选择"]').trigger('click')
    await settle(500)
    await openPage(wrapper, 'home')
    const autoNow = store.snapshot.value.node_catalog.find((group) => group.name === '自动选择')!.now
    const now = wrapper.find('[data-group="节点选择"] [data-testid="home-group-now"]')
    expect(now.find('.chain-via').text()).toBe('自动选择')
    expect(now.find('.chain-exit').text()).toBe(autoNow)
    expect(now.find('.chain').attributes('title')).toBe(`自动选择 → ${autoNow}`)
  })

  it('R11: subscription quota nodes collapse into an info line', async () => {
    vi.useFakeTimers()
    const backend = createDemoBackend()
    const readState = backend.state
    const info = ['【KLM】Traffic Reset：17 Days Left', '【KLM】4.49 GB | 500 GB', '剩余流量：120 GB']
    backend.state = async () => {
      const state = await readState.call(backend)
      return {
        ...state,
        node_catalog: state.node_catalog.map((group) =>
          group.name === '节点选择'
            ? {
                ...group,
                nodes: [
                  ...info.map((name) => ({ name, delay_ms: null, failed: false, selected: false, node_type: 'Shadowsocks', tags: [] })),
                  ...group.nodes,
                ],
              }
            : group,
        ),
      }
    }
    const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
    mounted.push(wrapper)
    await settle(50)
    await openPage(wrapper, 'proxies')

    const card = wrapper.find('[data-group-card="节点选择"]')
    const line = card.find('[data-testid="group-info"]')
    // Quota reads as a usage bar with figures; reset and leftover become quiet chips (UI/UX R6).
    const usage = line.find('[data-testid="group-quota-usage"]')
    expect(usage.find('.group-quota-figure').text()).toBe('4.49 GB / 500 GB')
    expect(usage.find('.group-quota-pct').text()).toBe('0.9%')
    expect(usage.find('[role="progressbar"]').attributes('aria-valuenow')).toBe('1')
    expect(line.findAll('.group-info-item').map((item) => item.text())).toEqual([
      '剩余 120 GB',
      '17 天后重置',
    ])
    expect(line.findAll('.group-info-item').map((item) => item.attributes('title'))).toEqual([
      '剩余流量：120 GB',
      'Traffic Reset：17 Days Left',
    ])
    for (const name of info) expect(card.find(`[data-node="${name}"]`).exists()).toBe(false)

    // Searching still finds them as rows.
    await wrapper.find('[data-testid="node-search"]').setValue('traffic')
    await flushPromises()
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="【KLM】Traffic Reset：17 Days Left"]').exists()).toBe(true)
  })

  it('R4: disabled rules are marked and keep a pinned enable action', async () => {
    const { wrapper } = await mountApp()
    await connect(wrapper)
    await openPage(wrapper, 'rules')
    await settle(500)

    const row = wrapper.findAll('[data-testid="rule-row"]')[0]!
    const key = row.attributes('data-rule-key')!
    const toggle = row.find('[data-testid="rule-toggle"]')
    expect(toggle.classes()).not.toContain('pinned')
    expect(toggle.attributes('aria-label')).toContain('临时禁用规则')
    expect(row.find('[data-testid="rule-off-tag"]').exists()).toBe(false)

    await toggle.trigger('click')
    await settle(300)
    const disabled = wrapper.findAll('[data-testid="rule-row"]').find((item) => item.attributes('data-rule-key') === key)!
    expect(disabled.find('[data-testid="rule-off-tag"]').text()).toBe('已禁用')
    const pinned = disabled.find('[data-testid="rule-toggle"]')
    expect(pinned.classes()).toContain('pinned')
    expect(pinned.text()).toBe('启用')
  })

  it('R17: rule columns are captioned and a group policy opens that proxy group', async () => {
    const { wrapper } = await mountApp()
    await connect(wrapper)
    await openPage(wrapper, 'rules')
    await settle(500)

    const head = wrapper.find('[data-testid="rule-head"]')
    expect(head.text()).toContain('策略')
    expect(head.text()).toContain('命中')
    expect(head.text()).toContain('最近命中')

    const store = storeOf(wrapper)
    const rows = wrapper.findAll('[data-testid="rule-row"]')
    // DIRECT is a built-in policy, not a group: it stays a plain label.
    const direct = rows.find((row) => row.find('.rule-proxy').attributes('data-policy') === 'DIRECT')!
    expect(direct.find('[data-testid="rule-proxy-link"]').exists()).toBe(false)

    const link = rows[0]!.find('[data-testid="rule-proxy-link"]')
    const group = link.text()
    expect(store.snapshot.value.node_catalog.some((item) => item.name === group)).toBe(true)
    await link.trigger('click')
    await flushPromises()
    expect(store.page.value).toBe('proxies')
    expect(wrapper.find(`[data-group-card="${group}"]`).exists()).toBe(true)
  })

  it('R17: phones keep the wrapped rule rows without a caption row', async () => {
    const { wrapper } = await mountApp({}, 390)
    void storeOf(wrapper).connect()
    await settle(1500)
    storeOf(wrapper).go('rules')
    await settle(500)
    expect(wrapper.findAll('[data-testid="rule-row"]').length).toBeGreaterThan(0)
    expect(wrapper.find('[data-testid="rule-head"]').exists()).toBe(false)
  })

  it('R18: connections list download before upload and sort from the table headers on desktop', async () => {
    const { wrapper } = await mountApp()
    await connect(wrapper)
    await openPage(wrapper, 'connections')
    await settle(1100)

    const summary = wrapper.find('[data-testid="connection-summary"]')
    const marks = summary.findAll('span[title]').map((item) => item.attributes('title'))
    expect(marks).toEqual(['本次累计下载', '本次累计上传'])

    // The header buttons own sorting; the duplicate switch is phone-only.
    expect(wrapper.find('[data-testid="connection-sort"]').exists()).toBe(false)
    const sortable = wrapper.findAll('.conn-table th[aria-sort]')
    expect(sortable).toHaveLength(5)
    const host = sortable[0]!
    await host.find('button').trigger('click')
    expect(host.attributes('aria-sort')).toBe('ascending')

    const row = wrapper.find('[data-testid="connection-row"]')
    expect(row.find('.conn-close').attributes('aria-label')).toContain('断开')
    await row.trigger('click')
    await flushPromises()
    const labels = new DOMWrapper(document.body).findAll('.modal .detail dt').map((item) => item.text())
    expect(labels.indexOf('下载')).toBeGreaterThan(-1)
    expect(labels.indexOf('下载')).toBeLessThan(labels.indexOf('上传'))
  })

  it('R18: phone connection cards keep the sort switch and lead with download', async () => {
    const { wrapper } = await mountApp({}, 390)
    void storeOf(wrapper).connect()
    await settle(1500)
    storeOf(wrapper).go('connections')
    await settle(1100)
    expect(wrapper.find('[data-testid="connection-sort"]').exists()).toBe(true)
    const traffic = wrapper.find('.conn [data-testid="connection-traffic"]').text()
    expect(traffic.indexOf('↓')).toBeGreaterThan(-1)
    expect(traffic.indexOf('↓')).toBeLessThan(traffic.indexOf('↑'))
  })

  it('R19: home tests every node in place and only offers it while connected', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.find('[data-testid="home-test-all"]').exists()).toBe(false)

    await connect(wrapper)
    const button = () => wrapper.find('[data-testid="home-test-all"]')
    const delay = () => wrapper.find('[data-testid="groups-card"] [data-group="节点选择"] [data-testid="home-group-delay"]').text()
    expect(button().text()).toBe('测速')
    expect(delay()).toBe('—')

    await button().trigger('click')
    await flushPromises()
    expect(button().attributes('disabled')).toBeDefined()
    expect(button().text()).toBe('测速中')

    await settle(4000)
    expect(button().attributes('disabled')).toBeUndefined()
    expect(storeOf(wrapper).page.value).toBe('home')
    expect(delay()).toMatch(/^(\d+ ms|超时)$/)
  })

  it('R20: mod+digit follows the sidebar order, mod+comma opens settings, and overlays keep the keys', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    const press = (key: string) =>
      document.dispatchEvent(new KeyboardEvent('keydown', { key, ctrlKey: true, bubbles: true, cancelable: true }))

    press('2')
    await flushPromises()
    expect(store.page.value).toBe('proxies')
    press('7')
    await flushPromises()
    expect(store.page.value).toBe('logs')
    press(',')
    await flushPromises()
    expect(store.page.value).toBe('settings')
    // Nothing is bound past the sidebar list.
    press('8')
    await flushPromises()
    expect(store.page.value).toBe('settings')

    expect(wrapper.find('.sidebar [data-page="proxies"]').attributes('title')).toMatch(/^代理 \((Ctrl \+ 2|⌘2)\)$/)

    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await flushPromises()
    press('1')
    await flushPromises()
    expect(store.page.value).toBe('settings')
  })

  it('R21: the phone import field drops the desktop-only drag hint', async () => {
    const phone = await mountApp({}, 390)
    storeOf(phone.wrapper).go('profiles')
    await flushPromises()
    expect(phone.wrapper.find('.quick-import input').attributes('placeholder')).toBe('粘贴订阅链接')

    const desktop = await mountApp()
    await openPage(desktop.wrapper, 'profiles')
    expect(desktop.wrapper.find('.quick-import input').attributes('placeholder')).toContain('拖入 YAML 文件')
  })

  it('R4: phones toggle rules with a labelled icon button', async () => {
    const { wrapper } = await mountApp({}, 390)
    void storeOf(wrapper).connect()
    await settle(1500)
    storeOf(wrapper).go('rules')
    await settle(500)
    const toggle = wrapper.findAll('[data-testid="rule-toggle"]')[0]!
    expect(toggle.classes()).toContain('icon-btn')
    expect(toggle.attributes('aria-label')).toContain('临时禁用规则')
    await toggle.trigger('click')
    await settle(300)
    expect(wrapper.find('[data-rule-disabled="true"] [data-testid="rule-toggle"]').attributes('aria-label')).toContain('启用规则')
  })

  it('R6: the phone hero states the connection once and keeps the orb named', async () => {
    const { wrapper } = await mountApp({}, 390)
    const hero = wrapper.find('[data-testid="home-status"]')
    expect(hero.find('[data-testid="status"]').text()).toBe('未连接')
    // The orb label is visually hidden on phones but still names the button.
    expect(hero.find('.connect-label').text()).toBe('连接')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="status"]').text()).toBe('连接中')
    await settle(1500)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')
  })

  it('keeps the sidebar status capsule on one rate row with full values in tooltips', async () => {
    const { wrapper } = await mountApp()
    await connect(wrapper)
    const rates = wrapper.find('[data-testid="side-status"] .side-rates')
    const cells = rates.findAll(':scope > span')
    expect(cells).toHaveLength(2)
    for (const cell of cells) {
      // Compact value in the row, the unabridged speed in the tooltip.
      expect(cell.find('.side-rate-num').text()).toMatch(/^\d+(\.\d+)?[BKMGT]$/)
      expect(cell.attributes('title')).toMatch(/[下上][载传] .+\/s$/)
    }
  })

  it('R7: empty states use the page icon, and errors keep the warning icon', async () => {
    const { wrapper } = await mountApp({ connectionsFailure: true })
    await openPage(wrapper, 'connections')
    expect(wrapper.find('.empty-state [data-icon]').attributes('data-icon')).toBe('activity')
    await openPage(wrapper, 'resources')
    expect(wrapper.find('.empty-state [data-icon]').attributes('data-icon')).toBe('database')
    await openPage(wrapper, 'rules')
    expect(wrapper.find('.empty-state [data-icon]').attributes('data-icon')).toBe('route')

    void storeOf(wrapper).connect()
    await settle(1500)
    await openPage(wrapper, 'connections')
    await settle(1000)
    const error = wrapper.find('.empty-state.error')
    expect(error.exists()).toBe(true)
    expect(error.find('[data-icon]').attributes('data-icon')).toBe('alert')
  })

  describe('R16: age private key for encrypted subscriptions', () => {
    const body = () => new DOMWrapper(document.body)
    const SECRET = `AGE-SECRET-KEY-1${'Q'.repeat(58)}`

    async function openEditor(wrapper: Wrapper, id = 'p1') {
      await openPage(wrapper, 'profiles')
      await wrapper.find(`[data-profile="${id}"] [data-menu-trigger="${id}"]`).trigger('click')
      await flushPromises()
      const edit = [...document.body.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')].find((item) =>
        item.textContent?.includes('编辑信息'),
      )!
      edit.click()
      await flushPromises()
    }

    it('saves a subscription UA override and can return to the inherited versioned default', async () => {
      const { wrapper, backend } = await mountApp()
      const setUa = vi.spyOn(backend, 'setUserAgent')
      await openEditor(wrapper)
      expect(body().find('[data-testid="profile-advanced"]').attributes('open')).toBeUndefined()
      const input = body().find('[data-testid="profile-user-agent"]')
      expect(input.attributes('placeholder')).toBe('clash.meta/v1.19.17')
      await input.setValue('custom-client/2')
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await settle(300)
      expect(setUa).toHaveBeenCalledWith('p1', 'custom-client/2')
      await openEditor(wrapper)
      expect(body().find('[data-testid="profile-advanced"]').attributes('open')).toBeDefined()
      expect((body().find('[data-testid="profile-user-agent"]').element as HTMLInputElement).value).toBe('custom-client/2')
      await body().find('[data-testid="profile-user-agent"]').setValue('')
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await settle(300)
      expect(storeOf(wrapper).snapshot.value.profiles[0]!.user_agent).toBe('')
      storeOf(wrapper).openSettings('behavior')
      await flushPromises()
      const global = wrapper.find('[data-testid="global-subscription-user-agent"]')
      await global.trigger('focus')
      await global.setValue('global-client/3')
      await global.trigger('blur')
      await settle(300)
      await openEditor(wrapper)
      expect(body().find('[data-testid="profile-user-agent"]').attributes('placeholder')).toBe('global-client/3')
    })

    it('saves a key, shows only its public key, and can clear it', async () => {
      const { wrapper, backend } = await mountApp()
      const setAgeKey = vi.spyOn(backend, 'setAgeKey')
      await openEditor(wrapper)

      // Pasting the public key is caught before saving.
      await body().find('[data-testid="age-input"]').setValue('age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs')
      expect(body().find('[data-testid="age-hint"]').text()).toContain('这是公钥')
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await flushPromises()
      expect(setAgeKey).not.toHaveBeenCalled()

      await body().find('[data-testid="age-input"]').setValue(`# public key: age1xyz\n${SECRET}\n`)
      expect(body().find('[data-testid="age-hint"]').exists()).toBe(false)
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await settle(300)
      expect(setAgeKey).toHaveBeenCalledWith('p1', `# public key: age1xyz\n${SECRET}\n`)
      const store = storeOf(wrapper)
      const saved = store.snapshot.value.profiles.find((profile) => profile.id === 'p1')!
      expect(saved.age_recipients).toHaveLength(1)
      expect(wrapper.find('[data-profile="p1"] .profile-foot').text()).toContain('age')

      // Reopening shows the configured state, never the secret.
      await openEditor(wrapper)
      const status = body().find('[data-testid="age-status"]')
      expect(status.text()).toContain('已配置 1 个')
      expect(body().find('.modal').text()).not.toContain(SECRET)
      await body().find('[data-testid="age-clear"]').trigger('click')
      expect(body().find('[data-testid="age-status"]').text()).toContain('保存后将清除私钥')
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await settle(300)
      expect(setAgeKey).toHaveBeenLastCalledWith('p1', '')
      expect(store.snapshot.value.profiles.find((profile) => profile.id === 'p1')!.age_recipients).toEqual([])
    })

    it('keeps the dialog open with the backend reason for a malformed key', async () => {
      const { wrapper } = await mountApp()
      await openEditor(wrapper)
      await body().find('[data-testid="age-input"]').setValue('AGE-SECRET-KEY-1NOTVALID')
      await body().findAll('.modal button').find((button) => button.text() === '保存')!.trigger('click')
      await settle(300)
      expect(body().find('.modal').exists()).toBe(true)
      expect(body().find('.modal .field-error').text()).toContain('age 私钥格式不正确')
    })

    it('offers to fill the key from an age decryption failure', async () => {
      vi.useFakeTimers()
      const backend = createDemoBackend()
      const readState = backend.state
      backend.state = async () => {
        const state = await readState.call(backend)
        return {
          ...state,
          profiles: state.profiles.map((profile) =>
            profile.id === 'p2'
              ? { ...profile, failure: '订阅内容已使用 age 加密，请在「编辑配置信息」中填写 age 私钥后重新更新' }
              : profile,
          ),
        }
      }
      const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
      mounted.push(wrapper)
      await settle(50)
      await openPage(wrapper, 'profiles')
      await wrapper.find('[data-profile="p2"] [data-testid="age-fix"]').trigger('click')
      await flushPromises()
      expect(body().find('.modal [data-testid="age-input"]').exists()).toBe(true)
      expect(body().find('[data-testid="profile-advanced"]').attributes('open')).toBeDefined()
      expect(document.activeElement).toBe(body().find('[data-testid="age-input"]').element)
    })
  })

  describe('R22–R24: long node names and proxy chains', () => {
    it('R22: desktop switches between card and list views, remembering the choice', async () => {
      localStorage.setItem('billow:proxy-dense', 'true')
      const { wrapper } = await mountApp({ longNames: true })
      await openPage(wrapper, 'proxies')
      // The retired desktop 紧凑 view reads as cards.
      expect(wrapper.find('[data-testid="node-view"]').attributes('data-value')).toBe('card')
      expect(wrapper.find('[data-group-card="节点选择"] .nodes').classes()).not.toContain('dense')

      await wrapper.find('[data-testid="node-view-list"]').trigger('click')
      const grid = wrapper.find('[data-group-card="节点选择"] .nodes')
      expect(grid.classes()).toContain('list')
      expect(grid.classes()).not.toContain('dense')
      const long = grid.find(`[data-node="${DEMO_LONG_NAMES[0]}"] .node-name`)
      expect(long.text()).toBe(DEMO_LONG_NAMES[0])
      expect(grid.find(`[data-node="${DEMO_LONG_NAMES[0]}"] [data-testid="node-meta"]`).exists()).toBe(true)
      expect(localStorage.getItem('billow:proxy-view')).toBe('"list"')
    })

    it('R23: group headers and dense entries name the server a nested chain ends at', async () => {
      const { wrapper } = await mountApp({ longNames: true })
      await connect(wrapper)
      await openPage(wrapper, 'proxies')
      const store = storeOf(wrapper)
      const autoNow = store.snapshot.value.node_catalog.find((group) => group.name === '自动选择')!.now
      expect(autoNow).toBeTruthy()

      const head = wrapper.find('[data-group-card="节点选择"] .group-now')
      expect(head.find('.chain-via').text()).toBe('自动选择')
      expect(head.find('.chain-exit').text()).toBe(autoNow)

      // The entry's caption names how it picks and the server it currently leads to.
      const entry = wrapper.find('[data-group-card="节点选择"] [data-node="自动选择"]')
      expect(entry.find('[data-testid="node-via"] .node-via-target').text()).toBe(`→ ${autoNow}`)
      expect(entry.find('[data-testid="node-via"] .node-via-target').attributes('title')).toBe(autoNow)

      // Home tiles fold the middle hops but keep the server.
      await openPage(wrapper, 'home')
      const tile = wrapper.find('[data-group="漏网之鱼"] [data-testid="home-group-now"]')
      expect(tile.find('.chain-via').text()).toBe('节点选择')
      expect(tile.find('.chain-more').text()).toBe('+1')
      expect(tile.find('.chain-exit').text()).toBe(autoNow)
      expect(tile.find('.chain').attributes('title')).toBe(`节点选择 → 自动选择 → ${autoNow}`)
    })

    it('R24: connections show entry and exit, and the detail lists every hop', async () => {
      const { wrapper } = await mountApp({ longNames: true })
      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await settle(100)
      const store = storeOf(wrapper)
      const autoNow = store.snapshot.value.node_catalog.find((group) => group.name === '自动选择')!.now
      const row = wrapper.findAll('[data-testid="connection-row"]').find((item) => item.find('.chain-via').exists())!
      expect(row).toBeTruthy()
      const chain = row.find('[data-testid="chain-path"]')
      expect(chain.find('.chain-via').text()).toBe('漏网之鱼')
      expect(chain.find('.chain-exit').text()).toBe(autoNow)
      expect(chain.find('.chain-exit').classes()).toContain('outbound-pill')
      expect(chain.attributes('title')).toBe(`漏网之鱼 → 节点选择 → 自动选择 → ${autoNow}`)

      await row.trigger('click')
      await flushPromises()
      const hops = [...document.body.querySelectorAll('[data-testid="chain-steps"] li')]
      expect(hops.map((hop) => hop.querySelector('.chain-step-name')?.textContent)).toEqual(['漏网之鱼', '节点选择', '自动选择', autoNow])
      expect(hops[3]?.classList.contains('exit')).toBe(true)
      expect(hops[3]?.textContent).toContain('出口')
    })

    it('R24: the phone hero pill names only the server', async () => {
      const { wrapper } = await mountApp({ longNames: true, platform: 'android' }, 390)
      await connect(wrapper)
      const store = storeOf(wrapper)
      const autoNow = store.snapshot.value.node_catalog.find((group) => group.name === '自动选择')!.now
      const pill = wrapper.find('[data-testid="hero-node-pill"]')
      expect(pill.find('.chain-via').exists()).toBe(false)
      expect(pill.find('.chain-exit').text()).toBe(autoNow)
    })
  })

  describe('workflow efficiency and boundary states', () => {
    const body = () => new DOMWrapper(document.body)

    it('switches nodes and profiles directly from the command palette search', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      const store = storeOf(wrapper)

      await wrapper.find('[data-testid="open-palette"]').trigger('click')
      await flushPromises()
      const input = body().find('.palette-search input')
      await input.setValue('日本 02')
      await flushPromises()
      await input.trigger('keydown', { key: 'Enter' })
      await settle(400)
      expect(store.snapshot.value.node_catalog.find((g) => g.name === '节点选择')!.now).toBe('日本 02')

      await wrapper.find('[data-testid="open-palette"]').trigger('click')
      await flushPromises()
      const input2 = body().find('.palette-search input')
      await input2.setValue('备用机场')
      await flushPromises()
      await input2.trigger('keydown', { key: 'Enter' })
      await settle(800)
      expect(store.snapshot.value.active_id).toBe('p2')
    })

    it('warns on the proxy page when in direct mode and matches 3+ char protocol/tag prefixes without false positives', async () => {
      const { wrapper } = await mountApp()
      const store = storeOf(wrapper)
      void store.setMode('direct')
      await settle(300)
      await openPage(wrapper, 'proxies')

      const directBar = wrapper.find('[data-testid="proxies-direct-bar"]')
      expect(directBar.exists()).toBe(true)
      await directBar.find('[data-testid="proxies-switch-rule"]').trigger('click')
      await settle(300)
      expect(store.snapshot.value.mode).toBe('rule')
      expect(wrapper.find('[data-testid="proxies-direct-bar"]').exists()).toBe(false)

      // "real" matches Reality-tagged VLESS nodes; "ss" stays exact so VLESS is not matched.
      await wrapper.find('[data-testid="node-search"]').setValue('real')
      await flushPromises()
      const realNodes = wrapper.findAll('[data-group-card="节点选择"] .node')
      expect(realNodes.length).toBeGreaterThan(0)
      expect(realNodes.every((n) => n.text().includes('Reality'))).toBe(true)

      await wrapper.find('[data-testid="node-search"]').setValue('ss')
      await flushPromises()
      const ssNodes = wrapper.findAll('[data-group-card="节点选择"] .node')
      expect(ssNodes.length).toBeGreaterThan(0)
      expect(ssNodes.some((n) => n.text().includes('VLESS'))).toBe(false)
    })

    it('filters temporarily disabled rules and auto-resets when the last one is re-enabled, and sorts from column headers', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'rules')
      await settle(500)

      expect(wrapper.find('[data-testid="rule-disabled-filter"]').exists()).toBe(false)
      await wrapper.findAll('[data-testid="rule-row"]')[0]!.find('[data-testid="rule-toggle"]').trigger('click')
      await settle(300)

      const chip = wrapper.find('[data-testid="rule-disabled-filter"]')
      expect(chip.text()).toBe('已禁用 1')
      await chip.trigger('click')
      await flushPromises()
      expect(wrapper.findAll('[data-testid="rule-row"]')).toHaveLength(1)

      // Re-enabling the sole disabled rule exits the filter instead of stranding on no-match.
      await wrapper.find('[data-testid="rule-row"] [data-testid="rule-toggle"]').trigger('click')
      await settle(300)
      expect(wrapper.find('[data-testid="rule-disabled-filter"]').exists()).toBe(false)
      expect(wrapper.findAll('[data-testid="rule-row"]').length).toBeGreaterThan(1)

      // Sequence numbers (#) are omitted; column header sort toggles hits descending and back to default order.
      expect(wrapper.find('.rule-index').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rule-sort-order"]').exists()).toBe(false)
      const defaultFirst = wrapper.findAll('[data-testid="rule-row"]')[0]!.find('.rule-payload').text()
      await wrapper.find('[data-testid="rule-sort-hits"]').trigger('click')
      await flushPromises()
      const firstHit = Number(wrapper.findAll('[data-testid="rule-row"]')[0]!.find('[data-rule-hit]').text().replace(/,/g, ''))
      expect(firstHit).toBe(1204)
      await wrapper.find('[data-testid="rule-sort-hits"]').trigger('click')
      await flushPromises()
      expect(wrapper.findAll('[data-testid="rule-row"]')[0]!.find('.rule-payload').text()).toBe(defaultFirst)
    })

    it('jumps from connection detail to its entry proxy group', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await settle(500)

      const proxied = wrapper.findAll('[data-testid="connection-row"]').find((r) => !r.text().includes('DIRECT'))!
      await proxied.trigger('click')
      await flushPromises()
      const jump = body().find('[data-testid="open-conn-group"]')
      expect(jump.exists()).toBe(true)
      await jump.trigger('click')
      await flushPromises()
      expect(storeOf(wrapper).page.value).toBe('proxies')
      expect(body().find('.modal').exists()).toBe(false)
    })

    it('opens overrides in one click from profile cards or error banners, and saves dirty settings with Ctrl+S', async () => {
      const { wrapper, backend } = await mountApp()
      const saveSpy = vi.spyOn(backend, 'saveSettings')
      const store = storeOf(wrapper)
      void store.saveOverride('p1', '+rules:\n  - DOMAIN-SUFFIX,example.com,DIRECT\n')
      await settle(300)

      await openPage(wrapper, 'profiles')
      const quickTag = wrapper.find('[data-profile="p1"] [data-testid="quick-override"]')
      expect(quickTag.exists()).toBe(true)
      await quickTag.trigger('click')
      await settle(200)
      expect(body().find('.modal').text()).toContain('覆写 · 星河云')
      await body().find('[data-testid="cancel-editor"]').trigger('click')
      await flushPromises()

      // Settings editors: Ctrl+S saves the open dialog; clear-bypass empties the list.
      store.openSettings('proxy')
      await flushPromises()
      await wrapper.find('[data-testid="open-bypass"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="add-default-bypass"]').trigger('click')
      expect(body().findAll('[data-testid="bypass-list"] li').length).toBeGreaterThan(0)
      await body().find('[data-testid="clear-bypass"]').trigger('click')
      expect(body().find('[data-testid="bypass-list"]').exists()).toBe(false)

      await body().find('[data-testid="bypass-add-input"]').setValue('*.corp.internal')
      await body().find('[data-testid="bypass-add-btn"]').trigger('click')
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 's', ctrlKey: true, bubbles: true, cancelable: true }))
      await settle(400)
      expect(saveSpy).toHaveBeenCalled()
      expect(store.snapshot.value.settings.system_proxy.bypass).toEqual(['*.corp.internal'])
      expect(body().find('[data-testid="save-bypass"]').exists()).toBe(false)
    })

    it('resolves nested group latency on Home & Proxies and uses full-width mobile group rows', async () => {
      const { wrapper } = await mountApp({ longNames: true, platform: 'android' }, 390)
      await connect(wrapper)
      await wrapper.find('[data-testid="home-test-all"]').trigger('click')
      await settle(3000)

      // 漏网之鱼 → 节点选择 → 自动选择 → exit server: nested group inherits exit server delay instead of "—".
      const primaryDelay = wrapper.find('[data-group="节点选择"] [data-testid="home-group-delay"]').text()
      const nestedCard = wrapper.find('[data-group="漏网之鱼"]')
      expect(primaryDelay).toMatch(/^\d+ ms$/)
      expect(nestedCard.find('[data-testid="home-group-delay"]').text()).toBe(primaryDelay)
      expect(nestedCard.find('.group-row-head').exists()).toBe(true)
      expect(nestedCard.find('.group-row-side').exists()).toBe(true)
    })

    it('displays upstream transit hops for chained proxies across Home, Proxies and Connections', async () => {
      const { wrapper } = await mountApp({ longNames: true })
      await connect(wrapper)
      const store = storeOf(wrapper)
      const chainedName = DEMO_LONG_NAMES[2]!

      void store.selectNode('节点选择', chainedName)
      await settle(400)

      // Home tile shows both the transit server (香港 01) and the landing exit server with 链式 badge.
      const homeTile = wrapper.find('[data-group="漏网之鱼"] [data-testid="home-group-now"]')
      expect(homeTile.find('[data-testid="chain-relay-badge"]').text()).toBe('链式')
      expect(homeTile.find('[data-testid="chain-relay"]').text()).toBe('香港 01')
      expect(homeTile.find('.chain-exit').text()).toBe(chainedName)

      // Proxies card annotates the chained node with its dialer-proxy target.
      await openPage(wrapper, 'proxies')
      const nodeCard = wrapper.find(`[data-group-card="节点选择"] [data-node="${CSS.escape(chainedName)}"]`)
      expect(nodeCard.find('.node-tag.chained').text()).toBe('链式 · 香港 01')

      // Connections generated after switching resolve the transit hop and label roles in detail steps.
      await settle(2500)
      await openPage(wrapper, 'connections')
      await settle(500)
      const chainedRow = wrapper.findAll('[data-testid="connection-row"]').find((row) =>
        row.find('[data-testid="chain-relay-badge"]').exists(),
      )
      expect(chainedRow).toBeTruthy()
      await chainedRow!.trigger('click')
      await flushPromises()
      const steps = [...document.body.querySelectorAll('[data-testid="chain-steps"] li')]
      expect(steps.some((li) => li.classList.contains('relay') && li.textContent?.includes('中转'))).toBe(true)
      expect(steps.some((li) => li.textContent?.includes('策略组'))).toBe(true)
      expect(steps.at(-1)?.textContent).toContain('出口')
    })

    it('records closed connections, inspects them, and copies or writes Mihomo rules while skipping Fake-IP', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)

      // Inject deterministic Fake-IP and real-IP connections, then close one to populate history.
      const origState = backend.state.bind(backend)
      let phase: 'both' | 'one' = 'both'
      backend.state = async () => {
        const snap = await origState()
        const fakeRow = {
          id: 'c-fake',
          host: 'api.openai.com',
          outbound: '美国 01',
          network: 'tcp',
          conn_type: 'HTTPS',
          destination: '198.18.0.42:443',
          source: '127.0.0.1:52100',
          process: '/Applications/Cursor.app/Contents/MacOS/Cursor',
          rule: 'DomainSuffix',
          rule_payload: 'openai.com',
          chains: ['美国 01', 'OpenAI'],
          upload: 2048,
          download: 16384,
          start: new Date(Date.now() - 8000).toISOString(),
        }
        const realRow = {
          id: 'c-real',
          host: 'cdn.example.co.uk',
          outbound: '香港 01',
          network: 'tcp',
          conn_type: 'HTTPS',
          destination: '104.21.8.9:443',
          source: '127.0.0.1:52101',
          process: 'curl',
          rule: 'Match',
          rule_payload: '',
          chains: ['香港 01', '节点选择'],
          upload: 512,
          download: 4096,
          start: new Date(Date.now() - 5000).toISOString(),
        }
        return {
          ...snap,
          connections: phase === 'both' ? [fakeRow, realRow] : [realRow],
          connection_total: phase === 'both' ? 2 : 1,
        }
      }

      await openPage(wrapper, 'connections')
      await settle(1200)
      storeOf(wrapper).clearClosedConnections()
      phase = 'one'
      await settle(1200)

      // Switch to 已关闭 tab and inspect the ended Fake-IP connection.
      const tabBar = wrapper.find('[data-testid="connection-tab"]')
      expect(tabBar.text()).toContain('已关闭 1')
      await tabBar.findAll('button')[1]!.trigger('click')
      await flushPromises()

      const closedRows = wrapper.findAll('[data-testid="connection-row"]')
      expect(closedRows).toHaveLength(1)
      expect(closedRows[0]!.text()).toContain('api.openai.com')

      await closedRows[0]!.trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="detail-disconnected"]').text()).toContain('关闭于')
      expect(body().find('.modal').text()).toContain('Fake-IP')
      // Fake-IP 198.18.0.42 must NOT produce a broken IP-CIDR rule.
      expect(body().find('[data-testid="copy-rule-ip-cidr"]').exists()).toBe(false)
      expect(body().find('[data-testid="copy-rule-domain-suffix"]').text()).toContain('DOMAIN-SUFFIX,openai.com,DIRECT')
      expect(body().find('[data-testid="copy-rule-process"]').text()).toContain('PROCESS-NAME,Cursor,DIRECT')

      // Switch target policy to OpenAI and copy the generated rule.
      await body().find('[data-testid="rule-policy-OpenAI"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="copy-rule-domain-suffix"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenLastCalledWith('DOMAIN-SUFFIX,openai.com,OpenAI')

      // One-click write to active profile override opens the override editor with +rules.
      await body().find('[data-testid="write-rule-domain"]').trigger('click')
      await settle(250)
      expect(storeOf(wrapper).page.value).toBe('profiles')
      expect(body().find('.modal').text()).toContain('覆写 · 星河云')
      await body().find('[data-testid="cancel-editor"]').trigger('click')
      await flushPromises()
      if (body().find('.modal').exists()) {
        // Confirm discarding unsaved draft if prompted.
        const buttons = body().findAll('.modal .btn')
        await buttons.at(-1)!.trigger('click')
        await flushPromises()
      }
    })

    it('persists auto-connect kernel startup setting on desktop and phone', async () => {
      const { wrapper, backend } = await mountApp()
      const saveSpy = vi.spyOn(backend, 'saveSettings')
      await openPage(wrapper, 'settings')
      const toggle = wrapper.find('[data-testid="auto-connect-toggle"]')
      expect(toggle.exists()).toBe(true)
      expect(storeOf(wrapper).snapshot.value.settings.auto_connect).toBe(false)
      await toggle.trigger('click')
      await settle(300)
      expect(saveSpy).toHaveBeenCalled()
      expect(storeOf(wrapper).snapshot.value.settings.auto_connect).toBe(true)
    })

    it('renders custom desktop SelectField popover with search, keyboard navigation, and Escape dismissal', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'rules')
      await settle(500)

      const trigger = wrapper.find('[data-testid="rule-proxy-filter"]')
      expect(trigger.element.tagName).toBe('BUTTON')
      await trigger.trigger('click')
      await flushPromises()

      const popover = body().find('[data-testid="select-popover"]')
      expect(popover.exists()).toBe(true)

      // Escape closes the popover without mutating the filter.
      popover.element.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
      await flushPromises()
      expect(body().find('[data-testid="select-popover"]').exists()).toBe(false)

      // Keyboard ArrowDown + Enter chooses an option cleanly.
      await trigger.trigger('click')
      await flushPromises()
      const directOption = body().find('[data-testid="select-popover"] [data-option-value="DIRECT"]')
      expect(directOption.exists()).toBe(true)
      await directOption.trigger('click')
      await flushPromises()
      expect(trigger.classes()).toContain('filtered')
      expect(wrapper.findAll('[data-testid="rule-row"]').every((row) => row.text().includes('DIRECT'))).toBe(true)
    })

    it('supports dragging column dividers to resize and double-clicking to reset in Connections and Rules', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await settle(1100)

      const hostCol = () => wrapper.find('.conn-table colgroup col').attributes('style') ?? ''
      expect(hostCol()).toContain('214px')

      const resizer = wrapper.find('[data-testid="col-resize-host"]')
      resizer.element.dispatchEvent(new MouseEvent('pointerdown', { clientX: 200, bubbles: true }))
      expect(document.documentElement.getAttribute('data-col-resizing')).toBe('true')
      window.dispatchEvent(new MouseEvent('mousemove', { clientX: 340, bubbles: true }))
      window.dispatchEvent(new MouseEvent('mouseup', { clientX: 340, bubbles: true }))
      await flushPromises()

      expect(document.documentElement.getAttribute('data-col-resizing')).toBeNull()
      expect(hostCol()).toContain('354px')
      expect(JSON.parse(localStorage.getItem('billow:cols:connections') ?? '{}').host).toBe(354)

      // Double-click resets the column back to its default width.
      await resizer.trigger('dblclick')
      await flushPromises()
      expect(hostCol()).toContain('214px')

      // Rules table columns also resize and persist cleanly.
      await openPage(wrapper, 'rules')
      await settle(500)
      const kindResizer = wrapper.find('[data-testid="col-resize-rule-kind"]')
      kindResizer.element.dispatchEvent(new MouseEvent('pointerdown', { clientX: 160, bubbles: true }))
      window.dispatchEvent(new MouseEvent('mousemove', { clientX: 220, bubbles: true }))
      window.dispatchEvent(new MouseEvent('mouseup', { clientX: 220, bubbles: true }))
      await flushPromises()
      expect(wrapper.find('[data-testid="rule-scroll"]').attributes('style')).toContain('--col-rule-kind: 184px')
      expect(JSON.parse(localStorage.getItem('billow:cols:rules') ?? '{}').kind).toBe(184)
    })

    it('updates subscriptions and rule sets concurrently with load limits and retries only failed items', async () => {
      const backend = createDemoBackend({ manyProviders: true })
      let inFlight = 0
      let maxInFlight = 0
      let failTelegram = true
      const origProviderAction = backend.providerAction.bind(backend)
      backend.providerAction = async (kind, name, action) => {
        inFlight += 1
        maxInFlight = Math.max(maxInFlight, inFlight)
        try {
          await new Promise((resolve) => setTimeout(resolve, 250))
          if (kind === 'rule' && name === 'telegram' && failTelegram) {
            throw new Error('上游节点限流 429')
          }
          return await origProviderAction(kind, name, action)
        } finally {
          inFlight -= 1
        }
      }

      vi.useFakeTimers()
      const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
      mounted.push(wrapper)
      await settle(50)
      await connect(wrapper)
      await openPage(wrapper, 'resources')
      await settle(500)

      await wrapper.find('[data-testid="update-all-rule"]').trigger('click')
      await settle(80)
      // Bounded rule-provider concurrency (exact cap = 4 across 15 rule sets) instead of 1-by-1 serial or unbounded flood.
      expect(maxInFlight).toBe(4)
      // Pending row shows only one spinner (in the action button), never two.
      expect(wrapper.find('[data-provider="Apple"]').findAll('.spinner')).toHaveLength(1)

      await settle(6000)
      expect(wrapper.find('[data-provider="telegram"] [data-provider-state="error"]').text()).toContain('上游节点限流 429')
      const retryBtn = wrapper.find('[data-testid="retry-failed-rule"]')
      expect(retryBtn.exists()).toBe(true)
      expect(retryBtn.text()).toContain('重试失败 (1)')

      // One-click retry only re-runs the failed rule set.
      failTelegram = false
      const spy = vi.spyOn(backend, 'providerAction')
      await retryBtn.trigger('click')
      await settle(2000)
      expect(spy).toHaveBeenCalledTimes(1)
      expect(spy).toHaveBeenCalledWith('rule', 'telegram', 'update')
      expect(wrapper.find('[data-testid="retry-failed-rule"]').exists()).toBe(false)

      // Subscription refreshAll also runs concurrently and surfaces 1-click 重试失败.
      let failSub = true
      const origRefresh = backend.refresh.bind(backend)
      backend.refresh = async (id) => {
        if (failSub) throw new Error('TLS 握手超时')
        return origRefresh(id)
      }
      await openPage(wrapper, 'profiles')
      await settle(200)
      await wrapper.find('[data-testid="update-all-profiles"]').trigger('click')
      await settle(2500)
      const retrySub = wrapper.find('[data-testid="retry-failed-profiles"]')
      expect(retrySub.exists()).toBe(true)
      failSub = false
      await retrySub.trigger('click')
      await settle(2000)
      expect(wrapper.find('[data-testid="retry-failed-profiles"]').exists()).toBe(false)
    })

    it('matches multi-keyword queries across Proxies, CommandPalette, Rules and Logs, hides timed-out nodes, and copies node/rule text', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })
      const { wrapper, backend } = await mountApp({ longNames: true })
      const flushSpy = vi.spyOn(backend, 'flushCache')
      await connect(wrapper)
      const store = storeOf(wrapper)

      // Multi-keyword proxy search ("香港 iplc") matches non-contiguous tokens and highlights both.
      await openPage(wrapper, 'proxies')
      await wrapper.find('[data-testid="node-search"]').setValue('香港 iplc')
      await flushPromises()
      const matchedNodes = wrapper.findAll('[data-group-card="节点选择"] .node')
      expect(matchedNodes).toHaveLength(1)
      expect(matchedNodes[0]!.findAll('.node-name mark').map((m) => m.text())).toEqual(['香港', 'IPLC'])

      // Right-click on a node card opens ContextMenu and copies its full name via the copy item.
      await matchedNodes[0]!.trigger('contextmenu')
      await flushPromises()
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(true)
      await body().find('[data-testid="context-menu"] [data-menu-item="copy"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenLastCalledWith(DEMO_LONG_NAMES[0])
      await wrapper.find('[data-testid="clear-search"]').trigger('click')

      // Speed test surfaces 隐藏超时 chip and hides timed-out nodes while keeping active selection visible.
      void store.testAll()
      await settle(4000)
      const hideChip = wrapper.find('[data-testid="hide-failed-nodes"]')
      expect(hideChip.exists()).toBe(true)
      await hideChip.trigger('click')
      await flushPromises()
      expect(hideChip.attributes('aria-pressed')).toBe('true')
      const unselectedFailed = wrapper
        .findAll('[data-group-card="节点选择"] .node')
        .filter((n) => n.classes().includes('failed-node') && !n.classes().includes('selected'))
      expect(unselectedFailed).toHaveLength(0)

      // Command palette switches nodes in non-primary manual groups ("OpenAI 美国 02") and flushes DNS/FakeIP cache.
      await wrapper.find('[data-testid="open-palette"]').trigger('click')
      await flushPromises()
      const paletteInput = body().find('.palette-search input')
      await paletteInput.setValue('OpenAI 美国 02')
      await flushPromises()
      await paletteInput.trigger('keydown', { key: 'Enter' })
      await settle(400)
      expect(store.snapshot.value.node_catalog.find((g) => g.name === 'OpenAI')!.now).toBe('美国 02')

      await wrapper.find('[data-testid="open-palette"]').trigger('click')
      await flushPromises()
      await body().find('[data-command="action:flush-dns"]').trigger('click')
      await settle(300)
      expect(flushSpy).toHaveBeenCalledWith('dns')

      // Logs level badge filters in 1 click and toggles back to all.
      await openPage(wrapper, 'logs')
      await settle(300)
      const badge = wrapper.find('[data-testid="log-level-badge"]')
      expect(badge.exists()).toBe(true)
      await badge.trigger('click')
      await flushPromises()
      await badge.trigger('click')
      await flushPromises()
    })

    it('jumps from RuleSet rules and connections straight into the rule-set detail modal in Resources, and shows pause bar', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const store = storeOf(wrapper)

      // Rules page: copy rule expression, click rule kind badge to filter, and jump from RuleSet to Resources detail.
      await openPage(wrapper, 'rules')
      await settle(500)
      await wrapper.findAll('[data-testid="rule-copy"]')[0]!.trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenCalledWith(expect.stringContaining(','))

      const kindTag = wrapper.findAll('[data-testid="rule-kind-tag"]').find((b) => b.text() === 'RuleSet')!
      await kindTag.trigger('click')
      await flushPromises()
      expect(wrapper.findAll('[data-testid="rule-row"]').every((r) => r.text().includes('RuleSet'))).toBe(true)

      const jumpProvider = wrapper.find('[data-testid="rule-open-provider"]')
      expect(jumpProvider.exists()).toBe(true)
      await jumpProvider.trigger('click')
      await settle(500)
      expect(store.page.value).toBe('resources')
      expect(body().find('[data-testid="provider-detail"]').exists()).toBe(true)
      expect(body().find('.modal').text()).toContain('telegram')
      await body().find('[data-testid="close-provider-detail"]').trigger('click')
      await flushPromises()

      // Connections page: pause banner with 1-click resume, plus RuleSet connection jump & expanded manual group policies.
      const origState = backend.state.bind(backend)
      backend.state = async () => {
        const snap = await origState()
        return {
          ...snap,
          connections: [
            {
              id: 'c-rs',
              host: 'web.telegram.org',
              outbound: '香港 01',
              network: 'tcp',
              conn_type: 'HTTPS',
              destination: '149.154.167.99:443',
              source: '127.0.0.1:53000',
              process: 'Telegram',
              rule: 'RuleSet',
              rule_payload: 'telegram',
              chains: ['香港 01', '漏网之鱼'],
              upload: 1024,
              download: 8192,
              start: new Date(Date.now() - 4000).toISOString(),
            },
          ],
          connection_total: 1,
        }
      }

      await openPage(wrapper, 'connections')
      await settle(1200)
      await wrapper.find('[data-testid="pause-connections"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-testid="connections-paused-bar"]').exists()).toBe(true)
      await wrapper.find('[data-testid="resume-connections-bar"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-testid="connections-paused-bar"]').exists()).toBe(false)

      await wrapper.find('[data-testid="connection-row"]').trigger('click')
      await flushPromises()
      // Even when matched via 漏网之鱼, primary manual groups (节点选择, OpenAI) are offered for rule generation.
      expect(body().find('[data-testid="rule-policy-节点选择"]').exists()).toBe(true)
      expect(body().find('[data-testid="rule-policy-OpenAI"]').exists()).toBe(true)
      const rulesetChip = body().find('[data-testid="open-conn-ruleset"]')
      expect(rulesetChip.exists()).toBe(true)
      await rulesetChip.trigger('click')
      await settle(500)
      expect(store.page.value).toBe('resources')
      expect(body().find('[data-testid="provider-detail"]').exists()).toBe(true)
    })

    it('renders unlimited-bandwidth subscription expiry, Home takeover/direct cues, expandable groups, and mobile SelectField search', async () => {
      const { wrapper, backend } = await mountApp({ big: true })
      const origState = backend.state.bind(backend)
      const soonExpire = Math.floor(Date.now() / 1000) + 3 * 86400
      backend.state = async () => {
        const snap = await origState()
        return {
          ...snap,
          profiles: snap.profiles.map((p) =>
            p.id === 'p1' ? { ...p, used: null, total: null, expire: soonExpire } : p,
          ),
        }
      }
      const store = storeOf(wrapper)
      await store.refresh()
      await flushPromises()

      // Unlimited-bandwidth subscription still displays expiry date and 不限流量 on Home and Profiles.
      expect(wrapper.find('[data-testid="profile-card"]').text()).toContain('不限流量')
      expect(wrapper.find('[data-testid="profile-card"]').text()).toContain('到期')
      await openPage(wrapper, 'profiles')
      expect(wrapper.find('[data-profile="p1"]').text()).toContain('不限流量')
      expect(wrapper.find('[data-profile="p1"]').text()).toContain('到期')
      await openPage(wrapper, 'home')

      // Expandable groups on Home when >8 manual groups exist.
      expect(wrapper.findAll('[data-testid="groups-card"] .group-row')).toHaveLength(8)
      const expandBtn = wrapper.find('[data-testid="home-groups-expand"]')
      expect(expandBtn.exists()).toBe(true)
      await expandBtn.trigger('click')
      await flushPromises()
      expect(wrapper.findAll('[data-testid="groups-card"] .group-row').length).toBeGreaterThan(8)

      // Direct mode hero offers 1-click return to rule mode.
      void store.setMode('direct')
      await settle(300)
      const switchRule = wrapper.find('[data-testid="home-switch-rule"]')
      expect(switchRule.exists()).toBe(true)
      await switchRule.trigger('click')
      await settle(300)
      expect(store.snapshot.value.mode).toBe('rule')

      // Mobile SelectField sheet renders a search input when options > 8.
      const phone = await mountApp({ platform: 'android' }, 390)
      const origRules = phone.backend.rules.bind(phone.backend)
      phone.backend.rules = async () => {
        const res = await origRules()
        return {
          ...res,
          rules: Array.from({ length: 10 }, (_, idx) => ({
            kind: idx === 0 ? 'RuleSet' : `DomainType${idx}`,
            payload: `p${idx}`,
            proxy: 'DIRECT',
            hit_count: idx,
            last_hit: null,
            key: `k${idx}`,
            disabled: false,
          })),
        }
      }
      void storeOf(phone.wrapper).connect()
      await settle(1500)
      storeOf(phone.wrapper).go('rules')
      await settle(500)
      await phone.wrapper.find('[data-testid="rule-kind-filter"]').trigger('click')
      await flushPromises()
      const sheetSearch = body().find('[data-testid="select-sheet-search"]')
      expect(sheetSearch.exists()).toBe(true)
      await sheetSearch.setValue('RuleSet')
      await flushPromises()
      expect(body().findAll('.modal .option-row')).toHaveLength(1)
    })

    it('grants Tauri ACL permissions and main-window capabilities for every registered command', () => {
      const root = resolve(process.cwd(), 'src-tauri')
      const libRs = readFileSync(resolve(root, 'src/lib.rs'), 'utf8')
      const handlerMatch = /tauri::generate_handler!\[([\s\S]*?)\]/.exec(libRs)
      expect(handlerMatch).toBeTruthy()
      const commands = handlerMatch![1]!
        .split(',')
        .map((entry) => entry.replace(/\/\/.*$/, '').trim())
        .filter(Boolean)
        .map((entry) => entry.split('::').pop()!)
      expect(commands).toContain('preview_profile_override')
      expect(commands).toContain('set_profile_age_key')
      expect(commands).toContain('export_logs')

      const permDir = resolve(root, 'permissions')
      const permByCommand = new Map<string, string>()
      for (const file of readdirSync(permDir).filter((name) => name.endsWith('.toml'))) {
        const text = readFileSync(resolve(permDir, file), 'utf8')
        for (const block of text.split('[[permission]]').slice(1)) {
          const id = /identifier\s*=\s*"([^"]+)"/.exec(block)?.[1]
          const allow = /commands\.allow\s*=\s*\[([^\]]+)\]/.exec(block)?.[1]
          if (!id || !allow) continue
          for (const raw of allow.split(',')) {
            const cmd = raw.replace(/["'\s]/g, '')
            if (cmd) permByCommand.set(cmd, id)
          }
        }
      }

      const capDir = resolve(root, 'capabilities')
      const granted = new Set<string>()
      for (const file of readdirSync(capDir).filter((name) => name.endsWith('.json'))) {
        const cap = JSON.parse(readFileSync(resolve(capDir, file), 'utf8')) as {
          windows?: string[]
          permissions?: (string | { identifier: string })[]
        }
        if (!cap.windows?.includes('main')) continue
        for (const perm of cap.permissions ?? []) {
          granted.add(typeof perm === 'string' ? perm : perm.identifier)
        }
      }

      for (const cmd of commands) {
        const permId = permByCommand.get(cmd)
        expect(permId, `Command "${cmd}" is missing from src-tauri/permissions/*.toml`).toBeTruthy()
        expect(granted.has(permId!), `Permission "${permId}" for "${cmd}" is missing from capabilities`).toBe(true)
      }
    })

    it('filters connections by outbound route, opens row context menus, and blocks WebView chrome menus', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await settle(1100)

      // Global contextmenu guard blocks browser Back/Reload on non-editable elements, but spares inputs.
      const blocked = new MouseEvent('contextmenu', { bubbles: true, cancelable: true })
      wrapper.find('.page-head h1').element.dispatchEvent(blocked)
      expect(blocked.defaultPrevented).toBe(true)

      const allowed = new MouseEvent('contextmenu', { bubbles: true, cancelable: true })
      wrapper.find('[data-testid="connection-search"]').element.dispatchEvent(allowed)
      expect(allowed.defaultPrevented).toBe(false)

      // Route filter segments cleanly isolate proxied vs DIRECT connections.
      const routeBar = wrapper.find('[data-testid="connection-route-filter"]')
      expect(routeBar.exists()).toBe(true)
      const buttons = routeBar.findAll('button')
      await buttons[2]!.trigger('click') // 直连
      await flushPromises()
      const directRows = wrapper.findAll('[data-testid="connection-row"]')
      expect(directRows.length).toBeGreaterThan(0)
      expect(directRows.every((row) => row.text().includes('DIRECT'))).toBe(true)

      await buttons[1]!.trigger('click') // 代理
      await flushPromises()
      const proxyRows = wrapper.findAll('[data-testid="connection-row"]')
      expect(proxyRows.length).toBeGreaterThan(0)
      expect(proxyRows.every((row) => !row.text().includes('DIRECT'))).toBe(true)

      // Right-clicking a connection row opens the custom context menu and copies host.
      await proxyRows[0]!.trigger('contextmenu', { clientX: 240, clientY: 180 })
      await flushPromises()
      const ctx = body().find('[data-testid="context-menu"]')
      expect(ctx.exists()).toBe(true)
      await ctx.find('[data-menu-item="copy-host"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenCalled()
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(false)

      // Rules page policy tags (DIRECT) also toggle policy filtering and support row context menu.
      await openPage(wrapper, 'rules')
      await settle(500)
      const directTag = wrapper.find('[data-testid="rule-proxy-filter-tag"]')
      expect(directTag.exists()).toBe(true)
      await directTag.trigger('click')
      await flushPromises()
      expect(wrapper.findAll('[data-testid="rule-row"]').every((row) => row.text().includes('DIRECT'))).toBe(true)
      await wrapper.findAll('[data-testid="rule-row"]')[0]!.trigger('contextmenu', { clientX: 200, clientY: 200 })
      await flushPromises()
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(true)
      await body().find('[data-menu-item="copy"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenCalledTimes(2)
    })

    it('merges connection rules into an existing +rules override without duplicating YAML keys', async () => {
      const { wrapper } = await mountApp()
      const store = storeOf(wrapper)
      void store.saveOverride(
        'p1',
        ['+rules:', '  - DOMAIN-SUFFIX,e6gpshk.com,DIRECT', '  - DOMAIN,g7e6ai.com,DIRECT', ''].join('\n'),
      )
      await settle(300)
      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await settle(1100)

      await wrapper.find('[data-testid="connection-row"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="detail-stats"]').exists()).toBe(true)

      const writeBtn = body().find('[data-testid^="write-rule-"]')
      expect(writeBtn.exists()).toBe(true)
      await writeBtn.trigger('click')
      await settle(300)

      expect(store.page.value).toBe('profiles')
      const modalText = body().find('.modal').text()
      expect(modalText).toContain('覆写 · 星河云')
      // Preview works cleanly without duplicate +rules keys.
      await body().find('[data-testid="override-preview"]').trigger('click')
      await settle(300)
      const previewPanel = body().find('[data-testid="override-preview-panel"]')
      expect(previewPanel.exists()).toBe(true)
      expect(previewPanel.text()).toContain('合并结果')
    })

    it('provides copy feedback on home port pill, one-click fastest node pick, and connections toolbar reset', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
      const { wrapper } = await mountApp()
      const store = storeOf(wrapper)
      await connect(wrapper)

      // Home port pill gives immediate copied feedback and resets after 1.6s.
      const portBtn = wrapper.find('[data-testid="copy-proxy-cmd"]')
      expect(portBtn.exists()).toBe(true)
      await portBtn.trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenCalled()
      expect(portBtn.classes()).toContain('copied')
      await settle(1700)
      expect(portBtn.classes()).not.toContain('copied')

      // Proxies manual group offers 选最快 after testing when a faster proxy exists.
      await openPage(wrapper, 'proxies')
      void store.testGroup('节点选择')
      await settle(3000)
      const pickFastestBtn = wrapper.find('[data-testid="pick-fastest-节点选择"]')
      expect(pickFastestBtn.exists()).toBe(true)
      await pickFastestBtn.trigger('click')
      await settle(300)
      // Once switched to the fastest proxy node, the button hides cleanly.
      expect(wrapper.find('[data-testid="pick-fastest-节点选择"]').exists()).toBe(false)

      // Connections toolbar reset clears combined route + search filters in one click.
      await openPage(wrapper, 'connections')
      await settle(1100)
      expect(wrapper.find('[data-testid="reset-connection-toolbar"]').exists()).toBe(false)
      await wrapper.find('[data-testid="connection-search"]').setValue('example')
      await flushPromises()
      const resetBtn = wrapper.find('[data-testid="reset-connection-toolbar"]')
      expect(resetBtn.exists()).toBe(true)
      await resetBtn.trigger('click')
      await flushPromises()
      expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('')
      expect(wrapper.find('[data-testid="reset-connection-toolbar"]').exists()).toBe(false)
    })

    it('opens the redesigned in-app UWP loopback manager on Windows and saves exemption changes', async () => {
      const { wrapper } = await mountApp({ os: 'windows' })
      const store = storeOf(wrapper)
      store.openSettings('proxy')
      await flushPromises()

      const openBtn = wrapper.find('[data-testid="open-uwp-tool"]')
      expect(openBtn.exists()).toBe(true)
      await openBtn.trigger('click')
      await settle(200)

      expect(body().find('[data-testid="uwp-dialog"]').exists()).toBe(true)
      const rows = body().findAll('[data-testid="uwp-row"]')
      expect(rows.length).toBeGreaterThanOrEqual(3)

      // Toggle Windows Terminal to exempted, verify dirty counter, then save.
      const terminalRow = body().find('[data-uwp-family="Microsoft.WindowsTerminal_8wekyb3d8bbwe"]')
      expect(terminalRow.exists()).toBe(true)
      expect(terminalRow.attributes('aria-pressed')).toBe('false')
      await terminalRow.trigger('click')
      await flushPromises()
      expect(terminalRow.attributes('aria-pressed')).toBe('true')
      expect(body().find('[data-testid="uwp-dirty-count"]').text()).toContain('1')

      await body().find('[data-testid="uwp-save"]').trigger('click')
      await settle(200)
      expect(body().find('[data-testid="uwp-dirty-count"]').exists()).toBe(false)
      expect(body().find('[data-uwp-family="Microsoft.WindowsTerminal_8wekyb3d8bbwe"]').attributes('aria-pressed')).toBe('true')
    })
  })
})
