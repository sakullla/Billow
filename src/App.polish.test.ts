import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'

// Regression coverage for docs/requirements/2026-11-08-ui-ux-polish.md (R1–R8).

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
  it('R1: home group cards show the group type and a delay slot that never fakes a value', async () => {
    const { wrapper } = await mountApp()
    const card = () => wrapper.find('[data-testid="groups-card"] [data-group="节点选择"]')
    expect(card().find('[data-testid="home-group-type"]').text()).toBe('手选')
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

  it('R3: desktop proxy view controls carry text and a pressed state', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'proxies')
    expect(wrapper.find('[data-testid="toggle-dense"]').text()).toContain('紧凑')
    expect(wrapper.find('[data-testid="locate-active-node"]').text()).toContain('定位')

    const dense = wrapper.find('[data-testid="toggle-dense"]')
    expect(dense.attributes('aria-pressed')).toBe('false')
    await dense.trigger('click')
    expect(wrapper.find('[data-testid="toggle-dense"]').attributes('aria-pressed')).toBe('true')
    expect(wrapper.find('[data-testid="toggle-dense"]').classes()).toContain('active')
    expect(wrapper.find('[data-testid="toggle-dense"]').attributes('aria-label')).toBe('紧凑视图')

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
    expect(wrapper.find('[data-group="节点选择"] [data-testid="home-group-now"]').text()).toBe(`自动选择 → ${autoNow}`)
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
    expect(line.findAll('.group-info-item').map((item) => item.text())).toEqual([
      'Traffic Reset：17 Days Left',
      '4.49 GB | 500 GB',
      '剩余流量：120 GB',
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
      expect(document.activeElement).toBe(body().find('[data-testid="age-input"]').element)
    })
  })
})
