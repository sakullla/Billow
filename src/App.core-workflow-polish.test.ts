import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import { locale } from './lib/i18n'
import type { Store } from './lib/store'
import type { Snapshot } from './lib/types'
import { layerDepth } from './lib/ui/focus'
import { applyInsets } from './lib/ui/insets'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

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

function body() {
  return new DOMWrapper(document.body)
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

async function hardwareBack() {
  window.history.back()
  await settle(30)
}

async function openPage(wrapper: Wrapper, page: string) {
  const desktopBtn = wrapper.find(`.sidebar [data-page="${page}"]`)
  if (desktopBtn.exists()) {
    await desktopBtn.trigger('click')
  } else {
    storeOf(wrapper).go(page as Parameters<Store['go']>[0])
  }
  await settle(100)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  applyInsets({ top: 0, right: 0, bottom: 0, left: 0, ime: 0 })
  document.documentElement.removeAttribute('data-theme')
  locale.value = 'zh-CN'
  localStorage.clear()
  vi.useRealTimers()
})

describe('Core workflow polish (R1–R2)', () => {
  describe('R1: Home in-place NodePickerModal', () => {
    it('opens from hero-node-pill and group-row in place, filters nodes, tests group, picks fastest, and links to proxies', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const testGroupSpy = vi.spyOn(backend, 'testGroup')
      const selectNodeSpy = vi.spyOn(backend, 'selectNode')

      // Open from hero-node-pill without leaving Home
      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('.main').attributes('data-page')).toBe('home')
      expect(body().find('[data-testid="home-node-picker"]').attributes('data-group')).toBe('节点选择')

      // Search filter + highlight + no-match reset
      const search = body().find('[data-testid="node-picker-search"]')
      await search.setValue('日本')
      await flushPromises()
      const rows = body().findAll('[data-picker-node]')
      expect(rows.length).toBeGreaterThan(0)
      expect(rows.every((row) => row.attributes('data-picker-node')?.includes('日本'))).toBe(true)
      expect(body().find('.node-picker-name mark').text()).toBe('日本')

      await search.setValue('不存在的节点关键字')
      await flushPromises()
      expect(body().find('[data-testid="node-picker-empty"]').exists()).toBe(true)
      await body().find('[data-testid="node-picker-clear-filter"]').trigger('click')
      await flushPromises()
      expect(body().findAll('[data-picker-node]').length).toBeGreaterThan(1)

      // Single-group latency test
      await body().find('[data-testid="node-picker-test"]').trigger('click')
      await settle(1500)
      expect(testGroupSpy).toHaveBeenCalledWith('节点选择')

      // Pick fastest candidate if available (after testGroup delays are populated)
      const fastestBtn = body().find('[data-testid="node-picker-fastest"]')
      if (fastestBtn.exists()) {
        await fastestBtn.trigger('click')
        await settle(500)
        expect(selectNodeSpy).toHaveBeenCalled()
        expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      }

      // Open from a group-row card and navigate to proxies via footer action
      await wrapper.find('[data-testid="groups-card"] [data-group="流媒体"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="home-node-picker"]').attributes('data-group')).toBe('流媒体')
      await body().find('[data-testid="node-picker-open-proxies"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
      expect(wrapper.find('[data-group-card="流媒体"]').classes()).toContain('open')
    })

    it('clears search on Escape before closing and picks the sole matching node on Enter', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const selectSpy = vi.spyOn(backend, 'selectNode')

      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()
      const search = body().find('[data-testid="node-picker-search"]')
      await search.setValue('日本 01')
      await flushPromises()
      expect(body().findAll('[data-picker-node]')).toHaveLength(1)

      // Escape clears the query while keeping the modal open
      await search.trigger('keydown', { key: 'Escape' })
      await flushPromises()
      expect((search.element as HTMLInputElement).value).toBe('')
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(true)

      // Typing a unique match and pressing Enter picks it immediately
      await search.setValue('日本 01')
      await flushPromises()
      await search.trigger('keydown', { key: 'Enter' })
      await settle(400)
      expect(selectSpy).toHaveBeenCalledWith('节点选择', '日本 01')
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
    })

    it('locks switching against duplicate clicks and close, keeps modal open with inline retry on failure', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const origSelect = backend.selectNode.bind(backend)
      const gate = deferred<Snapshot>()
      const selectSpy = vi
        .spyOn(backend, 'selectNode')
        .mockImplementationOnce(() => gate.promise)
        .mockImplementationOnce((group, node) => origSelect(group, node))

      const initialNow = storeOf(wrapper).snapshot.value.node_catalog.find((g) => g.name === '节点选择')!.now
      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()

      const targetName = '日本 01'
      const targetBtn = () => body().find(`[data-testid="picker-node-${targetName}"]`)
      const otherBtn = () => body().find('[data-testid="picker-node-美国 01"]')

      // Click target, then rapidly click again & another node & try to close via close button
      await targetBtn().trigger('click')
      await targetBtn().trigger('click')
      if (otherBtn().exists()) await otherBtn().trigger('click')
      await body().find('.modal-head .icon-btn').trigger('click')
      await flushPromises()

      expect(selectSpy).toHaveBeenCalledTimes(1)
      expect(selectSpy).toHaveBeenCalledWith('节点选择', targetName)
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(true)
      expect(targetBtn().attributes('aria-busy')).toBe('true')
      expect(body().find('[data-testid="node-picker-switching"]').text()).toContain('切换中')

      // Fail the switch
      gate.reject(new Error('controller rejected node switch'))
      await settle(100)

      // Modal stays open, original node remains active, inline error + retry under failed row
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(true)
      expect(storeOf(wrapper).snapshot.value.node_catalog.find((g) => g.name === '节点选择')!.now).toBe(initialNow)
      expect(body().find('[data-testid="node-picker-error"]').text()).toContain('controller rejected node switch')
      expect(body().find('[data-testid="node-picker-retry"]').exists()).toBe(true)

      // Retry succeeds and closes modal
      await body().find('[data-testid="node-picker-retry"]').trigger('click')
      await settle(400)
      expect(selectSpy).toHaveBeenCalledTimes(2)
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(storeOf(wrapper).snapshot.value.node_catalog.find((g) => g.name === '节点选择')!.now).toBe(targetName)
    })

    it('supports pinning and unfixing an automatic group, and disables test/unfix when disconnected', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const unfixSpy = vi.spyOn(backend, 'unfixGroup')

      // Pin a node in 自动选择
      await wrapper.find('[data-testid="groups-card"] [data-group="自动选择"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="picker-node-日本 01"]').trigger('click')
      await settle(400)
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="groups-card"] [data-group="自动选择"] [data-testid="home-group-fixed"]').exists()).toBe(true)

      // Reopen while disconnected -> test, unfix, and auto-group node rows are disabled with explicit titles
      const selectSpy = vi.spyOn(backend, 'selectNode')
      await wrapper.find('[data-testid="power"]').trigger('click')
      await settle(1200)
      await wrapper.find('[data-testid="groups-card"] [data-group="自动选择"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="node-picker-test"]').attributes('disabled')).toBeDefined()
      expect(body().find('[data-testid="node-picker-unfix"]').attributes('disabled')).toBeDefined()
      expect(body().find('[data-testid="node-picker-offline-hint"]').text()).toContain('连接后才能固定节点')
      const offlineAutoRow = body().find('[data-testid="picker-node-香港 01"]')
      expect(offlineAutoRow.attributes('disabled')).toBeDefined()
      expect(offlineAutoRow.attributes('title')).toContain('内核没有运行，连接后才能固定节点')
      await offlineAutoRow.trigger('click')
      await flushPromises()
      expect(selectSpy).not.toHaveBeenCalled()

      // Close, reconnect, reopen and click 恢复自动
      await body().find('.modal-head .icon-btn').trigger('click')
      await flushPromises()
      await connect(wrapper)
      await wrapper.find('[data-testid="groups-card"] [data-group="自动选择"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="node-picker-unfix"]').attributes('disabled')).toBeUndefined()
      await body().find('[data-testid="node-picker-unfix"]').trigger('click')
      await settle(400)
      expect(unfixSpy).toHaveBeenCalledWith('自动选择')
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="groups-card"] [data-group="自动选择"] [data-testid="home-group-fixed"]').exists()).toBe(false)
    })

    it('supports Android compact sheet + hardware back and English localization', async () => {
      const { wrapper } = await mountApp({ platform: 'android' }, 390)
      locale.value = 'en'
      await flushPromises()
      await connect(wrapper)

      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(true)
      expect(body().find('[data-testid="node-picker-open-proxies"]').attributes('aria-label')).toBe('Open Proxies')

      await hardwareBack()
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(wrapper.find('.main').attributes('data-page')).toBe('home')
    })

    it('renders translated chained tag, nested policy group target, and matches dialer_proxy in search', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      const store = storeOf(wrapper)

      // Inject a chained node with dialer_proxy into 节点选择
      store.snapshot.value = {
        ...store.snapshot.value,
        node_catalog: store.snapshot.value.node_catalog.map((group) =>
          group.name === '节点选择'
            ? {
                ...group,
                nodes: [
                  ...group.nodes,
                  {
                    name: '落地专线 01',
                    delay_ms: 88,
                    failed: false,
                    selected: false,
                    node_type: 'vless',
                    tags: ['UDP', 'chained'],
                    dialer_proxy: '前置中转 HK',
                  },
                ],
              }
            : group,
        ),
      }
      await flushPromises()

      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()

      // Nested policy group entry shows → target
      const nestedRow = body().find('[data-testid="picker-node-自动选择"]')
      expect(nestedRow.exists()).toBe(true)
      const nestedVia = nestedRow.find('[data-testid="picker-node-via"]')
      expect(nestedVia.exists()).toBe(true)
      expect(nestedVia.text()).toContain('→')

      // Chained node translates 'chained' tag (never renders raw 'chained')
      const chainedRow = body().find('[data-testid="picker-node-落地专线 01"]')
      expect(chainedRow.exists()).toBe(true)
      expect(chainedRow.text()).toContain('链式 · 前置中转 HK')
      expect(chainedRow.text()).not.toContain('chained')

      // Search matches dialer_proxy
      const search = body().find('[data-testid="node-picker-search"]')
      await search.setValue('前置中转')
      await flushPromises()
      const filtered = body().findAll('[data-picker-node]')
      expect(filtered.map((el) => el.attributes('data-picker-node'))).toEqual(['落地专线 01'])

      // English localization translates chained tag as well
      locale.value = 'en'
      await flushPromises()
      expect(body().find('[data-testid="picker-node-落地专线 01"]').text()).toContain('Chained · 前置中转 HK')
    })
  })

  describe('Node picker layout (UI/UX R2–R4)', () => {
    it('marks the current node once, keeps actions in the pinned head, and drops the footer', async () => {
      const { wrapper } = await mountApp({}, 390)
      await connect(wrapper)
      await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
      await flushPromises()

      const current = body().find('[data-picker-node][aria-current="true"]')
      expect(current.attributes('data-picker-node')).toBe('香港 01')
      // The 当前 marker stays for screen readers only; no visible badge or check icon.
      expect(current.find('[data-testid="picker-current-tag"]').classes()).toContain('sr-only')
      expect(current.find('.option-check').exists()).toBe(false)
      expect(current.find('.node-picker-name').attributes('style') ?? '').not.toContain('line-clamp')

      // Search, test and open-proxies live in the sticky head; the sheet has no footer bar.
      const head = body().find('[data-testid="node-picker-head"]')
      expect(head.find('.node-picker-toolbar [data-testid="node-picker-search"]').exists()).toBe(true)
      expect(head.find('.node-picker-toolbar [data-testid="node-picker-test"]').exists()).toBe(true)
      expect(head.find('.node-picker-summary [data-testid="node-picker-open-proxies"]').exists()).toBe(true)
      expect(body().find('.modal-foot').exists()).toBe(false)

      // Protocol and capability tags use the proxy page's row vocabulary.
      const meta = current.find('[data-testid="picker-node-meta"]')
      expect(meta.classes()).toContain('node-meta')
      expect(meta.find('.node-type').exists()).toBe(true)
      expect(meta.findAll('.node-tag').map((tag) => tag.text())).toContain('UDP')
    })

    it('keeps the pinned node, status tags and actions in separate summary slots for a fixed group', async () => {
      const { wrapper } = await mountApp({}, 390)
      await connect(wrapper)
      void storeOf(wrapper).selectNode('自动选择', '德国 02')
      await settle(800)
      await wrapper.find('[data-testid="groups-card"] [data-group="自动选择"]').trigger('click')
      await flushPromises()

      const summary = body().find('.node-picker-summary')
      const info = summary.find('.node-picker-summary-body')
      expect(info.text()).toContain('自动')
      expect(info.find('[data-testid="node-picker-fixed-tag"]').text()).toBe('已固定')
      expect(info.find('[data-testid="chain-path"]').text()).toContain('德国 02')
      // Actions sit in their own wrapping group so they never squeeze the chain out.
      const actions = summary.find('.node-picker-summary-actions')
      expect(actions.find('[data-testid="node-picker-unfix"]').exists()).toBe(true)
      expect(actions.find('[data-testid="node-picker-open-proxies"]').exists()).toBe(true)
      expect(info.find('[data-testid="node-picker-unfix"]').exists()).toBe(false)
    })

    it('scrolls the active node into view on open without moving focus on touch screens', async () => {
      const matchMedia = vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({
        matches: query.includes('coarse'),
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as MediaQueryList)
      const original = HTMLElement.prototype.getBoundingClientRect
      const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
        if (this.classList.contains('modal-body')) return { top: 0, bottom: 600, left: 0, right: 390, width: 390, height: 600, x: 0, y: 0, toJSON: () => ({}) } as DOMRect
        if (this.dataset.pickerNode === '香港 01') return { top: 1800, bottom: 1852, left: 0, right: 390, width: 390, height: 52, x: 0, y: 1800, toJSON: () => ({}) } as DOMRect
        return original.call(this)
      })
      const scrolled: string[] = []
      const proto = HTMLElement.prototype as HTMLElement & { scrollIntoView: (arg?: ScrollIntoViewOptions) => void }
      const previous = proto.scrollIntoView
      proto.scrollIntoView = function (this: HTMLElement) {
        scrolled.push(this.dataset.pickerNode ?? '')
      }
      try {
        const { wrapper } = await mountApp({ platform: 'android' }, 390)
        await connect(wrapper)
        await wrapper.find('[data-testid="hero-node-pill"]').trigger('click')
        await settle(50)
        expect(scrolled).toEqual(['香港 01'])
        expect(document.activeElement?.getAttribute('data-picker-node')).toBeNull()
      } finally {
        proto.scrollIntoView = previous
        rect.mockRestore()
        matchMedia.mockRestore()
      }
    })
  })

  describe('R2: Home subscription retry, desktop narrow port copy, and hero state transitions', () => {
    it('shows inline retry for failed subscription profile and hides it for local profile', async () => {
      const { wrapper, backend } = await mountApp()
      const store = storeOf(wrapper)
      const updateSpy = vi.spyOn(backend, 'update')

      // Simulate subscription failure on current profile (p1 is subscription)
      store.snapshot.value = {
        ...store.snapshot.value,
        profiles: store.snapshot.value.profiles.map((p) =>
          p.id === 'p1' ? { ...p, failure: '订阅下载超时' } : p,
        ),
      }
      await flushPromises()

      const retryBtn = wrapper.find('[data-testid="home-profile-retry"]')
      expect(retryBtn.exists()).toBe(true)
      await retryBtn.trigger('click')
      await settle(700)
      expect(updateSpy).toHaveBeenCalledWith('p1')

      // Switch to local profile with failure -> no inline subscription retry button
      store.snapshot.value = {
        ...store.snapshot.value,
        active_id: 'p3',
        profiles: store.snapshot.value.profiles.map((p) =>
          p.id === 'p3'
            ? { ...p, current: true, kind: 'local', failure: '本地配置解析失败' }
            : { ...p, current: false },
        ),
      }
      await flushPromises()
      expect(wrapper.find('[data-testid="profile-card"]').text()).toContain('本地配置解析失败')
      expect(wrapper.find('[data-testid="home-profile-retry"]').exists()).toBe(false)
    })

    it('keeps port copy button on desktop narrow windows while hiding it on Android', async () => {
      // Desktop narrow window (compact = true, isAndroid = false)
      const desktopNarrow = await mountApp({ platform: 'desktop' }, 640)
      await connect(desktopNarrow.wrapper)
      const portBtn = desktopNarrow.wrapper.find('[data-testid="copy-proxy-cmd"]')
      expect(portBtn.exists()).toBe(true)
      await portBtn.trigger('click')
      await flushPromises()
      expect(portBtn.classes()).toContain('copied')

      // Android phone (compact = true, isAndroid = true)
      const androidPhone = await mountApp({ platform: 'android' }, 390)
      await connect(androidPhone.wrapper)
      expect(androidPhone.wrapper.find('[data-testid="copy-proxy-cmd"]').exists()).toBe(false)
    })

    it('reveals and hides connected hero sections cleanly across connect/disconnect', async () => {
      const { wrapper } = await mountApp()
      expect(wrapper.find('[data-testid="rates"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="traffic-card"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="runtime"]').exists()).toBe(false)

      await connect(wrapper)
      expect(wrapper.find('[data-testid="rates"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="traffic-card"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="runtime"]').exists()).toBe(true)

      await wrapper.find('[data-testid="power"]').trigger('click')
      await settle(1200)
      expect(wrapper.find('[data-testid="rates"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="traffic-card"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="runtime"]').exists()).toBe(false)
    })
  })
})

describe('Core workflow polish (R3–R4)', () => {
  describe('R3: ProxiesView ContextMenu, persisted hide-failed preference, and group-pill testing state', () => {
    it('opens unified ContextMenu on desktop node right-click with select/pin, test, copy, and open-auto actions, and stays off on compact', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
      })
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const selectSpy = vi.spyOn(backend, 'selectNode')
      const testNodeSpy = vi.spyOn(backend, 'testNode')

      await openPage(wrapper, 'proxies')

      // Right-click unselected node in manual group -> select, test, copy
      const jpNode = wrapper.find('[data-group-card="节点选择"] [data-node="日本 01"]')
      expect(jpNode.exists()).toBe(true)
      await jpNode.trigger('contextmenu')
      await flushPromises()
      const menu = () => body().find('[data-testid="context-menu"]')
      expect(menu().exists()).toBe(true)
      expect(menu().find('[data-menu-item="pick"]').text()).toContain('选择此节点')
      expect(menu().find('[data-menu-item="pick"]').attributes('aria-disabled')).toBeUndefined()
      expect(menu().find('[data-menu-item="test"]').attributes('aria-disabled')).toBeUndefined()
      expect(menu().find('[data-menu-item="copy"]').text()).toContain('复制节点名称')
      expect(menu().find('[data-menu-item="open-auto"]').exists()).toBe(false)

      // Trigger pick via ContextMenu
      await menu().find('[data-menu-item="pick"]').trigger('click')
      await settle(400)
      expect(selectSpy).toHaveBeenCalledWith('节点选择', '日本 01')
      expect(menu().exists()).toBe(false)

      // Right-click the now-selected node -> pick is disabled with reason; test & copy work
      await wrapper.find('[data-group-card="节点选择"] [data-node="日本 01"]').trigger('contextmenu')
      await flushPromises()
      expect(menu().find('[data-menu-item="pick"]').attributes('aria-disabled')).toBe('true')
      expect(menu().find('[data-menu-item="pick"]').text()).toContain('当前已选')
      await menu().find('[data-menu-item="copy"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenLastCalledWith('日本 01')

      // Trigger single-node latency test via ContextMenu
      await wrapper.find('[data-group-card="节点选择"] [data-node="日本 01"]').trigger('contextmenu')
      await flushPromises()
      await menu().find('[data-menu-item="test"]').trigger('click')
      await settle(600)
      expect(testNodeSpy).toHaveBeenCalledWith('日本 01')

      // Right-click an auto-group entry (自动选择) -> shows open-auto and reveals the auto group
      await wrapper.find('[data-group-card="节点选择"] [data-node="自动选择"]').trigger('contextmenu')
      await flushPromises()
      expect(menu().find('[data-menu-item="open-auto"]').text()).toContain('查看组策略与成员')
      await menu().find('[data-menu-item="open-auto"]').trigger('click')
      await settle(200)
      expect(wrapper.find('[data-group-card="自动选择"]').exists()).toBe(true)
      expect(wrapper.find('[data-group-card="自动选择"]').classes()).toContain('open')

      // Disconnect -> test disabled with 未连接; auto-group pin disabled with 未连接
      void storeOf(wrapper).disconnect()
      await settle(1200)
      await wrapper.find('[data-group-card="自动选择"] [data-node="香港 01"]').trigger('contextmenu')
      await flushPromises()
      expect(menu().find('[data-menu-item="pick"]').text()).toContain('固定此节点')
      expect(menu().find('[data-menu-item="pick"]').attributes('aria-disabled')).toBe('true')
      expect(menu().find('[data-menu-item="pick"]').text()).toContain('未连接')
      expect(menu().find('[data-menu-item="test"]').attributes('aria-disabled')).toBe('true')
      expect(menu().find('[data-menu-item="test"]').text()).toContain('未连接')

      // English localization in ContextMenu
      locale.value = 'en'
      await flushPromises()
      await wrapper.find('[data-group-card="节点选择"] [data-node="美国 01"]').trigger('contextmenu')
      await flushPromises()
      expect(menu().find('[data-menu-item="pick"]').text()).toContain('Select node')
      expect(menu().find('[data-menu-item="copy"]').text()).toContain('Copy node name')
      await menu().trigger('keydown', { key: 'Escape' })
      await flushPromises()
      expect(menu().exists()).toBe(false)

      // Compact/mobile suppresses browser default contextmenu AND does not open desktop ContextMenu
      const mobile = await mountApp({ platform: 'android' }, 390)
      await openPage(mobile.wrapper, 'proxies')
      const mobileNodeEl = mobile.wrapper.find('[data-group-card="节点选择"] [data-node="日本 01"]').element
      const mobileCtxEvent = new MouseEvent('contextmenu', { bubbles: true, cancelable: true })
      mobileNodeEl.dispatchEvent(mobileCtxEvent)
      await flushPromises()
      expect(mobileCtxEvent.defaultPrevented).toBe(true)
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(false)

      // Wide Android tablet (not compact, but Android) also suppresses default menu and does not open desktop ContextMenu
      const tablet = await mountApp({ platform: 'android' }, 1024)
      await openPage(tablet.wrapper, 'proxies')
      const tabletNodeEl = tablet.wrapper.find('[data-group-card="节点选择"] [data-node="日本 01"]').element
      const tabletCtxEvent = new MouseEvent('contextmenu', { bubbles: true, cancelable: true })
      tabletNodeEl.dispatchEvent(tabletCtxEvent)
      await flushPromises()
      expect(tabletCtxEvent.defaultPrevented).toBe(true)
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(false)
    })

    it('persists hide-failed preference across transient zero failures, keeps single-group empty prompt, and resets filters', async () => {
      // Corrupt localStorage falls back safely to false
      localStorage.setItem('billow:proxy-hide-failed', '{not-json')
      const { wrapper } = await mountApp()
      await connect(wrapper)
      const store = storeOf(wrapper)

      await openPage(wrapper, 'proxies')
      const makeSnapshotWithFailures = (failStreamAll = false) => ({
        ...store.snapshot.value,
        node_catalog: store.snapshot.value.node_catalog.map((group) => {
          if (failStreamAll && group.name === '流媒体') {
            return {
              ...group,
              nodes: group.nodes.map((node) => ({ ...node, selected: false, delay_ms: null, failed: true })),
            }
          }
          return {
            ...group,
            nodes: group.nodes.map((node) =>
              node.name.includes('新加坡') ? { ...node, delay_ms: null, failed: true } : node,
            ),
          }
        }),
      })
      store.snapshot.value = makeSnapshotWithFailures(false)
      await flushPromises()

      const hideChip = () => wrapper.find('[data-testid="hide-failed-nodes"]')
      expect(hideChip().exists()).toBe(true)
      expect(hideChip().attributes('aria-pressed')).toBe('false')

      // Toggle on -> persists to localStorage
      await hideChip().trigger('click')
      await flushPromises()
      expect(hideChip().attributes('aria-pressed')).toBe('true')
      expect(localStorage.getItem('billow:proxy-hide-failed')).toBe('true')

      // Transient zero failed nodes (e.g. delays cleared on reconnect/switch) MUST NOT overwrite saved preference
      store.snapshot.value = {
        ...store.snapshot.value,
        node_catalog: store.snapshot.value.node_catalog.map((group) => ({
          ...group,
          nodes: group.nodes.map((node) => ({ ...node, failed: false, delay_ms: 80 })),
        })),
      }
      await flushPromises()
      expect(localStorage.getItem('billow:proxy-hide-failed')).toBe('true')

      // When failures reappear (including all nodes in 流媒体 timed out), preference is still active and 流媒体 is not swallowed
      store.snapshot.value = makeSnapshotWithFailures(true)
      await flushPromises()
      expect(hideChip().attributes('aria-pressed')).toBe('true')
      expect(wrapper.find('[data-group-card="流媒体"]').exists()).toBe(true)
      await wrapper.find('[data-testid="group-toggle-流媒体"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-group-card="流媒体"] [data-testid="group-hidden-failed"]').exists()).toBe(true)
      expect(wrapper.find('[data-group-card="流媒体"] [data-testid="show-failed-nodes"]').exists()).toBe(true)

      // One-click recovery inside the group disables hideFailed and restores nodes
      await wrapper.find('[data-group-card="流媒体"] [data-testid="show-failed-nodes"]').trigger('click')
      await flushPromises()
      expect(hideChip().attributes('aria-pressed')).toBe('false')
      expect(wrapper.find('[data-group-card="流媒体"] [data-testid="group-hidden-failed"]').exists()).toBe(false)
      expect(wrapper.findAll('[data-group-card="流媒体"] .node').length).toBeGreaterThan(0)

      // Turn back on, switch away and come back -> restored from localStorage
      await hideChip().trigger('click')
      await flushPromises()
      await openPage(wrapper, 'home')
      await openPage(wrapper, 'proxies')
      expect(hideChip().attributes('aria-pressed')).toBe('true')

      // Search for a timed-out node while hideFailed is active -> empty state with one-click reset
      await wrapper.find('[data-testid="node-search"]').setValue('新加坡')
      await flushPromises()
      expect(wrapper.find('[data-testid="no-match"]').exists()).toBe(true)
      await wrapper.find('[data-testid="reset-proxy-filters"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-testid="no-match"]').exists()).toBe(false)
      expect(hideChip().attributes('aria-pressed')).toBe('false')
      expect(localStorage.getItem('billow:proxy-hide-failed')).toBe('false')
    })

    it('reflects active single-group latency test state on group-pills', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'proxies')

      const gate = deferred<Snapshot>()
      vi.spyOn(backend, 'testGroup').mockImplementationOnce(() => gate.promise)

      const pill = () => wrapper.find('[data-testid="jump-group-节点选择"]')
      expect(pill().exists()).toBe(true)
      expect(pill().classes()).not.toContain('testing')

      void storeOf(wrapper).testGroup('节点选择')
      await flushPromises()
      expect(pill().classes()).toContain('testing')
      expect(pill().attributes('aria-busy')).toBe('true')
      expect(pill().find('.group-pill-dot').exists()).toBe(true)

      gate.resolve(storeOf(wrapper).snapshot.value)
      await settle(200)
      expect(pill().classes()).not.toContain('testing')
      expect(pill().find('.group-pill-dot').exists()).toBe(false)
    })
  })

  describe('R4: ProfilesView quick-import auto-enable, update-all label reset, card keyboard/context menu, and instant filter', () => {
    it('auto-enables the first subscription added via quickImport when none is active, without preempting an active profile', async () => {
      // First profile (no active_id): quickImport auto-enables it
      const emptyApp = await mountApp({ profiles: false })
      const enableSpyEmpty = vi.spyOn(emptyApp.backend, 'enable')
      await openPage(emptyApp.wrapper, 'profiles')
      const formEmpty = emptyApp.wrapper.find('.quick-import')
      await formEmpty.find('input').setValue('https://first.example.com/sub.yaml')
      await formEmpty.trigger('submit')
      await settle(1000)
      expect(enableSpyEmpty).toHaveBeenCalledTimes(1)
      expect(storeOf(emptyApp.wrapper).snapshot.value.active_id).toBeTruthy()

      // Existing active profile: quickImport adds without preempting active_id
      const filledApp = await mountApp()
      const enableSpyFilled = vi.spyOn(filledApp.backend, 'enable')
      const prevActive = storeOf(filledApp.wrapper).snapshot.value.active_id
      await openPage(filledApp.wrapper, 'profiles')
      const formFilled = filledApp.wrapper.find('.quick-import')
      await formFilled.find('input').setValue('https://second.example.com/sub.yaml')
      await formFilled.trigger('submit')
      await settle(800)
      expect(enableSpyFilled).not.toHaveBeenCalled()
      expect(storeOf(filledApp.wrapper).snapshot.value.active_id).toBe(prevActive)
    })

    it('resets update-all button label back to default after brief feedback while keeping retry-failed visible', async () => {
      const { wrapper } = await mountApp({ failRefreshId: 'p2' })
      await openPage(wrapper, 'profiles')

      const updateAllBtn = () => wrapper.find('[data-testid="update-all-profiles"]')
      expect(updateAllBtn().text()).toContain('全部更新')

      await updateAllBtn().trigger('click')
      await settle(2200)
      // Brief summary right after completion
      expect(updateAllBtn().text()).toContain('已完成 2/2')
      expect(updateAllBtn().text()).toContain('1 个失败')
      expect(wrapper.find('[data-testid="retry-failed-profiles"]').exists()).toBe(true)

      // After brief feedback window, button returns to default label while retry-failed remains
      await settle(4200)
      expect(updateAllBtn().text()).toContain('全部更新')
      expect(updateAllBtn().text()).not.toContain('已完成')
      expect(wrapper.find('[data-testid="retry-failed-profiles"]').exists()).toBe(true)

      // Leaving and returning to Profiles MUST NOT replay the expired completion summary
      await openPage(wrapper, 'home')
      await openPage(wrapper, 'profiles')
      expect(updateAllBtn().text()).toContain('全部更新')
      expect(updateAllBtn().text()).not.toContain('已完成')
    })

    it('supports keyboard focus/Enter/Space activation and desktop ContextMenu on profile cards', async () => {
      const { wrapper, backend } = await mountApp()
      const enableSpy = vi.spyOn(backend, 'enable')
      await openPage(wrapper, 'profiles')

      const p2Card = wrapper.find('[data-profile="p2"]')
      expect(p2Card.attributes('tabindex')).toBe('0')

      // Pressing Enter on a nested button does NOT trigger card activation
      const p2Refresh = p2Card.find('button[title="更新订阅"]')
      expect(p2Refresh.exists()).toBe(true)
      await p2Refresh.trigger('keydown', { key: 'Enter' })
      await flushPromises()
      expect(enableSpy).not.toHaveBeenCalled()

      // Pressing Enter on the card itself activates p2
      await p2Card.trigger('keydown', { key: 'Enter' })
      await settle(700)
      expect(enableSpy).toHaveBeenCalledWith('p2')

      // Pressing Space on p1 activates p1
      const p1Card = wrapper.find('[data-profile="p1"]')
      await p1Card.trigger('keydown', { key: ' ' })
      await settle(700)
      expect(enableSpy).toHaveBeenCalledWith('p1')

      // Desktop right-click opens unified ContextMenu reusing menuItems
      await p2Card.trigger('contextmenu')
      await flushPromises()
      const menu = () => body().find('[data-testid="context-menu"]')
      expect(menu().exists()).toBe(true)
      expect(menu().find('[data-menu-item="enable"]').exists()).toBe(true)
      expect(menu().find('[data-menu-item="edit"]').exists()).toBe(true)
      expect(menu().find('[data-menu-item="copy"]').exists()).toBe(true)
      await menu().find('[data-menu-item="edit"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="profile-edit-name"]').exists()).toBe(true)
      await body().find('.modal-head .icon-btn').trigger('click')
      await flushPromises()

      // Compact/mobile does not open desktop ContextMenu on card right-click
      const mobile = await mountApp({ platform: 'android' }, 390)
      await openPage(mobile.wrapper, 'profiles')
      await mobile.wrapper.find('[data-profile="p2"]').trigger('contextmenu')
      await flushPromises()
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(false)
    })

    it('filters multiple profiles by name or host and resets cleanly on no-match (zh-CN and en)', async () => {
      const { wrapper } = await mountApp()
      await openPage(wrapper, 'profiles')

      const search = wrapper.find('[data-testid="profile-search"]')
      expect(search.exists()).toBe(true)
      expect(search.attributes('data-page-search')).toBeDefined()
      const totalBefore = wrapper.findAll('[data-profile]').length
      expect(totalBefore).toBeGreaterThan(1)

      // Filter by subscription host
      await search.setValue('sub.example.com')
      await flushPromises()
      const matchedByHost = wrapper.findAll('[data-profile]')
      expect(matchedByHost.length).toBeGreaterThanOrEqual(1)
      expect(matchedByHost.length).toBeLessThan(totalBefore)
      expect(wrapper.find('[data-testid="profile-match-count"]').exists()).toBe(true)

      // No match shows EmptyState with clear button
      await search.setValue('no-such-profile-xyz')
      await flushPromises()
      expect(wrapper.find('[data-testid="profiles-no-match"]').exists()).toBe(true)

      // English localization check on no-match state
      locale.value = 'en'
      await flushPromises()
      expect(wrapper.find('[data-testid="profiles-no-match"]').text()).toContain('No matching profiles')
      expect(wrapper.find('[data-testid="clear-profile-filter"]').text()).toContain('Clear filters')

      // Click clear filter -> restores all cards
      await wrapper.find('[data-testid="clear-profile-filter"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-testid="profiles-no-match"]').exists()).toBe(false)
      expect(wrapper.findAll('[data-profile]')).toHaveLength(totalBefore)
    })
  })
})

describe('Core workflow polish (R5–R6)', () => {
  describe('R5: Global shell transitions, structured startup skeleton, and sidebar theme/status visibility', () => {
    it('renders structured startup skeleton while !store.loaded on desktop and mobile (zh-CN and en), then transitions to Home', async () => {
      vi.useFakeTimers()
      const gate = deferred<Snapshot>()
      const baseBackend = createDemoBackend()
      const initialSnap = await baseBackend.state()
      const delayedBackend = {
        ...baseBackend,
        state: vi.fn(() => gate.promise),
      }

      const wrapper = mount(App, { props: { backend: delayedBackend, width: 1200 }, attachTo: document.body })
      mounted.push(wrapper)
      await flushPromises()

      const skeleton = wrapper.find('[data-testid="app-loading-skeleton"]')
      expect(skeleton.exists()).toBe(true)
      expect(skeleton.attributes('role')).toBe('status')
      expect(skeleton.attributes('aria-busy')).toBe('true')
      expect(skeleton.text()).toContain('正在加载应用状态')
      expect(wrapper.find('.loading .spinner').exists()).toBe(false)
      expect(skeleton.find('.app-skeleton-hero').exists()).toBe(true)
      expect(skeleton.findAll('.app-skeleton-bento .sk-card')).toHaveLength(2)

      // English localization on loading skeleton
      locale.value = 'en'
      await flushPromises()
      expect(skeleton.text()).toContain('Loading application state')

      // Resolve initial snapshot -> skeleton disappears and Home mounts
      gate.resolve(initialSnap)
      await settle(100)
      expect(wrapper.find('[data-testid="app-loading-skeleton"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="power"]').exists()).toBe(true)
    })

    it('keeps sidebar theme toggle available when collapsed and shows status, speeds, outbound mode, and profile when connected', async () => {
      const { wrapper } = await mountApp({}, 1200)
      const store = storeOf(wrapper)

      // Collapse sidebar -> theme toggle remains accessible in .side-foot and cycles light/dark themes
      await wrapper.find('[data-testid="sidebar-toggle"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('.sidebar').classes()).toContain('collapsed')

      const collapsedThemeBtns = wrapper.findAll('[data-testid="sidebar-theme-toggle"]')
      expect(collapsedThemeBtns).toHaveLength(1)
      expect(wrapper.find('.side-foot [data-testid="sidebar-theme-toggle"]').exists()).toBe(true)
      expect(store.theme.value).toBe('system')

      await collapsedThemeBtns[0]!.trigger('click')
      await flushPromises()
      expect(store.theme.value).toBe('light')
      expect(document.documentElement.getAttribute('data-theme')).toBe('light')

      await wrapper.find('[data-testid="sidebar-theme-toggle"]').trigger('click')
      await flushPromises()
      expect(store.theme.value).toBe('dark')
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark')

      // Expand sidebar again -> exactly one theme toggle in header
      await wrapper.find('[data-testid="sidebar-toggle"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('.sidebar').classes()).not.toContain('collapsed')
      expect(wrapper.findAll('[data-testid="sidebar-theme-toggle"]')).toHaveLength(1)

      // Disconnected: no side-status-meta row
      expect(wrapper.find('[data-testid="side-status-meta"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="side-status"]').text()).toContain('未连接')

      // Connected: shows status, live rates, outbound mode, and active profile name
      await connect(wrapper)
      const sideStatus = wrapper.find('[data-testid="side-status"]')
      const meta = wrapper.find('[data-testid="side-status-meta"]')
      expect(sideStatus.text()).toContain('已连接')
      expect(sideStatus.find('.side-rates .down').exists()).toBe(true)
      expect(sideStatus.find('.side-rates .up').exists()).toBe(true)
      expect(meta.exists()).toBe(true)
      expect(meta.text()).toContain('规则')
      expect(meta.text()).toContain(store.current.value!.name)
      expect(meta.attributes('title')).toContain('规则')
      expect(meta.attributes('title')).toContain(store.current.value!.name)

      // Switching outbound mode updates sidebar status meta in zh-CN and English
      void store.setMode('global')
      await settle(400)
      expect(wrapper.find('[data-testid="side-status-meta"]').text()).toContain('全局')

      void store.setMode('direct')
      await settle(400)
      expect(wrapper.find('[data-testid="side-status-meta"]').text()).toContain('直连')

      locale.value = 'en'
      await flushPromises()
      expect(wrapper.find('[data-testid="side-status-meta"]').text()).toContain('Direct')
      expect(wrapper.find('[data-testid="side-status-meta"]').text()).toContain(store.current.value!.name)
    })

    it('preserves layerDepth, focus restoration, and Android hardware back across Modal, CommandPalette, Menu, and ContextMenu transitions', async () => {
      const { wrapper } = await mountApp({}, 1200)
      expect(layerDepth()).toBe(0)

      // 1. CommandPalette open -> layerDepth 1 -> Escape closes cleanly, restores focus, layerDepth 0
      const paletteBtn = wrapper.find('[data-testid="open-palette"]')
      ;(paletteBtn.element as HTMLElement).focus()
      await paletteBtn.trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      expect(body().find('.palette').exists()).toBe(true)

      document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
      await flushPromises()
      expect(layerDepth()).toBe(0)
      expect(body().find('.palette').exists()).toBe(false)
      expect(document.activeElement).toBe(paletteBtn.element)

      // 2. Modal (add-profile) open -> layerDepth 1 -> close button restores layerDepth 0
      await openPage(wrapper, 'profiles')
      await wrapper.find('[data-testid="add-profile"]').trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      expect(body().find('.modal').exists()).toBe(true)
      await body().find('.modal-head .icon-btn').trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(0)
      expect(body().find('.modal').exists()).toBe(false)

      // 3. Profile card more Menu (:open driven) -> open, ArrowDown, Escape restores focus & layerDepth, reopen resets active to 0
      const menuTrigger = wrapper.find('[data-menu-trigger="p2"]')
      ;(menuTrigger.element as HTMLElement).focus()
      await menuTrigger.trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      const cardMenu = () => wrapper.find('[data-profile="p2"] [role="menu"]')
      expect(cardMenu().exists()).toBe(true)
      const firstItems = cardMenu().findAll('[role="menuitem"]')
      expect(document.activeElement).toBe(firstItems[0]!.element)

      await cardMenu().trigger('keydown', { key: 'ArrowDown' })
      await flushPromises()
      expect(document.activeElement).toBe(firstItems[1]!.element)

      await cardMenu().trigger('keydown', { key: 'Escape' })
      await flushPromises()
      expect(layerDepth()).toBe(0)
      expect(cardMenu().exists()).toBe(false)
      expect(document.activeElement).toBe(menuTrigger.element)

      // Reopen resets active index to 0 and outside click dismisses cleanly
      await menuTrigger.trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      expect(cardMenu().exists()).toBe(true)
      expect(document.activeElement).toBe(cardMenu().findAll('[role="menuitem"]')[0]!.element)
      document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
      await flushPromises()
      expect(layerDepth()).toBe(0)
      expect(cardMenu().exists()).toBe(false)

      // 4. ContextMenu on profile card -> layerDepth 1 -> Escape closes cleanly, layerDepth 0
      await wrapper.find('[data-profile="p2"]').trigger('contextmenu')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(true)
      await body().find('[data-testid="context-menu"]').trigger('keydown', { key: 'Escape' })
      await flushPromises()
      expect(layerDepth()).toBe(0)
      expect(body().find('[data-testid="context-menu"]').exists()).toBe(false)

      // 5. Android compact bottom sheet Modal + hardware back -> layerDepth returns to 0 without leaving page
      const mobile = await mountApp({ platform: 'android' }, 390)
      await openPage(mobile.wrapper, 'profiles')
      await mobile.wrapper.find('[data-testid="add-profile"]').trigger('click')
      await flushPromises()
      expect(layerDepth()).toBe(1)
      expect(body().find('.modal').exists()).toBe(true)

      await hardwareBack()
      expect(layerDepth()).toBe(0)
      expect(body().find('.modal').exists()).toBe(false)
      expect(mobile.wrapper.find('.main').attributes('data-page')).toBe('profiles')
    })
  })
})
