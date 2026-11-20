import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import { locale } from './lib/i18n'
import type { Store } from './lib/store'
import type { Snapshot } from './lib/types'
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

      // Reopen while disconnected -> test & unfix are disabled with explicit titles
      await wrapper.find('[data-testid="power"]').trigger('click')
      await settle(1200)
      await wrapper.find('[data-testid="groups-card"] [data-group="自动选择"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="node-picker-test"]').attributes('disabled')).toBeDefined()
      expect(body().find('[data-testid="node-picker-unfix"]').attributes('disabled')).toBeDefined()
      expect(body().find('[data-testid="node-picker-offline-hint"]').exists()).toBe(true)

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
      expect(body().find('[data-testid="node-picker-open-proxies"]').text()).toContain('Open Proxies')

      await hardwareBack()
      expect(body().find('[data-testid="home-node-picker"]').exists()).toBe(false)
      expect(wrapper.find('.main').attributes('data-page')).toBe('home')
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
