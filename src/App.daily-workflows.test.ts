import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'
import type { ConnectionRow, Snapshot } from './lib/types'
import { applyInsets } from './lib/ui/insets'

// Regression coverage for docs/requirements/2026-11-18-ui-ux-daily-workflows.md (R1–R5).

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

async function openPage(wrapper: Wrapper, page: string) {
  await wrapper.find(`.sidebar [data-page="${page}"]`).trigger('click')
  await flushPromises()
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
  localStorage.clear()
  vi.useRealTimers()
})

describe('Daily UI/UX workflows (R1–R5)', () => {
  describe('R1: Home profile switcher progress, actual active state, and in-place retry', () => {
    it('keeps the sheet open with 正在启用 while switching, blocks concurrent switches, and updates active marker on completion', async () => {
      const { wrapper, backend } = await mountApp()
      const origEnable = backend.enable.bind(backend)
      const gate = deferred<Snapshot>()
      const enableSpy = vi.spyOn(backend, 'enable').mockImplementationOnce(() => gate.promise)

      expect(storeOf(wrapper).current.value?.id).toBe('p1')
      await wrapper.find('[data-testid="mobile-profile-trigger"]').trigger('click')
      await flushPromises()

      const rowA = () => body().find('[data-testid="sheet-profile-p1"]')
      const rowB = () => body().find('[data-testid="sheet-profile-p2"]')
      const rowC = () => body().find('[data-testid="sheet-profile-p3"]')

      expect(rowA().attributes('aria-current')).toBe('true')
      expect(rowA().text()).toContain('使用中')

      // Select B, then rapidly click B and C while B is still enabling.
      await rowB().trigger('click')
      await rowB().trigger('click')
      await rowC().trigger('click')
      await flushPromises()

      expect(enableSpy).toHaveBeenCalledTimes(1)
      expect(enableSpy).toHaveBeenCalledWith('p2')
      expect(body().find('[data-testid="home-profile-sheet"]').exists()).toBe(true)
      // A retains current marker while B shows 正在启用.
      expect(rowA().attributes('aria-current')).toBe('true')
      expect(rowA().text()).toContain('使用中')
      expect(rowB().attributes('aria-busy')).toBe('true')
      expect(rowB().find('[data-testid="sheet-enabling"]').text()).toContain('正在启用')
      expect(rowC().find('[data-testid="sheet-enabling"]').exists()).toBe(false)

      // Finish enabling B.
      const enablingPromise = origEnable('p2')
      await settle(700)
      gate.resolve(await enablingPromise)
      await settle(100)

      expect(body().find('[data-testid="home-profile-sheet"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="mobile-profile-trigger"]').text()).toContain('备用机场')
      expect(wrapper.find('[data-testid="profile-card"]').text()).toContain('备用机场')

      // Reopen sheet: B is now the current item; clicking B again does not re-enable or show waiting state.
      enableSpy.mockClear()
      await wrapper.find('[data-testid="mobile-profile-trigger"]').trigger('click')
      await flushPromises()
      expect(rowB().attributes('aria-current')).toBe('true')
      expect(rowB().text()).toContain('使用中')
      expect(rowA().attributes('aria-current')).toBeUndefined()

      await rowB().trigger('click')
      await flushPromises()
      expect(enableSpy).not.toHaveBeenCalled()
      expect(body().find('[data-testid="sheet-enabling"]').exists()).toBe(false)
    })

    it('keeps A marked current when B fails to enable, shows the reason on B, and retries B in place', async () => {
      const { wrapper, backend } = await mountApp()
      const origEnable = backend.enable.bind(backend)
      const origState = backend.state.bind(backend)
      let failB = true
      const enableSpy = vi.spyOn(backend, 'enable').mockImplementation(async (id) => {
        if (id === 'p2' && failB) {
          const snap = await origState()
          return {
            ...snap,
            active_id: 'p1',
            failure: '配置无法应用：YAML 端口冲突',
            profiles: snap.profiles.map((p) =>
              p.id === 'p2' ? { ...p, current: false, failure: '配置无法应用：YAML 端口冲突' } : p,
            ),
          }
        }
        return origEnable(id)
      })

      await wrapper.find('[data-testid="mobile-profile-trigger"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="sheet-profile-p2"]').trigger('click')
      await settle(100)

      // Sheet stays open, A stays current, B displays reason + retry action.
      expect(body().find('[data-testid="home-profile-sheet"]').exists()).toBe(true)
      expect(body().find('[data-testid="sheet-profile-p1"]').attributes('aria-current')).toBe('true')
      expect(body().find('[data-testid="sheet-profile-p2"]').attributes('aria-current')).toBeUndefined()
      const err = body().find('[data-testid="sheet-error-p2"]')
      expect(err.exists()).toBe(true)
      expect(err.text()).toContain('配置无法应用：YAML 端口冲突')

      // Fix failure condition and retry B directly in place.
      failB = false
      await body().find('[data-testid="sheet-retry-p2"]').trigger('click')
      await settle(700)

      expect(enableSpy).toHaveBeenCalledTimes(2)
      expect(body().find('[data-testid="home-profile-sheet"]').exists()).toBe(false)
      expect(storeOf(wrapper).current.value?.id).toBe('p2')
      expect(wrapper.find('[data-testid="mobile-profile-trigger"]').text()).toContain('备用机场')
    })
  })

  describe('R2: Subscription edit pre-validation, input retention, and partial-save retry', () => {
    async function openProfileEdit(wrapper: Wrapper, id = 'p1') {
      await openPage(wrapper, 'profiles')
      await wrapper.find(`[data-menu-trigger="${id}"]`).trigger('click')
      await flushPromises()
      const item = Array.from(document.body.querySelectorAll<HTMLElement>('[role="menuitem"]')).find((el) =>
        el.textContent?.includes('编辑信息'),
      )!
      item.click()
      await flushPromises()
    }

    it('validates the whole form before saving, retains all inputs, and unfolds collapsed invalid fields', async () => {
      const { wrapper, backend } = await mountApp()
      const renameSpy = vi.spyOn(backend, 'rename')
      const sourceSpy = vi.spyOn(backend, 'setSource')
      const uaSpy = vi.spyOn(backend, 'setUserAgent')

      await openProfileEdit(wrapper, 'p1')
      const nameInput = body().find('[data-testid="profile-edit-name"]')
      const urlInput = body().find('[data-testid="profile-edit-url"]')
      await nameInput.setValue('星河云 Pro')
      await urlInput.setValue('ftp://invalid-link')
      await body().find('[data-testid="save-profile-edit"]').trigger('click')
      await flushPromises()

      // Both inputs are preserved, URL shows inline error, name was NOT saved yet.
      expect((nameInput.element as HTMLInputElement).value).toBe('星河云 Pro')
      expect((urlInput.element as HTMLInputElement).value).toBe('ftp://invalid-link')
      expect(urlInput.attributes('aria-invalid')).toBe('true')
      expect(body().find('[data-testid="field-error-url"]').text()).toContain('http://')
      expect(document.activeElement).toBe(urlInput.element)
      expect(renameSpy).not.toHaveBeenCalled()
      expect(sourceSpy).not.toHaveBeenCalled()
      expect(storeOf(wrapper).snapshot.value.profiles.find((p) => p.id === 'p1')!.name).toBe('星河云')

      // Fix URL, put an invalid non-ASCII value in User-Agent, then collapse advanced options before saving.
      await urlInput.setValue('https://valid.example.com/sub')
      const uaInput = body().find('[data-testid="profile-user-agent"]')
      await uaInput.setValue('非法UA中文')
      const details = body().find('[data-testid="profile-advanced"]')
      ;(details.element as HTMLDetailsElement).open = false
      details.element.dispatchEvent(new Event('toggle'))
      await flushPromises()
      expect(details.attributes('open')).toBeUndefined()

      await body().find('[data-testid="save-profile-edit"]').trigger('click')
      await flushPromises()

      // Advanced section automatically unfolds and focuses the invalid User-Agent input; nothing submitted yet.
      expect(details.attributes('open')).toBeDefined()
      expect(uaInput.attributes('aria-invalid')).toBe('true')
      expect(body().find('[data-testid="field-error-userAgent"]').text()).toContain('ASCII')
      expect(document.activeElement).toBe(uaInput.element)
      expect(renameSpy).not.toHaveBeenCalled()
      expect(sourceSpy).not.toHaveBeenCalled()
      expect(uaSpy).not.toHaveBeenCalled()
    })

    it('distinguishes saved, failed, and pending fields after partial save, retries only remaining diffs, and deduplicates concurrent submits', async () => {
      const { wrapper, backend } = await mountApp()
      const origSetSource = backend.setSource.bind(backend)
      let failSource = true
      const sourceGate = deferred<void>()

      const renameSpy = vi.spyOn(backend, 'rename')
      const sourceSpy = vi.spyOn(backend, 'setSource').mockImplementation(async (id, url) => {
        if (failSource) {
          await sourceGate.promise
          throw new Error('订阅源写入磁盘失败')
        }
        return origSetSource(id, url)
      })
      const intervalSpy = vi.spyOn(backend, 'setInterval')

      await openProfileEdit(wrapper, 'p1')
      await body().find('[data-testid="profile-edit-name"]').setValue('星河云旗舰')
      await body().find('[data-testid="profile-edit-url"]').setValue('https://new.example.com/api/sub')
      // Change interval from 12h to 24h (每天).
      await body().find('[data-testid="profile-interval-field"] .select-trigger').trigger('click')
      await flushPromises()
      const dailyOption = Array.from(document.body.querySelectorAll<HTMLElement>('.select-option')).find((el) =>
        el.textContent?.includes('每天'),
      )!
      dailyOption.click()
      await flushPromises()

      // Trigger save and immediately spam click + Enter while in progress.
      const saveBtn = body().find('[data-testid="save-profile-edit"]')
      await saveBtn.trigger('click')
      await saveBtn.trigger('click')
      await body().find('.modal form').trigger('submit')
      await settle(200)

      // Only one save round started: rename ran once, setSource ran once and is waiting.
      expect(renameSpy).toHaveBeenCalledTimes(1)
      expect(sourceSpy).toHaveBeenCalledTimes(1)
      expect(intervalSpy).not.toHaveBeenCalled()

      sourceGate.resolve()
      await settle(200)

      // Modal stays open; name is 已保存, url is 保存失败 with reason, interval is 待保存; no overall success toast yet.
      expect(body().find('.modal').exists()).toBe(true)
      expect(body().find('[data-testid="field-state-name"]').text()).toContain('已保存')
      expect(body().find('[data-testid="field-state-url"]').text()).toContain('保存失败')
      expect(body().find('[data-testid="field-error-url"]').text()).toContain('订阅源写入磁盘失败')
      expect(body().find('[data-testid="field-state-interval"]').text()).toContain('待保存')
      const summary = body().find('[data-testid="edit-save-summary"]').text()
      expect(summary).toContain('已保存：名称')
      expect(summary).toContain('保存失败：订阅链接')
      expect(summary).toContain('待保存：自动更新')
      expect(storeOf(wrapper).toasts.value.some((t) => t.tone === 'success' && t.text.includes('已保存'))).toBe(false)

      // Fix failure condition and save again: only url and pending interval are submitted!
      failSource = false
      renameSpy.mockClear()
      sourceSpy.mockClear()
      intervalSpy.mockClear()

      await body().find('[data-testid="save-profile-edit"]').trigger('click')
      await settle(400)

      expect(renameSpy).not.toHaveBeenCalled()
      expect(sourceSpy).toHaveBeenCalledTimes(1)
      expect(sourceSpy).toHaveBeenCalledWith('p1', 'https://new.example.com/api/sub')
      expect(intervalSpy).toHaveBeenCalledTimes(1)
      expect(intervalSpy).toHaveBeenCalledWith('p1', 24)
      expect(body().find('.modal').exists()).toBe(false)
      expect(storeOf(wrapper).toasts.value.some((t) => t.tone === 'success' && t.text === '已保存')).toBe(true)

      // Reopen configuration: every field matches the last successfully saved value.
      await openProfileEdit(wrapper, 'p1')
      expect((body().find('[data-testid="profile-edit-name"]').element as HTMLInputElement).value).toBe('星河云旗舰')
      expect((body().find('[data-testid="profile-edit-url"]').element as HTMLInputElement).value).toBe(
        'https://new.example.com/api/sub',
      )
      expect(body().find('[data-testid="profile-interval-field"] .select-trigger').text()).toContain('每天')
    })
  })

  describe('R3: Mixed port inline validation and in-place correction', () => {
    it('retains invalid port values (65536, 0, decimals), shows valid range 1–65535 while keeping current port active, and saves valid bounds and clear', async () => {
      const { wrapper, backend } = await mountApp()
      const saveSpy = vi.spyOn(backend, 'saveSettings')

      await openPage(wrapper, 'settings')
      await wrapper.find('[data-testid="settings-tabs"] [data-value="kernel"]').trigger('click')
      await flushPromises()

      // First save 7890 explicitly as the saved port override.
      const portInput = () => wrapper.find('[data-testid="mixed-port-input"]')
      await portInput().setValue('7890')
      await wrapper.find('[data-testid="save-port"]').trigger('click')
      await settle(400)
      expect(storeOf(wrapper).snapshot.value.settings.mixed_port).toBe(7890)
      saveSpy.mockClear()

      // Submit 65536: input keeps 65536, inline error explains 1–65535, active port remains 7890.
      await portInput().setValue('65536')
      await wrapper.find('[data-testid="save-port"]').trigger('click')
      await flushPromises()
      expect((portInput().element as HTMLInputElement).value).toBe('65536')
      expect(portInput().attributes('aria-invalid')).toBe('true')
      expect(wrapper.find('[data-testid="mixed-port-error"]').text()).toContain('1–65535')
      expect(wrapper.find('[data-testid="mixed-port-effective"]').text()).toContain('7890')
      expect(storeOf(wrapper).snapshot.value.mixed_port).toBe(7890)
      expect(saveSpy).not.toHaveBeenCalled()

      // Fix directly to 7891 and save: error disappears, re-entering settings still shows 7891.
      await portInput().setValue('7891')
      await wrapper.find('[data-testid="save-port"]').trigger('click')
      await settle(400)
      expect(wrapper.find('[data-testid="mixed-port-error"]').exists()).toBe(false)
      expect(storeOf(wrapper).snapshot.value.settings.mixed_port).toBe(7891)

      await openPage(wrapper, 'home')
      await openPage(wrapper, 'settings')
      await wrapper.find('[data-testid="settings-tabs"] [data-value="kernel"]').trigger('click')
      await flushPromises()
      expect((portInput().element as HTMLInputElement).value).toBe('7891')

      // Reject 0 and decimals in place.
      for (const bad of ['0', '7890.5', '7890.0']) {
        await portInput().setValue(bad)
        await portInput().trigger('keydown', { key: 'Enter' })
        await flushPromises()
        expect((portInput().element as HTMLInputElement).value).toBe(bad)
        expect(wrapper.find('[data-testid="mixed-port-error"]').text()).toContain('1–65535')
        expect(storeOf(wrapper).snapshot.value.settings.mixed_port).toBe(7891)
      }

      // Boundary values 1 and 65535 succeed.
      for (const bound of [1, 65535]) {
        await portInput().setValue(String(bound))
        await wrapper.find('[data-testid="save-port"]').trigger('click')
        await settle(400)
        expect(wrapper.find('[data-testid="mixed-port-error"]').exists()).toBe(false)
        expect(storeOf(wrapper).snapshot.value.settings.mixed_port).toBe(bound)
      }

      // Clearing and saving cancels the port override and restores the inherited value (7890).
      await portInput().setValue('')
      await wrapper.find('[data-testid="save-port"]').trigger('click')
      await settle(400)
      expect(wrapper.find('[data-testid="mixed-port-error"]').exists()).toBe(false)
      expect(storeOf(wrapper).snapshot.value.settings.mixed_port).toBeNull()
      expect(storeOf(wrapper).snapshot.value.mixed_port).toBe(7890)
    })
  })

  describe('R4: Restoring connection investigation context across proxy-group and rule-set jumps', () => {
    function makeConn(overrides: Partial<ConnectionRow> & { id: string; host: string }): ConnectionRow {
      return {
        outbound: '香港 01',
        network: 'tcp',
        conn_type: 'HTTPS',
        destination: '140.82.114.4:443',
        source: '127.0.0.1:52001',
        process: 'curl',
        rule: 'RuleSet',
        rule_payload: 'telegram',
        chains: ['香港 01', '节点选择'],
        upload: 2048,
        download: 16384,
        start: new Date(Date.now() - 12_000).toISOString(),
        ...overrides,
      }
    }

    it('restores filter, sort, scroll offset, paused list, and exact connection identity after jumping to entry proxy group', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)

      let liveConnections: ConnectionRow[] = Array.from({ length: 25 }, (_, i) =>
        makeConn({
          id: `conn-${i}`,
          host: i < 20 ? `sub${String(i).padStart(2, '0')}.github.com` : `other-${i}.example.org`,
          source: `127.0.0.1:${54000 + i}`,
          download: (i + 1) * 10_000,
        }),
      )
      const origState = backend.state.bind(backend)
      backend.state = async () => {
        const snap = await origState()
        return {
          ...snap,
          connections: liveConnections.map((row) => ({ ...row })),
          connection_total: liveConnections.length,
        }
      }

      await openPage(wrapper, 'connections')
      await settle(1100)

      // Filter host, adjust sort (download ascending), scroll list, pause list, and open conn-5.
      await wrapper.find('[data-testid="connection-search"]').setValue('github.com')
      await wrapper.find('[data-testid="connection-route-filter"] [data-value="proxy"]').trigger('click')
      const downloadSortBtn = wrapper.findAll('.conn-table th button.th-sort').find((b) => b.text().includes('下载'))!
      await downloadSortBtn.trigger('click') // desc
      await downloadSortBtn.trigger('click') // asc
      await flushPromises()

      const scroller = wrapper.find('[data-testid="connection-scroll"]')
      ;(scroller.element as HTMLElement).scrollTop = 160
      await scroller.trigger('scroll')
      await wrapper.find('[data-testid="pause-connections"]').trigger('click')
      await flushPromises()

      const targetRow = wrapper.find('[data-connection-id="conn-5"]')
      expect(targetRow.exists()).toBe(true)
      await targetRow.trigger('click')
      await flushPromises()
      expect(body().find('.modal').text()).toContain('127.0.0.1:54005')

      // Jump to entry proxy group.
      await body().find('[data-testid="open-conn-group"]').trigger('click')
      await flushPromises()
      expect(storeOf(wrapper).page.value).toBe('proxies')

      // New connections arrive while away, including another connection with the exact same host as conn-5!
      liveConnections = [
        makeConn({
          id: 'conn-same-host-new',
          host: 'sub05.github.com',
          source: '127.0.0.1:59999',
          download: 999_999,
        }),
        ...liveConnections,
      ]
      await settle(1100)

      // Return along the contextual return bar.
      await wrapper.find('[data-testid="connection-return"]').trigger('click')
      await flushPromises()
      expect(storeOf(wrapper).page.value).toBe('connections')

      // Still shows original conn-5 detail (source 54005), NOT conn-same-host-new (source 59999).
      expect(body().find('.modal').exists()).toBe(true)
      expect(body().find('.modal').text()).toContain('sub05.github.com')
      expect(body().find('.modal').text()).toContain('127.0.0.1:54005')
      expect(body().find('.modal').text()).not.toContain('127.0.0.1:59999')

      // Close detail: filter, sort, paused state, frozen list, and scroll offset are preserved.
      const closeBtn = body().findAll('.modal-foot button').find((b) => b.text() === '关闭')!
      await closeBtn.trigger('click')
      await flushPromises()

      expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('github.com')
      expect(wrapper.find('[data-testid="connections-paused-bar"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="new-connections"]').text()).toContain('1 条新连接')
      expect((wrapper.find('[data-testid="connection-scroll"]').element as HTMLElement).scrollTop).toBe(160)
      expect(wrapper.find('[data-connection-id="conn-same-host-new"]').exists()).toBe(false)

      // Only switches back to live list when user chooses 继续刷新.
      await wrapper.find('[data-testid="resume-connections-bar"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-testid="connections-paused-bar"]').exists()).toBe(false)
      expect(wrapper.find('[data-connection-id="conn-same-host-new"]').exists()).toBe(true)
    })

    it('restores live detail when still active, or last info with 已关闭 and disabled disconnect when ended while viewing rule-set', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)

      let active = true
      let downloadBytes = 8192
      const origState = backend.state.bind(backend)
      backend.state = async () => {
        const snap = await origState()
        const rows = active
          ? [
              makeConn({
                id: 'c-live-rs',
                host: 'web.telegram.org',
                source: '127.0.0.1:53111',
                download: downloadBytes,
              }),
            ]
          : []
        return { ...snap, connections: rows, connection_total: rows.length }
      }

      await openPage(wrapper, 'connections')
      await settle(1100)
      await wrapper.find('[data-connection-id="c-live-rs"]').trigger('click')
      await flushPromises()

      // Jump to rule-set while connection stays active, and download grows.
      await body().find('[data-testid="open-conn-ruleset"]').trigger('click')
      await settle(500)
      expect(storeOf(wrapper).page.value).toBe('resources')
      expect(body().find('[data-testid="provider-detail"]').exists()).toBe(true)

      downloadBytes = 65536
      await settle(1100)
      await body().find('[data-testid="provider-return-connection"]').trigger('click')
      await flushPromises()

      expect(storeOf(wrapper).page.value).toBe('connections')
      expect(body().find('[data-testid="detail-disconnected"]').exists()).toBe(false)
      expect(body().find('[data-testid="detail-stats"]').text()).toContain('64.0 KB')
      expect((body().find('[data-testid="disconnect-connection"]').element as HTMLButtonElement).disabled).toBe(false)

      // Jump to rule-set again; this time the connection ends while viewing the rule-set.
      await body().find('[data-testid="open-conn-ruleset"]').trigger('click')
      await settle(500)
      active = false
      await settle(1100)

      await body().find('[data-testid="provider-return-connection"]').trigger('click')
      await flushPromises()

      expect(storeOf(wrapper).page.value).toBe('connections')
      expect(body().find('.modal').text()).toContain('web.telegram.org')
      expect(body().find('[data-testid="detail-stats"]').text()).toContain('64.0 KB')
      expect(body().find('[data-testid="detail-disconnected"]').text()).toContain('已关闭')
      expect((body().find('[data-testid="disconnect-connection"]').element as HTMLButtonElement).disabled).toBe(true)
    })

    it('explains unavailable records without matching same-host connections, and handles disconnected or reconnected sessions cleanly', async () => {
      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      const store = storeOf(wrapper)

      let rows: ConnectionRow[] = [
        makeConn({ id: 'orig-1', host: 'api.openai.com', source: '127.0.0.1:51001' }),
      ]
      const origState = backend.state.bind(backend)
      backend.state = async () => {
        const snap = await origState()
        const list = snap.connected ? rows.map((r) => ({ ...r })) : []
        return { ...snap, connections: list, connection_total: list.length }
      }

      await openPage(wrapper, 'connections')
      await settle(1100)
      await wrapper.find('[data-testid="connection-search"]').setValue('api.openai.com')
      await flushPromises()
      await wrapper.find('[data-connection-id="orig-1"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="open-conn-group"]').trigger('click')
      await flushPromises()

      // Case A: orig-1 closes, closed buffer is cleared, and a DIFFERENT connection to the same host exists.
      rows = [makeConn({ id: 'other-2', host: 'api.openai.com', source: '127.0.0.1:51002' })]
      await settle(1100)
      store.clearClosedConnections()

      await wrapper.find('[data-testid="connection-return"]').trigger('click')
      await flushPromises()

      expect(body().find('.modal').exists()).toBe(false)
      expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('api.openai.com')
      expect(wrapper.find('[data-testid="connection-return-notice"]').text()).toContain('记录已不可用')
      expect(wrapper.find('[data-connection-id="other-2"]').exists()).toBe(true)

      // Case B: Jump from other-2, then disconnect and reconnect a new session with same host AND even same id.
      await wrapper.find('[data-connection-id="other-2"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="open-conn-group"]').trigger('click')
      await flushPromises()

      void store.disconnect()
      await settle(500)
      void store.connect()
      await settle(1200)

      await wrapper.find('[data-testid="connection-return"]').trigger('click')
      await flushPromises()
      expect(body().find('.modal').exists()).toBe(false)
      expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('api.openai.com')
      expect(wrapper.find('[data-testid="connection-return-notice"]').text()).toContain('重新建立')

      // Case C: Jump and disconnect without reconnecting -> shows disconnected state.
      await wrapper.find('[data-connection-id="other-2"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="open-conn-group"]').trigger('click')
      await flushPromises()
      void store.disconnect()
      await settle(500)
      await wrapper.find('[data-testid="connection-return"]').trigger('click')
      await flushPromises()
      expect(body().find('.modal').exists()).toBe(false)
      expect(wrapper.find('[data-testid="empty-connect"]').exists()).toBe(true)
    })
  })

  describe('R5: Desktop/Android takeover clarity, keyboard focus in light/dark themes, and 390px touch/back', () => {
    it('surfaces current profile and non-takeover state on desktop when kernel runs with proxy & TUN off, and reflects VPN on Android', async () => {
      const desktop = await mountApp()
      await connect(desktop.wrapper)
      // Turn off system proxy while kernel keeps running (TUN is also off).
      const origState = desktop.backend.state.bind(desktop.backend)
      desktop.backend.state = async () => {
        const snap = await origState()
        return { ...snap, kernel_running: true, system_proxy: false, tun: false, connected: false }
      }
      await storeOf(desktop.wrapper).refresh()
      await flushPromises()

      expect(desktop.wrapper.find('[data-testid="home-status"]').classes()).toContain('bare')
      expect(desktop.wrapper.find('[data-testid="hero-eyebrow"]').text()).toContain('未接管系统流量')
      expect(desktop.wrapper.find('[data-testid="takeover-hint"]').text()).toContain('未接管系统流量')
      expect(desktop.wrapper.find('[data-testid="mobile-profile-trigger"]').text()).toContain('星河云')

      // Android reflects actual VPN takeover status in the hero.
      const android = await mountApp({ platform: 'android' }, 390)
      const origAndroidState = android.backend.state.bind(android.backend)
      let vpnOn = false
      android.backend.state = async () => {
        const snap = await origAndroidState()
        return { ...snap, kernel_running: true, vpn: vpnOn, connected: vpnOn }
      }
      await storeOf(android.wrapper).refresh()
      await flushPromises()
      expect(android.wrapper.find('[data-testid="hero-eyebrow"]').text()).toBe('VPN 未开启 · 未接管设备流量')

      vpnOn = true
      await storeOf(android.wrapper).refresh()
      await flushPromises()
      expect(android.wrapper.find('[data-testid="hero-eyebrow"]').text()).toBe('VPN 已接管设备流量')
    })

    it('maintains visible keyboard focus across light and dark themes for profile switching, error recovery, and cross-page return', async () => {
      const { wrapper } = await mountApp()
      const store = storeOf(wrapper)
      await connect(wrapper)

      for (const theme of ['light', 'dark'] as const) {
        store.setTheme(theme)
        await flushPromises()
        expect(document.documentElement.getAttribute('data-theme')).toBe(theme)

        // 1. Open switcher from focused trigger -> switch profile -> focus returns to trigger.
        const trigger = wrapper.find('[data-testid="mobile-profile-trigger"]')
        ;(trigger.element as HTMLElement).focus()
        expect(document.activeElement).toBe(trigger.element)
        await trigger.trigger('click')
        await flushPromises()

        const targetId = store.current.value?.id === 'p1' ? 'p2' : 'p1'
        const targetBtn = body().find(`[data-testid="sheet-profile-${targetId}"]`)
        ;(targetBtn.element as HTMLElement).focus()
        await targetBtn.trigger('click')
        await settle(700)
        expect(body().find('[data-testid="home-profile-sheet"]').exists()).toBe(false)
        expect(document.activeElement).toBe(trigger.element)
      }

      // 2. Settings port error keeps focus on the port input.
      await openPage(wrapper, 'settings')
      await wrapper.find('[data-testid="settings-tabs"] [data-value="kernel"]').trigger('click')
      await flushPromises()
      const portInput = wrapper.find('[data-testid="mixed-port-input"]')
      ;(portInput.element as HTMLElement).focus()
      await portInput.setValue('99999')
      await portInput.trigger('keydown', { key: 'Enter' })
      await flushPromises()
      expect(document.activeElement).toBe(portInput.element)
      await portInput.setValue('7892')
      await portInput.trigger('keydown', { key: 'Enter' })
      await settle(400)
      expect(document.activeElement).toBe(portInput.element)

      // 3. Connections keyboard open -> jump to proxy group -> return -> Escape restores row focus.
      await openPage(wrapper, 'connections')
      await settle(1100)
      const firstRow = wrapper.findAll('[data-testid="connection-row"]').find((r) => !r.text().includes('DIRECT'))!
      const connId = firstRow.attributes('data-connection-id')!
      ;(firstRow.element as HTMLElement).focus()
      await firstRow.trigger('keydown', { key: 'Enter' })
      await flushPromises()
      expect(body().find('.modal').exists()).toBe(true)

      await body().find('[data-testid="open-conn-group"]').trigger('click')
      await settle(100)
      expect(store.page.value).toBe('proxies')
      expect(document.activeElement).not.toBe(document.body)

      const returnBtn = wrapper.find('[data-testid="connection-return"]')
      ;(returnBtn.element as HTMLElement).focus()
      await returnBtn.trigger('click')
      await flushPromises()
      expect(store.page.value).toBe('connections')
      expect(body().find('.modal').exists()).toBe(true)
      expect(document.activeElement).not.toBe(document.body)

      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
      await settle(50)
      expect(body().find('.modal').exists()).toBe(false)
      expect((document.activeElement as HTMLElement | null)?.getAttribute('data-connection-id')).toBe(connId)
    })

    it('handles 390px Android layout with long names/errors, soft keyboard insets, and hardware back from rule-set detail to connection detail', async () => {
      const longName = '🇭🇰 香港 IPLC 专线企业级高防超长订阅配置名称测试 2026 旗舰版'
      const longError = '启用配置失败：外部规则集与订阅上游节点分组校验未通过，请检查网络连接或覆写语法后重试'
      const { wrapper, backend } = await mountApp({ platform: 'android' }, 390)
      const store = storeOf(wrapper)

      void backend.rename('p2', longName)
      await settle(200)
      void store.refresh()
      await settle(100)

      // Long profile name + long failure message in 390px switcher sheet.
      const origEnable = backend.enable.bind(backend)
      const origState = backend.state.bind(backend)
      let failSwitch = true
      vi.spyOn(backend, 'enable').mockImplementation(async (id) => {
        if (id === 'p2' && failSwitch) {
          const snap = await origState()
          return {
            ...snap,
            active_id: 'p1',
            profiles: snap.profiles.map((p) => (p.id === 'p2' ? { ...p, failure: longError } : p)),
          }
        }
        return origEnable(id)
      })

      await wrapper.find('[data-testid="mobile-profile-trigger"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="sheet-profile-p2"]').text()).toContain(longName)
      await body().find('[data-testid="sheet-profile-p2"]').trigger('click')
      await settle(100)
      expect(body().find('[data-testid="sheet-error-p2"]').text()).toContain(longError)
      expect(body().find('[data-testid="sheet-retry-p2"]').exists()).toBe(true)

      failSwitch = false
      await body().find('[data-testid="sheet-retry-p2"]').trigger('click')
      await settle(700)
      expect(store.current.value?.id).toBe('p2')

      // Soft keyboard open on 390px Android during subscription edit: dock hides and Save remains reachable.
      await wrapper.find('.tabbar [data-page="profiles"]').trigger('click')
      await flushPromises()
      await wrapper.find('[data-menu-trigger="p2"]').trigger('click')
      await flushPromises()
      Array.from(document.body.querySelectorAll<HTMLElement>('[role="menuitem"]'))
        .find((el) => el.textContent?.includes('编辑信息'))!
        .click()
      await flushPromises()

      applyInsets({ top: 24, right: 0, bottom: 0, left: 0, ime: 300 })
      expect(document.documentElement.hasAttribute('data-keyboard')).toBe(true)
      await body().find('[data-testid="profile-edit-url"]').setValue('not-a-valid-url')
      await body().find('[data-testid="save-profile-edit"]').trigger('click')
      await flushPromises()
      expect(body().find('[data-testid="field-error-url"]').exists()).toBe(true)
      expect(body().find('[data-testid="save-profile-edit"]').exists()).toBe(true)

      await body().find('[data-testid="profile-edit-url"]').setValue('https://fixed.example.net/sub')
      await body().find('[data-testid="save-profile-edit"]').trigger('click')
      await settle(300)
      expect(body().find('.modal').exists()).toBe(false)
      applyInsets({ top: 24, right: 0, bottom: 16, left: 0, ime: 0 })

      // Connect, navigate Settings -> Connections -> Connection Detail -> RuleSet Detail -> 2x Android hardware back.
      await wrapper.find('.tabbar [data-page="home"]').trigger('click')
      await flushPromises()
      await connect(wrapper)

      const baseState = backend.state.bind(backend)
      backend.state = async () => {
        const snap = await baseState()
        return {
          ...snap,
          connections: [
            {
              id: 'android-rs-1',
              host: 't.me',
              outbound: '香港 01',
              network: 'tcp',
              conn_type: 'HTTPS',
              destination: '149.154.167.99:443',
              source: '127.0.0.1:56123',
              process: 'org.telegram.messenger',
              rule: 'RuleSet',
              rule_payload: 'telegram',
              chains: ['香港 01', '节点选择'],
              upload: 512,
              download: 4096,
              start: new Date(Date.now() - 5000).toISOString(),
            },
          ],
          connection_total: 1,
        }
      }

      await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
      await flushPromises()
      await wrapper.find('[data-tool="connections"]').trigger('click')
      await settle(1100)

      await wrapper.find('[data-testid="connection-search"]').setValue('t.me')
      await flushPromises()
      await wrapper.find('[data-connection-id="android-rs-1"]').trigger('click')
      await flushPromises()
      await body().find('[data-testid="open-conn-ruleset"]').trigger('click')
      await settle(500)

      expect(store.page.value).toBe('resources')
      expect(body().find('[data-testid="provider-detail"]').exists()).toBe(true)

      // 1st hardware back exits rule-set detail modal while staying on Resources.
      await hardwareBack()
      expect(body().find('[data-testid="provider-detail"]').exists()).toBe(false)
      expect(store.page.value).toBe('resources')

      // 2nd hardware back returns to Connections and restores filter + android-rs-1 detail modal!
      await hardwareBack()
      await flushPromises()
      expect(store.page.value).toBe('connections')
      expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('t.me')
      expect(body().find('.modal').exists()).toBe(true)
      expect(body().find('.modal').text()).toContain('t.me')
      expect(body().find('.modal').text()).toContain('127.0.0.1:56123')
    })
  })
})
