import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope } from 'vue'
import App from '../App.vue'
import { createDemoBackend } from './demo'
import { looksLikeCustomNodeInput } from './links'
import { createStore, type Store } from './store'
import { CUSTOM_PROFILE_ID, LANDING_GROUP_NAME, emptySnapshot, type Snapshot, type TrafficHistoryView } from './types'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

const cleanup: (() => void)[] = []

function setup() {
  const backend = createDemoBackend()
  const state = vi.spyOn(backend, 'state').mockResolvedValue(emptySnapshot())
  const scope = effectScope()
  const store = scope.run(() => createStore(backend))!
  cleanup.push(() => { store.stop(); scope.stop() })
  return { backend, state, store }
}

function visibility(value: DocumentVisibilityState) {
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue(value)
  document.dispatchEvent(new Event('visibilitychange'))
}

beforeEach(() => {
  vi.useFakeTimers()
  visibility('visible')
})

afterEach(() => {
  cleanup.splice(0).forEach((stop) => stop())
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('store lifecycle', () => {
  it('navigates immediately and coalesces pending page writes in order', async () => {
    const { store, backend } = setup()
    const first = deferred<void>()
    const save = vi.spyOn(backend, 'setEntry').mockReturnValueOnce(first.promise).mockResolvedValue(undefined)
    store.go('proxies')
    store.go('rules')
    store.go('logs')
    store.go('logs')
    expect(store.page.value).toBe('logs')
    expect(save.mock.calls).toEqual([['proxies']])
    first.resolve()
    await vi.advanceTimersByTimeAsync(0)
    expect(save.mock.calls).toEqual([['proxies'], ['logs']])
  })

  it('shares an active subscription download between a manual update and a batch', async () => {
    const { backend, state, store } = setup()
    const adding = backend.addSubscription('https://example.org/sub')
    await vi.runAllTimersAsync()
    const initial = await adding
    const id = initial.profiles.find((profile) => profile.source === 'https://example.org/sub')!.id
    initial.active_id = id
    state.mockResolvedValue(initial)
    await store.start()
    const download = deferred<Snapshot>()
    const refresh = vi.spyOn(backend, 'refresh').mockReturnValue(download.promise)
    const activate = vi.spyOn(backend, 'update')
    const manual = store.update(id)
    const batch = store.updateAll([id, id])
    await Promise.resolve()
    expect(refresh.mock.calls).toEqual([[id]])
    expect(activate).not.toHaveBeenCalled()
    expect(store.busy[`update:${id}`]).toBe(true)
    download.resolve(initial)
    await Promise.all([manual, batch])
    expect(store.busy[`update:${id}`]).toBeUndefined()
    expect(store.refreshProgress.value).toEqual({ done: 1, total: 1, failed: 0 })
  })

  it('releases feedback for a deleted subscription and discards its late update', async () => {
    const { backend, state, store } = setup()
    const adding = backend.addSubscription('https://example.org/sub')
    await vi.runAllTimersAsync()
    const initial = await adding
    const id = initial.profiles.find((profile) => profile.source === 'https://example.org/sub')!.id
    state.mockResolvedValue(initial)
    await store.start()

    const download = deferred<Snapshot>()
    vi.spyOn(backend, 'refresh').mockReturnValue(download.promise)
    const update = store.update(id)
    await Promise.resolve()
    expect(store.profileUpdates[id]?.state).toBe('updating')

    const removed = { ...initial, profiles: initial.profiles.filter((profile) => profile.id !== id) }
    vi.spyOn(backend, 'remove').mockResolvedValue(removed)
    await store.remove(id)
    expect(store.profileUpdates[id]).toBeUndefined()
    expect(store.busy[`update:${id}`]).toBeUndefined()

    download.resolve(initial)
    await update
    expect(store.snapshot.value.profiles.some((profile) => profile.id === id)).toBe(false)
    expect(store.profileUpdates[id]).toBeUndefined()
  })

  it('preserves unaffected groups and log rows when one group changes', async () => {
    const { store, state } = setup()
    const catalog: Snapshot['node_catalog'] = ['a', 'b'].map((name) => ({ name, kind: 'manual', now: '',
      sort: 'default', group_type: 'select', icon: null, nodes: [] }))
    const logs: Snapshot['logs'] = [{ level: 'info', message: 'ready', time_ms: 1 }]
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: catalog, logs })
    await store.start()
    const changed = structuredClone(catalog)
    changed[1]!.now = 'new'
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: changed, logs: structuredClone(logs) })
    await vi.advanceTimersByTimeAsync(1000)
    expect(store.snapshot.value.node_catalog[0]).toBe(catalog[0])
    expect(store.snapshot.value.node_catalog[1]!.now).toBe('new')
    expect(store.snapshot.value.logs).toBe(logs)
  })

  it('keeps the proxy catalog stable on traffic-only polls, but applies changed members and selection', async () => {
    const { store, state } = setup()
    const catalog: Snapshot['node_catalog'] = [{ name: 'Available', kind: 'manual', now: 'a', sort: 'default',
      group_type: 'select', icon: null, nodes: [{ name: 'a', node_type: 'ss', tags: [], delay_ms: null, failed: false, selected: true }] }]
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: catalog })
    await store.start()
    state.mockResolvedValue({ ...emptySnapshot(), upload: 10, node_catalog: structuredClone(catalog) })
    await vi.advanceTimersByTimeAsync(1000)
    expect(store.snapshot.value.node_catalog).toBe(catalog)
    const changed = structuredClone(catalog)
    changed[0]!.now = 'b'
    changed[0]!.nodes[0]!.selected = false
    changed[0]!.nodes.push({ name: 'b', node_type: 'vmess', tags: [], delay_ms: 18, failed: false, selected: true })
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: changed })
    await vi.advanceTimersByTimeAsync(3000)
    expect(store.snapshot.value.node_catalog).toBe(changed)
    expect(store.snapshot.value.node_catalog[0]!.now).toBe('b')
  })

  it('retains app list identity but publishes changed node capabilities', async () => {
    const { store, state } = setup()
    const initial = emptySnapshot()
    initial.installed = [{ name: 'Browser', package_name: 'com.example.browser', system: false }]
    initial.excluded = ['com.example.browser']
    initial.node_catalog = [{ name: 'Available', kind: 'manual', now: 'a', sort: 'default',
      group_type: 'select', icon: null, nodes: [{ name: 'a', node_type: 'ss', tags: [], delay_ms: null, failed: false, selected: true }] }]
    state.mockResolvedValue(initial)
    await store.start()
    const changed = structuredClone(initial)
    changed.node_catalog[0]!.nodes[0]!.tags = ['UDP']
    state.mockResolvedValue(changed)
    await vi.advanceTimersByTimeAsync(3000)
    expect(store.snapshot.value.installed).toBe(initial.installed)
    expect(store.snapshot.value.excluded).toBe(initial.excluded)
    expect(store.snapshot.value.node_catalog[0]!.nodes[0]!.tags).toEqual(['UDP'])
  })

  it('publishes changes to group pinning, visibility and structured log hints on poll', async () => {
    const { store, state } = setup()
    const initial = emptySnapshot()
    initial.node_catalog = [{ name: 'Auto', kind: 'auto', now: 'a', sort: 'default',
      group_type: 'url-test', icon: null, nodes: [], pinnable: true, hidden: false, fixed: null }]
    initial.logs = [{ time_ms: 1, level: 'error', message: 'listen', hint: 'port', hint_kind: 'socks' }]
    state.mockResolvedValue(initial)
    await store.start()
    const changed = structuredClone(initial)
    Object.assign(changed.node_catalog[0]!, { hidden: true, fixed: 'a' })
    changed.logs[0]!.hint_kind = 'mixed'
    state.mockResolvedValue(changed)
    await vi.advanceTimersByTimeAsync(1000)
    expect(store.snapshot.value.node_catalog[0]).toMatchObject({ hidden: true, fixed: 'a' })
    expect(store.snapshot.value.logs[0]?.hint_kind).toBe('mixed')

    const next = structuredClone(changed)
    next.node_catalog[0]!.pinnable = false
    state.mockResolvedValue(next)
    await vi.advanceTimersByTimeAsync(3000)
    expect(store.snapshot.value.node_catalog[0]?.pinnable).toBe(false)
  })

  it('suspends polling while hidden and refreshes immediately on return', async () => {
    const { store, state } = setup()
    await store.start()
    visibility('hidden')
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(state).toHaveBeenCalledTimes(1)
    visibility('visible')
    await vi.advanceTimersByTimeAsync(0)
    expect(state).toHaveBeenCalledTimes(2)
    expect(vi.getTimerCount()).toBe(1)
  })

  it('does not publish or schedule a poll that finishes after stop', async () => {
    const { store, state } = setup()
    await store.start()
    const pending = deferred<Snapshot>()
    state.mockReturnValueOnce(pending.promise)
    await vi.advanceTimersByTimeAsync(1000)
    store.stop()
    pending.resolve({ ...emptySnapshot(), notice: 'obsolete' })
    await vi.advanceTimersByTimeAsync(0)
    expect(store.snapshot.value.notice).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['onChange', 'onNodeTest'] as const)('releases %s if registration finishes after stop', async (event) => {
    const { store, backend } = setup()
    const pending = deferred<() => void>()
    const unsubscribe = vi.fn()
    const registration = vi.spyOn(backend, event).mockReturnValue(pending.promise)
    const starting = store.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(registration).toHaveBeenCalledTimes(1)
    store.stop()
    pending.resolve(unsubscribe)
    await starting
    expect(unsubscribe).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps one request in flight across visibility changes', async () => {
    const { store, state } = setup()
    await store.start()
    const pending = deferred<Snapshot>()
    state.mockReturnValueOnce(pending.promise)
    await vi.advanceTimersByTimeAsync(1000)
    visibility('hidden')
    visibility('visible')
    await vi.advanceTimersByTimeAsync(3000)
    expect(state).toHaveBeenCalledTimes(2)
    visibility('hidden')
    pending.resolve(emptySnapshot())
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(0)
    visibility('visible')
    await vi.advanceTimersByTimeAsync(0)
    expect(state).toHaveBeenCalledTimes(3)
    expect(vi.getTimerCount()).toBe(1)
  })

  it('starts only once and releases both listeners on repeated stop', async () => {
    const { store, backend, state } = setup()
    const changes = vi.fn()
    const nodes = vi.fn()
    vi.spyOn(backend, 'onChange').mockResolvedValue(changes)
    vi.spyOn(backend, 'onNodeTest').mockResolvedValue(nodes)
    await Promise.all([store.start(), store.start()])
    expect(state).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(1)
    store.stop()
    store.stop()
    expect(changes).toHaveBeenCalledTimes(1)
    expect(nodes).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('ignores an old initialization after a new start', async () => {
    const { store, state } = setup()
    const pending = deferred<Snapshot>()
    state.mockReturnValueOnce(pending.promise)
    const first = store.start()
    await vi.advanceTimersByTimeAsync(0)
    store.stop()
    await store.start()
    pending.resolve({ ...emptySnapshot(), notice: 'old session' })
    await first
    expect(store.snapshot.value.notice).toBeNull()
    expect(vi.getTimerCount()).toBe(1)
  })

  it('bounds toast timers to visible messages and clears them on stop', () => {
    const { store } = setup()
    for (let i = 0; i < 100; i += 1) store.toast(`message ${i}`)
    expect(store.toasts.value).toHaveLength(4)
    expect(vi.getTimerCount()).toBe(4)
    store.stop()
    expect(vi.getTimerCount()).toBe(0)
    expect(store.toasts.value).toHaveLength(0)
  })

  it('deduplicates active toasts with the same tone and text, supports dedupe:false and respects paused state', async () => {
    const { store } = setup()
    const firstClick = vi.fn()
    const secondClick = vi.fn()

    store.toast('连接失败', 'error', { label: '重试', onClick: firstClick })
    expect(store.toasts.value).toHaveLength(1)
    const firstId = store.toasts.value[0]!.id

    await vi.advanceTimersByTimeAsync(4000)
    expect(store.toasts.value).toHaveLength(1)

    // Same tone + text updates in-place and resets the 5200ms timer.
    store.toast('连接失败', 'error', { label: '立即重试', onClick: secondClick })
    expect(store.toasts.value).toHaveLength(1)
    expect(store.toasts.value[0]!.id).toBe(firstId)
    expect(store.toasts.value[0]!.action?.label).toBe('立即重试')
    expect(store.toasts.value[0]!.action?.onClick).toBe(secondClick)

    // Refreshing a paused toast keeps it paused instead of restarting the timer.
    store.pauseToast(firstId)
    store.toast('连接失败', 'error', { label: '继续重试', onClick: secondClick })
    await vi.advanceTimersByTimeAsync(10_000)
    expect(store.toasts.value.some((item) => item.id === firstId)).toBe(true)
    store.resumeToast(firstId)

    // Explicit dedupe: false allows repeated identical prompts.
    store.toast('连接失败', 'error', { dedupe: false })
    expect(store.toasts.value.filter((item) => item.tone === 'error')).toHaveLength(2)

    // Different tone with same text is kept separate.
    store.toast('连接失败', 'info')
    expect(store.toasts.value).toHaveLength(3)

    await vi.advanceTimersByTimeAsync(5300)
    expect(store.toasts.value.some((item) => item.id === firstId)).toBe(false)
  })

  it('attaches real interactive retry actions on subscription update failure and renders clickable .toast-action in App', async () => {
    const { backend, state, store } = setup()
    const adding = backend.addSubscription('https://example.org/sub')
    await vi.runAllTimersAsync()
    const initial = await adding
    const id = initial.profiles.find((profile) => profile.source === 'https://example.org/sub')!.id
    state.mockResolvedValue(initial)
    await store.start()

    const refresh = vi
      .spyOn(backend, 'refresh')
      .mockRejectedValueOnce(new Error('网络超时'))
      .mockResolvedValueOnce(initial)

    await store.update(id)
    const errToast = store.toasts.value.find((item) => item.tone === 'error' && item.text.includes('网络超时'))
    expect(errToast?.action?.label).toBe('重试')
    errToast?.action?.onClick()
    await vi.advanceTimersByTimeAsync(0)
    expect(refresh).toHaveBeenCalledTimes(2)

    // Verify App.vue renders .toast-action, pauses on focusin, invokes onClick and dismisses.
    const appBackend = createDemoBackend()
    const wrapper = mount(App, { props: { backend: appBackend, width: 1200 }, attachTo: document.body })
    cleanup.push(() => wrapper.unmount())
    await vi.advanceTimersByTimeAsync(50)
    await flushPromises()

    const appStore = (wrapper.vm as unknown as { store: Store }).store
    const onAction = vi.fn()
    appStore.toast('已添加订阅，点击即可启用', 'success', { label: '查看配置', onClick: onAction })
    await flushPromises()

    const actionBtn = wrapper.find('[data-testid="toast-action"]')
    expect(actionBtn.exists()).toBe(true)
    expect(actionBtn.text()).toBe('查看配置')

    await wrapper.find('.toast').trigger('focusin')
    await vi.advanceTimersByTimeAsync(10_000)
    expect(wrapper.find('[data-testid="toast-action"]').exists()).toBe(true)

    await actionBtn.trigger('click')
    await flushPromises()
    expect(onAction).toHaveBeenCalledTimes(1)
    expect(wrapper.find('.toast').exists()).toBe(false)
  })

  it('exposes customNodeImportRequest for cross-view handoff and detects custom node inputs', () => {
    const { store } = setup()
    expect(store.customNodeImportRequest.value).toBeNull()
    store.customNodeImportRequest.value = 'vless://uuid@example.com:443#Node'
    expect(store.customNodeImportRequest.value).toBe('vless://uuid@example.com:443#Node')

    expect(looksLikeCustomNodeInput('vless://uuid@example.com:443#HK')).toBe(true)
    expect(looksLikeCustomNodeInput('hy2://pwd@example.com:443#JP')).toBe(true)
    expect(looksLikeCustomNodeInput('http://user:pass@proxy.example.com:8080')).toBe(true)
    expect(looksLikeCustomNodeInput('proxies:\n  - name: demo\n    type: ss\n    server: 1.2.3.4')).toBe(true)
    expect(looksLikeCustomNodeInput('https://sub.example.com/clash?token=abc')).toBe(false)
    expect(looksLikeCustomNodeInput('   ')).toBe(false)
  })
})

describe('traffic history reads', () => {
  it('coalesces rapid range changes and discards the superseded result', async () => {
    const { store, backend } = setup()
    const today = await backend.trafficHistory('today')
    const first = deferred<TrafficHistoryView>()
    const last = deferred<TrafficHistoryView>()
    const read = vi.spyOn(backend, 'trafficHistory')
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(last.promise)

    store.openTrafficStats()
    void store.loadTrafficStats('today')
    await Promise.resolve()
    void store.loadTrafficStats('7d')
    const latest = store.loadTrafficStats('30d')
    expect(read.mock.calls).toEqual([['today', null, null]])

    first.resolve(today)
    await Promise.resolve()
    expect(read.mock.calls).toEqual([['today', null, null], ['30d', null, null]])
    expect(store.trafficStats.value).toBeNull()
    expect(store.trafficStatsBusy.value).toBe(true)

    const month = { ...today, from: '2026-11-01' }
    last.resolve(month)
    expect(await latest).toBe(month)
    expect(store.trafficStats.value).toBe(month)
    expect(store.trafficStatsBusy.value).toBe(false)
  })

  it('releases loaded rows and drops reads that complete after closing', async () => {
    const { store, backend } = setup()
    const today = await backend.trafficHistory('today')
    const read = vi.spyOn(backend, 'trafficHistory').mockResolvedValue(today)
    await store.setTrafficRecording(true)
    expect(read).not.toHaveBeenCalled()

    store.openTrafficStats()
    await store.loadTrafficStats()
    expect(store.trafficStats.value).toBe(today)

    const next = deferred<TrafficHistoryView>()
    read.mockReturnValueOnce(next.promise)
    const inFlight = store.loadTrafficStats('7d')
    await Promise.resolve()
    store.releaseTrafficStats()
    expect(store.trafficStats.value).toBeNull()
    expect(store.trafficStatsBusy.value).toBe(false)
    next.resolve(today)
    expect(await inFlight).toBeUndefined()
    expect(store.trafficStats.value).toBeNull()
    expect(store.trafficStatsRange.value.range).toBe('7d')
  })
})

describe('custom nodes & chain proxy store + demo parity', () => {
  function setupLiveDemo(profiles = true) {
    const backend = createDemoBackend({ profiles })
    const scope = effectScope()
    const store = scope.run(() => createStore(backend))!
    cleanup.push(() => { store.stop(); scope.stop() })
    return { backend, store }
  }

  it('previews and imports multi-protocol links (including anytls://) with partial error isolation and deduplication', async () => {
    const { store } = setupLiveDemo(true)
    const startP = store.start()
    await vi.advanceTimersByTimeAsync(200)
    await startP

    const raw = [
      'anytls://secret@anytls.example.com:443?sni=anytls.example.com#US-AnyTLS',
      'anytls://secret@anytls.example.com:443#US-AnyTLS',
      'socks5://user:pass@1.2.3.4:1080#Resi-Socks',
      'ftp://unsupported.example.com:21#Bad',
    ].join('\n')

    const preview = await store.previewCustomNodesImport(raw)
    expect(preview.parsed.map((item) => item.name)).toEqual(['US-AnyTLS', 'US-AnyTLS (2)', 'Resi-Socks'])
    expect(preview.parsed[0]?.protocol).toBe('anytls')
    expect(preview.errors).toHaveLength(1)

    const importP = store.importCustomNodes(raw, { kind: 'profile_group', group: null })
    await vi.advanceTimersByTimeAsync(200)
    const result = await importP
    expect(result?.imported).toHaveLength(3)
    expect(result?.errors).toHaveLength(1)
    expect(store.hasCustomNodes.value).toBe(true)
    expect(store.snapshot.value.node_catalog.some((g) => g.name === LANDING_GROUP_NAME)).toBe(true)

    // Toggling overlay off must remove the injected landing group cleanly
    const overlayOffP = store.setCustomNodesOverlay(false)
    await vi.advanceTimersByTimeAsync(200)
    await overlayOffP
    expect(store.customNodes.value.overlay_enabled).toBe(false)
    expect(store.snapshot.value.node_catalog.some((g) => g.name === LANDING_GROUP_NAME)).toBe(false)
  })

  it('supports SOCKS5 form save, rejects dialer cycles, auto-activates pure custom mode, and saves landing rules', async () => {
    const { store } = setupLiveDemo(false)
    const startP = store.start()
    await vi.advanceTimersByTimeAsync(200)
    await startP
    expect(store.hasProfiles.value).toBe(false)
    expect(store.customProfileActive.value).toBe(false)

    // Save node A via SOCKS5 quick form -> auto-activates pure custom mode
    const saveA = store.saveCustomNode({
      simple: {
        name: 'Home-Socks',
        protocol: 'socks5',
        server: '198.51.100.10',
        port: 1080,
        username: 'u',
        password: 'p',
        tls: false,
        skip_cert_verify: false,
        udp: true,
      },
      dialer: { kind: 'direct' },
    })
    await vi.advanceTimersByTimeAsync(200)
    await saveA
    expect(store.customProfileActive.value).toBe(true)
    expect(store.snapshot.value.active_id).toBe(CUSTOM_PROFILE_ID)
    const nodeA = store.customNodes.value.nodes[0]!

    // Save node B chained via node A
    const saveB = store.saveCustomNode({
      raw_yaml: 'name: Exit-AnyTLS\ntype: anytls\nserver: 203.0.113.5\nport: 443\npassword: pwd',
      dialer: { kind: 'custom_node', id: nodeA.id },
    })
    await vi.advanceTimersByTimeAsync(200)
    await saveB
    const nodeB = store.customNodes.value.nodes[1]!

    // Attempting to chain node A back through node B must be rejected
    const cycleP = store.saveCustomNode({
      id: nodeA.id,
      dialer: { kind: 'custom_node', id: nodeB.id },
    })
    await vi.advanceTimersByTimeAsync(200)
    const cycleRes = await cycleP
    expect(cycleRes).toBeUndefined()
    expect(store.lastRunError.value).toContain('循环引用')

    // Save AI preset + custom domain landing rules
    const rulesP = store.saveLandingRules(true, [
      { id: '', enabled: true, rule: { kind: 'preset', id: 'ai' }, target: { kind: 'custom_group' } },
      { id: '', enabled: true, rule: { kind: 'domain', pattern: 'claude.ai' }, target: { kind: 'custom_node', id: nodeB.id } },
    ])
    await vi.advanceTimersByTimeAsync(200)
    await rulesP
    expect(store.customNodes.value.rules).toHaveLength(2)
    expect(store.customNodes.value.rules[0]?.id).toBeTruthy()
  })
})
