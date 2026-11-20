import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope } from 'vue'
import { createDemoBackend } from './demo'
import { createStore } from './store'
import { emptySnapshot, type Snapshot, type TrafficHistoryView } from './types'

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
