import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope } from 'vue'
import { createDemoBackend } from './demo'
import { createStore } from './store'
import { emptySnapshot, type Snapshot } from './types'

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
      group_type: 'select', icon: null, nodes: [{ name: 'a', node_type: 'ss', delay_ms: null, failed: false, selected: true }] }]
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: catalog })
    await store.start()
    state.mockResolvedValue({ ...emptySnapshot(), upload: 10, node_catalog: structuredClone(catalog) })
    await vi.advanceTimersByTimeAsync(1000)
    expect(store.snapshot.value.node_catalog).toBe(catalog)
    const changed = structuredClone(catalog)
    changed[0]!.now = 'b'
    changed[0]!.nodes[0]!.selected = false
    changed[0]!.nodes.push({ name: 'b', node_type: 'vmess', delay_ms: 18, failed: false, selected: true })
    state.mockResolvedValue({ ...emptySnapshot(), node_catalog: changed })
    await vi.advanceTimersByTimeAsync(3000)
    expect(store.snapshot.value.node_catalog).toBe(changed)
    expect(store.snapshot.value.node_catalog[0]!.now).toBe('b')
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
