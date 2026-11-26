import { nextTick, ref } from 'vue'
import { describe, expect, it } from 'vitest'
import { createDemoBackend } from '../demo'
import { createStore } from '../store'
import { useDynamicVirtualList } from './dynamicVirtual'

function makeContainer(clientHeight = 320, scrollTop = 0, scrollHeight = 0) {
  const el = document.createElement('div')
  Object.defineProperty(el, 'clientHeight', { value: clientHeight, configurable: true })
  Object.defineProperty(el, 'scrollHeight', {
    get: () => scrollHeight,
    set: (v: number) => {
      scrollHeight = v
    },
    configurable: true,
  })
  el.scrollTop = scrollTop
  return el
}

describe('useDynamicVirtualList', () => {
  it('uses estimated heights before measurement and windows 1000 rows tightly', () => {
    const count = ref(1000)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 4 })
    const el = makeContainer(320, 0)
    list.measure(el)

    expect(list.totalHeight.value).toBe(32000)
    expect(list.window.value.start).toBe(0)
    // 320 / 32 = 10 visible + 4 overscan below = 14
    expect(list.window.value.end).toBe(14)
    expect(list.offset.value).toBe(0)
    expect(list.tail.value).toBe((1000 - 14) * 32)
  })

  it('recomputes offsets and totalHeight when measured row heights arrive', () => {
    const count = ref(20)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 2 })
    const el = makeContainer(160, 0)
    list.measure(el)

    // Row 0 wraps to 96px (+64px), row 1 wraps to 64px (+32px)
    expect(list.setItemHeight(0, 96)).toBe(64)
    expect(list.setItemHeight(1, 64)).toBe(32)
    // Sub-pixel / identical update is a no-op
    expect(list.setItemHeight(0, 96.2)).toBe(0)
    // Invalid height is ignored
    expect(list.setItemHeight(2, 0)).toBe(0)
    expect(list.setItemHeight(2, Number.NaN)).toBe(0)

    expect(list.heightOf(0)).toBe(96)
    expect(list.heightOf(1)).toBe(64)
    expect(list.offsetOf(1)).toBe(96)
    expect(list.offsetOf(2)).toBe(160)
    expect(list.totalHeight.value).toBe(20 * 32 + 64 + 32)
  })

  it('preserves visual scroll anchor when not following (history reading)', () => {
    const count = ref(100)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 3 })
    const el = makeContainer(320, 640)
    list.measure(el)
    expect(list.scrollTop.value).toBe(640)

    // Row 5 is strictly above scrollTop (5 * 32 = 160 < 640): growing by +48 shifts scrollTop by +48
    const deltaAbove = list.setItemHeight(5, 80, el, { follow: false })
    expect(deltaAbove).toBe(48)
    expect(list.scrollTop.value).toBe(688)
    expect(el.scrollTop).toBe(688)

    // Row 25 is below scrollTop: growing does NOT push scrollTop away from reading position
    const deltaBelow = list.setItemHeight(25, 96, el, { follow: false })
    expect(deltaBelow).toBe(64)
    expect(list.scrollTop.value).toBe(688)
    expect(el.scrollTop).toBe(688)
  })

  it('stays pinned to bottom in follow mode when rows expand or append', () => {
    const count = ref(50)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 3 })
    const el = makeContainer(320, 0, 1600)
    list.measure(el)
    list.scrollToBottom(el)
    expect(list.scrollTop.value).toBe(1600 - 320)

    // Last row wraps taller while following -> scrollTop advances to new bottom
    list.setItemHeight(49, 96, el, { follow: true })
    expect(list.totalHeight.value).toBe(50 * 32 + 64)
    expect(list.scrollTop.value).toBe(list.totalHeight.value - 320)
    expect(el.scrollTop).toBe(list.totalHeight.value - 320)

    // Append 10 new logs and scrollToBottom
    count.value = 60
    list.scrollToBottom(el)
    expect(list.scrollTop.value).toBe(list.totalHeight.value - 320)
  })

  it('invalidates cached heights on wrap/width change while optionally keeping scroll', () => {
    const count = ref(100)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 2 })
    const el = makeContainer(320, 500)
    list.measure(el)
    list.setItemHeight(10, 120)
    expect(list.heightOf(10)).toBe(120)

    // Toggling word wrap while reading history keeps scrollTop instead of jumping
    list.invalidate(el, { keepScroll: true })
    expect(list.heightOf(10)).toBe(32)
    expect(list.scrollTop.value).toBe(500)
    expect(el.scrollTop).toBe(500)

    // Full invalidation resets scrollTop to 0
    list.invalidate(el)
    expect(list.scrollTop.value).toBe(0)
    expect(el.scrollTop).toBe(0)
  })

  it('keeps measured heights attached to stable keys across ring-buffer shifts', () => {
    const items = ref(Array.from({ length: 10 }, (_, i) => ({ id: i + 1 })))
    const count = ref(items.value.length)
    const list = useDynamicVirtualList(count, {
      estimateHeight: 32,
      overscan: 2,
      keyOf: (index) => items.value[index]?.id ?? index,
    })

    // Measure item id=5 (at index 4) as 88px
    list.setItemHeight(4, 88)
    expect(list.heightOf(4)).toBe(88)

    // Drop first 2 items and append 2 new items (ring-buffer shift)
    items.value = [...items.value.slice(2), { id: 11 }, { id: 12 }]
    // Item id=5 is now at index 2 and still has height 88px
    expect(list.heightOf(2)).toBe(88)
    expect(list.heightOf(4)).toBe(32)
  })

  it('prunes evicted keys during setItemHeight when ring buffer stays at fixed count', () => {
    const baseKey = ref(0)
    const count = ref(10)
    const list = useDynamicVirtualList(count, {
      estimateHeight: 32,
      overscan: 2,
      keyOf: (index) => baseKey.value + index,
    })

    // Measure key=0 as 96px, then rotate keys past the 2048 pruning threshold with fixed count=10
    list.setItemHeight(0, 96)
    expect(list.heightOf(0)).toBe(96)
    for (let step = 1; step <= 2060; step++) {
      baseKey.value = step
      list.setItemHeight(0, 64)
    }
    // Current live key (2060) retains its measured height
    expect(list.heightOf(0)).toBe(64)
    // Evicted key (0) was pruned and falls back to estimateHeight (32)
    baseKey.value = 0
    expect(list.heightOf(0)).toBe(32)
  })

  it('clamps window safely when list shrinks or refills from empty', async () => {
    const count = ref(100)
    const list = useDynamicVirtualList(count, { estimateHeight: 32, overscan: 2 })
    const el = makeContainer(320, 2500)
    list.measure(el)
    expect(list.window.value.start).toBeGreaterThan(50)

    // Shrink list dramatically
    count.value = 5
    expect(list.window.value.start).toBe(0)
    expect(list.window.value.end).toBe(5)

    // Empty then refill resets scrollTop to 0
    count.value = 0
    await nextTick()
    expect(list.window.value).toEqual({ start: 0, end: 0 })
    count.value = 40
    await nextTick()
    expect(list.scrollTop.value).toBe(0)
    expect(list.window.value.start).toBe(0)
  })
})

describe('store cross-page diagnostic return state machine', () => {
  it('preserves connectionReturn across connections -> rules -> resources -> rules -> connections', async () => {
    const backend = createDemoBackend()
    const store = createStore(backend)
    await store.start()
    try {
      store.go('connections')
      store.connectionReturn.value = {
        sessionId: store.connectionSessionId.value,
        targetPage: 'rules',
        tab: 'active',
        query: 'openai.com',
        routeFilter: 'reject',
        protocolFilter: 'tcp',
        activeOnly: true,
        quickProcess: 'curl',
        quickHost: 'openai.com',
        sortKey: 'time',
        sortDir: 'desc',
        listScrollTop: 120,
        paused: false,
        pausedAt: null,
        frozenRows: [],
        frozenIds: [],
        frozenTotal: 0,
        frozenUp: null,
        frozenDown: null,
        connectionKey: null,
        detailFromClosed: false,
        rulePolicy: 'DIRECT',
      }

      // Hop 1: connections -> rules
      store.openRuleMatch({ target: 'openai.com', dstPort: 443, process: 'curl', fromConnections: true })
      expect(store.page.value).toBe('rules')
      expect(store.connectionReturn.value?.targetPage).toBe('rules')
      expect(store.diagnosticTarget.value).toEqual({
        kind: 'rule-match',
        target: 'openai.com',
        dstPort: 443,
        process: 'curl',
      })

      // Hop 2: rules -> resources (saving ruleReturn first)
      store.ruleReturn.value = {
        sessionId: store.connectionSessionId.value,
        profileId: store.snapshot.value.active_id,
        targetPage: 'resources',
        query: 'cn',
        kindFilter: 'all',
        proxyFilter: 'all',
        disabledOnly: false,
        listScrollTop: 64,
        limit: 400,
        matcherOpen: true,
        matchTarget: 'openai.com',
        matchPort: '443',
        matchProcess: 'curl',
        matchResult: null,
      }
      store.openProvider('rule', 'cn-domains')
      expect(store.page.value).toBe('resources')
      expect(store.ruleReturn.value?.targetPage).toBe('resources')
      // connectionReturn MUST survive the nested rules -> resources hop
      expect(store.connectionReturn.value?.query).toBe('openai.com')

      // Return 1: resources -> rules
      store.go('rules')
      expect(store.page.value).toBe('rules')
      expect(store.ruleReturn.value?.query).toBe('cn')
      expect(store.connectionReturn.value?.query).toBe('openai.com')

      // Return 2: rules -> connections
      store.go('connections')
      expect(store.page.value).toBe('connections')
      expect(store.connectionReturn.value?.query).toBe('openai.com')
      expect(store.ruleReturn.value).toBeNull()

      // Navigating away to an unrelated page clears connectionReturn
      store.go('settings')
      expect(store.connectionReturn.value).toBeNull()
    } finally {
      store.stop()
    }
  })

  it('increments connectionSessionId and clears ruleReturn/diagnosticTarget when switching profile while connected', async () => {
    const backend = createDemoBackend()
    const store = createStore(backend)
    await store.start()
    try {
      await store.connect()
      expect(store.snapshot.value.connected).toBe(true)
      const beforeSession = store.connectionSessionId.value
      const other = store.snapshot.value.profiles.find((p) => !p.current)
      expect(other).toBeDefined()

      store.ruleReturn.value = {
        sessionId: beforeSession,
        profileId: store.snapshot.value.active_id,
        targetPage: 'resources',
        query: '',
        kindFilter: 'all',
        proxyFilter: 'all',
        disabledOnly: false,
        listScrollTop: 0,
        limit: 400,
        matcherOpen: false,
        matchTarget: '',
        matchPort: '',
        matchProcess: '',
        matchResult: null,
      }
      store.diagnosticTarget.value = { kind: 'connection-search', query: 'github.com' }
      store.go('resources')

      await store.enable(other!.id)
      expect(store.snapshot.value.connected).toBe(true)
      expect(store.snapshot.value.active_id).toBe(other!.id)
      expect(store.connectionSessionId.value).toBe(beforeSession + 1)
      expect(store.ruleReturn.value).toBeNull()
      expect(store.diagnosticTarget.value).toBeNull()
    } finally {
      store.stop()
    }
  })
})
