import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, provide } from 'vue'
import { createDemoBackend } from '../lib/demo'
import { createStore, STORE } from '../lib/store'
import type { Backend } from '../lib/backend'
import type { TrafficHistoryEntry, TrafficHistoryView } from '../lib/types'
import TrafficStatsDialog from './TrafficStatsDialog.vue'

const cleanups: (() => void)[] = []
afterEach(() => {
  cleanups.splice(0).forEach((stop) => stop())
  document.body.innerHTML = ''
})

const ENTRIES: TrafficHistoryEntry[] = [
  { date: '2026-11-20', profile: '配置 A', group: '节点选择', node: '香港 01', direct: false, upload: 10, download: 100 },
  { date: '2026-11-20', profile: '配置 B', group: '自动选择', node: '日本 02', direct: false, upload: 20, download: 200 },
  { date: '2026-11-20', profile: '配置 A', group: '', node: '', direct: true, upload: 5, download: 50 },
]

function view(overrides: Partial<TrafficHistoryView> = {}): TrafficHistoryView {
  return {
    enabled: true,
    retention_days: 90,
    today: '2026-11-20',
    from: '2026-11-20',
    to: '2026-11-20',
    entries: ENTRIES,
    ...overrides,
  }
}

async function setup(initial: TrafficHistoryView) {
  const demo = createDemoBackend()
  let current = initial
  const calls: { range: string; from?: string | null; to?: string | null }[] = []
  const cleared = vi.fn()
  const backend: Backend = {
    ...demo,
    async trafficHistory(range, from, to) {
      calls.push({ range, from, to })
      const start = from ?? current.from
      const end = to ?? current.to
      return { ...current, from: start, to: end }
    },
    async setTrafficRecording(enabled) {
      current = { ...current, enabled }
      const info = await demo.appInfo()
      return { ...info, traffic_history: enabled }
    },
    async clearTrafficHistory() {
      cleared()
      current = { ...current, entries: [] }
    },
  }
  const store = createStore(backend)
  const Harness = defineComponent({
    setup() {
      provide(STORE, store)
      return () => h(TrafficStatsDialog, { onClose: () => undefined })
    },
  })
  const wrapper = mount(Harness, { attachTo: document.body })
  await flushPromises()
  cleanups.push(() => {
    wrapper.unmount()
    store.stop()
  })
  return { wrapper, store, calls, cleared, backend }
}

function find<T extends HTMLElement = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector)
  if (!element) throw new Error(`missing ${selector}`)
  return element
}

async function click(testid: string) {
  find(`[data-testid="${testid}"]`).click()
  await flushPromises()
}

describe('TrafficStatsDialog (R43)', () => {
  it('says recording is off and turns it on from the empty state', async () => {
    const { store } = await setup(view({ enabled: false, entries: [] }))
    expect(find('[data-testid="traffic-off"]').textContent).toContain('未开启流量记录')
    expect(document.querySelector('[data-testid="traffic-row"]')).toBeNull()
    expect(document.querySelector('[data-testid="traffic-daily-bars"]')).toBeNull()

    await click('traffic-enable')
    expect(store.app.value?.traffic_history).toBe(true)
    // Once the switch is on the controls and the (still empty) summary appear.
    expect(document.querySelector('[data-testid="traffic-off"]')).toBeNull()
    expect(find('[data-testid="traffic-totals"]')).toBeTruthy()
    expect(find('[data-testid="traffic-empty"]').textContent).toContain('没有记录')
  })

  it('keeps earlier rows readable and clearable after recording is turned off', async () => {
    const { cleared } = await setup(view({ enabled: false }))
    // The off banner names the switch, but the rows are still there (R43).
    expect(find('[data-testid="traffic-off"]').textContent).toContain('未开启流量记录')
    expect(document.querySelectorAll('[data-testid="traffic-row"]').length).toBe(2)
    expect(find('[data-testid="traffic-total-download"]').textContent).toContain('350 B')
    expect(find('[data-testid="traffic-daily-bars"]')).toBeTruthy()

    await click('traffic-clear')
    await click('traffic-clear-confirm')
    expect(cleared).toHaveBeenCalledTimes(1)
    // With no rows left the dialog falls back to the on-switch empty state.
    expect(find('[data-testid="traffic-off"]').textContent).toContain('未开启流量记录')
    expect(document.querySelector('[data-testid="traffic-row"]')).toBeNull()
    expect(document.querySelector('[data-testid="traffic-enable"]')).not.toBeNull()
  })

  it('groups the same rows by profile, group or node and keeps the totals', async () => {
    await setup(view())
    // Default grouping: by profile; A also owns the DIRECT bytes.
    const profileRows = () => [...document.querySelectorAll<HTMLElement>('[data-testid="traffic-row"]')]
    expect(profileRows().map((row) => row.dataset.key)).toEqual(['profile:配置 B', 'profile:配置 A'])
    expect(profileRows()[0]!.textContent).toContain('200 B')
    // 100 download + 50 DIRECT download under profile A.
    expect(profileRows()[1]!.textContent).toContain('150 B')
    expect(find('[data-testid="traffic-total-download"]').textContent).toContain('350 B')
    expect(find('[data-testid="traffic-total-upload"]').textContent).toContain('35 B')
    expect(find('[data-testid="traffic-total-all"]').textContent).toContain('385 B')
    expect(find('[data-testid="traffic-daily-bars"]')).toBeTruthy()

    // Grouping by node keeps DIRECT/REJECT in one "Direct" row.
    find('[data-testid="traffic-grouping"] [data-value="node"]').click()
    await flushPromises()
    const nodeKeys = profileRows().map((row) => row.dataset.key)
    expect(nodeKeys).toContain('node:direct')
    expect(nodeKeys).toContain('node:香港 01')
    expect(nodeKeys).toContain('node:日本 02')
    const direct = find('[data-key="node:direct"]')
    expect(direct.textContent).toContain('直连')
    expect(direct.textContent).toContain('55 B')

    // Grouping by proxy group is the third view over the same numbers.
    find('[data-testid="traffic-grouping"] [data-value="group"]').click()
    await flushPromises()
    expect(profileRows().map((row) => row.dataset.key)).toContain('group:节点选择')
  })

  it('switches ranges, keeps custom inside the retention window and clears everything', async () => {
    const { calls, cleared } = await setup(view())

    find('[data-testid="traffic-range"] [data-value="7d"]').click()
    await flushPromises()
    expect(calls.at(-1)?.range).toBe('7d')

    find('[data-testid="traffic-range"] [data-value="custom"]').click()
    await flushPromises()
    const from = find<HTMLInputElement>('[data-testid="traffic-from"]')
    const to = find<HTMLInputElement>('[data-testid="traffic-to"]')
    // The pickers cannot reach past the 90-day retention window.
    expect(from.min).toBe('2026-08-23')
    expect(from.max).toBe('2026-11-20')
    expect(to.max).toBe('2026-11-20')
    from.value = '2026-11-01'
    from.dispatchEvent(new Event('input', { bubbles: true }))
    from.dispatchEvent(new Event('change', { bubbles: true }))
    await flushPromises()
    expect(calls.at(-1)).toMatchObject({ range: 'custom', from: '2026-11-01' })

    // Clear-all asks first, then empties the view.
    expect(document.querySelector('[data-testid="traffic-clear-confirm"]')).toBeNull()
    await click('traffic-clear')
    expect(document.querySelector('[data-testid="traffic-clear-confirm"]')).not.toBeNull()
    await click('traffic-clear-cancel')
    expect(cleared).not.toHaveBeenCalled()
    await click('traffic-clear')
    await click('traffic-clear-confirm')
    expect(cleared).toHaveBeenCalledTimes(1)
    expect(document.querySelector('[data-testid="traffic-row"]')).toBeNull()
    expect(find('[data-testid="traffic-empty"]')).toBeTruthy()
  })
})

describe('demo traffic history (R43)', () => {
  it('records only while the switch is on and keeps the rows after it is turned off', async () => {
    const backend = createDemoBackend()
    await backend.connect()
    await backend.state()
    await backend.state()
    expect((await backend.trafficHistory('today')).entries).toHaveLength(0)
    expect((await backend.appInfo()).traffic_history).toBe(false)

    await backend.setTrafficRecording(true)
    await backend.state()
    const recorded = await backend.trafficHistory('today')
    expect(recorded.enabled).toBe(true)
    expect(recorded.entries.length).toBeGreaterThan(0)
    const before = recorded.entries.reduce((sum, entry) => sum + entry.upload + entry.download, 0)

    await backend.setTrafficRecording(false)
    await backend.state()
    await backend.state()
    const after = (await backend.trafficHistory('today')).entries.reduce(
      (sum, entry) => sum + entry.upload + entry.download,
      0,
    )
    expect(after).toBe(before)
  })
})
