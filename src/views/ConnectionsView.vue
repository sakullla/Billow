<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue'
import ChainPath from '../components/ChainPath.vue'
import ContextMenu from '../components/ContextMenu.vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import type { MenuItem } from '../components/Menu.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import {
  connectionRules,
  extractEndpointIp,
  formatBytes,
  formatClock,
  formatDuration,
  formatSpeed,
  isFakeIp,
  processBasename,
  resolveChain,
} from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import { useColumnResize } from '../lib/ui/columns'
import { useVirtualList } from '../lib/ui/virtual'
import type { ClosedConnectionRow, ConnectionRow } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type ConnTab = 'active' | 'closed'
type RouteFilter = 'all' | 'proxy' | 'direct'
type SortKey = 'time' | 'speed' | 'download' | 'upload' | 'host'
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'time', label: '时间' },
  { id: 'speed', label: '速度' },
  { id: 'download', label: '下载' },
  { id: 'upload', label: '上传' },
  { id: 'host', label: '主机' },
]
const CLOSED_SORTS: { id: SortKey; label: string }[] = [
  { id: 'time', label: '关闭时间' },
  { id: 'download', label: '下载' },
  { id: 'upload', label: '上传' },
  { id: 'host', label: '主机' },
]

const TABLE_ROW = 40
const CARD_ROW = 100

const connCols = useColumnResize('connections', [
  { id: 'host', defaultWidth: 214, minWidth: 120, maxWidth: 680 },
  { id: 'process', defaultWidth: 96, minWidth: 68, maxWidth: 360 },
  { id: 'rule', defaultWidth: 142, minWidth: 84, maxWidth: 480 },
  { id: 'chain', defaultWidth: 192, minWidth: 110, maxWidth: 640 },
  { id: 'speed', defaultWidth: 88, minWidth: 70, maxWidth: 200 },
  { id: 'download', defaultWidth: 74, minWidth: 60, maxWidth: 180 },
  { id: 'upload', defaultWidth: 74, minWidth: 60, maxWidth: 180 },
  { id: 'time', defaultWidth: 64, minWidth: 54, maxWidth: 180 },
])

const connTableStyle = computed(() => {
  if (!connCols.customized.value) return undefined
  const total =
    connCols.widths.host +
    connCols.widths.process +
    connCols.widths.rule +
    connCols.widths.chain +
    connCols.widths.speed +
    connCols.widths.download +
    connCols.widths.upload +
    connCols.widths.time +
    36
  return { '--conn-table-w': `${total}px` }
})

const tab = ref<ConnTab>('active')
const routeFilter = ref<RouteFilter>('all')
const query = ref('')
const sortKey = ref<SortKey>('time')
const sortDir = ref<'asc' | 'desc'>('desc')

function setTab(next: ConnTab) {
  if (tab.value === next) return
  tab.value = next
  if (next === 'closed' && sortKey.value === 'speed') {
    sortKey.value = 'time'
    sortDir.value = 'desc'
  }
}

function setSort(key: SortKey) {
  sortKey.value = key
  sortDir.value = key === 'host' ? 'asc' : 'desc'
}

function toggleColumnSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'desc' ? 'asc' : 'desc'
  } else {
    setSort(key)
  }
}

function ariaSortOf(key: SortKey): 'ascending' | 'descending' | 'none' {
  if (sortKey.value !== key) return 'none'
  return sortDir.value === 'asc' ? 'ascending' : 'descending'
}

const paused = ref(false)
const pausedAt = ref<number | null>(null)
const frozenRows = shallowRef<ConnectionRow[]>([])
const frozenIds = shallowRef(new Set<string>())
const frozenTotal = ref(0)
const frozenUp = ref<number | null>(null)
const frozenDown = ref<number | null>(null)
const selecting = ref<string | null>(null)
const selectedHost = ref('')
const selectedLast = shallowRef<(ConnectionRow & { closed_at_ms?: number }) | null>(null)
const selectedAt = ref(Date.now())
const detailFromClosed = ref(false)
const rulePolicy = ref('DIRECT')
const confirmAll = ref(false)
const returnNotice = ref<string | null>(null)
let restoringContext = false
const rates = shallowRef(new Map<string, { up: number; down: number }>())
let previous = new Map<string, { upload: number; download: number; at: number }>()

const idOf = (row: ConnectionRow) => row.id || `${row.host}|${row.source}|${row.start}`
const closedRows = computed(() => store.closedConnections.value)

const groupNames = computed(() => new Set(snap.value.node_catalog.map((group) => group.name)))
const dialersByNode = computed(() => {
  const map = new Map<string, string>()
  for (const group of snap.value.node_catalog) {
    for (const node of group.nodes) {
      if (node.dialer_proxy && !map.has(node.name)) {
        map.set(node.name, node.dialer_proxy)
      }
    }
  }
  return map
})

/**
 * Mihomo lists chains from the server back to the rule's target; people read them forwards.
 * If the exit server declares a `dialer-proxy` that was not expanded in `chains`, insert it
 * right before the exit server so chained proxies always show their transit hop.
 */
function hopsOf(row: ConnectionRow): string[] {
  const hops = row.chains.length ? [...row.chains].reverse() : [row.outbound]
  if (hops.length === 0 || dialersByNode.value.size === 0) return hops
  const exit = hops[hops.length - 1]!
  const dialer = dialersByNode.value.get(exit)
  if (!dialer) return hops
  let transit = dialer
  if (groupNames.value.has(dialer)) {
    const sub = resolveChain(dialer, snap.value.node_catalog)
    transit = sub[sub.length - 1] || dialer
  }
  if (transit && !hops.includes(transit)) {
    hops.splice(hops.length - 1, 0, transit)
  }
  return hops
}

watch(
  () => snap.value.connections,
  (rows) => {
    const now = Date.now()
    const next = new Map<string, { upload: number; download: number; at: number }>()
    const speed = new Map<string, { up: number; down: number }>()
    for (const row of rows) {
      const key = idOf(row)
      const before = previous.get(key)
      next.set(key, { upload: row.upload, download: row.download, at: now })
      if (before) {
        const seconds = Math.max(0.25, (now - before.at) / 1000)
        speed.set(key, {
          up: Math.max(0, (row.upload - before.upload) / seconds),
          down: Math.max(0, (row.download - before.download) / seconds),
        })
      }
    }
    previous = next
    rates.value = speed
  },
  { immediate: true },
)

const rateOf = (row: ConnectionRow) => rates.value.get(idOf(row)) ?? { up: 0, down: 0 }

function pause() {
  frozenRows.value = snap.value.connections
  frozenIds.value = new Set(snap.value.connections.map(idOf))
  frozenTotal.value = snap.value.connection_total || snap.value.connections.length
  frozenUp.value = snap.value.upload_total
  frozenDown.value = snap.value.download_total
  pausedAt.value = Date.now()
  paused.value = true
}

function resume() {
  paused.value = false
  pausedAt.value = null
  frozenRows.value = []
  frozenIds.value = new Set()
}

function togglePause() {
  if (paused.value) resume()
  else pause()
}

/** The list source: closed ring buffer in 已关闭, frozen or live snapshot in 活动 (R28). */
const activeSourceRows = computed(() => (paused.value ? frozenRows.value : snap.value.connections))
const sourceRows = computed<(ConnectionRow & { closed_at_ms?: number })[]>(() =>
  tab.value === 'closed' ? closedRows.value : activeSourceRows.value,
)

/** New ids that arrived after the freeze, so the pause screen can say how far behind it is. */
const newCount = computed(() => {
  if (!paused.value || tab.value !== 'active') return 0
  return snap.value.connections.filter((row) => !frozenIds.value.has(idOf(row))).length
})

const queryTokens = computed(() => splitQueryTokens(query.value))

function highlight(value: string) {
  return highlightTokens(value, query.value)
}

function isDirectRow(row: ConnectionRow): boolean {
  const hops = hopsOf(row)
  const exit = (hops[hops.length - 1] ?? row.outbound ?? '').toUpperCase()
  return exit === 'DIRECT'
}

function isProxyRow(row: ConnectionRow): boolean {
  const hops = hopsOf(row)
  const exit = (hops[hops.length - 1] ?? row.outbound ?? '').toUpperCase()
  return !['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'].includes(exit)
}

const routeCounts = computed(() => {
  let proxy = 0
  let direct = 0
  for (const row of sourceRows.value) {
    if (isDirectRow(row)) direct += 1
    else if (isProxyRow(row)) proxy += 1
  }
  return { proxy, direct }
})

const routeOptions = computed<{ id: RouteFilter; label: string }[]>(() => [
  { id: 'all', label: '全部' },
  { id: 'proxy', label: routeCounts.value.proxy ? `代理 ${routeCounts.value.proxy}` : '代理' },
  { id: 'direct', label: routeCounts.value.direct ? `直连 ${routeCounts.value.direct}` : '直连' },
])

const isFiltered = computed(() => Boolean(query.value.trim()) || routeFilter.value !== 'all')

const rows = computed(() => {
  const tokens = queryTokens.value
  const route = routeFilter.value
  const list = sourceRows.value.filter((row) => {
    if (route === 'proxy' && !isProxyRow(row)) return false
    if (route === 'direct' && !isDirectRow(row)) return false
    if (!tokens.length) return true
    return matchesTokens(
      `${row.host} ${row.destination} ${row.process} ${row.rule} ${row.rule_payload} ${hopsOf(row).join(' ')} ${row.network} ${row.conn_type}`,
      tokens,
    )
  })
  const dir = sortDir.value === 'asc' ? -1 : 1
  switch (sortKey.value) {
    case 'speed':
      if (tab.value === 'closed') {
        list.sort((a, b) => dir * ((b.closed_at_ms ?? 0) - (a.closed_at_ms ?? 0)))
      } else {
        list.sort((a, b) => dir * (rateOf(b).down + rateOf(b).up - (rateOf(a).down + rateOf(a).up)))
      }
      break
    case 'download':
      list.sort((a, b) => dir * (b.download - a.download))
      break
    case 'upload':
      list.sort((a, b) => dir * (b.upload - a.upload))
      break
    case 'host':
      list.sort((a, b) => (sortDir.value === 'asc' ? 1 : -1) * a.host.localeCompare(b.host))
      break
    default:
      if (tab.value === 'closed') {
        list.sort((a, b) => dir * ((b.closed_at_ms ?? 0) - (a.closed_at_ms ?? 0)))
      } else {
        list.sort((a, b) => dir * (Date.parse(b.start || '0') - Date.parse(a.start || '0')))
      }
  }
  return list
})

const tableScroll = ref<HTMLElement | null>(null)
const cardScroll = ref<HTMLElement | null>(null)
const table = useVirtualList(computed(() => rows.value.length), TABLE_ROW, 6)
const cards = useVirtualList(computed(() => rows.value.length), CARD_ROW, 4)
const tableRows = computed(() => rows.value.slice(table.window.value.start, table.window.value.end))
const cardRows = computed(() => rows.value.slice(cards.window.value.start, cards.window.value.end))

function coarsePointer(): boolean {
  return typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches === true
}

function saveReturnContext(targetPage: 'proxies' | 'resources', includeDetail = true) {
  const listEl = props.compact ? cardScroll.value : tableScroll.value
  const fallbackScroll = props.compact ? cards.scrollTop.value : table.scrollTop.value
  store.connectionReturn.value = {
    sessionId: store.connectionSessionId.value,
    targetPage,
    tab: tab.value,
    query: query.value,
    routeFilter: routeFilter.value,
    sortKey: sortKey.value,
    sortDir: sortDir.value,
    listScrollTop: listEl ? listEl.scrollTop : fallbackScroll,
    paused: paused.value,
    pausedAt: pausedAt.value,
    frozenRows: [...frozenRows.value],
    frozenIds: [...frozenIds.value],
    frozenTotal: frozenTotal.value,
    frozenUp: frozenUp.value,
    frozenDown: frozenDown.value,
    connectionKey: includeDetail ? selecting.value : null,
    detailFromClosed: includeDetail ? detailFromClosed.value : false,
    rulePolicy: rulePolicy.value,
  }
}

async function restoreReturnContext() {
  const saved = store.connectionReturn.value
  if (!saved) {
    table.measure(tableScroll.value)
    cards.measure(cardScroll.value)
    return
  }
  store.connectionReturn.value = null

  // Disconnected session: keep the current disconnected empty state and never reopen stale details (R4).
  if (!snap.value.connected) {
    return
  }

  // Reconnected new session: restore filter/sort context, explain unavailability, never match by host (R4).
  if (saved.sessionId !== store.connectionSessionId.value) {
    restoringContext = true
    tab.value = 'active'
    query.value = saved.query
    routeFilter.value = saved.routeFilter
    sortKey.value = saved.sortKey
    sortDir.value = saved.sortDir
    await nextTick()
    restoringContext = false
    table.measure(tableScroll.value)
    cards.measure(cardScroll.value)
    if (saved.connectionKey !== null) {
      returnNotice.value = '连接会话已重新建立，原连接记录已不可用'
    }
    if (!coarsePointer() && document.activeElement === document.body) {
      await nextTick()
      const target =
        document.querySelector<HTMLElement>('[data-testid="dismiss-return-notice"]') ??
        document.querySelector<HTMLElement>('[data-testid="connection-search"]')
      target?.focus({ preventScroll: true })
    }
    return
  }

  restoringContext = true
  tab.value = saved.tab
  query.value = saved.query
  routeFilter.value = saved.routeFilter
  sortKey.value = saved.sortKey
  sortDir.value = saved.sortDir
  rulePolicy.value = saved.rulePolicy
  if (saved.paused) {
    paused.value = true
    pausedAt.value = saved.pausedAt
    frozenRows.value = saved.frozenRows
    frozenIds.value = new Set(saved.frozenIds)
    frozenTotal.value = saved.frozenTotal
    frozenUp.value = saved.frozenUp
    frozenDown.value = saved.frozenDown
  }
  table.scrollTop.value = saved.listScrollTop
  cards.scrollTop.value = saved.listScrollTop

  await nextTick()
  restoringContext = false

  const scroller = props.compact ? cardScroll.value : tableScroll.value
  if (scroller) {
    scroller.scrollTop = saved.listScrollTop
  }
  table.measure(tableScroll.value)
  cards.measure(cardScroll.value)

  if (saved.connectionKey !== null) {
    const liveMatch = !saved.detailFromClosed
      ? snap.value.connections.find((row) => idOf(row) === saved.connectionKey) ?? null
      : null
    if (liveMatch) {
      openDetail(liveMatch)
      if (rulePolicies.value.includes(saved.rulePolicy)) rulePolicy.value = saved.rulePolicy
      return
    }

    const closedMatch = closedRows.value.find((row) => idOf(row) === saved.connectionKey) ?? null
    if (closedMatch) {
      detailFromClosed.value = saved.detailFromClosed
      selecting.value = saved.connectionKey
      selectedHost.value = closedMatch.host || closedMatch.destination
      selectedLast.value = closedMatch
      selectedAt.value = closedMatch.closed_at_ms
      if (rulePolicies.value.includes(saved.rulePolicy)) rulePolicy.value = saved.rulePolicy
      return
    }

    const frozenMatch = saved.paused
      ? saved.frozenRows.find((row) => idOf(row) === saved.connectionKey) ?? null
      : null
    if (frozenMatch) {
      detailFromClosed.value = false
      selecting.value = saved.connectionKey
      selectedHost.value = frozenMatch.host || frozenMatch.destination
      selectedLast.value = frozenMatch
      selectedAt.value = saved.pausedAt ?? Date.now()
      if (rulePolicies.value.includes(saved.rulePolicy)) rulePolicy.value = saved.rulePolicy
      return
    }

    returnNotice.value = '原连接已结束且记录已不可用，已恢复筛选列表'
  }

  if (!coarsePointer() && document.activeElement === document.body) {
    await nextTick()
    const target =
      document.querySelector<HTMLElement>('[data-testid="dismiss-return-notice"]') ??
      document.querySelector<HTMLElement>('[data-testid="connection-search"]')
    target?.focus({ preventScroll: true })
  }
}

onMounted(() => {
  void nextTick(() => restoreReturnContext())
})

// Empty/error states unmount the list, so a remount must not reuse the old offset
// or window index; a filter, sort or tab change returns to the first row (R31).
watch(tableScroll, (el) => table.measure(el))
watch(cardScroll, (el) => cards.measure(el))
watch([query, routeFilter, sortKey, sortDir, tab], () => {
  if (restoringContext) return
  returnNotice.value = null
  table.reset(tableScroll.value)
  cards.reset(cardScroll.value)
})

// Totals and the count stay frozen with the list; only the live source moves.
const displayTotal = computed(() =>
  paused.value ? frozenTotal.value : snap.value.connection_total || snap.value.connections.length,
)
const displayUp = computed(() => (paused.value ? frozenUp.value : snap.value.upload_total))
const displayDown = computed(() => (paused.value ? frozenDown.value : snap.value.download_total))
const hiddenRows = computed(() =>
  tab.value === 'active' ? Math.max(0, displayTotal.value - activeSourceRows.value.length) : 0,
)

const tabOptions = computed<{ id: ConnTab; label: string }[]>(() => [
  { id: 'active', label: `活动 ${displayTotal.value}` },
  { id: 'closed', label: closedRows.value.length ? `已关闭 ${closedRows.value.length}` : '已关闭' },
])

const showToolbar = computed(
  () =>
    snap.value.connected &&
    (snap.value.connections.length > 0 ||
      closedRows.value.length > 0 ||
      paused.value ||
      Boolean(returnNotice.value) ||
      tab.value === 'closed' ||
      Boolean(query.value) ||
      routeFilter.value !== 'all'),
)

const detailRow = computed(() => {
  if (selecting.value === null || detailFromClosed.value) return null
  return snap.value.connections.find((row) => idOf(row) === selecting.value) ?? null
})
const detailSource = computed(() => detailRow.value ?? selectedLast.value)
const detailGone = computed(() => selecting.value !== null && !detailRow.value)
const detailClosedClock = computed(() => {
  const closedMs = selectedLast.value?.closed_at_ms
  if (closedMs) return formatClock(closedMs)
  return detailFromClosed.value ? formatClock(selectedAt.value) : ''
})
const detailDisconnectedText = computed(() => {
  if (detailFromClosed.value) {
    return detailClosedClock.value ? `已关闭 · 关闭于 ${detailClosedClock.value}` : '已关闭'
  }
  return detailClosedClock.value ? `已关闭 · 已断开 · 关闭于 ${detailClosedClock.value}` : '已关闭 · 已断开'
})

watch(detailRow, (row) => {
  if (!row) {
    if (selecting.value !== null && !detailFromClosed.value) {
      const closed = closedRows.value.find((item) => idOf(item) === selecting.value)
      if (closed) {
        selectedLast.value = closed
        selectedAt.value = closed.closed_at_ms
      }
    }
    return
  }
  selectedLast.value = row
  selectedAt.value = Date.now()
})

const ctxMenu = ref<{ x: number; y: number; items: MenuItem[]; row?: ConnectionRow & { closed_at_ms?: number } } | null>(null)

// A dropped session or a restarted kernel invalidates the frozen rows and the open detail (R31).
watch(
  () => [snap.value.connected, snap.value.kernel_running] as const,
  ([connected]) => {
    if (connected) return
    tab.value = 'active'
    routeFilter.value = 'all'
    returnNotice.value = null
    ctxMenu.value = null
    resume()
    frozenRows.value = []
    frozenIds.value = new Set()
    if (selecting.value !== null) {
      selectedLast.value = null
      selecting.value = null
      selectedHost.value = ''
      detailFromClosed.value = false
    }
  },
)

function entryGroupOf(row: ConnectionRow): string | null {
  const entry = hopsOf(row)[0]
  return entry && groupNames.value.has(entry) ? entry : null
}

const detailEntryGroup = computed(() => (detailSource.value ? entryGroupOf(detailSource.value) : null))

const manualGroupNames = computed(() =>
  snap.value.node_catalog
    .filter((group) => group.kind === 'manual' && (snap.value.mode === 'global' || group.name !== 'GLOBAL'))
    .map((group) => group.name),
)

const primaryManualGroup = computed(() => manualGroupNames.value[0] ?? null)

const rulePolicies = computed(() => {
  const set = new Set<string>(['DIRECT'])
  if (detailEntryGroup.value) set.add(detailEntryGroup.value)
  if (primaryManualGroup.value) set.add(primaryManualGroup.value)
  for (const name of manualGroupNames.value) {
    if (set.size >= 6) break
    set.add(name)
  }
  set.add('REJECT')
  return [...set]
})

function ruleSetOf(row: ConnectionRow): string | null {
  if (!row.rule_payload) return null
  return /^rule-?set$/i.test(row.rule.trim()) ? row.rule_payload.trim() : null
}

const detailRuleSet = computed(() => (detailSource.value ? ruleSetOf(detailSource.value) : null))

function openConnectionRuleSet(name: string) {
  saveReturnContext('resources', true)
  closeDetail(false)
  store.openProvider('rule', name)
}

const generatedRules = computed(() =>
  detailSource.value ? connectionRules(detailSource.value, rulePolicy.value) : [],
)

const detailDestIp = computed(() => {
  const dest = detailSource.value?.destination ?? ''
  const info = extractEndpointIp(dest)
  return info && !isFakeIp(info.ip) ? info.ip : ''
})

const detailIsFakeIp = computed(() => {
  const dest = detailSource.value?.destination ?? ''
  return Boolean(dest && isFakeIp(dest))
})

function openConnectionGroup(group: string) {
  saveReturnContext('proxies', true)
  closeDetail(false)
  store.go('proxies', group)
}

interface DetailStat {
  label: string
  value: string
  sub?: string
}

const detailStats = computed<DetailStat[]>(() => {
  const row = detailSource.value
  if (!row) return []
  const endAt = detailRow.value ? Date.now() : (selectedLast.value?.closed_at_ms ?? selectedAt.value)
  const liveRate = detailRow.value ? rateOf(detailRow.value) : null
  return [
    {
      label: '下载',
      value: formatBytes(row.download),
      sub: liveRate && liveRate.down >= 1 ? formatSpeed(liveRate.down) : undefined,
    },
    {
      label: '上传',
      value: formatBytes(row.upload),
      sub: liveRate && liveRate.up >= 1 ? formatSpeed(liveRate.up) : undefined,
    },
    { label: '持续', value: formatDuration(row.start, endAt) || '0 秒' },
    { label: '网络', value: `${row.network.toUpperCase() || 'TCP'}${row.conn_type ? ` · ${row.conn_type}` : ''}` },
  ]
})

interface DetailEntry {
  label: string
  value: string
  copyValue?: string
  copyToast?: string
  badge?: string
}

const detail = computed<DetailEntry[]>(() => {
  const row = detailSource.value
  if (!row) return []
  const entries: DetailEntry[] = [
    { label: '主机', value: row.host, copyValue: row.host, copyToast: '已复制主机' },
    {
      label: '目标地址',
      value: row.destination,
      copyValue: row.destination,
      copyToast: '已复制目标地址',
      badge: detailIsFakeIp.value ? 'Fake-IP' : undefined,
    },
    { label: '来源', value: row.source, copyValue: row.source, copyToast: '已复制来源地址' },
    { label: '进程', value: row.process, copyValue: row.process, copyToast: '已复制进程名' },
    { label: '规则', value: row.rule ? `${row.rule}${row.rule_payload ? ` (${row.rule_payload})` : ''}` : '' },
    { label: '代理链', value: hopsOf(row).join(' → ') },
  ]
  return entries.filter((item) => Boolean(item.value))
})

function openDetail(row: ConnectionRow & { closed_at_ms?: number }) {
  const isClosed = Boolean(row.closed_at_ms) || tab.value === 'closed'
  detailFromClosed.value = isClosed
  selecting.value = idOf(row)
  selectedHost.value = row.host || row.destination
  selectedLast.value = row
  selectedAt.value = row.closed_at_ms ?? Date.now()
  if (!rulePolicies.value.includes(rulePolicy.value)) {
    rulePolicy.value = 'DIRECT'
  }
}

function closeDetail(restoreFocus = true) {
  const closedKey = selecting.value
  selecting.value = null
  selectedHost.value = ''
  selectedLast.value = null
  detailFromClosed.value = false
  if (restoreFocus && closedKey && !coarsePointer()) {
    void nextTick(() => {
      if (document.activeElement && document.activeElement !== document.body) return
      const target =
        document.querySelector<HTMLElement>(`[data-connection-id="${CSS.escape(closedKey)}"]`) ??
        document.querySelector<HTMLElement>('[data-testid="connection-search"]') ??
        document.querySelector<HTMLElement>('[data-testid="pause-connections"]')
      target?.focus({ preventScroll: true })
    })
  }
}

async function copySummary() {
  const row = detailSource.value
  if (!row) return
  const at = detailRow.value ? Date.now() : (selectedLast.value?.closed_at_ms ?? selectedAt.value)
  const text = [
    `主机: ${row.host}`,
    row.destination ? `目标地址: ${row.destination}` : '',
    row.process ? `进程: ${row.process}` : '',
    `规则: ${row.rule}${row.rule_payload ? ` (${row.rule_payload})` : ''}`,
    `代理链: ${hopsOf(row).join(' → ')}`,
    `下载: ${formatBytes(row.download)}`,
    `上传: ${formatBytes(row.upload)}`,
    `持续: ${formatDuration(row.start, at)}`,
  ].filter(Boolean)
  await store.copyText(text.join('\n'), '已复制连接摘要')
}

async function copyRule(rule: string) {
  await store.copyText(rule, `已复制规则：${rule}`)
}

function writeRuleToOverride(rule: string) {
  const id = snap.value.active_id
  if (!id) {
    store.toast('请先启用一份配置', 'info')
    return
  }
  closeDetail()
  store.overrideRequest.value = { id, append: `# 由连接详情添加\n+rules:\n  - ${rule}\n` }
  store.go('profiles')
}

async function closeOne(row: ConnectionRow) {
  await store.closeConnection(row.id)
}

async function disconnectAll() {
  confirmAll.value = false
  const result = await store.closeConnection(null)
  if (result) store.toast('已断开全部连接', 'success')
}

function resetFilters() {
  query.value = ''
  routeFilter.value = 'all'
}

function filterBy(value: string) {
  if (!value) return
  query.value = value
  closeDetail()
}

function openHeadMenu(event: MouseEvent) {
  if (props.compact || !connCols.customized.value) return
  event.preventDefault()
  ctxMenu.value = {
    x: event.clientX,
    y: event.clientY,
    items: [{ id: 'reset-cols', label: '恢复默认列宽', icon: 'refresh' }],
  }
}

function openRowMenu(row: ConnectionRow & { closed_at_ms?: number }, event: MouseEvent) {
  if (props.compact) return
  event.preventDefault()
  const entry = entryGroupOf(row)
  const rset = ruleSetOf(row)
  const directRule = connectionRules(row, 'DIRECT')[0]
  const items: MenuItem[] = [
    { id: 'detail', label: '查看连接详情', icon: 'info' },
    { id: 'copy-host', label: '复制目标主机', icon: 'copy' },
  ]
  if (row.host) items.push({ id: 'filter-host', label: '筛选此主机', icon: 'filter' })
  if (row.process) {
    items.push({
      id: 'filter-process',
      label: `筛选进程「${processBasename(row.process)}」`,
      icon: 'filter',
    })
  }
  if (entry) items.push({ id: 'open-group', label: `前往「${entry}」`, icon: 'globe' })
  if (rset) items.push({ id: 'open-ruleset', label: `查看规则集「${rset}」`, icon: 'database' })
  if (directRule) {
    items.push({ id: 'copy-direct', label: `复制直连规则 (${directRule.label})`, icon: 'route' })
    if (snap.value.active_id) {
      items.push({ id: 'write-direct', label: '添加直连覆写', icon: 'layers' })
    }
  }
  if (tab.value === 'active' && !row.closed_at_ms) {
    items.push({ id: 'close', label: '断开此连接', icon: 'x', danger: true })
  }
  ctxMenu.value = { x: event.clientX, y: event.clientY, items, row }
}

function onContextSelect(item: MenuItem) {
  const row = ctxMenu.value?.row
  ctxMenu.value = null
  if (item.id === 'reset-cols') {
    connCols.resetAll()
    return
  }
  if (!row) return
  const directRule = connectionRules(row, 'DIRECT')[0]
  if (item.id === 'detail') openDetail(row)
  else if (item.id === 'copy-host') void store.copyText(row.host || row.destination, '已复制目标主机')
  else if (item.id === 'filter-host') filterBy(row.host)
  else if (item.id === 'filter-process') filterBy(row.process)
  else if (item.id === 'open-group') {
    const entry = entryGroupOf(row)
    if (entry) {
      saveReturnContext('proxies', false)
      store.go('proxies', entry)
    }
  } else if (item.id === 'open-ruleset') {
    const rset = ruleSetOf(row)
    if (rset) {
      saveReturnContext('resources', false)
      store.openProvider('rule', rset)
    }
  } else if (item.id === 'copy-direct' && directRule) void copyRule(directRule.rule)
  else if (item.id === 'write-direct' && directRule) writeRuleToOverride(directRule.rule)
  else if (item.id === 'close') void closeOne(row)
}

function rowDuration(row: ConnectionRow & { closed_at_ms?: number }): string {
  return row.closed_at_ms ? formatDuration(row.start, row.closed_at_ms) : formatDuration(row.start)
}

function closedTimeText(row: ConnectionRow & { closed_at_ms?: number }): string {
  return row.closed_at_ms ? formatClock((row as ClosedConnectionRow).closed_at_ms) : '—'
}

function speedDisplay(row: ConnectionRow): { text: string; idle: boolean; upOnly: boolean; title: string } {
  const r = rateOf(row)
  const total = r.down + r.up
  if (total < 1) {
    return { text: '—', idle: true, upOnly: false, title: '当前无活动传输' }
  }
  if (r.down < 1 && r.up >= 1) {
    return {
      text: `↑ ${formatSpeed(r.up)}`,
      idle: false,
      upOnly: true,
      title: `上传 ${formatSpeed(r.up)} · 下载 ${formatSpeed(r.down)}`,
    }
  }
  return {
    text: formatSpeed(r.down),
    idle: false,
    upOnly: false,
    title: r.up >= 1 ? `下载 ${formatSpeed(r.down)} · 上传 ${formatSpeed(r.up)}` : `下载 ${formatSpeed(r.down)}`,
  }
}
</script>

<template>
  <div class="page connections">
    <header class="page-head">
      <div>
        <h1>连接</h1>
        <p class="muted small mono" data-testid="connection-summary">
          <template v-if="!snap.connected">未连接</template>
          <template v-else-if="tab === 'closed'">
            已记录 {{ closedRows.length }} 条已关闭连接
            <template v-if="isFiltered"> · 匹配 {{ rows.length }} 条</template>
          </template>
          <template v-else>
            {{ displayTotal }} 个活动连接
            <template v-if="isFiltered"> · 匹配 {{ rows.length }} 条</template>
            <template v-if="hiddenRows"> · 显示前 {{ activeSourceRows.length }} 条</template>
            <template v-if="paused"> · 暂停于 {{ formatClock(pausedAt ?? 0) }}</template>
            <template v-if="paused && newCount"> · <span data-testid="new-connections">{{ newCount }} 条新连接</span></template>
            · <span title="本次累计下载"><Icon name="down" :size="11" />{{ formatBytes(displayDown) }}</span>
            · <span title="本次累计上传"><Icon name="up" :size="11" />{{ formatBytes(displayUp) }}</span>
          </template>
        </p>
      </div>
      <!-- Nothing to pause or close while disconnected; the empty state owns the next step. -->
      <div v-if="snap.connected" class="head-actions">
        <button
          v-if="!compact && connCols.customized.value"
          type="button"
          class="btn ghost sm"
          title="恢复默认列宽"
          data-testid="reset-conn-cols"
          @click="connCols.resetAll()"
        >
          恢复列宽
        </button>
        <template v-if="tab === 'closed'">
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!closedRows.length"
            data-testid="clear-closed-connections"
            @click="store.clearClosedConnections()"
          >
            <Icon name="trash" :size="14" />清空记录
          </button>
        </template>
        <template v-else>
          <button
            type="button"
            class="btn ghost sm"
            :class="{ active: paused }"
            :disabled="!snap.connected"
            :aria-pressed="paused"
            data-testid="pause-connections"
            @click="togglePause"
          >
            <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? '继续' : '暂停' }}
          </button>
          <button
            type="button"
            class="btn ghost sm danger-text"
            :disabled="!snap.connections.length"
            data-testid="disconnect-all"
            @click="confirmAll = true"
          >
            <Icon name="x" :size="15" />全部断开
          </button>
        </template>
      </div>
    </header>

    <div v-if="showToolbar" class="toolbar">
      <Segmented
        :model-value="tab"
        :options="tabOptions"
        size="sm"
        label="连接范围"
        data-testid="connection-tab"
        @update:model-value="setTab"
      />
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="按主机、进程、规则或节点筛选" data-testid="connection-search" data-page-search />
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          aria-label="清空筛选"
          data-testid="clear-connection-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <Segmented
        v-model="routeFilter"
        :options="routeOptions"
        size="sm"
        label="出站分流筛选"
        data-testid="connection-route-filter"
      />
      <!-- The desktop table sorts from its column headers; phone cards have none, so they keep the switch. -->
      <Segmented
        v-if="compact"
        :model-value="sortKey"
        :options="tab === 'closed' ? CLOSED_SORTS : SORTS"
        size="sm"
        label="排序"
        data-testid="connection-sort"
        @update:model-value="setSort"
      />
    </div>

    <div
      v-if="snap.connected && paused && tab === 'active'"
      class="banner paused-bar small"
      role="status"
      aria-live="polite"
      data-testid="connections-paused-bar"
    >
      <Icon name="pause" :size="14" />
      <span class="grow">
        列表已暂停于 {{ formatClock(pausedAt ?? 0) }}<template v-if="newCount"> · 已缓存 {{ newCount }} 条新连接</template>
      </span>
      <button type="button" class="btn ghost sm" data-testid="resume-connections-bar" @click="resume()">
        <Icon name="play" :size="13" />继续刷新
      </button>
    </div>

    <div
      v-if="snap.connected && returnNotice"
      class="banner info small"
      role="status"
      aria-live="polite"
      data-testid="connection-return-notice"
    >
      <Icon name="info" :size="14" />
      <span class="grow">{{ returnNotice }}</span>
      <button
        type="button"
        class="icon-btn sm"
        aria-label="关闭提示"
        data-testid="dismiss-return-notice"
        @click="returnNotice = null"
      >
        <Icon name="x" :size="14" />
      </button>
    </div>

    <EmptyState v-if="!snap.connected" variant="unavailable" icon="activity" title="未连接" description="连接后这里会实时显示经过 Billow 的连接。">
      <template #action>
        <button
          type="button"
          class="btn primary sm"
          :disabled="store.connecting.value"
          :aria-busy="store.connecting.value || undefined"
          data-testid="empty-connect"
          @click="store.connect()"
        >
          <span v-if="store.connecting.value" class="spinner xs" aria-hidden="true" />
          <Icon v-else :name="store.hasProfiles.value ? 'power' : 'plus'" :size="14" />
          {{ store.hasProfiles.value ? (store.connecting.value ? '连接中' : '立即连接') : '添加配置' }}
        </button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="tab === 'active' && snap.connections_error" variant="error" title="读取失败" :description="snap.connections_error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-connections" @click="store.refresh()">重试</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="!rows.length && isFiltered" variant="no-match" title="没有匹配的连接" description="换一个关键词或切换出站范围，或清空当前筛选。">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="clear-connection-filter" @click="resetFilters">清空筛选</button>
      </template>
    </EmptyState>
    <EmptyState
      v-else-if="!rows.length && tab === 'closed'"
      variant="no-data"
      icon="clock"
      title="暂无已关闭连接"
      description="本次连接期间结束的请求会自动保留在这里，便于排查规则与节点链路。"
    />
    <EmptyState v-else-if="!rows.length" variant="no-data" icon="activity" title="没有当前连接" description="应用发起连接后会出现在这里。">
      <template #action>
        <button type="button" class="btn ghost sm" @click="store.refresh()">刷新</button>
      </template>
    </EmptyState>

    <div v-else-if="!compact" ref="tableScroll" class="card table-card conn-table" :class="{ paused: paused && tab === 'active' }" data-testid="connection-scroll" @scroll="table.onScroll">
      <table class="table virtual resizable-table" :class="{ 'custom-cols': connCols.customized.value }" :style="connTableStyle">
        <colgroup>
          <col :style="{ width: `${connCols.widths.host}px` }" />
          <col class="col-process" :style="{ width: `${connCols.widths.process}px` }" />
          <col :style="{ width: `${connCols.widths.rule}px` }" />
          <col :style="{ width: `${connCols.widths.chain}px` }" />
          <col :style="{ width: `${connCols.widths.speed}px` }" />
          <col class="col-down" :style="{ width: `${connCols.widths.download}px` }" />
          <col class="col-up" :style="{ width: `${connCols.widths.upload}px` }" />
          <col :style="{ width: `${connCols.widths.time}px` }" />
          <col style="width: 36px" />
        </colgroup>
        <thead @contextmenu="openHeadMenu">
          <tr>
            <th :aria-sort="ariaSortOf('host')">
              <button type="button" class="th-sort" :class="{ active: sortKey === 'host' }" @click="toggleColumnSort('host')">
                主机
                <Icon v-if="sortKey === 'host'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'host' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-host"
                @pointerdown="connCols.startResize('host', $event)"
                @dblclick="connCols.resetColumn('host', $event)"
                @click.stop
              />
            </th>
            <th class="col-process">
              进程
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'process' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-process"
                @pointerdown="connCols.startResize('process', $event)"
                @dblclick="connCols.resetColumn('process', $event)"
                @click.stop
              />
            </th>
            <th>
              规则
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'rule' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-rule"
                @pointerdown="connCols.startResize('rule', $event)"
                @dblclick="connCols.resetColumn('rule', $event)"
                @click.stop
              />
            </th>
            <th>
              代理链
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'chain' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-chain"
                @pointerdown="connCols.startResize('chain', $event)"
                @dblclick="connCols.resetColumn('chain', $event)"
                @click.stop
              />
            </th>
            <th class="num" :aria-sort="ariaSortOf(tab === 'closed' ? 'time' : 'speed')">
              <button
                type="button"
                class="th-sort num"
                :class="{ active: sortKey === (tab === 'closed' ? 'time' : 'speed') }"
                @click="toggleColumnSort(tab === 'closed' ? 'time' : 'speed')"
              >
                {{ tab === 'closed' ? '关闭于' : '速度' }}
                <Icon v-if="sortKey === (tab === 'closed' ? 'time' : 'speed')" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'speed' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-speed"
                @pointerdown="connCols.startResize('speed', $event)"
                @dblclick="connCols.resetColumn('speed', $event)"
                @click.stop
              />
            </th>
            <th class="num col-down" :aria-sort="ariaSortOf('download')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'download' }" @click="toggleColumnSort('download')">
                下载
                <Icon v-if="sortKey === 'download'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'download' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-download"
                @pointerdown="connCols.startResize('download', $event)"
                @dblclick="connCols.resetColumn('download', $event)"
                @click.stop
              />
            </th>
            <th class="num col-up" :aria-sort="ariaSortOf('upload')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'upload' }" @click="toggleColumnSort('upload')">
                上传
                <Icon v-if="sortKey === 'upload'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'upload' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-upload"
                @pointerdown="connCols.startResize('upload', $event)"
                @dblclick="connCols.resetColumn('upload', $event)"
                @click.stop
              />
            </th>
            <th class="num" :aria-sort="tab === 'active' ? ariaSortOf('time') : undefined">
              <button v-if="tab === 'active'" type="button" class="th-sort num" :class="{ active: sortKey === 'time' }" @click="toggleColumnSort('time')">
                时长
                <Icon v-if="sortKey === 'time'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
              <span v-else>历时</span>
              <span
                class="col-resizer"
                :class="{ active: connCols.resizingId.value === 'time' }"
                role="separator"
                aria-orientation="vertical"
                title="拖拽调整列宽，双击恢复默认"
                data-testid="col-resize-time"
                @pointerdown="connCols.startResize('time', $event)"
                @dblclick="connCols.resetColumn('time', $event)"
                @click.stop
              />
            </th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-if="table.offset.value" class="v-spacer" aria-hidden="true" :style="{ height: `${table.offset.value}px` }">
            <td colspan="9" />
          </tr>
          <tr
            v-for="(row, index) in tableRows"
            :key="`${idOf(row)}:${row.closed_at_ms ?? ''}`"
            :data-row-index="table.window.value.start + index"
            :data-connection-id="idOf(row)"
            tabindex="0"
            data-testid="connection-row"
            @click="openDetail(row)"
            @contextmenu="openRowMenu(row, $event)"
            @keydown.enter.prevent="openDetail(row)"
            @keydown.space.prevent="openDetail(row)"
          >
            <td>
              <div class="cell-host">
                <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
                <span class="ellipsis" :title="row.host || row.destination">
                  <template v-for="(part, partIdx) in highlight(row.host || row.destination)" :key="partIdx">
                    <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                  </template>
                </span>
              </div>
            </td>
            <td class="muted ellipsis col-process" :title="row.process || undefined">
              <template v-if="row.process">
                <template v-for="(part, partIdx) in highlight(row.process)" :key="partIdx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </template>
              <template v-else>—</template>
            </td>
            <td class="ellipsis" :title="row.rule_payload ? `${row.rule} ${row.rule_payload}` : row.rule">
              <span class="muted">
                <template v-for="(part, partIdx) in highlight(row.rule)" :key="partIdx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span><span v-if="row.rule_payload" class="rule-payload-inline"><template v-for="(part, partIdx) in highlight(row.rule_payload)" :key="partIdx"><mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template></template></span>
            </td>
            <td><ChainPath :hops="hopsOf(row)" :groups="groupNames" pill fold /></td>
            <td v-if="tab === 'closed'" class="num mono muted">{{ closedTimeText(row) }}</td>
            <td
              v-else
              class="num mono"
              :class="{
                muted: speedDisplay(row).idle,
                'conn-rate-up': speedDisplay(row).upOnly,
                'conn-rate-down': !speedDisplay(row).idle && !speedDisplay(row).upOnly,
              }"
              :title="speedDisplay(row).title"
            >
              {{ speedDisplay(row).text }}
            </td>
            <td class="num mono col-down">{{ formatBytes(row.download) }}</td>
            <td class="num mono muted col-up">{{ formatBytes(row.upload) }}</td>
            <td class="num muted">{{ rowDuration(row) }}</td>
            <td class="num">
              <button
                v-if="tab === 'active'"
                type="button"
                class="icon-btn sm conn-close"
                :aria-label="`断开 ${row.host}`"
                title="断开"
                @click.stop="closeOne(row)"
              >
                <Icon name="x" :size="14" />
              </button>
            </td>
          </tr>
          <tr v-if="table.tail.value" class="v-spacer" aria-hidden="true" :style="{ height: `${table.tail.value}px` }">
            <td colspan="9" />
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else ref="cardScroll" class="conn-list-scroll" data-testid="connection-scroll" @scroll="cards.onScroll">
      <ul class="conn-list">
        <li v-if="cards.offset.value" class="v-spacer" aria-hidden="true" :style="{ height: `${cards.offset.value}px` }" />
        <li
          v-for="(row, index) in cardRows"
          :key="`${idOf(row)}:${row.closed_at_ms ?? ''}`"
          :data-row-index="cards.window.value.start + index"
          :data-connection-id="idOf(row)"
          class="card conn"
          tabindex="0"
          data-testid="connection-row"
          @click="openDetail(row)"
          @keydown.enter.prevent="openDetail(row)"
          @keydown.space.prevent="openDetail(row)"
        >
          <div class="conn-top">
            <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
            <strong class="ellipsis grow">
              <template v-for="(part, partIdx) in highlight(row.host || row.destination)" :key="partIdx">
                <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
              </template>
            </strong>
            <span v-if="tab === 'closed'" class="mono small muted">{{ closedTimeText(row) }}</span>
            <template v-else>
              <span
                class="mono small"
                :class="{
                  muted: speedDisplay(row).idle,
                  'conn-rate-up': speedDisplay(row).upOnly,
                  'conn-rate-down': !speedDisplay(row).idle && !speedDisplay(row).upOnly,
                }"
              >
                {{ speedDisplay(row).text }}
              </span>
              <button type="button" class="icon-btn sm" :aria-label="`断开 ${row.host}`" title="断开" @click.stop="closeOne(row)">
                <Icon name="x" :size="14" />
              </button>
            </template>
          </div>
          <div class="conn-meta small muted">
            <ChainPath :hops="hopsOf(row)" :groups="groupNames" pill fold />
            <span v-if="row.process" class="ellipsis conn-process">{{ row.process }}</span>
          </div>
          <div class="conn-meta small muted" data-testid="connection-traffic">
            <span class="mono">↓{{ formatBytes(row.download) }}</span>
            <span class="mono">↑{{ formatBytes(row.upload) }}</span>
            <span class="grow" />
            <span>{{ rowDuration(row) }}</span>
          </div>
        </li>
        <li v-if="cards.tail.value" class="v-spacer" aria-hidden="true" :style="{ height: `${cards.tail.value}px` }" />
      </ul>
    </div>

    <Modal v-if="selecting !== null" title="连接详情" :subtitle="selectedHost" @close="closeDetail()">
      <p
        v-if="detailGone"
        class="detail-status"
        :class="{ calm: detailFromClosed }"
        role="status"
        data-testid="detail-disconnected"
      >
        <Icon :name="detailFromClosed ? 'clock' : 'x'" :size="14" />
        <span>{{ detailDisconnectedText }}</span>
      </p>

      <dl v-if="detailStats.length" class="detail conn-detail-stats" data-testid="detail-stats">
        <div v-for="stat in detailStats" :key="stat.label" class="conn-stat-item">
          <dt class="conn-stat-label muted">{{ stat.label }}</dt>
          <dd class="conn-stat-body">
            <strong class="conn-stat-val mono">{{ stat.value }}</strong>
            <span v-if="stat.sub" class="conn-stat-sub mono">{{ stat.sub }}</span>
          </dd>
        </div>
      </dl>

      <dl class="detail conn-detail-grid">
        <template v-for="entry in detail" :key="entry.label">
          <dt>{{ entry.label }}</dt>
          <dd v-if="entry.label === '代理链' && detailSource" data-testid="detail-chain">
            <ChainPath :hops="hopsOf(detailSource)" :groups="groupNames" variant="steps" />
          </dd>
          <dd v-else class="mono detail-val-row">
            <span>{{ entry.value }}</span>
            <span v-if="entry.badge" class="tag sm" title="内核分配的虚拟映射地址">{{ entry.badge }}</span>
            <button
              v-if="entry.copyValue && entry.copyToast"
              type="button"
              class="icon-btn xs detail-copy-inline"
              :aria-label="`复制${entry.label}`"
              :title="`复制${entry.label}`"
              @click="store.copyText(entry.copyValue, entry.copyToast)"
            >
              <Icon name="copy" :size="12" />
            </button>
          </dd>
        </template>
      </dl>

      <div v-if="detailSource" class="chips conn-detail-chips">
        <button
          v-if="detailEntryGroup"
          type="button"
          class="chip"
          data-testid="open-conn-group"
          @click="openConnectionGroup(detailEntryGroup)"
        >
          <Icon name="globe" :size="13" />前往「{{ detailEntryGroup }}」
        </button>
        <button
          v-if="detailRuleSet"
          type="button"
          class="chip"
          data-testid="open-conn-ruleset"
          @click="openConnectionRuleSet(detailRuleSet)"
        >
          <Icon name="database" :size="13" />查看规则集「{{ detailRuleSet }}」
        </button>
        <button
          type="button"
          class="chip"
          data-testid="copy-conn-host"
          @click="store.copyText(detailSource.host || detailSource.destination, '已复制目标主机')"
        >
          <Icon name="copy" :size="13" />复制主机
        </button>
        <button
          v-if="detailDestIp"
          type="button"
          class="chip"
          data-testid="copy-conn-ip"
          @click="store.copyText(detailDestIp, '已复制目标 IP')"
        >
          <Icon name="copy" :size="13" />复制 IP
        </button>
        <button
          v-if="detailSource.host"
          type="button"
          class="chip"
          data-testid="filter-conn-host"
          @click="filterBy(detailSource.host)"
        >
          <Icon name="filter" :size="13" />筛选此主机
        </button>
        <button
          v-if="detailSource.process"
          type="button"
          class="chip"
          data-testid="filter-conn-process"
          @click="filterBy(detailSource.process)"
        >
          <Icon name="filter" :size="13" />筛选 {{ detailSource.process }}
        </button>
      </div>

      <section v-if="generatedRules.length" class="conn-rule-box" data-testid="conn-rule-box">
        <header class="conn-rule-head">
          <span class="small muted">复制为规则</span>
          <div class="conn-rule-policies" role="group" aria-label="规则出站策略">
            <button
              v-for="policy in rulePolicies"
              :key="policy"
              type="button"
              class="conn-policy-pill"
              :class="{ active: rulePolicy === policy }"
              :data-testid="`rule-policy-${policy}`"
              @click="rulePolicy = policy"
            >
              {{ policy }}
            </button>
          </div>
        </header>
        <div class="conn-rule-list">
          <div v-for="item in generatedRules" :key="item.id" class="conn-rule-row">
            <button
              type="button"
              class="conn-rule-copy"
              :data-testid="`copy-rule-${item.id}`"
              :title="`点击复制 ${item.rule}`"
              @click="copyRule(item.rule)"
            >
              <span class="tag sm">{{ item.label }}</span>
              <code class="mono ellipsis">{{ item.rule }}</code>
              <Icon name="copy" :size="13" class="muted" />
            </button>
            <button
              v-if="snap.active_id"
              type="button"
              class="btn ghost sm conn-rule-write"
              :data-testid="`write-rule-${item.id}`"
              title="写入当前配置的覆写编辑器"
              @click="writeRuleToOverride(item.rule)"
            >
              覆写
            </button>
          </div>
        </div>
      </section>

      <template #footer>
        <button type="button" class="btn ghost" @click="closeDetail()">关闭</button>
        <button type="button" class="btn ghost" data-testid="copy-connection" :disabled="!detailSource" @click="copySummary">
          <Icon name="copy" :size="15" />复制摘要
        </button>
        <button
          v-if="!detailFromClosed"
          type="button"
          class="btn danger"
          data-testid="disconnect-connection"
          :disabled="!detailRow"
          @click="detailRow && closeOne(detailRow)"
        >
          断开连接
        </button>
      </template>
    </Modal>

    <Modal v-if="confirmAll" title="断开全部连接" @close="confirmAll = false">
      <p class="small">将断开当前 {{ displayTotal }} 个活动连接，已建立的连接会立即中断。</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="cancel-disconnect-all" @click="confirmAll = false">取消</button>
        <button type="button" class="btn danger" data-testid="confirm-disconnect-all" @click="disconnectAll">断开全部</button>
      </template>
    </Modal>

    <ContextMenu
      v-if="ctxMenu"
      :x="ctxMenu.x"
      :y="ctxMenu.y"
      :items="ctxMenu.items"
      label="连接操作"
      @select="onContextSelect"
      @close="ctxMenu = null"
    />
  </div>
</template>
