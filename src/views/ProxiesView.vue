<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import ChainPath from '../components/ChainPath.vue'
import ContextMenu from '../components/ContextMenu.vue'
import EmptyState from '../components/EmptyState.vue'
import GroupIcon from '../components/GroupIcon.vue'
import ProxyNodeGrid from '../components/ProxyNodeGrid.vue'
import Icon from '../components/Icon.vue'
import type { MenuItem } from '../components/Menu.vue'
import Segmented from '../components/Segmented.vue'
import { autoTypeLabel, canPickNode, compareText, delayText, delayTone, effectiveGroupDelay, formatRelative, groupStrategy, groupTypeLabel, isInfoNode, listedGroups, parseSubscriptionInfo, protocolLabel, resolveChain, splitNodePrefix, type SubscriptionInfo } from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import type { Mode, NodeGroup, NodeItem } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const grids = new Map<string, InstanceType<typeof ProxyNodeGrid>>()
const snap = computed(() => store.snapshot.value)
const catalog = computed(() => snap.value.node_catalog)
/** Config `hidden: true` groups stay out of every list; chains still resolve through `catalog` (R29). */
const listed = computed(() => listedGroups(catalog.value))
const allGroupsHidden = computed(() => catalog.value.length > 0 && listed.value.length === 0)
const mode = computed(() => snap.value.mode)
const modeListed = computed(() => {
  if (mode.value === 'global') {
    const globalGroup = listed.value.find((group) => group.name === 'GLOBAL')
    return globalGroup
      ? [globalGroup, ...listed.value.filter((group) => group.name !== 'GLOBAL')]
      : listed.value
  }
  return listed.value.filter((group) => group.name !== 'GLOBAL')
})
const busyKeys = computed(() => Object.keys(store.busy).join('\0'))

type Sort = 'default' | 'delay' | 'name'
const SORTS: { id: Sort; label: string }[] = [
  { id: 'default', get label() { return tr('默认') } },
  { id: 'delay', get label() { return tr('延迟') } },
  { id: 'name', get label() { return tr('名称') } },
]
const MODES: { id: Mode; label: string }[] = [
  { id: 'rule', get label() { return tr('规则') } },
  { id: 'global', get label() { return tr('全局') } },
  { id: 'direct', get label() { return tr('直连') } },
]

const OPEN_KEY = 'proxy-open'

function readPref<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(`billow:${key}`)
    return raw == null ? fallback : (JSON.parse(raw) as T)
  } catch {
    return fallback
  }
}
function writePref(key: string, value: unknown) {
  try {
    localStorage.setItem(`billow:${key}`, JSON.stringify(value))
  } catch {
    /* storage unavailable */
  }
}

const query = ref('')
const toolbarEl = ref<HTMLElement | null>(null)
/** Phones fold sort and view options behind one button so the sticky bar stays one row. */
const optionsOpen = ref<boolean>(readPref('proxy-options-open', false))
const showOptions = computed(() => !props.compact || optionsOpen.value)
watch(optionsOpen, (value) => writePref('proxy-options-open', value))
/** Desktop keeps the sticky bar a calm single row by default; filter chips & group jump fold behind a persisted toggle. */
const filtersOpen = ref<boolean>(readPref<unknown>('proxy-filters-open', false) === true)
watch(filtersOpen, (value) => writePref('proxy-filters-open', value))
/** Open group headers stick under the toolbar; its height can change when options open. */
const toolbarHeight = ref(0)
let toolbarObserver: ResizeObserver | null = null
const sort = ref<Sort>(readPref('proxy-sort', 'default'))
type NodeView = 'card' | 'dense' | 'list'
/** Desktop offers a card grid and a one-row-per-node list; phones keep their two-column toggle. */
const VIEWS: { id: NodeView; label: string; icon: string }[] = [
  { id: 'card', get label() { return tr('卡片') }, icon: 'grid' },
  { id: 'list', get label() { return tr('列表') }, icon: 'list' },
]
function readView(): NodeView {
  const stored = readPref<string>('proxy-view', '')
  if (stored === 'card' || stored === 'dense' || stored === 'list') return stored
  // Earlier versions only stored the two-column toggle.
  return readPref('proxy-dense', false) ? 'dense' : 'card'
}
const view = ref<NodeView>(readView())
/** The retired desktop 紧凑 view reads as cards; phones still use it as their two-column grid. */
const desktopView = computed<NodeView>(() => (view.value === 'list' ? 'list' : 'card'))
const dense = computed(() => Boolean(props.compact) && view.value === 'dense')
/** Phones already list one node per row; there 列表 is simply their default view. */
const listView = computed(() => !props.compact && view.value === 'list')
/**
 * Auto groups (url-test, fallback, load-balance) are picked by the kernel and cannot be
 * switched by hand, so the page leaves them out by default; their current pick already
 * shows as an entry inside the manual groups. A deep link can still reveal one, and a
 * config with no manual group falls back to listing them (R13).
 */
const revealedAuto = ref<Set<string>>(new Set())
const hasManualGroups = computed(() => listed.value.some((group) => group.kind !== 'auto'))
function autoHidden(group: NodeGroup): boolean {
  return group.kind === 'auto' && hasManualGroups.value && !revealedAuto.value.has(group.name)
}
function revealAuto(group: NodeGroup) {
  if (group.kind !== 'auto' || revealedAuto.value.has(group.name)) return
  revealedAuto.value = new Set([...revealedAuto.value, group.name])
}
/** Rows of manual groups show where their auto entries point; the memo key must follow those picks. */
const autoNowKey = computed(() =>
  catalog.value.filter((group) => group.kind === 'auto').map((group) => `${group.name}=${group.now}`).join('\0'),
)
const catalogByName = computed(() => new Map(catalog.value.map((group) => [group.name, group])))

/** A manual group's entry that is itself an automatic group (自动选择, 故障转移, 智能…). */
function autoOf(node: NodeItem): NodeGroup | null {
  const group = catalogByName.value.get(node.name)
  return group && group.kind === 'auto' ? group : null
}

/** Where a group currently leads, ending at the server that carries the traffic. */
function groupHops(group: NodeGroup): string[] {
  const chain = resolveChain(group.name, catalog.value)
  return chain.length ? chain : group.now ? [group.now] : []
}

/** The server an auto entry currently resolves to, following nested groups (R14). */
function viaOf(node: NodeItem): string {
  const chain = resolveChain(node.name, catalog.value)
  return chain[chain.length - 1] ?? ''
}

/** Fallback priority is the config order, independent of the current sort (R14). */
function rankOf(group: NodeGroup, node: NodeItem): number {
  return (catalogByName.value.get(group.name)?.nodes.findIndex((item) => item.name === node.name) ?? -1) + 1
}

/** Reveal a hidden automatic group and jump to it from the entry that uses it. */
function openAuto(name: string) {
  const group = catalogByName.value.get(name)
  if (!group) return
  revealAuto(group)
  void locate(name, 'smooth')
}

const hiddenAutoCount = computed(() => modeListed.value.filter((group) => autoHidden(group)).length)
/** Read once at setup so the first paint already has the right groups expanded (R26). */
const storedOpen = readOpen()
const open = ref<Set<string>>(storedOpen ?? defaultOpen())
// Only seed storage when there is a real default group; an empty catalog must not
// be remembered as the user's "everything collapsed" choice (R26).
if (!storedOpen && open.value.size > 0) persistOpen()

watch(sort, (value) => writePref('proxy-sort', value))
watch(view, (value) => writePref('proxy-view', value))

function readBoolPref(key: string, fallback: boolean): boolean {
  const value = readPref<unknown>(key, fallback)
  return typeof value === 'boolean' ? value : fallback
}

const needle = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))
const hideFailed = ref<boolean>(readBoolPref('proxy-hide-failed', false))
watch(hideFailed, (value) => writePref('proxy-hide-failed', value))

interface QuickFilter {
  id: string
  label: string
  kind: 'udp' | 'chained' | 'protocol'
  count: number
}

const BUILTIN_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'])
const groupNamesSet = computed(() => new Set(catalog.value.map((group) => group.name)))

const NON_PROTOCOL_TYPES = new Set([
  'direct',
  'reject',
  'reject-drop',
  'pass',
  'selector',
  'url-test',
  'urltest',
  'fallback',
  'load-balance',
  'loadbalance',
  'smart',
  'relay',
  'compatible',
])
const MAX_PROTOCOL_QUICK_FILTERS = 4

const activeTag = ref<string | null>(null)

function isUdpNode(node: NodeItem): boolean {
  return node.tags.some((tag) => tag.toUpperCase() === 'UDP')
}

function isChainedNode(node: NodeItem): boolean {
  return Boolean(node.dialer_proxy) || node.tags.some((tag) => tag === 'chained' || tag === '链式')
}

const quickFilters = computed<QuickFilter[]>(() => {
  const seen = new Set<string>()
  let udpCount = 0
  let chainedCount = 0
  const protocolCounts = new Map<string, number>()

  for (const group of modeListed.value) {
    if (autoHidden(group)) continue
    for (const node of group.nodes) {
      if (
        groupNamesSet.value.has(node.name) ||
        BUILTIN_POLICIES.has(node.name.toUpperCase()) ||
        isInfoNode(node.name) ||
        seen.has(node.name)
      ) {
        continue
      }
      seen.add(node.name)
      if (isUdpNode(node)) udpCount += 1
      if (isChainedNode(node)) chainedCount += 1
      const rawType = node.node_type.trim().toLowerCase()
      if (rawType && !NON_PROTOCOL_TYPES.has(rawType)) {
        const label = protocolLabel(node.node_type).trim()
        if (label) protocolCounts.set(label, (protocolCounts.get(label) ?? 0) + 1)
      }
    }
  }

  const chips: QuickFilter[] = []
  if (udpCount > 0) chips.push({ id: 'tag:udp', label: 'UDP', kind: 'udp', count: udpCount })
  if (chainedCount > 0) chips.push({ id: 'tag:chained', label: tr('链式'), kind: 'chained', count: chainedCount })
  const topProtocols = [...protocolCounts.entries()]
    .sort((a, b) => b[1] - a[1] || compareText(a[0], b[0]))
    .slice(0, MAX_PROTOCOL_QUICK_FILTERS)
  for (const [label, count] of topProtocols) {
    chips.push({ id: `proto:${label}`, label, kind: 'protocol', count })
  }
  return chips
})

watch(quickFilters, (chips) => {
  if (activeTag.value && !chips.some((chip) => chip.id === activeTag.value)) {
    activeTag.value = null
  }
})

function toggleQuickTag(id: string) {
  activeTag.value = activeTag.value === id ? null : id
}

function matchesQuickTag(node: NodeItem): boolean {
  const selectedId = activeTag.value
  if (!selectedId) return true
  if (selectedId === 'tag:udp') return isUdpNode(node)
  if (selectedId === 'tag:chained') return isChainedNode(node)
  if (selectedId.startsWith('proto:')) {
    const target = selectedId.slice('proto:'.length)
    return protocolLabel(node.node_type).trim() === target
  }
  return true
}

const hasSearchOrTag = computed(() => Boolean(needle.value || activeTag.value))
const hasActiveFilter = computed(() => Boolean(hasSearchOrTag.value || (hideFailed.value && failedNodeCount.value > 0)))
const activeQuickFilter = computed(() =>
  activeTag.value ? (quickFilters.value.find((chip) => chip.id === activeTag.value) ?? null) : null,
)
const totalVisibleGroups = computed(() => modeListed.value.filter((group) => !autoHidden(group)).length)
const canToggleFilters = computed(() => quickFilters.value.length > 0 || totalVisibleGroups.value > 2)
const drawerExpanded = computed(() => (props.compact ? optionsOpen.value : filtersOpen.value))

function resetFilters() {
  query.value = ''
  activeTag.value = null
  hideFailed.value = false
}

type ViewGroup = NodeGroup & { info?: NodeItem[]; hiddenFailedCount?: number }

/** Info text without the provider's leading 【tag】 prefix. */
function infoText(name: string): string {
  return name.replace(/^\s*[【\[][^】\]]*[】\]]\s*/, '').trim() || name
}

const quotaCache = new Map<string, SubscriptionInfo>()
/** Subscription quota / expiry / reset parsed from a group's info nodes (R6); cached per text set. */
function quotaOf(info: readonly NodeItem[]): SubscriptionInfo {
  const texts = info.map((item) => infoText(item.name))
  const key = texts.join('\n')
  let parsed = quotaCache.get(key)
  if (!parsed) {
    parsed = parseSubscriptionInfo(texts)
    if (quotaCache.size > 64) quotaCache.clear()
    quotaCache.set(key, parsed)
  }
  return parsed
}

function quotaTagCount(info: SubscriptionInfo): number {
  return Number(Boolean(info.remaining)) + Number(Boolean(info.expire)) + Number(Boolean(info.resetDays)) + info.others.length
}

function resetText(days: number): string {
  if (days <= 0) return tr('今天重置')
  if (days === 1) return tr('明天重置')
  return tr('{0} 天后重置', { 0: days })
}

function percentText(value: number): string {
  if (value > 0 && value < 0.1) return '<0.1%'
  return `${value < 10 ? value.toFixed(1) : Math.round(value)}%`
}

function manifest(): NodeGroup[] {
  return listedGroups(snap.value.node_catalog)
}

/** The group a first visit opens: the selected manual group, else the first manual one (R26). */
function currentManualGroup(): NodeGroup | null {
  const manual = manifest().filter(
    (group) => group.kind === 'manual' && (mode.value === 'global' || group.name !== 'GLOBAL'),
  )
  if (mode.value === 'global') {
    const globalGroup = manual.find((group) => group.name === 'GLOBAL')
    if (globalGroup) return globalGroup
  }
  return manual.find((group) => Boolean(group.now)) ?? manual[0] ?? null
}

function defaultOpen(): Set<string> {
  const group = currentManualGroup()
  return new Set(group ? [group.name] : [])
}

function persistOpen() {
  writePref(OPEN_KEY, [...open.value])
}

/**
 * Saved names only survive while their groups still exist. Missing or corrupt
 * storage returns null (fall back to the default expansion); a saved empty array
 * is a real "everything collapsed" state and stays empty (R26).
 */
function readOpen(): Set<string> | null {
  try {
    const raw = localStorage.getItem(`billow:${OPEN_KEY}`)
    if (raw == null) return null
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return null
    if (parsed.length === 0) return new Set()
    const names = parsed.filter((item): item is string => typeof item === 'string')
    // Non-string entries only: treat as corrupt rather than "all collapsed".
    if (names.length === 0) return null
    const known = new Set(manifest().map((group) => group.name))
    const valid = names.filter((name) => known.has(name))
    return valid.length ? new Set(valid) : null
  } catch {
    return null
  }
}

function toggle(name: string) {
  const wasOpen = open.value.has(name)
  const card = wasOpen ? document.querySelector(`[data-group-card="${CSS.escape(name)}"]`) : null
  const beforeTop = card instanceof HTMLElement ? card.getBoundingClientRect().top : null
  const barBottom = toolbarEl.value?.getBoundingClientRect().bottom ?? 0
  const next = new Set(open.value)
  if (wasOpen) next.delete(name)
  else next.add(name)
  open.value = next
  persistOpen()
  if (wasOpen && beforeTop != null && beforeTop < barBottom - 4) {
    void scrollToGroup(name, 'instant')
  }
}

/** Search matches multi-word tokens across node name, dialer-proxy, and protocol/tags ("ss" exact, 3+ chars prefix like "real" → "reality"). */
function matches(node: NodeItem): boolean {
  if (!queryTokens.value.length) return true
  const nameLower = node.name.toLowerCase()
  if (nameLower.includes(needle.value)) return true
  const dialerLower = node.dialer_proxy?.toLowerCase() ?? ''
  const labels = [node.node_type, protocolLabel(node.node_type), ...node.tags].map((label) => label.toLowerCase())
  return queryTokens.value.every(
    (token) =>
      nameLower.includes(token) ||
      (dialerLower.length > 0 && dialerLower.includes(token)) ||
      labels.some((label) => label === token || (token.length >= 3 && label.startsWith(token))),
  )
}

/** Full protocol and tag list for the tooltip; rows may clip the tail. */
function metaTitle(node: NodeItem): string {
  const parts = [
    protocolLabel(node.node_type),
    ...node.tags.map((tag) =>
      tag === 'chained'
        ? node.dialer_proxy
          ? tr('链式（前置：{0}）', { 0: dialerTargetLabel(node) })
          : tr('链式')
        : tag,
    ),
  ]
  return parts.filter(Boolean).join(' · ')
}

function dialerTargetLabel(node: NodeItem): string {
  const dp = node.dialer_proxy
  if (!dp) return ''
  const group = catalogByName.value.get(dp)
  if (group) {
    const chain = resolveChain(dp, catalog.value)
    const leaf = chain[chain.length - 1]
    return leaf ? `${dp} › ${leaf}` : dp
  }
  return dp
}

function sorted(nodes: NodeItem[]): NodeItem[] {
  if (sort.value === 'default') return nodes
  const list = nodes.map((node, index) => ({ node, index }))
  if (sort.value === 'name') list.sort((a, b) => compareText(a.node.name, b.node.name) || a.index - b.index)
  if (sort.value === 'delay') {
    const key = (node: NodeItem) => (node.failed ? 2e9 : node.delay_ms == null ? 1e9 : node.delay_ms)
    list.sort((a, b) => key(a.node) - key(b.node) || a.index - b.index)
  }
  return list.map((item) => item.node)
}

const groups = computed(() => {
  const source = modeListed.value
  return source
    .filter((group) => !autoHidden(group))
    .map((group): ViewGroup => {
      let nodes = group.nodes
      if (needle.value) nodes = nodes.filter(matches)
      if (activeTag.value) nodes = nodes.filter(matchesQuickTag)
      const beforeHideFailed = nodes.length
      if (hideFailed.value && failedNodeCount.value > 0) {
        nodes = nodes.filter((node) => node.selected || !nodeState(node).failed)
      }
      const hiddenFailedCount = beforeHideFailed - nodes.length
      nodes = sorted(nodes)
      // Quota/expiry pseudo-nodes leave the grid unless selected or searched for (R11).
      const info = needle.value ? [] : nodes.filter((node) => !node.selected && isInfoNode(node.name))
      if (info.length) nodes = nodes.filter((node) => !info.includes(node))
      if (nodes === group.nodes && hiddenFailedCount === 0) return group
      return {
        ...group,
        nodes,
        ...(info.length ? { info } : {}),
        ...(hiddenFailedCount > 0 ? { hiddenFailedCount } : {}),
      }
    })
    .filter(
      (group) =>
        !hasSearchOrTag.value ||
        group.nodes.length > 0 ||
        (!activeTag.value && matchesTokens(group.name, queryTokens.value)),
    )
})

const matchCount = computed(() =>
  hasSearchOrTag.value ? groups.value.reduce((total, group) => total + group.nodes.length, 0) : 0,
)

/** Groups share nodes, so the page total counts distinct names instead of row copies. */
const distinctNodeCount = computed(() => {
  const seen = new Set<string>()
  modeListed.value.forEach((group) => group.nodes.forEach((node) => seen.add(node.name)))
  return seen.size
})

const allExpanded = computed(
  () => groups.value.length > 0 && groups.value.every((group) => open.value.has(group.name)),
)

function toggleAll() {
  const next = new Set(open.value)
  if (allExpanded.value) groups.value.forEach((group) => next.delete(group.name))
  else groups.value.forEach((group) => next.add(group.name))
  open.value = next
  persistOpen()
}

/** A running test streams results before the next snapshot; afterwards rows use the snapshot (R26). */
function nodeState(node: NodeItem): { delay: number | null; failed: boolean } {
  const result = store.testResults.value[node.name]
  return result ? { delay: result.delay, failed: result.failed } : { delay: node.delay_ms, failed: node.failed }
}

function nodeDelay(node: NodeItem): string {
  const state = nodeState(node)
  return delayText(state.delay, state.failed)
}

function nodeTone(node: NodeItem): string {
  const state = nodeState(node)
  return delayTone(state.delay, state.failed)
}

function groupNowDelay(group: NodeGroup): string {
  const state = effectiveGroupDelay(group, catalog.value, store.testResults.value)
  if (!state.target) return ''
  return delayText(state.delay, state.failed)
}

function groupNowTone(group: NodeGroup): string {
  const state = effectiveGroupDelay(group, catalog.value, store.testResults.value)
  if (!state.target) return 'none'
  return delayTone(state.delay, state.failed)
}

/** Latest local test time in the group; unknown groups show nothing rather than a fake time. */
function groupTestedAt(group: NodeGroup): number | null {
  let latest = 0
  group.nodes.forEach((node) => {
    const at = store.testTimes.value[node.name]
    if (at && at > latest) latest = at
  })
  return latest || null
}

const failedNodeCount = computed(() => {
  const seen = new Set<string>()
  let count = 0
  for (const group of modeListed.value) {
    if (autoHidden(group)) continue
    for (const node of group.nodes) {
      if (
        groupNamesSet.value.has(node.name) ||
        BUILTIN_POLICIES.has(node.name.toUpperCase()) ||
        isInfoNode(node.name) ||
        seen.has(node.name)
      ) {
        continue
      }
      seen.add(node.name)
      if (nodeState(node).failed) count += 1
    }
  }
  return count
})

function groupHealthText(group: NodeGroup): string {
  let tested = 0
  let ok = 0
  for (const node of group.nodes) {
    if (
      groupNamesSet.value.has(node.name) ||
      BUILTIN_POLICIES.has(node.name.toUpperCase()) ||
      isInfoNode(node.name)
    ) {
      continue
    }
    const state = nodeState(node)
    if (state.failed) {
      tested += 1
    } else if (state.delay != null) {
      tested += 1
      ok += 1
    }
  }
  if (!tested) return ''
  return props.compact ? `${ok}/${tested}` : tr('可用 {0}/{1}', { 0: ok, 1: tested })
}

function highlight(name: string) {
  return highlightTokens(name, query.value)
}

/** The provider tag is dimmed; search hits still mark both parts. */
function nameParts(name: string) {
  const { prefix, rest } = splitNodePrefix(name)
  return { prefix: prefix ? highlight(prefix) : [], rest: highlight(rest) }
}

function copyNodeName(node: NodeItem) {
  void store.copyText(node.name, tr('已复制节点名称：{0}', { 0: node.name }))
}

const ctxMenu = ref<{ x: number; y: number; items: MenuItem[]; group: NodeGroup; node: NodeItem } | null>(null)

function isTouchOrCompact(): boolean {
  return (
    Boolean(props.compact) ||
    store.isAndroid.value ||
    (typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches === true)
  )
}

function openNodeContextMenu(event: MouseEvent, group: NodeGroup, node: NodeItem) {
  event.preventDefault()
  if (isTouchOrCompact()) return
  const items: MenuItem[] = []
  if (canPickNode(group)) {
    const isAuto = group.kind === 'auto'
    const busy = Boolean(store.busy[`select:${group.name}`])
    const alreadyPicked = isAuto ? group.fixed === node.name : node.selected
    const offlineAuto = isAuto && !snap.value.kernel_running
    items.push({
      id: 'pick',
      label: isAuto ? tr('固定此节点') : tr('选择此节点'),
      icon: 'check',
      disabled: alreadyPicked || offlineAuto || busy,
      reason: busy
        ? tr('切换中')
        : alreadyPicked
          ? (isAuto ? tr('已固定') : tr('当前已选'))
          : offlineAuto
            ? tr('未连接')
            : undefined,
    })
  }
  const testBusy = store.testing.value || store.pendingTests.value.has(node.name)
  items.push({
    id: 'test',
    label: tr('测试延迟'),
    icon: 'zap',
    disabled: !snap.value.kernel_running || testBusy,
    reason: !snap.value.kernel_running ? tr('未连接') : testBusy ? tr('测速中') : undefined,
  })
  items.push({
    id: 'copy',
    label: tr('复制节点名称'),
    icon: 'copy',
  })
  const nestedAuto = autoOf(node)
  if (nestedAuto && !nestedAuto.hidden) {
    items.push({
      id: 'open-auto',
      label: tr('查看组策略与成员'),
      icon: 'chevron-right',
    })
  }
  ctxMenu.value = { x: event.clientX, y: event.clientY, items, group, node }
}

function onNodeContextSelect(item: MenuItem) {
  const target = ctxMenu.value
  ctxMenu.value = null
  if (!target) return
  if (item.id === 'pick') pick(target.group, target.node)
  else if (item.id === 'test') void store.testNode(target.node.name)
  else if (item.id === 'copy') copyNodeName(target.node)
  else if (item.id === 'open-auto') openAuto(target.node.name)
}

function pick(group: NodeGroup, node: NodeItem) {
  if (!canPickNode(group)) return
  // An auto group's current node can still be picked to fix it there (R28).
  if (node.selected && (group.kind === 'manual' || group.fixed === node.name)) return
  void store.selectNode(group.name, node.name)
}

/** Lowest-latency tested proxy in a manual group, hidden if it is already selected. */
function fastestCandidate(group: NodeGroup): { node: NodeItem; delay: number } | null {
  if (group.kind !== 'manual' || !snap.value.kernel_running) return null
  let best: { node: NodeItem; delay: number } | null = null
  for (const node of group.nodes) {
    if (groupNamesSet.value.has(node.name)) continue
    if (BUILTIN_POLICIES.has(node.name.toUpperCase()) || isInfoNode(node.name)) continue
    const state = nodeState(node)
    if (state.failed || state.delay == null || state.delay <= 0) continue
    if (!best || state.delay < best.delay) {
      best = { node, delay: state.delay }
    }
  }
  if (!best || best.node.selected) return null
  return best
}

async function pickFastest(group: NodeGroup) {
  const best = fastestCandidate(group)
  if (!best) return
  const res = await store.selectNode(group.name, best.node.name)
  if (res) {
    store.toast(tr('已切至最快节点：{0} ({1})', { 0: best.node.name, 1: delayText(best.delay, false) }), 'success')
  }
}

const testAllProgressPct = computed<number | null>(() => {
  if (!store.busy.testAll || store.testProgress.value.total <= 0) return null
  return Math.min(100, Math.round((store.testProgress.value.tested / store.testProgress.value.total) * 100))
})

function groupTestProgressPct(name: string): number | null {
  if (store.activeTest.value?.group !== name || store.testProgress.value.total <= 0) return null
  return Math.min(100, Math.round((store.testProgress.value.tested / store.testProgress.value.total) * 100))
}

function nodeTitle(group: NodeGroup): string | undefined {
  if (group.kind === 'manual') return undefined
  if (group.pinnable) return snap.value.kernel_running ? tr('点选后固定使用该节点，可随时恢复自动') : tr('内核没有运行，连接后才能固定节点')
  return tr('{0}组由内核自动择优，不可手动切换', { 0: groupTypeLabel(group) })
}

function isOpen(name: string) {
  return hasSearchOrTag.value || open.value.has(name)
}

/** Gap between the sticky toolbar and a located group header. */
const TOOLBAR_GAP = 12

/**
 * Landing on the page jumps straight to the group before the first paint; a long
 * smooth scroll through every card above it reads as lag, especially on phones.
 * Smooth scrolling is kept for moves within an already visible list.
 */
async function scrollToGroup(name: string | null, behavior: ScrollBehavior = 'instant') {
  if (!name) return
  await nextTick()
  const el = document.querySelector(`[data-group-card="${CSS.escape(name)}"]`)
  if (!(el instanceof HTMLElement)) return
  // The toolbar is sticky and wraps to two rows on phones, so the located card
  // needs a scroll margin equal to its measured height plus a gap (R26).
  const toolbarHeight = toolbarEl.value?.getBoundingClientRect().height ?? 0
  el.style.scrollMarginTop = `${Math.ceil(toolbarHeight) + TOOLBAR_GAP}px`
  el.scrollIntoView?.({ block: 'start', behavior })
  const pill = document.querySelector(`[data-testid="jump-group-${CSS.escape(name)}"]`)
  if (pill instanceof HTMLElement) {
    pill.scrollIntoView?.({ inline: 'nearest', block: 'nearest', behavior })
  }
}

/** The located ring is a short cue, not a lasting state: it fades and the request is cleared. */
const LOCATE_CUE_MS = 1600
let locateTimer: ReturnType<typeof setTimeout> | null = null
const locatedNodeKey = ref<string | null>(null)
let locateNodeTimer: ReturnType<typeof setTimeout> | null = null

function scheduleLocateClear(name: string) {
  if (locateTimer) clearTimeout(locateTimer)
  locateTimer = setTimeout(() => {
    locateTimer = null
    if (store.focusGroup.value === name) store.focusGroup.value = null
  }, LOCATE_CUE_MS)
}

const canLocateActive = computed(() => {
  if (mode.value === 'global') {
    const globalGroup = catalog.value.find((item) => item.name === 'GLOBAL')
    if (globalGroup?.now) return true
  }
  return Boolean(currentManualGroup()?.now)
})

async function locateActiveNode() {
  const preferred =
    mode.value === 'global'
      ? (catalog.value.find((item) => item.name === 'GLOBAL' && item.now) ?? currentManualGroup())
      : currentManualGroup()
  if (!preferred || !preferred.now) return
  revealAuto(preferred)
  if (query.value) query.value = ''
  if (activeTag.value) activeTag.value = null
  if (!open.value.has(preferred.name)) {
    open.value = new Set([...open.value, preferred.name])
    persistOpen()
  }
  await nextTick()
  await grids.get(preferred.name)?.reveal(preferred.now)
  const groupCard = document.querySelector(`[data-group-card="${CSS.escape(preferred.name)}"]`)
  const nodeEl = groupCard?.querySelector(`[data-node="${CSS.escape(preferred.now)}"]`)
  const target = nodeEl instanceof HTMLElement ? nodeEl : groupCard instanceof HTMLElement ? groupCard : null
  if (target) {
    const barH = toolbarEl.value?.getBoundingClientRect().height ?? 0
    target.style.scrollMarginTop = `${Math.ceil(barH) + TOOLBAR_GAP + 52}px`
    target.scrollIntoView?.({ block: 'center', behavior: 'smooth' })
  }
  locatedNodeKey.value = `${preferred.name}::${preferred.now}`
  if (locateNodeTimer) clearTimeout(locateNodeTimer)
  locateNodeTimer = setTimeout(() => {
    locateNodeTimer = null
    locatedNodeKey.value = null
  }, LOCATE_CUE_MS)
}

/** Home deep links win: open the group, drop a filter that hides it, then scroll to it (R26). */
async function locate(name: string | null, behavior: ScrollBehavior = 'instant') {
  if (!name) return
  const group = manifest().find((item) => item.name === name)
  if (!group) return
  revealAuto(group)
  // A search or quick tag could hide the group or its nodes; the deep link wins.
  if (query.value) query.value = ''
  if (activeTag.value) activeTag.value = null
  if (!open.value.has(name)) {
    open.value = new Set([...open.value, name])
    persistOpen()
  }
  await scrollToGroup(name, behavior)
  scheduleLocateClear(name)
}

/**
 * On phones, tapping the quick-jump pill bar switches focus cleanly to that
 * single group (unless "展开全部" is active), avoiding a 3000px stack of open groups.
 */
async function jumpToGroup(name: string) {
  if (props.compact && !allExpanded.value) {
    open.value = new Set([name])
    persistOpen()
    await scrollToGroup(name, 'smooth')
    scheduleLocateClear(name)
    return
  }
  await locate(name, 'smooth')
}

onMounted(() => {
  void (async () => {
    const target = store.focusGroup.value
    if (target) {
      await locate(target)
      if (
        typeof window !== 'undefined' &&
        window.matchMedia?.('(pointer: coarse)').matches !== true &&
        document.activeElement === document.body
      ) {
        const groupBtn = document.querySelector<HTMLElement>(
          `[data-group-card="${CSS.escape(target)}"] [data-testid^="group-toggle-"]`,
        )
        const returnBtn = document.querySelector<HTMLElement>('[data-testid="connection-return"]')
        ;(groupBtn ?? returnBtn)?.focus({ preventScroll: true })
      }
      return
    }
    if (mode.value === 'global' && modeListed.value.some((group) => group.name === 'GLOBAL') && !open.value.has('GLOBAL')) {
      open.value = new Set([...open.value, 'GLOBAL'])
      persistOpen()
    }
    // Only a first visit scrolls to the default group; a saved state stays where the user left it.
    // When that group already leads the list, scrolling would only hide the page head and its
    // 全部测速 action, so the page stays at the top.
    const fallback = currentManualGroup()?.name ?? null
    if (!storedOpen && fallback && groups.value[0]?.name !== fallback) await scrollToGroup(fallback)
  })()
})

watch(() => store.focusGroup.value, (name) => void locate(name, 'smooth'))

watch(
  [mode, () => modeListed.value.some((group) => group.name === 'GLOBAL')],
  ([nextMode, hasGlobal], [prevMode]) => {
    if (nextMode === 'global' && hasGlobal && prevMode !== 'global' && !open.value.has('GLOBAL')) {
      open.value = new Set([...open.value, 'GLOBAL'])
      persistOpen()
    }
  },
)

function measureToolbar() {
  toolbarHeight.value = Math.ceil(toolbarEl.value?.getBoundingClientRect().height ?? 0)
}

watch(toolbarEl, (element, previous) => {
  if (previous) toolbarObserver?.unobserve(previous)
  if (!element) {
    toolbarHeight.value = 0
    return
  }
  if (typeof ResizeObserver !== 'undefined') {
    toolbarObserver ??= new ResizeObserver(measureToolbar)
    toolbarObserver.observe(element)
  }
  measureToolbar()
})

onBeforeUnmount(() => {
  toolbarObserver?.disconnect()
  toolbarObserver = null
  if (locateTimer) clearTimeout(locateTimer)
  locateTimer = null
  if (locateNodeTimer) clearTimeout(locateNodeTimer)
  locateNodeTimer = null
  // Leaving early must not keep the request alive for the next visit.
  if (store.focusGroup.value) store.focusGroup.value = null
})

/** Phones list one node per row and offer a two-column grid as their only other view. */
/** A pressed toggle keeps one stable name; aria-pressed carries the on/off state (R3). */
const denseLabel = computed(() => tr('双列视图'))
const denseIcon = 'grid'

const groupPillsEl = ref<HTMLElement | null>(null)
const draggingPills = ref(false)
let pillsDragCleanup: (() => void) | null = null
let suppressNextPillClick = false
let suppressClickTimer: ReturnType<typeof setTimeout> | null = null

function stopPillsDrag() {
  pillsDragCleanup?.()
  pillsDragCleanup = null
  draggingPills.value = false
}

function onPillsMouseDown(event: MouseEvent) {
  if (event.button !== 0) return
  const el = groupPillsEl.value
  if (!el || el.scrollWidth <= el.clientWidth) return
  stopPillsDrag()
  const startX = event.clientX
  const startScrollLeft = el.scrollLeft
  let moved = false

  const onMove = (moveEvent: MouseEvent) => {
    const dx = moveEvent.clientX - startX
    if (!moved && Math.abs(dx) >= 4) {
      moved = true
      draggingPills.value = true
    }
    if (moved) {
      el.scrollLeft = startScrollLeft - dx
      moveEvent.preventDefault()
    }
  }

  const onUp = () => {
    stopPillsDrag()
    if (moved) {
      suppressNextPillClick = true
      if (suppressClickTimer) clearTimeout(suppressClickTimer)
      suppressClickTimer = setTimeout(() => {
        suppressNextPillClick = false
        suppressClickTimer = null
      }, 0)
    }
  }

  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp, { once: true })
  pillsDragCleanup = () => {
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
  }
}

function onPillsClickCapture(event: MouseEvent) {
  if (!suppressNextPillClick) return
  suppressNextPillClick = false
  if (suppressClickTimer) {
    clearTimeout(suppressClickTimer)
    suppressClickTimer = null
  }
  event.preventDefault()
  event.stopPropagation()
}

function onPillsWheel(event: WheelEvent) {
  const el = groupPillsEl.value
  if (!el || el.scrollWidth <= el.clientWidth) return
  if (Math.abs(event.deltaY) > Math.abs(event.deltaX) && event.deltaY !== 0) {
    el.scrollLeft += event.deltaY
    event.preventDefault()
  }
}

onBeforeUnmount(() => {
  stopPillsDrag()
  if (suppressClickTimer) {
    clearTimeout(suppressClickTimer)
    suppressClickTimer = null
  }
})
</script>

<template>
  <div class="page proxies" :style="{ '--toolbar-h': `${toolbarHeight}px` }">
    <header class="page-head">
      <div>
        <h1>{{ tr('代理') }}</h1>
        <p class="muted small" :title="hiddenAutoCount ? tr('另有 {0} 个自动组由内核择优，未单独列出', { 0: hiddenAutoCount }) : undefined">
          <template v-if="modeListed.length">{{ modeListed.length - hiddenAutoCount }} {{ tr('个代理组 ·') }} {{ distinctNodeCount }} {{ tr('个节点') }}</template>
          <template v-else-if="allGroupsHidden">{{ tr('配置中的代理组均已隐藏') }}</template>
          <template v-else>{{ snap.nodes_notice ? tr(snap.nodes_notice) : tr('没有代理组') }}</template>
        </p>
      </div>
      <div class="head-actions">
        <Segmented
          v-if="snap.active_id && !compact"
          :model-value="snap.mode"
          :options="MODES"
          size="sm"
          :label="tr('出站模式')"
          :disabled="store.busy.mode"
          @update:model-value="store.setMode"
        />
        <span
          v-if="store.busy.testAll && store.testProgress.value.total > 0"
          class="test-progress small mono"
          data-testid="test-progress"
          aria-live="polite"
        >{{ tr('已测') }} {{ store.testProgress.value.tested }}/{{ store.testProgress.value.total }}</span>
        <span
          v-if="!snap.kernel_running && snap.node_catalog.length"
          id="proxy-test-hint"
          class="test-hint sr-only"
          data-testid="test-hint"
        > {{ tr('连接后可测速') }} </span>
        <!-- Without groups there is nothing to test; the empty state below owns the next step. -->
        <button
          v-if="snap.node_catalog.length"
          type="button"
          class="btn primary sm"
          :disabled="store.testing.value || !snap.kernel_running"
          :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
          :title="snap.kernel_running ? tr('测试全部节点延迟') : tr('连接后才能测速')"
          data-testid="test-all"
          @click="store.testAll()"
        >
          <span v-if="store.busy.testAll" class="spinner sm" />
          <Icon v-else name="zap" :size="15" />
          {{ compact ? tr('测速') : tr('全部测速') }}
        </button>
      </div>
    </header>

    <div
      v-if="!snap.kernel_running && snap.node_catalog.length"
      class="proxies-connect-bar"
      data-testid="proxies-connect-bar"
    >
      <span class="proxies-connect-text small">{{ tr('当前未连接，连接后即可测速与实时生效') }}</span>
      <button
        type="button"
        class="btn primary sm"
        :disabled="store.connecting.value"
        data-testid="proxies-connect"
        @click="store.connect()"
      >
        <span v-if="store.connecting.value" class="spinner xs" />
        <Icon v-else name="power" :size="14" />
        {{ store.connecting.value ? tr('连接中') : tr('立即连接') }}
      </button>
    </div>

    <div
      v-if="snap.mode === 'direct' && snap.node_catalog.length"
      class="proxies-connect-bar direct-bar"
      data-testid="proxies-direct-bar"
    >
      <span class="proxies-connect-text small">
        <Icon name="zap" :size="15" /> {{ tr('当前为直连模式，选择的代理节点不会生效') }} </span>
      <button
        type="button"
        class="btn ghost sm"
        :disabled="Boolean(store.busy.mode)"
        data-testid="proxies-switch-rule"
        @click="store.setMode('rule')"
      > {{ tr('切回规则模式') }} </button>
    </div>

    <div v-if="listed.length" ref="toolbarEl" class="toolbar proxies-toolbar" data-testid="proxy-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索节点、协议或 UDP 等标签')" data-testid="node-search" data-page-search />
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button v-if="query" type="button" class="icon-btn sm" :aria-label="tr('清空搜索')" data-testid="clear-search" @click="query = ''">
          <Icon name="x" :size="14" />
        </button>
      </div>
      <button
        v-if="compact"
        type="button"
        class="icon-btn options-btn"
        :class="{ active: optionsOpen }"
        :aria-expanded="optionsOpen"
        aria-controls="proxy-options"
        :aria-label="tr('排序与视图')"
        :title="tr('排序与视图')"
        data-testid="toggle-options"
        @click="optionsOpen = !optionsOpen"
      >
        <Icon name="sliders" />
      </button>
      <span v-if="hasSearchOrTag && matchCount > 0" class="toolbar-count small" data-testid="match-count" aria-live="polite"> {{ tr('匹配') }} {{ matchCount }} {{ tr('个节点') }} </span>
      <button
        v-if="!drawerExpanded && activeQuickFilter"
        type="button"
        class="chip-btn active proxy-active-filter-pill"
        :aria-label="tr('清除筛选：{0}', { 0: activeQuickFilter.label })"
        :title="tr('点击清除筛选')"
        data-testid="active-quick-filter-pill"
        @click="activeTag = null"
      >
        <span>{{ activeQuickFilter.label }}</span>
        <span class="proxy-quick-count mono">{{ activeQuickFilter.count }}</span>
        <Icon name="x" :size="12" />
      </button>
      <button
        v-if="compact && !drawerExpanded && hideFailed && failedNodeCount > 0"
        type="button"
        class="chip-btn active proxy-active-filter-pill"
        :aria-label="tr('显示超时节点')"
        :title="tr('显示超时节点')"
        data-testid="active-hide-failed-pill"
        @click="hideFailed = false"
      >
        <span>{{ tr('隐藏超时') }}</span>
        <span class="proxy-quick-count mono">{{ failedNodeCount }}</span>
        <Icon name="x" :size="12" />
      </button>
      <button
        v-if="!compact && failedNodeCount > 0"
        type="button"
        class="chip-btn hide-failed-chip"
        :class="{ active: hideFailed }"
        :aria-pressed="hideFailed"
        data-testid="hide-failed-nodes"
        @click="hideFailed = !hideFailed"
      > {{ tr('隐藏超时') }} {{ failedNodeCount }}
      </button>
      <div v-if="showOptions" id="proxy-options" class="toolbar-options">
        <button
          v-if="!compact && canToggleFilters"
          type="button"
          class="btn ghost sm tool-btn filter-drawer-toggle"
          :class="{ active: filtersOpen }"
          :aria-expanded="filtersOpen"
          :aria-pressed="filtersOpen"
          aria-controls="proxy-filter-drawer"
          :title="filtersOpen ? tr('收起筛选与分组导航') : tr('展开筛选与分组导航')"
          data-testid="toggle-proxy-filters"
          @click="filtersOpen = !filtersOpen"
        >
          <Icon name="filter" :size="14" />
          <span>{{ tr('筛选') }}</span>
          <Icon name="chevron-down" :size="13" class="filter-toggle-chevron" :class="{ open: filtersOpen }" />
        </button>
        <Segmented v-model="sort" :options="SORTS" size="sm" :label="tr('排序')" />
        <!-- Desktop: quiet icon buttons with tooltips; phones lay them out as labelled chips (R3, R12). Auto groups need no toggle (R13). -->
        <div
          v-if="!compact"
          class="view-switch"
          role="group"
          :aria-label="tr('节点视图')"
          :data-value="desktopView"
          data-testid="node-view"
        >
          <button
            v-for="item in VIEWS"
            :key="item.id"
            type="button"
            class="view-switch-btn"
            :class="{ active: desktopView === item.id }"
            :aria-pressed="desktopView === item.id"
            :aria-label="tr('{0}视图', { 0: item.label })"
            :title="tr('{0}视图', { 0: item.label })"
            :data-testid="`node-view-${item.id}`"
            @click="view = item.id"
          >
            <Icon :name="item.icon" :size="15" />
          </button>
        </div>
        <button
          type="button"
          class="btn ghost sm tool-btn"
          :class="{ 'icon-only': !compact }"
          :disabled="!canLocateActive"
          :aria-label="tr('定位当前选中节点')"
          :title="canLocateActive ? tr('定位当前选中节点') : tr('当前没有已选中的节点')"
          data-testid="locate-active-node"
          @click="locateActiveNode"
        >
          <Icon name="locate" :size="15" />
          <span class="tool-btn-label" :class="{ 'sr-only': !compact }">{{ tr('定位') }}</span>
        </button>
        <button
          v-if="compact"
          type="button"
          class="btn ghost sm tool-btn"
          :class="{ active: dense }"
          :aria-pressed="dense"
          :aria-label="denseLabel"
          :title="denseLabel"
          data-testid="toggle-dense"
          @click="view = dense ? 'card' : 'dense'"
        >
          <Icon :name="denseIcon" :size="15" />
          <span class="tool-btn-label">{{ tr('双列') }}</span>
        </button>
        <button
          type="button"
          class="btn ghost sm tool-btn"
          :class="{ 'icon-only': !compact }"
          :title="allExpanded ? tr('收起全部代理组') : tr('展开全部代理组')"
          data-testid="toggle-all"
          @click="toggleAll"
        >
          <Icon :name="allExpanded ? 'collapse-all' : 'expand-all'" :size="15" />
          <span class="tool-btn-label" :class="{ 'sr-only': !compact }">{{ allExpanded ? tr('收起全部') : tr('展开全部') }}</span>
        </button>
      </div>

      <div
        v-if="drawerExpanded && (quickFilters.length || (compact && failedNodeCount > 0) || (groups.length > 2 && !hasSearchOrTag))"
        id="proxy-filter-drawer"
        class="proxy-filter-drawer"
        data-testid="proxy-filter-drawer"
      >
        <div
          v-if="quickFilters.length || (compact && failedNodeCount > 0)"
          class="proxy-quick-filters"
          role="group"
          :aria-label="tr('筛选')"
          data-testid="proxy-quick-filters"
        >
          <span class="drawer-row-label">{{ tr('标签') }}</span>
          <button
            v-if="compact && failedNodeCount > 0"
            type="button"
            class="chip-btn proxy-quick-chip hide-failed-chip"
            :class="{ active: hideFailed }"
            :aria-pressed="hideFailed"
            data-testid="hide-failed-nodes"
            @click="hideFailed = !hideFailed"
          >
            <span>{{ tr('隐藏超时') }}</span>
            <span class="proxy-quick-count mono">{{ failedNodeCount }}</span>
          </button>
          <button
            v-for="chip in quickFilters"
            :key="chip.id"
            type="button"
            class="chip-btn proxy-quick-chip"
            :class="{ active: activeTag === chip.id }"
            :aria-pressed="activeTag === chip.id"
            :data-testid="`quick-filter-${chip.id}`"
            @click="toggleQuickTag(chip.id)"
          >
            <span>{{ chip.label }}</span>
            <span class="proxy-quick-count mono">{{ chip.count }}</span>
          </button>
          <button
            v-if="hasActiveFilter"
            type="button"
            class="btn ghost sm proxy-quick-reset"
            data-testid="clear-proxy-quick-filters"
            @click="resetFilters"
          >
            <Icon name="x" :size="13" />
            {{ tr('重置筛选') }}
          </button>
          <button
            v-if="!compact"
            type="button"
            class="icon-btn sm drawer-close-btn"
            :aria-label="tr('收起筛选与分组导航')"
            :title="tr('收起筛选与分组导航')"
            data-testid="close-proxy-filters"
            @click="filtersOpen = false"
          >
            <Icon name="x" :size="14" />
          </button>
        </div>

        <div v-if="groups.length > 2 && !hasSearchOrTag" class="proxy-group-nav-row">
          <span class="drawer-row-label">{{ tr('分组') }}</span>
          <nav
            ref="groupPillsEl"
            class="group-pills"
            :class="{ dragging: draggingPills }"
            :aria-label="tr('代理组快速跳转')"
            data-testid="group-jump-bar"
            @mousedown="onPillsMouseDown"
            @click.capture="onPillsClickCapture"
            @wheel="onPillsWheel"
          >
            <button
              v-for="group in groups"
              :key="group.name"
              type="button"
              class="group-pill"
              :class="{
                open: isOpen(group.name),
                focused: store.focusGroup.value === group.name,
                testing: store.activeTest.value?.group === group.name,
              }"
              :aria-busy="store.activeTest.value?.group === group.name || undefined"
              :data-testid="`jump-group-${group.name}`"
              @click="jumpToGroup(group.name)"
            >
              <span class="group-pill-name">{{ group.name }}</span>
              <span class="group-pill-count mono">{{ group.nodes.length }}</span>
            </button>
          </nav>
          <button
            v-if="!compact && !quickFilters.length"
            type="button"
            class="icon-btn sm drawer-close-btn"
            :aria-label="tr('收起筛选与分组导航')"
            :title="tr('收起筛选与分组导航')"
            data-testid="close-proxy-filters"
            @click="filtersOpen = false"
          >
            <Icon name="x" :size="14" />
          </button>
        </div>
      </div>
      <div v-if="testAllProgressPct != null" class="test-progress-track" aria-hidden="true">
        <span class="test-progress-fill" :style="{ width: `${testAllProgressPct}%` }" />
      </div>
    </div>

    <EmptyState
      v-if="!snap.node_catalog.length"
      variant="no-data"
      icon="globe"
      :title="snap.nodes_notice ? tr(snap.nodes_notice) : tr('没有代理组')"
      :description="tr('添加并启用一份配置后，这里会列出它的代理组与节点。')"
    >
      <template #action>
        <button type="button" class="btn primary sm" @click="store.go('profiles')">{{ tr('前往配置') }}</button>
      </template>
    </EmptyState>
    <EmptyState
      v-else-if="allGroupsHidden"
      variant="no-data"
      icon="globe"
      :title="tr('配置中的代理组均已隐藏')"
      :description="tr('这份配置把全部代理组标记为 hidden，如需在这里选择节点，请在配置中取消隐藏。')"
      data-testid="all-groups-hidden"
    />
    <EmptyState
      v-else-if="!groups.length"
      compact
      variant="no-match"
      :title="tr('没有匹配的节点')"
      :description="tr('换一个关键词或关闭「隐藏超时」筛选。')"
      data-testid="no-match"
    >
      <template #action>
        <button
          type="button"
          class="btn ghost sm"
          data-testid="reset-proxy-filters"
          @click="resetFilters"
        >{{ (hideFailed || activeTag) && !needle ? tr('重置筛选') : tr('清空筛选') }}</button>
      </template>
    </EmptyState>

    <section
      v-for="(group, index) in groups"
      :key="group.name"
      v-memo="[group, autoNowKey, isOpen(group.name), view, needle, activeTag, store.focusGroup.value, locatedNodeKey, snap.kernel_running, store.testProgress.value, store.testResults.value, store.activeTest.value, store.pendingTests.value.size, groupTestedAt(group), busyKeys]"
      class="card group"
      :class="{ open: isOpen(group.name), located: store.focusGroup.value === group.name }"
      :data-group-card="group.name"
    >
      <header class="group-head">
        <button
          type="button"
          class="group-toggle"
          :aria-expanded="isOpen(group.name)"
          :aria-controls="`group-nodes-${index}`"
          :data-testid="`group-toggle-${group.name}`"
          @click="toggle(group.name)"
        >
          <span class="group-head-icon"><GroupIcon :icon="group.icon" :type="group.group_type" :size="22" /></span>
          <span class="group-title">
            <span class="group-name">
              <strong>{{ group.name }}</strong>
              <span v-if="autoTypeLabel(group)" class="tag group-kind" data-testid="group-kind">{{ autoTypeLabel(group) }}</span>
              <span
                v-if="group.fixed"
                class="tag accent fixed-tag"
                :title="tr('已固定使用 {0}，恢复自动后由组策略选择', { 0: group.fixed })"
                :data-testid="`group-fixed-${group.name}`"
              >{{ tr('已固定') }}</span>
              <span class="muted small group-count mono">{{ group.nodes.length }}</span>
              <span v-if="groupHealthText(group)" class="group-health muted small">{{ groupHealthText(group) }}</span>
            </span>
            <span class="group-now small">
              <Icon v-if="group.kind === 'auto'" name="cpu" :size="13" />
              <ChainPath v-if="group.now" class="group-now-name" :hops="groupHops(group)" :groups="groupNamesSet" :fold="compact" />
              <span v-else class="group-now-name">{{ group.kind === 'auto' ? tr('连接后显示') : '—' }}</span>
              <span v-if="groupNowDelay(group)" class="group-delay mono" :class="groupNowTone(group)">{{ groupNowDelay(group) }}</span>
              <span v-if="store.activeTest.value?.group === group.name" class="small mono" data-testid="group-test-progress" aria-live="polite">{{ tr('已测') }} {{ store.testProgress.value.tested }}/{{ store.testProgress.value.total }}</span>
              <span v-else-if="groupTestedAt(group)" class="group-tested">{{ tr('测速') }} {{ formatRelative(groupTestedAt(group)!) }}</span>
            </span>
          </span>
          <Icon name="chevron-down" class="chevron" />
        </button>
        <button
          v-if="fastestCandidate(group)"
          type="button"
          class="btn ghost sm group-fastest"
          :disabled="Boolean(store.busy[`select:${group.name}`])"
          :title="tr('切换至当前最快的节点：{0} ({1})', { 0: fastestCandidate(group)!.node.name, 1: delayText(fastestCandidate(group)!.delay, false) })"
          :data-testid="`pick-fastest-${group.name}`"
          @click="pickFastest(group)"
        >
          <Icon name="zap" :size="13" />
          <span class="group-fastest-label">{{ compact ? tr('最快') : tr('选最快') }}</span>
        </button>
        <button
          v-if="group.fixed"
          type="button"
          class="btn ghost sm group-unfix"
          :disabled="!snap.kernel_running || Boolean(store.busy[`select:${group.name}`])"
          :title="snap.kernel_running ? tr('解除固定，由组策略重新选择节点') : tr('内核没有运行')"
          :data-testid="`unfix-group-${group.name}`"
          @click="store.unfixGroup(group.name)"
        > {{ tr('恢复自动') }} </button>
        <button
          type="button"
          class="icon-btn group-test"
          :aria-label="tr('测速 {0}', { 0: group.name })"
          :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
          :title="snap.kernel_running ? tr('测试该组延迟') : tr('连接后才能测速')"
          :disabled="!snap.kernel_running || store.testing.value"
          :aria-busy="store.activeTest.value?.group === group.name || undefined"
          :data-testid="`test-group-${group.name}`"
          @click="store.testGroup(group.name)"
        >
          <span v-if="store.busy[`test:${group.name}`]" class="spinner sm" />
          <Icon v-else name="zap" />
        </button>
        <div v-if="groupTestProgressPct(group.name) != null" class="test-progress-track" aria-hidden="true">
          <span class="test-progress-fill" :style="{ width: `${groupTestProgressPct(group.name)}%` }" />
        </div>
      </header>

      <ProxyNodeGrid
        v-if="isOpen(group.name)"
        :id="`group-nodes-${index}`"
        :ref="(el) => { if (el) grids.set(group.name, el as InstanceType<typeof ProxyNodeGrid>); else grids.delete(group.name) }"
        :nodes="group.nodes"
        :dense="dense"
        :list="listView"
        :compact="compact"
      >
        <template v-if="groupStrategy(group.group_type) || group.info?.length" #header>
          <p v-if="groupStrategy(group.group_type)" class="group-strategy small" data-testid="group-strategy">
            <Icon :name="groupStrategy(group.group_type)!.icon" :size="14" />
            <span>{{ groupStrategy(group.group_type)!.hint }}<template v-if="group.pinnable">{{ group.fixed ? tr('当前已固定为 {0}。', { 0: group.fixed }) : tr('点选节点可固定使用。') }}</template></span>
          </p>
          <div v-if="group.info?.length" class="group-quota small" data-testid="group-info">
            <div
              v-if="quotaOf(group.info).usage"
              class="group-quota-usage"
              :title="quotaOf(group.info).usage!.source"
              data-testid="group-quota-usage"
            >
              <div
                class="usage-bar"
                role="progressbar"
                aria-valuemin="0"
                aria-valuemax="100"
                :aria-valuenow="Math.round(quotaOf(group.info).usage!.percent)"
                :aria-label="tr('订阅流量用量')"
              >
                <span
                  :style="{ width: `${quotaOf(group.info).usage!.percent > 0 ? Math.max(quotaOf(group.info).usage!.percent, 1.5) : 0}%` }"
                  :class="{
                    danger: quotaOf(group.info).usage!.percent >= 98,
                    warn: quotaOf(group.info).usage!.percent > 85 && quotaOf(group.info).usage!.percent < 98,
                  }"
                />
              </div>
              <span class="group-quota-figure mono">{{ quotaOf(group.info).usage!.used }} / {{ quotaOf(group.info).usage!.total }}</span>
              <span class="group-quota-pct mono">{{ percentText(quotaOf(group.info).usage!.percent) }}</span>
            </div>
            <div v-if="quotaTagCount(quotaOf(group.info))" class="group-quota-tags">
              <span v-if="quotaOf(group.info).remaining" class="group-info-item" :title="quotaOf(group.info).remaining!.source">{{ tr('剩余 {0}', { 0: quotaOf(group.info).remaining!.value }) }}</span>
              <span v-if="quotaOf(group.info).expire" class="group-info-item" :title="quotaOf(group.info).expire!.source">{{ tr('到期 {0}', { 0: quotaOf(group.info).expire!.value }) }}</span>
              <span v-if="quotaOf(group.info).resetDays" class="group-info-item" :title="quotaOf(group.info).resetDays!.source">{{ resetText(quotaOf(group.info).resetDays!.value) }}</span>
              <span v-for="(text, textIndex) in quotaOf(group.info).others" :key="`${textIndex}:${text}`" class="group-info-item" :title="text">{{ text }}</span>
            </div>
          </div>
        </template>
        <template #default="{ nodes: visibleNodes }">
          <div
            v-if="!group.nodes.length && group.hiddenFailedCount"
            class="group-empty-filter small muted"
            data-testid="group-hidden-failed"
          >
            <span>{{ tr('当前已开启「隐藏超时」，已隐藏该组全部 {0} 个超时节点。', { 0: group.hiddenFailedCount }) }}</span>
            <button
              type="button"
              class="btn ghost sm"
              data-testid="show-failed-nodes"
              @click="hideFailed = false"
            >{{ tr('显示超时节点') }}</button>
          </div>
          <p v-else-if="!group.nodes.length" class="muted small">
            {{ hasSearchOrTag ? tr('没有匹配的节点') : snap.kernel_running ? tr('该组暂时没有可用节点，请检查资源页中的订阅源状态。') : tr('连接后加载订阅源节点。') }}
          </p>
          <div
            v-for="node in visibleNodes"
            :key="node.name"
            class="node"
            :class="{
              selected: node.selected,
              locked: !canPickNode(group),
              located: locatedNodeKey === `${group.name}::${node.name}`,
              'failed-node': nodeState(node).failed,
            }"
            :data-node="node.name"
            @contextmenu.prevent="openNodeContextMenu($event, group, node)"
          >
            <button
              type="button"
              class="node-select"
              :tabindex="canPickNode(group) ? undefined : -1"
              :aria-disabled="canPickNode(group) ? undefined : 'true'"
              :aria-pressed="canPickNode(group) ? node.selected : undefined"
              :title="nodeTitle(group)"
              :data-testid="`node-select-${node.name}`"
              @click="pick(group, node)"
              @keydown.enter.prevent="pick(group, node)"
              @keydown.space.prevent="pick(group, node)"
            >
              <span class="node-name" :title="dense && autoOf(node) && viaOf(node) ? `${node.name} → ${viaOf(node)}` : node.name">
                <Icon v-if="node.selected" name="check" :size="13" :stroke="2.8" class="node-check" />
                <span
                  v-if="groupStrategy(group.group_type)?.ordered"
                  class="node-rank mono"
                  :title="tr('优先级 {0}', { 0: rankOf(group, node) })"
                  data-testid="node-rank"
                >{{ rankOf(group, node) }}</span>
                <span v-if="nameParts(node.name).prefix.length" class="node-prefix"><template v-for="(part, partIndex) in nameParts(node.name).prefix" :key="partIndex"><mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template></template></span>
                <template v-for="(part, partIndex) in nameParts(node.name).rest" :key="`r${partIndex}`">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
                <!-- 紧凑 has no meta line, so an auto entry or chained node keeps its target beside the name. -->
                <span v-if="dense && autoOf(node) && viaOf(node)" class="node-via-inline">→ {{ viaOf(node) }}</span>
                <span v-else-if="dense && node.dialer_proxy" class="node-via-inline">{{ tr('经') }} {{ node.dialer_proxy }}</span>
              </span>
              <!-- An auto group entry says how it picks and where it currently points (R14). -->
              <span v-if="!dense && autoOf(node)" class="node-meta node-via" data-testid="node-via">
                <span class="node-type strategy">{{ groupTypeLabel(autoOf(node)!) }}</span>
                <span class="node-via-target" :title="viaOf(node) || undefined">{{ viaOf(node) ? `→ ${viaOf(node)}` : snap.kernel_running ? tr('→ 等待测速') : tr('→ 连接后显示') }}</span>
              </span>
              <span v-else-if="!dense" class="node-meta" :title="metaTitle(node) || undefined" data-testid="node-meta">
                <span class="node-type">{{ protocolLabel(node.node_type) || ' ' }}</span>
                <span
                  v-for="tag in node.tags"
                  :key="tag"
                  class="node-tag"
                  :class="{ udp: tag === 'UDP', chained: tag === 'chained' }"
                >{{ tag === 'chained' ? (node.dialer_proxy ? tr('链式 · {0}', { 0: node.dialer_proxy }) : tr('链式')) : tag }}</span>
              </span>
            </button>
            <button
              v-if="autoOf(node) && !autoOf(node)!.hidden"
              type="button"
              class="icon-btn sm node-open-auto"
              :aria-label="tr('查看{0}组 {1}', { 0: groupTypeLabel(autoOf(node)!), 1: node.name })"
              :title="tr('查看「{0}」的{1}策略与成员', { 0: node.name, 1: groupTypeLabel(autoOf(node)!) })"
              :data-testid="`open-auto-${node.name}`"
              @click="openAuto(node.name)"
            >
              <Icon name="chevron-right" :size="14" />
            </button>
            <button
              type="button"
              class="delay"
              :class="[nodeTone(node), { busy: store.pendingTests.value.has(node.name), untested: !nodeDelay(node) }]"
              :aria-label="tr('测速 {0}', { 0: node.name })"
              :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
              :disabled="!snap.kernel_running || store.testing.value"
              :aria-busy="store.pendingTests.value.has(node.name) || undefined"
              :title="snap.kernel_running ? tr('测试延迟') : tr('连接后才能测速')"
              :data-testid="`test-node-${node.name}`"
              @click="store.testNode(node.name)"
            >
              <template v-if="store.pendingTests.value.has(node.name)"><span class="spinner xs" /><span class="sr-only">{{ tr('测速中') }}</span></template>
              <template v-else-if="nodeDelay(node)">{{ nodeDelay(node) }}</template>
              <Icon v-else name="zap" :size="13" class="delay-zap" />
            </button>
          </div>
        </template>
      </ProxyNodeGrid>
    </section>

    <ContextMenu
      :open="Boolean(ctxMenu)"
      :x="ctxMenu?.x ?? 0"
      :y="ctxMenu?.y ?? 0"
      :items="ctxMenu?.items ?? []"
      :label="tr('节点操作')"
      @select="onNodeContextSelect"
      @close="ctxMenu = null"
    />
  </div>
</template>

<style scoped>
.filter-drawer-toggle {
  gap: 5px;
  height: 36px;
  padding: 0 11px;
  color: var(--text-2);
  font-size: var(--text-sm);
  font-weight: 560;
}

.filter-drawer-toggle.active {
  background: var(--accent-soft);
  color: var(--accent-ink);
  border-color: color-mix(in srgb, var(--accent) 30%, transparent);
}

.filter-toggle-chevron {
  opacity: 0.7;
  transition: transform var(--dur-fast) var(--ease);
}

.filter-toggle-chevron.open {
  transform: rotate(180deg);
}

.proxy-active-filter-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 30px;
  padding: 0 9px 0 11px;
  font-size: var(--text-xs);
  flex: none;
}

.proxy-filter-drawer {
  flex: 1 1 100%;
  order: 4;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding-top: 6px;
  margin-top: 2px;
  border-top: 1px solid var(--border);
}

.proxy-quick-filters,
.proxy-group-nav-row {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.proxy-quick-filters {
  overflow-x: auto;
  scrollbar-width: none;
  padding: 1px 0;
}

.proxy-quick-filters::-webkit-scrollbar {
  display: none;
}

.proxy-group-nav-row .group-pills {
  flex: 1 1 auto;
  min-width: 0;
  order: 0;
  margin: 0;
  padding: 1px 0;
}

.drawer-row-label {
  flex: none;
  font-size: var(--text-xs);
  font-weight: 580;
  color: var(--text-3);
  padding-right: 2px;
  user-select: none;
}

.drawer-close-btn {
  flex: none;
  margin-left: auto;
  width: 26px;
  height: 26px;
  color: var(--text-3);
}

.drawer-close-btn:hover {
  color: var(--text);
  background: var(--hover);
}

.proxy-quick-chip {
  display: inline-flex;
  align-items: center;
  height: 27px;
  padding: 0 10px;
  font-size: var(--text-xs);
  gap: 5px;
  flex: none;
}

.proxy-quick-chip:focus-visible,
.proxy-quick-reset:focus-visible,
.proxy-active-filter-pill:focus-visible {
  outline: 2px solid var(--accent-ring);
  outline-offset: 2px;
}

.proxy-quick-count {
  font-size: 11px;
  opacity: 0.72;
}

.proxy-quick-reset {
  flex: none;
  height: 27px;
  padding: 0 9px;
  font-size: var(--text-xs);
}

@media (prefers-reduced-motion: reduce) {
  .proxy-quick-chip,
  .proxy-quick-reset,
  .filter-toggle-chevron {
    transition: none;
  }
}
</style>
