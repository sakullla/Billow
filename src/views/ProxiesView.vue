<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import GroupIcon from '../components/GroupIcon.vue'
import ProxyNodeGrid from '../components/ProxyNodeGrid.vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import { delayText, delayTone, formatRelative, groupStrategy, groupTypeLabel, isInfoNode, protocolLabel, resolveChain } from '../lib/format'
import { useStore } from '../lib/store'
import type { Mode, NodeGroup, NodeItem } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const grids = new Map<string, InstanceType<typeof ProxyNodeGrid>>()
const snap = computed(() => store.snapshot.value)
const catalog = computed(() => snap.value.node_catalog)
const mode = computed(() => snap.value.mode)
const busyKeys = computed(() => Object.keys(store.busy).join('\0'))

type Sort = 'default' | 'delay' | 'name'
const SORTS: { id: Sort; label: string }[] = [
  { id: 'default', label: '默认' },
  { id: 'delay', label: '延迟' },
  { id: 'name', label: '名称' },
]
const MODES: { id: Mode; label: string }[] = [
  { id: 'rule', label: '规则' },
  { id: 'global', label: '全局' },
  { id: 'direct', label: '直连' },
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
/** Open group headers stick under the toolbar; its height can change when options open. */
const toolbarHeight = ref(0)
let toolbarObserver: ResizeObserver | null = null
const sort = ref<Sort>(readPref('proxy-sort', 'default'))
const dense = ref<boolean>(readPref('proxy-dense', false))
/**
 * Auto groups (url-test, fallback, load-balance) are picked by the kernel and cannot be
 * switched by hand, so the page leaves them out by default; their current pick already
 * shows as an entry inside the manual groups. A deep link can still reveal one, and a
 * config with no manual group falls back to listing them (R13).
 */
const revealedAuto = ref<Set<string>>(new Set())
const hasManualGroups = computed(() => catalog.value.some((group) => group.kind !== 'auto'))
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

const hiddenAutoCount = computed(() => catalog.value.filter((group) => autoHidden(group)).length)
/** Read once at setup so the first paint already has the right groups expanded (R26). */
const storedOpen = readOpen()
const open = ref<Set<string>>(storedOpen ?? defaultOpen())
// Only seed storage when there is a real default group; an empty catalog must not
// be remembered as the user's "everything collapsed" choice (R26).
if (!storedOpen && open.value.size > 0) persistOpen()

watch(sort, (value) => writePref('proxy-sort', value))
watch(dense, (value) => writePref('proxy-dense', value))

const needle = computed(() => query.value.trim().toLowerCase())

type ViewGroup = NodeGroup & { info?: NodeItem[] }

/** Info text without the provider's leading 【tag】 prefix. */
function infoText(name: string): string {
  return name.replace(/^\s*[【\[][^】\]]*[】\]]\s*/, '').trim() || name
}

function manifest(): NodeGroup[] {
  return snap.value.node_catalog
}

/** The group a first visit opens: the selected manual group, else the first manual one (R26). */
function currentManualGroup(): NodeGroup | null {
  const manual = snap.value.node_catalog.filter((group) => group.kind === 'manual')
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

/** Search matches the name, or exactly a protocol/tag ("udp", "reality", "vless"). */
function matches(node: NodeItem): boolean {
  if (node.name.toLowerCase().includes(needle.value)) return true
  const labels = [node.node_type, protocolLabel(node.node_type), ...node.tags].map((label) => label.toLowerCase())
  return labels.includes(needle.value)
}

/** Full protocol and tag list for the tooltip; rows may clip the tail. */
function metaTitle(node: NodeItem): string {
  return [protocolLabel(node.node_type), ...node.tags].filter(Boolean).join(' · ')
}

function sorted(nodes: NodeItem[]): NodeItem[] {
  if (sort.value === 'default') return nodes
  const list = nodes.map((node, index) => ({ node, index }))
  if (sort.value === 'name') list.sort((a, b) => a.node.name.localeCompare(b.node.name, 'zh-CN') || a.index - b.index)
  if (sort.value === 'delay') {
    const key = (node: NodeItem) => (node.failed ? 2e9 : node.delay_ms == null ? 1e9 : node.delay_ms)
    list.sort((a, b) => key(a.node) - key(b.node) || a.index - b.index)
  }
  return list.map((item) => item.node)
}

const groups = computed(() => {
  const source = mode.value === 'global'
    ? catalog.value
    : catalog.value.filter((group) => group.name !== 'GLOBAL')
  return source
    .filter((group) => !autoHidden(group))
    .map((group): ViewGroup => {
      let nodes = sorted(needle.value ? group.nodes.filter(matches) : group.nodes)
      // Quota/expiry pseudo-nodes leave the grid unless selected or searched for (R11).
      const info = needle.value ? [] : nodes.filter((node) => !node.selected && isInfoNode(node.name))
      if (info.length) nodes = nodes.filter((node) => !info.includes(node))
      if (nodes === group.nodes) return group
      return info.length ? { ...group, nodes, info } : { ...group, nodes }
    })
    .filter((group) => !needle.value || group.nodes.length > 0 || group.name.toLowerCase().includes(needle.value))
})

const matchCount = computed(() =>
  needle.value ? groups.value.reduce((total, group) => total + group.nodes.length, 0) : 0,
)

/** Groups share nodes, so the page total counts distinct names instead of row copies. */
const distinctNodeCount = computed(() => {
  const seen = new Set<string>()
  catalog.value.forEach((group) => group.nodes.forEach((node) => seen.add(node.name)))
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

function groupNowNode(group: NodeGroup): NodeItem | undefined {
  return group.nodes.find((node) => node.name === group.now)
}

function groupNowDelay(group: NodeGroup): string {
  const node = groupNowNode(group)
  if (!node) return ''
  const state = nodeState(node)
  return delayText(state.delay, state.failed)
}

function groupNowTone(group: NodeGroup): string {
  const node = groupNowNode(group)
  if (!node) return 'none'
  const state = nodeState(node)
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

const groupNamesSet = computed(() => new Set(catalog.value.map((group) => group.name)))

function groupHealthText(group: NodeGroup): string {
  let tested = 0
  let ok = 0
  for (const node of group.nodes) {
    if (groupNamesSet.value.has(node.name)) continue
    const state = nodeState(node)
    if (state.failed) {
      tested += 1
    } else if (state.delay != null) {
      tested += 1
      ok += 1
    }
  }
  if (!tested) return ''
  return `可用 ${ok}/${tested}`
}

interface HighlightPart {
  text: string
  hit: boolean
}

function highlight(name: string): HighlightPart[] {
  const text = needle.value
  if (!text) return [{ text: name, hit: false }]
  const lower = name.toLowerCase()
  const parts: HighlightPart[] = []
  let index = 0
  let found = lower.indexOf(text)
  while (found >= 0) {
    if (found > index) parts.push({ text: name.slice(index, found), hit: false })
    parts.push({ text: name.slice(found, found + text.length), hit: true })
    index = found + text.length
    found = lower.indexOf(text, index)
  }
  if (index < name.length) parts.push({ text: name.slice(index), hit: false })
  return parts.length ? parts : [{ text: name, hit: false }]
}

function pick(group: NodeGroup, node: NodeItem) {
  if (group.kind !== 'manual' || node.selected) return
  void store.selectNode(group.name, node.name)
}

function isOpen(name: string) {
  return needle.value.length > 0 || open.value.has(name)
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
  // A search could hide the group or its nodes; the deep link wins.
  if (query.value) query.value = ''
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
      return
    }
    // Only a first visit scrolls to the default group; a saved state stays where the user left it.
    // When that group already leads the list, scrolling would only hide the page head and its
    // 全部测速 action, so the page stays at the top.
    const fallback = currentManualGroup()?.name ?? null
    if (!storedOpen && fallback && groups.value[0]?.name !== fallback) await scrollToGroup(fallback)
  })()
})

watch(() => store.focusGroup.value, (name) => void locate(name, 'smooth'))

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

/** Phones list one node per row and offer a two-column grid as the dense view; desktop is the reverse. */
/** A pressed toggle keeps one stable name; aria-pressed carries the on/off state (R3). */
const denseLabel = computed(() => (props.compact ? '双列视图' : '紧凑视图'))
const denseIcon = computed(() => (props.compact ? 'grid' : 'list'))

const optionsActive = computed(() => sort.value !== 'default' || dense.value)
</script>

<template>
  <div class="page proxies" :style="{ '--toolbar-h': `${toolbarHeight}px` }">
    <header class="page-head">
      <div>
        <h1>代理</h1>
        <p class="muted small" :title="hiddenAutoCount ? `另有 ${hiddenAutoCount} 个自动组由内核择优，未单独列出` : undefined">
          <template v-if="snap.node_catalog.length">{{ snap.node_catalog.length - hiddenAutoCount }} 个代理组 · {{ distinctNodeCount }} 个节点</template>
          <template v-else>{{ snap.nodes_notice ?? '没有代理组' }}</template>
        </p>
      </div>
      <div class="head-actions">
        <Segmented
          v-if="snap.active_id && !compact"
          :model-value="snap.mode"
          :options="MODES"
          size="sm"
          label="出站模式"
          :disabled="store.busy.mode"
          @update:model-value="store.setMode"
        />
        <span
          v-if="store.busy.testAll && store.testProgress.value.total > 0"
          class="test-progress small mono"
          data-testid="test-progress"
          aria-live="polite"
        >已测 {{ store.testProgress.value.tested }}/{{ store.testProgress.value.total }}</span>
        <span
          v-if="!snap.kernel_running && snap.node_catalog.length"
          id="proxy-test-hint"
          class="test-hint sr-only"
          data-testid="test-hint"
        >
          连接后可测速
        </span>
        <!-- Without groups there is nothing to test; the empty state below owns the next step. -->
        <button
          v-if="snap.node_catalog.length"
          type="button"
          class="btn primary sm"
          :disabled="store.testing.value || !snap.kernel_running"
          :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
          :title="snap.kernel_running ? '测试全部节点延迟' : '连接后才能测速'"
          data-testid="test-all"
          @click="store.testAll()"
        >
          <span v-if="store.busy.testAll" class="spinner sm" />
          <Icon v-else name="zap" :size="15" />
          {{ compact ? '测速' : '全部测速' }}
        </button>
      </div>
    </header>

    <div
      v-if="!snap.kernel_running && snap.node_catalog.length"
      class="proxies-connect-bar"
      data-testid="proxies-connect-bar"
    >
      <span class="proxies-connect-text small">
        <span class="proxies-connect-dot" aria-hidden="true" />
        当前未连接，连接后即可测速与实时生效
      </span>
      <button
        type="button"
        class="btn primary sm"
        :disabled="store.connecting.value"
        data-testid="proxies-connect"
        @click="store.connect()"
      >
        <span v-if="store.connecting.value" class="spinner xs" />
        <Icon v-else name="power" :size="14" />
        {{ store.connecting.value ? '连接中' : '立即连接' }}
      </button>
    </div>

    <div v-if="snap.node_catalog.length" ref="toolbarEl" class="toolbar proxies-toolbar" data-testid="proxy-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索节点、协议或 UDP 等标签" data-testid="node-search" data-page-search />
        <button v-if="query" type="button" class="icon-btn sm" aria-label="清空搜索" data-testid="clear-search" @click="query = ''">
          <Icon name="x" :size="14" />
        </button>
      </div>
      <button
        v-if="compact"
        type="button"
        class="icon-btn options-btn"
        :class="{ active: optionsOpen, marked: optionsActive && !optionsOpen }"
        :aria-expanded="optionsOpen"
        aria-controls="proxy-options"
        aria-label="排序与视图"
        title="排序与视图"
        data-testid="toggle-options"
        @click="optionsOpen = !optionsOpen"
      >
        <Icon name="sliders" />
      </button>
      <span v-if="needle && matchCount > 0" class="toolbar-count small" data-testid="match-count" aria-live="polite">
        匹配 {{ matchCount }} 个节点
      </span>
      <div v-if="showOptions" id="proxy-options" class="toolbar-options">
        <Segmented v-model="sort" :options="SORTS" size="sm" label="排序" />
        <!-- Every view control carries a short text label; phones lay them out as equal chips (R3, R12). Auto groups need no toggle (R13). -->
        <button
          type="button"
          class="btn ghost sm tool-btn"
          :disabled="!canLocateActive"
          aria-label="定位当前选中节点"
          :title="canLocateActive ? '定位当前选中节点' : '当前没有已选中的节点'"
          data-testid="locate-active-node"
          @click="locateActiveNode"
        >
          <Icon name="locate" :size="15" />
          <span class="tool-btn-label">定位</span>
        </button>
        <button
          type="button"
          class="btn ghost sm tool-btn"
          :class="{ active: dense }"
          :aria-pressed="dense"
          :aria-label="denseLabel"
          :title="denseLabel"
          data-testid="toggle-dense"
          @click="dense = !dense"
        >
          <Icon :name="denseIcon" :size="15" />
          <span class="tool-btn-label">{{ compact ? '双列' : '紧凑' }}</span>
        </button>
        <button type="button" class="btn ghost sm tool-btn" data-testid="toggle-all" @click="toggleAll">
          <Icon name="chevron-down" :size="15" :class="{ 'icon-flip': allExpanded }" />
          <span class="tool-btn-label">{{ allExpanded ? '收起全部' : '展开全部' }}</span>
        </button>
      </div>

      <nav
        v-if="groups.length > 2 && !needle"
        class="group-pills"
        aria-label="代理组快速跳转"
        data-testid="group-jump-bar"
      >
        <button
          v-for="group in groups"
          :key="group.name"
          type="button"
          class="group-pill"
          :class="{ open: isOpen(group.name), focused: store.focusGroup.value === group.name }"
          :data-testid="`jump-group-${group.name}`"
          @click="jumpToGroup(group.name)"
        >
          <span class="group-pill-name">{{ group.name }}</span>
          <span class="group-pill-count mono">{{ group.nodes.length }}</span>
        </button>
      </nav>
    </div>

    <div v-if="!snap.node_catalog.length" class="empty">
      <Icon name="globe" :size="40" :stroke="1.4" />
      <h3>{{ snap.nodes_notice ?? '没有代理组' }}</h3>
      <p class="muted">添加并启用一份配置后，这里会列出它的代理组与节点。</p>
      <button type="button" class="btn primary" @click="store.go('profiles')">前往配置</button>
    </div>
    <div v-else-if="!groups.length" class="empty small" data-testid="no-match">
      <h3>没有匹配的节点</h3>
      <button type="button" class="btn ghost" @click="query = ''">清空搜索</button>
    </div>

    <section
      v-for="(group, index) in groups"
      :key="group.name"
      v-memo="[group, autoNowKey, isOpen(group.name), dense, needle, store.focusGroup.value, locatedNodeKey, snap.kernel_running, store.testProgress.value, store.testResults.value, store.activeTest.value, store.pendingTests.value.size, groupTestedAt(group), busyKeys]"
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
          <GroupIcon :icon="group.icon" :type="group.group_type" :size="24" />
          <span class="group-title">
            <span class="group-name">
              <strong>{{ group.name }}</strong>
              <span class="tag">{{ groupTypeLabel(group) }}</span>
              <span class="muted small group-count">{{ group.nodes.length }} 个</span>
              <span v-if="groupHealthText(group)" class="group-health muted small">{{ groupHealthText(group) }}</span>
            </span>
            <span class="group-now small">
              <Icon v-if="group.kind === 'auto'" name="cpu" :size="13" />
              <span class="group-now-name">{{ group.now || (group.kind === 'auto' ? '连接后显示' : '—') }}</span>
              <span v-if="groupNowDelay(group)" class="group-delay mono" :class="groupNowTone(group)">{{ groupNowDelay(group) }}</span>
              <span v-if="store.activeTest.value?.group === group.name" class="small mono" data-testid="group-test-progress" aria-live="polite">已测 {{ store.testProgress.value.tested }}/{{ store.testProgress.value.total }}</span>
              <span v-else-if="groupTestedAt(group)" class="group-tested">测速 {{ formatRelative(groupTestedAt(group)!) }}</span>
            </span>
          </span>
          <Icon name="chevron-down" class="chevron" />
        </button>
        <button
          type="button"
          class="icon-btn group-test"
          :aria-label="`测速 ${group.name}`"
          :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
          :title="snap.kernel_running ? '测试该组延迟' : '连接后才能测速'"
          :disabled="!snap.kernel_running || store.testing.value"
          :aria-busy="store.activeTest.value?.group === group.name || undefined"
          :data-testid="`test-group-${group.name}`"
          @click="store.testGroup(group.name)"
        >
          <span v-if="store.busy[`test:${group.name}`]" class="spinner sm" />
          <Icon v-else name="zap" />
        </button>
      </header>

      <ProxyNodeGrid
        v-if="isOpen(group.name)"
        :id="`group-nodes-${index}`"
        :ref="(el) => { if (el) grids.set(group.name, el as InstanceType<typeof ProxyNodeGrid>); else grids.delete(group.name) }"
        :nodes="group.nodes"
        :dense="dense"
        :compact="compact"
      >
        <template v-if="groupStrategy(group.group_type) || group.info?.length" #header>
          <p v-if="groupStrategy(group.group_type)" class="group-strategy small" data-testid="group-strategy">
            <Icon :name="groupStrategy(group.group_type)!.icon" :size="14" />
            <span>{{ groupStrategy(group.group_type)!.hint }}</span>
          </p>
          <p v-if="group.info?.length" class="group-info small" data-testid="group-info">
            <Icon name="info" :size="13" />
            <span v-for="item in group.info" :key="item.name" class="group-info-item" :title="item.name">{{ infoText(item.name) }}</span>
          </p>
        </template>
        <template #default="{ nodes: visibleNodes }">
          <p v-if="!group.nodes.length" class="muted small">
            {{ needle ? '没有匹配的节点' : snap.kernel_running ? '该组暂时没有可用节点，请检查资源页中的订阅源状态。' : '连接后加载订阅源节点。' }}
          </p>
          <div
            v-for="node in visibleNodes"
            :key="node.name"
            class="node"
            :class="{
              selected: node.selected,
              locked: group.kind !== 'manual',
              located: locatedNodeKey === `${group.name}::${node.name}`,
              'failed-node': nodeState(node).failed,
            }"
            :data-node="node.name"
          >
            <button
              type="button"
              class="node-select"
              :tabindex="group.kind === 'manual' ? undefined : -1"
              :aria-disabled="group.kind === 'manual' ? undefined : 'true'"
              :aria-pressed="group.kind === 'manual' ? node.selected : undefined"
              :title="group.kind === 'manual' ? undefined : `${groupTypeLabel(group)}组由内核自动择优，不可手动切换`"
              :data-testid="`node-select-${node.name}`"
              @click="pick(group, node)"
              @keydown.enter.prevent="pick(group, node)"
              @keydown.space.prevent="pick(group, node)"
            >
              <span class="node-name" :title="node.name">
                <span
                  v-if="groupStrategy(group.group_type)?.ordered"
                  class="node-rank mono"
                  :title="`优先级 ${rankOf(group, node)}`"
                  data-testid="node-rank"
                >{{ rankOf(group, node) }}</span>
                <template v-for="(part, partIndex) in highlight(node.name)" :key="partIndex">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <!-- An auto group entry says how it picks and where it currently points (R14). -->
              <span v-if="!dense && autoOf(node)" class="node-meta node-via" data-testid="node-via">
                <span class="node-type strategy">{{ groupTypeLabel(autoOf(node)!) }}</span>
                <span class="node-via-target" :title="viaOf(node) || undefined">{{ viaOf(node) ? `→ ${viaOf(node)}` : snap.kernel_running ? '→ 等待测速' : '→ 连接后显示' }}</span>
              </span>
              <span v-else-if="!dense" class="node-meta" :title="metaTitle(node) || undefined" data-testid="node-meta">
                <span class="node-type">{{ protocolLabel(node.node_type) || ' ' }}</span>
                <span v-for="tag in node.tags" :key="tag" class="node-tag" :class="{ udp: tag === 'UDP' }">{{ tag }}</span>
              </span>
            </button>
            <button
              v-if="autoOf(node)"
              type="button"
              class="icon-btn sm node-open-auto"
              :aria-label="`查看${groupTypeLabel(autoOf(node)!)}组 ${node.name}`"
              :title="`查看「${node.name}」的${groupTypeLabel(autoOf(node)!)}策略与成员`"
              :data-testid="`open-auto-${node.name}`"
              @click="openAuto(node.name)"
            >
              <Icon name="chevron-right" :size="14" />
            </button>
            <button
              type="button"
              class="delay"
              :class="[nodeTone(node), { busy: store.pendingTests.value.has(node.name), untested: !nodeDelay(node) }]"
              :aria-label="`测速 ${node.name}`"
              :aria-describedby="snap.kernel_running ? undefined : 'proxy-test-hint'"
              :disabled="!snap.kernel_running || store.testing.value"
              :aria-busy="store.pendingTests.value.has(node.name) || undefined"
              :title="snap.kernel_running ? '测试延迟' : '连接后才能测速'"
              :data-testid="`test-node-${node.name}`"
              @click="store.testNode(node.name)"
            >
              <template v-if="store.pendingTests.value.has(node.name)"><span class="spinner xs" /><span class="small">测速中</span></template>
              <template v-else-if="nodeDelay(node)">{{ nodeDelay(node) }}</template>
              <Icon v-else name="zap" :size="13" />
            </button>
            <Icon v-if="node.selected" name="check" :size="14" class="node-check" :stroke="2.6" />
          </div>
        </template>
      </ProxyNodeGrid>
    </section>
  </div>
</template>
