<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Menu, { type MenuItem } from '../components/Menu.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import { formatClock } from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import type { LogLevel, LogLine } from '../lib/types'
import { useDynamicVirtualList } from '../lib/ui/dynamicVirtual'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type Filter = 'all' | 'issues' | LogLevel
interface LogEntry {
  line: LogLine
  key: string
}
interface ExtractedLogTarget {
  target: string
  port: number | null
}

const FILTERS: { id: Filter; label: string; shortLabel: string }[] = [
  { id: 'all', get label() { return tr('全部') }, get shortLabel() { return tr('全部') } },
  { id: 'issues', get label() { return tr('异常') }, get shortLabel() { return tr('异常') } },
  { id: 'debug', get label() { return tr('调试') }, get shortLabel() { return 'DBG' } },
  { id: 'info', get label() { return tr('信息') }, get shortLabel() { return 'INF' } },
  { id: 'warning', get label() { return tr('警告') }, get shortLabel() { return 'WRN' } },
  { id: 'error', get label() { return tr('错误') }, get shortLabel() { return 'ERR' } },
]
const LABEL: Record<LogLevel, string> = { debug: 'DBG', info: 'INF', warning: 'WRN', error: 'ERR' }

const FILE_EXT_RE = /\.(?:ya?ml|json|mrs|dat|mmdb|metadb|txt|log|exe|dll|so|dylib|js|mjs|cjs|ts|css|html?|pem|key|crt|db|sqlite|zip|gz|tar|apk)$/i
const BRACKET_IPV6_RE = /\[([0-9a-fA-F:]*:[0-9a-fA-F:]+)\](?::(\d{1,5}))?/
const URL_HOST_RE = /https?:\/\/(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::(\d{1,5}))?/i
const IPV4_RE = /\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?::(\d{1,5}))?\b/
const DOMAIN_RE = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})(?::(\d{1,5}))?\b/g
const BARE_IPV6_RE = /\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{0,4}:){2,6}:[0-9a-fA-F]{0,4})\b/

function parsePort(raw?: string): number | null {
  if (!raw) return null
  const num = Number(raw)
  return Number.isInteger(num) && num >= 1 && num <= 65535 ? num : null
}

function extractFromSegment(segment: string): ExtractedLogTarget | null {
  const urlMatch = URL_HOST_RE.exec(segment)
  if (urlMatch?.[1]) {
    const rawHost = urlMatch[1].replace(/^\[|\]$/g, '')
    if (rawHost && !FILE_EXT_RE.test(rawHost)) {
      return { target: rawHost, port: parsePort(urlMatch[2]) }
    }
  }

  const ipv6Bracket = BRACKET_IPV6_RE.exec(segment)
  if (ipv6Bracket?.[1]) {
    return { target: ipv6Bracket[1], port: parsePort(ipv6Bracket[2]) }
  }

  const ipv4Match = IPV4_RE.exec(segment)
  const ipv4Index = ipv4Match?.index ?? Number.POSITIVE_INFINITY

  DOMAIN_RE.lastIndex = 0
  let domainMatch: RegExpExecArray | null = null
  let domainIndex = Number.POSITIVE_INFINITY
  for (let hit = DOMAIN_RE.exec(segment); hit; hit = DOMAIN_RE.exec(segment)) {
    const candidate = hit[1] ?? ''
    if (!candidate || FILE_EXT_RE.test(candidate)) continue
    domainMatch = hit
    domainIndex = hit.index
    break
  }

  if (domainMatch && domainIndex < ipv4Index) {
    return { target: domainMatch[1]!, port: parsePort(domainMatch[2]) }
  }
  if (ipv4Match?.[1]) {
    return { target: ipv4Match[1], port: parsePort(ipv4Match[2]) }
  }
  if (domainMatch?.[1]) {
    return { target: domainMatch[1], port: parsePort(domainMatch[2]) }
  }

  const bareV6 = BARE_IPV6_RE.exec(segment)
  if (bareV6?.[1] && (bareV6[1].includes('::') || /[a-fA-F]/.test(bareV6[1]) || bareV6[1].split(':').length >= 4)) {
    return { target: bareV6[1], port: null }
  }
  return null
}

/** Extract the first likely destination domain or IP (with optional port) from a log message. */
function extractLogTarget(message: string): ExtractedLogTarget | null {
  if (!message) return null
  const arrow = message.indexOf('-->')
  if (arrow >= 0) {
    const dst = extractFromSegment(message.slice(arrow + 3))
    if (dst) return dst
  }
  const shortArrow = message.indexOf('->')
  if (shortArrow >= 0 && shortArrow !== arrow + 1) {
    const dst = extractFromSegment(message.slice(shortArrow + 2))
    if (dst) return dst
  }
  return extractFromSegment(message)
}

const filter = ref<Filter>('all')
const query = ref('')
const paused = ref(false)
const pausedAt = ref<number | null>(null)
const frozen = shallowRef<LogLine[]>([])
const wrap = ref(true)
const follow = ref(true)
const confirmClear = ref(false)
const scroller = ref<HTMLElement | null>(null)
const rowMenuKey = ref<string | null>(null)

const lineKey = (line: LogLine) => `${line.time_ms}|${line.level}|${line.message}`

/** Pausing freezes the list and every count, while the store keeps buffering (R28). */
const source = computed(() => (paused.value ? frozen.value : snap.value.logs))

const needle = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))
const isFiltered = computed(() => Boolean(needle.value) || filter.value !== 'all')

function highlight(value: string) {
  return highlightTokens(value, query.value)
}

function matchesLevelFilter(level: LogLevel): boolean {
  if (filter.value === 'all') return true
  if (filter.value === 'issues') return level === 'warning' || level === 'error'
  return level === filter.value
}

/**
 * Filtered rows keep a content-stable key (`time|level|message` plus an
 * occurrence counter for duplicate lines). Trimming the front of the capped
 * buffer then leaves every surviving key intact, so measured row heights and
 * mounted nodes survive ring-buffer shifts (R3, R31).
 */
const entries = computed<LogEntry[]>(() => {
  const tokens = queryTokens.value
  const seen = new Map<string, number>()
  const result: LogEntry[] = []
  for (const line of source.value) {
    const base = lineKey(line)
    const occurrence = seen.get(base) ?? 0
    seen.set(base, occurrence + 1)
    if (!matchesLevelFilter(line.level)) continue
    if (tokens.length && !matchesTokens(`${line.level} ${LABEL[line.level]} ${line.message}`, tokens)) continue
    result.push({ line, key: `${base}#${occurrence}` })
  }
  return result
})

const lines = computed(() => entries.value.map((entry) => entry.line))
const entryCount = computed(() => entries.value.length)

const virtual = useDynamicVirtualList(entryCount, {
  estimateHeight: 32,
  overscan: 6,
  keyOf: (index) => entries.value[index]?.key ?? index,
})

const visibleEntries = computed(() => {
  const { start, end } = virtual.window.value
  const list = entries.value
  const slice: { entry: LogEntry; index: number }[] = []
  for (let i = start; i < end && i < list.length; i += 1) {
    slice.push({ entry: list[i]!, index: i })
  }
  return slice
})

const rowElByKey = new Map<string, HTMLElement>()
const rowIndexByEl = new WeakMap<Element, number>()
let rowObserver: ResizeObserver | null = null
let containerObserver: ResizeObserver | null = null
let lastScrollerWidth = 0

if (typeof ResizeObserver !== 'undefined') {
  rowObserver = new ResizeObserver((observed) => {
    const el = scroller.value
    for (const item of observed) {
      const idx = rowIndexByEl.get(item.target)
      if (idx === undefined) continue
      const h = item.borderBoxSize?.[0]?.blockSize || item.contentRect.height || (item.target as HTMLElement).offsetHeight
      if (h > 0) virtual.setItemHeight(idx, h, el, { follow: follow.value })
    }
  })
}

function bindRow(key: string, index: number, el: unknown) {
  if (el instanceof HTMLElement) {
    const prev = rowElByKey.get(key)
    if (prev && prev !== el) {
      rowObserver?.unobserve(prev)
      rowIndexByEl.delete(prev)
    }
    rowElByKey.set(key, el)
    rowIndexByEl.set(el, index)
    rowObserver?.observe(el)
    const measured = el.getBoundingClientRect().height || el.offsetHeight
    if (measured > 0) {
      virtual.setItemHeight(index, measured, scroller.value, { follow: follow.value })
    }
  } else {
    const prev = rowElByKey.get(key)
    if (prev) {
      rowObserver?.unobserve(prev)
      rowIndexByEl.delete(prev)
      rowElByKey.delete(key)
    }
  }
}

const counts = computed(() => {
  const totals: Record<LogLevel, number> = { debug: 0, info: 0, warning: 0, error: 0 }
  for (const line of source.value) totals[line.level] += 1
  return totals
})

const issuesCount = computed(() => counts.value.warning + counts.value.error)

function countOfFilter(id: Filter): number {
  if (id === 'all') return source.value.length
  if (id === 'issues') return issuesCount.value
  return counts.value[id]
}

/** Level counts ride on the filter so pausing freezes them too (R28). */
const filterOptions = computed(() =>
  FILTERS.map((option) => ({
    id: option.id,
    label: `${props.compact ? option.shortLabel : option.label} ${countOfFilter(option.id)}`,
  })),
)

const emptyActionReason = computed(() =>
  source.value.length ? tr('当前筛选无匹配日志') : tr('没有日志'),
)
const copyButtonLabel = computed(() =>
  isFiltered.value ? tr('复制筛选 ({0})', { 0: lines.value.length }) : tr('复制'),
)
const exportButtonLabel = computed(() =>
  isFiltered.value ? tr('导出筛选 ({0})', { 0: lines.value.length }) : tr('导出'),
)
const copyButtonTitle = computed(() => {
  if (!lines.value.length) return emptyActionReason.value
  return isFiltered.value
    ? tr('复制当前筛选出的 {0} 行日志', { 0: lines.value.length })
    : tr('复制当前 {0} 行日志', { 0: lines.value.length })
})
const exportButtonTitle = computed(() => {
  if (!lines.value.length) return emptyActionReason.value
  return isFiltered.value
    ? tr('导出当前筛选出的 {0} 行日志', { 0: lines.value.length })
    : tr('导出当前 {0} 行日志', { 0: lines.value.length })
})

/** Phones keep pause in reach and fold the rarer actions into one menu so the head stays one row. */
const moreOpen = ref(false)
const moreItems = computed<MenuItem[]>(() => [
  { id: 'wrap', label: wrap.value ? tr('关闭自动换行') : tr('开启自动换行'), icon: 'list' },
  {
    id: 'copy',
    label: isFiltered.value
      ? tr('复制筛选 ({0})', { 0: lines.value.length })
      : tr('复制 {0} 行', { 0: lines.value.length }),
    icon: 'copy',
    disabled: !lines.value.length,
    reason: emptyActionReason.value,
  },
  {
    id: 'export',
    label: isFiltered.value
      ? tr('导出筛选 ({0})', { 0: lines.value.length })
      : tr('导出日志'),
    icon: 'download',
    disabled: !lines.value.length,
    reason: emptyActionReason.value,
  },
  {
    id: 'clear',
    label: tr('清空日志'),
    icon: 'trash',
    danger: true,
    disabled: !snap.value.logs.length,
    reason: tr('没有日志'),
  },
])
function onMore(item: MenuItem) {
  moreOpen.value = false
  if (item.id === 'wrap') wrap.value = !wrap.value
  else if (item.id === 'copy') void copyFiltered()
  else if (item.id === 'export') void exportLogs()
  else if (item.id === 'clear') confirmClear.value = true
}

/** Lines buffered since the freeze, found from the frozen tail so a capped buffer still counts. */
const newCount = computed(() => {
  if (!paused.value || !pausedAt.value) return 0
  const live = snap.value.logs
  const tail = frozen.value.length ? lineKey(frozen.value[frozen.value.length - 1] as LogLine) : null
  if (tail) {
    const index = live.findIndex((line) => lineKey(line) === tail)
    if (index >= 0) return live.length - index - 1
  }
  return live.filter((line) => line.time_ms > (pausedAt.value ?? 0)).length
})

function pause() {
  frozen.value = snap.value.logs
  pausedAt.value = Date.now()
  paused.value = true
}

function resume() {
  paused.value = false
  pausedAt.value = null
  frozen.value = []
  if (follow.value) void toBottom(true)
}

function togglePause() {
  if (paused.value) resume()
  else pause()
}

function onScroll(event: Event) {
  const el = scroller.value
  if (!el) return
  virtual.onScroll(event)
  follow.value = virtual.isNearBottom(el, 24)
}

async function toBottom(force = false) {
  if (!force && !follow.value) return
  await nextTick()
  const el = scroller.value
  if (el && (force || follow.value)) {
    virtual.scrollToBottom(el)
    await nextTick()
    if (scroller.value === el && (force || follow.value)) {
      virtual.scrollToBottom(el)
    }
  }
  if (force) follow.value = true
}

// The count stays pinned at the 1000-line cap, so a length watcher goes silent
// there. Watching the row list itself re-pins follow-tail after every append or
// trim, while a user-scrolled view is left exactly where it is (R3, R31).
watch(entries, () => {
  if (follow.value) void toBottom()
})
watch(paused, (on) => {
  rowMenuKey.value = null
  if (!on && follow.value) void toBottom()
})
watch([filter, query], () => {
  rowMenuKey.value = null
})
watch(wrap, () => {
  virtual.invalidate(scroller.value, { keepScroll: true })
  if (follow.value) void toBottom()
})

onMounted(() => {
  const el = scroller.value
  if (el) {
    virtual.measure(el)
    lastScrollerWidth = el.clientWidth
    if (typeof ResizeObserver !== 'undefined') {
      containerObserver = new ResizeObserver((observed) => {
        const current = scroller.value
        if (!current) return
        const width = observed[0]?.contentRect.width ?? current.clientWidth
        virtual.measure(current)
        if (lastScrollerWidth > 0 && Math.abs(width - lastScrollerWidth) >= 1) {
          virtual.invalidate(current, { keepScroll: true })
          if (follow.value) void toBottom()
        }
        lastScrollerWidth = width
      })
      containerObserver.observe(el)
    }
  }
  void toBottom(true)
})

onBeforeUnmount(() => {
  rowObserver?.disconnect()
  rowObserver = null
  containerObserver?.disconnect()
  containerObserver = null
  rowElByKey.clear()
})

function textOf(line: LogLine) {
  return `${formatClock(line.time_ms)} [${line.level}] ${line.message}`
}

async function copyLine(line: LogLine) {
  await store.copyText(textOf(line), tr('已复制这行日志'))
}

async function copyFiltered() {
  if (!lines.value.length) return
  const feedback = isFiltered.value
    ? tr('已复制筛选出的 {0} 行日志', { 0: lines.value.length })
    : tr('已复制 {0} 行日志', { 0: lines.value.length })
  await store.copyText(lines.value.map(textOf).join('\n'), feedback)
}

async function exportLogs() {
  if (!lines.value.length) return
  try {
    const path = await store.backend.exportLogs(lines.value.map(textOf).join('\n'))
    const feedback = isFiltered.value
      ? tr('已导出筛选出的 {0} 行日志到 {1}', { 0: lines.value.length, 1: path })
      : tr('已导出到 {0}', { 0: path })
    store.toast(feedback, 'success')
  } catch (err) {
    store.toast(tr('导出失败：{0}', { 0: err instanceof Error ? err.message : String(err) }), 'error')
  }
}

async function clear() {
  confirmClear.value = false
  rowMenuKey.value = null
  const result = await store.clearLogs()
  frozen.value = []
  pausedAt.value = paused.value ? Date.now() : null
  if (result) store.toast(tr('日志已清空'), 'success')
}

function resetFilters() {
  query.value = ''
  filter.value = 'all'
}

function rowMenuItems(line: LogLine): MenuItem[] {
  const extracted = extractLogTarget(line.message)
  const items: MenuItem[] = [
    { id: 'copy', label: tr('复制这行'), icon: 'copy' },
    {
      id: 'level',
      label: filter.value === line.level ? tr('恢复全部级别') : tr('仅看 {0} 级别', { 0: LABEL[line.level] }),
      icon: 'filter',
    },
  ]
  if (extracted) {
    items.push(
      {
        id: 'filter-target',
        label: tr('日志内筛选「{0}」', { 0: extracted.target }),
        icon: 'search',
      },
      {
        id: 'open-connections',
        label: tr('在连接页搜索「{0}」', { 0: extracted.target }),
        icon: 'activity',
      },
      {
        id: 'open-rule-match',
        label: tr('在规则页匹配测试「{0}」', { 0: extracted.target }),
        icon: 'route',
      },
    )
  }
  return items
}

function toggleRowMenu(key: string) {
  rowMenuKey.value = rowMenuKey.value === key ? null : key
}

function onRowAction(item: MenuItem, line: LogLine) {
  rowMenuKey.value = null
  if (item.id === 'copy') {
    void copyLine(line)
    return
  }
  if (item.id === 'level') {
    filter.value = filter.value === line.level ? 'all' : line.level
    return
  }
  const extracted = extractLogTarget(line.message)
  if (!extracted) return
  if (item.id === 'filter-target') {
    query.value = extracted.target
  } else if (item.id === 'open-connections') {
    store.openConnectionSearch(extracted.target)
  } else if (item.id === 'open-rule-match') {
    store.openRuleMatch({ target: extracted.target, dstPort: extracted.port })
  }
}

const conflictAction = computed<{ message: string; label: string; tab: 'network' | 'tun'; focus?: string } | null>(() => {
  if (snap.value.connected) return null
  for (let i = source.value.length - 1; i >= 0; i -= 1) {
    const line = source.value[i]!
    if (line.level !== 'error') continue
    if (line.hint === 'port') {
      const labels = {
        mixed: '混合代理端口',
        http: 'HTTP 端口',
        socks: 'SOCKS 端口',
        redir: 'redir 端口',
        tproxy: 'tproxy 端口',
      } as const
      const kind = tr(labels[line.hint_kind ?? 'mixed'])
      return {
        message: tr('本地监听端口冲突导致内核未能启动，可前往网络设置更换{0}后重新连接。', { 0: kind }),
        label: tr('更换{0}', { 0: kind }),
        tab: 'network',
        focus: line.hint_kind && line.hint_kind !== 'mixed' ? 'extra-ports' : 'mixed-port',
      }
    }
    if (line.hint === 'tun') {
      return {
        message: tr('虚拟网卡冲突导致内核未能启动，可前往 TUN 设置调整或关闭其他 VPN 后重试。'),
        get label() { return tr('TUN 设置') },
        tab: 'tun',
      }
    }
  }
  return null
})
</script>

<template>
  <div class="page logs">
    <header class="page-head">
      <div>
        <h1>{{ tr('日志') }}</h1>
        <p class="muted small">
          <span data-testid="log-count">{{ source.length }} {{ tr('条') }}</span>
          <template v-if="isFiltered"> {{ tr('· 显示') }} {{ lines.length }} {{ tr('条') }}</template>
          · {{ counts.warning }} {{ tr('警告 ·') }} {{ counts.error }} {{ tr('错误') }} <template v-if="paused"> {{ tr('· 暂停于') }} {{ formatClock(pausedAt ?? 0) }}</template>
        </p>
        <p v-if="paused" class="muted small log-status" role="status" aria-live="polite" data-testid="log-paused"> {{ tr('已暂停，新增') }} <strong data-testid="log-new">{{ newCount }}</strong> {{ tr('条日志；') }}<button type="button" class="link-btn" data-testid="log-resume-inline" @click="resume()">{{ tr('继续') }}</button>{{ tr('后追平。') }} </p>
      </div>
      <div class="head-actions">
        <button
          type="button"
          class="btn ghost sm"
          :class="{ active: paused }"
          :aria-pressed="paused"
          data-testid="pause-logs"
          @click="togglePause"
        >
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? tr('继续') : tr('暂停') }}
        </button>
        <div v-if="props.compact" class="menu-anchor">
          <button
            type="button"
            class="icon-btn"
            :aria-label="tr('更多日志操作')"
            aria-haspopup="menu"
            :aria-expanded="moreOpen"
            data-testid="log-more"
            @click="moreOpen = !moreOpen"
          >
            <Icon name="more" />
          </button>
          <Menu :open="moreOpen" :items="moreItems" :label="tr('日志操作')" @select="onMore" @close="moreOpen = false" />
        </div>
        <template v-else>
          <label class="wrap-field small muted" data-testid="wrap-field">
            <Toggle v-model="wrap" :label="tr('自动换行')" /> {{ tr('自动换行') }} </label>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!lines.length"
            :title="copyButtonTitle"
            :aria-label="copyButtonTitle"
            data-testid="copy-logs"
            @click="copyFiltered"
          >
            <Icon name="copy" :size="15" />{{ copyButtonLabel }} </button>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!lines.length"
            :title="exportButtonTitle"
            :aria-label="exportButtonTitle"
            data-testid="export-logs"
            @click="exportLogs"
          >
            <Icon name="download" :size="15" />{{ exportButtonLabel }} </button>
          <button
            type="button"
            class="btn ghost sm danger-text"
            :disabled="!snap.logs.length"
            :title="!snap.logs.length ? tr('没有日志') : tr('清空日志')"
            data-testid="clear-logs"
            @click="confirmClear = true"
          >
            <Icon name="trash" :size="15" />{{ tr('清空') }} </button>
        </template>
      </div>
    </header>

    <div class="toolbar log-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索日志')" data-page-search />
        <span v-if="isFiltered" class="search-count mono" data-testid="log-match-count">{{ lines.length }}/{{ source.length }}</span>
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          :aria-label="tr('清空搜索')"
          data-testid="clear-log-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <Segmented v-model="filter" class="log-level-filter" :options="filterOptions" size="sm" :label="tr('日志级别')" />
      <button v-if="isFiltered" type="button" class="btn ghost sm" data-testid="reset-log-toolbar" @click="resetFilters"> {{ tr('重置') }} </button>
    </div>

    <div v-if="conflictAction" class="banner error log-conflict" role="alert" data-testid="log-conflict">
      <Icon name="alert" :size="16" />
      <span class="grow small">{{ conflictAction.message }}</span>
      <button
        type="button"
        class="btn ghost sm"
        data-testid="logs-open-settings"
        @click="store.openSettings(conflictAction.tab, conflictAction.focus)"
      >
        <Icon name="sliders" :size="14" />{{ conflictAction.label }}
      </button>
    </div>

    <div class="card log-card" :class="{ paused }">
      <div
        ref="scroller"
        class="log-scroll"
        :class="{ 'no-wrap': !wrap }"
        data-testid="log-scroll"
        role="region"
        :aria-label="tr('日志内容')"
        tabindex="0"
        @scroll="onScroll"
      >
        <EmptyState
          v-if="!lines.length"
          compact
          :variant="source.length ? 'no-match' : 'no-data'"
          :icon="source.length ? undefined : 'terminal'"
          :title="source.length ? tr('没有匹配的日志') : tr('暂无日志')"
          :description="source.length ? tr('换一个关键词或级别，或清空当前筛选。') : tr('连接后内核输出会出现在这里。')"
        >
          <template v-if="source.length" #action>
            <button type="button" class="btn ghost sm" data-testid="clear-log-filter" @click="resetFilters">{{ tr('清空筛选') }}</button>
          </template>
        </EmptyState>
        <template v-else>
          <div
            v-if="virtual.offset.value > 0"
            class="log-spacer"
            aria-hidden="true"
            :style="{ height: `${virtual.offset.value}px` }"
          ></div>
          <div
            v-for="item in visibleEntries"
            :key="item.entry.key"
            :ref="(el) => bindRow(item.entry.key, item.index, el)"
            class="log-line"
            :class="[item.entry.line.level, { 'menu-open': rowMenuKey === item.entry.key }]"
            :data-log-index="item.index"
            :data-log-line="lineKey(item.entry.line)"
            :data-log-key="item.entry.key"
            @contextmenu.prevent="toggleRowMenu(item.entry.key)"
          >
            <span class="log-time mono">{{ formatClock(item.entry.line.time_ms) }}</span>
            <button
              type="button"
              class="log-level mono"
              :title="filter === item.entry.line.level ? tr('点击恢复全部级别') : tr('仅看 {0} 级别日志', { 0: LABEL[item.entry.line.level] })"
              data-testid="log-level-badge"
              @click="filter = filter === item.entry.line.level ? 'all' : item.entry.line.level"
            >{{ LABEL[item.entry.line.level] }}</button>
            <span class="log-msg mono">
              <template v-for="(part, partIdx) in highlight(item.entry.line.message)" :key="partIdx">
                <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
              </template>
            </span>
            <div class="log-line-actions">
              <button
                type="button"
                class="icon-btn sm log-copy"
                :aria-label="tr('复制 {0} 的这行日志', { 0: formatClock(item.entry.line.time_ms) })"
                :title="tr('复制这行')"
                data-testid="copy-log-line"
                @click="copyLine(item.entry.line)"
              >
                <Icon name="copy" :size="13" />
              </button>
              <div class="menu-anchor log-row-menu">
                <button
                  type="button"
                  class="icon-btn sm log-more-btn"
                  :aria-label="tr('更多行操作')"
                  :title="tr('日志行操作')"
                  aria-haspopup="menu"
                  :aria-expanded="rowMenuKey === item.entry.key"
                  data-testid="log-line-more"
                  @click.stop="toggleRowMenu(item.entry.key)"
                >
                  <Icon name="more" :size="13" />
                </button>
                <Menu
                  v-if="rowMenuKey === item.entry.key"
                  :open="true"
                  :items="rowMenuItems(item.entry.line)"
                  :label="tr('日志行操作')"
                  @select="onRowAction($event, item.entry.line)"
                  @close="rowMenuKey = null"
                />
              </div>
            </div>
          </div>
          <div
            v-if="virtual.tail.value > 0"
            class="log-spacer"
            aria-hidden="true"
            :style="{ height: `${virtual.tail.value}px` }"
          ></div>
        </template>
      </div>
      <Transition name="menu-pop">
        <button v-if="!follow" type="button" class="jump" data-testid="log-jump" @click="toBottom(true)">
          <Icon name="down" :size="14" />{{ tr('最新') }} </button>
      </Transition>
    </div>

    <Modal :open="confirmClear" :title="tr('清空日志')" @close="confirmClear = false">
      <p class="small">{{ tr('将清空当前') }} {{ snap.logs.length }} {{ tr('条日志，操作无法撤销。') }}</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="cancel-clear-logs" @click="confirmClear = false">{{ tr('取消') }}</button>
        <button type="button" class="btn danger" data-testid="confirm-clear-logs" @click="clear">{{ tr('清空日志') }}</button>
      </template>
    </Modal>
  </div>
</template>
