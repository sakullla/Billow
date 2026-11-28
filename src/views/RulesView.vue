<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import ContextMenu from '../components/ContextMenu.vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import type { MenuItem } from '../components/Menu.vue'
import Segmented from '../components/Segmented.vue'
import SelectField from '../components/SelectField.vue'
import Skeleton from '../components/Skeleton.vue'
import { compareText, formatRelative } from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import { useColumnResize } from '../lib/ui/columns'
import { useVirtualList } from '../lib/ui/virtual'
import type { RuleMatchResult, RuleRow } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type SortKey = 'order' | 'hits'

const ROW_HEIGHT = computed(() => (props.compact ? 88 : 52))
const PAGE = 300

const ruleCols = useColumnResize('rules', [
  { id: 'kind', defaultWidth: 124, minWidth: 80, maxWidth: 260 },
  { id: 'payload', defaultWidth: 180, minWidth: 110, maxWidth: 860 },
  { id: 'proxy', defaultWidth: 136, minWidth: 88, maxWidth: 380 },
  { id: 'hit', defaultWidth: 60, minWidth: 48, maxWidth: 180 },
  { id: 'last', defaultWidth: 74, minWidth: 62, maxWidth: 220 },
])

const ruleScrollStyle = computed(() =>
  props.compact
    ? undefined
    : {
        '--col-rule-kind': `${ruleCols.widths.kind}px`,
        '--col-rule-payload': `${ruleCols.widths.payload}px`,
        '--col-rule-proxy': `${ruleCols.widths.proxy}px`,
        '--col-rule-hit': `${ruleCols.widths.hit}px`,
        '--col-rule-last': `${ruleCols.widths.last}px`,
      },
)

const rules = shallowRef<RuleRow[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
const loaded = ref(false)
const query = ref('')
const kind = ref<string | number>('all')
const proxy = ref<string | number>('all')
const sort = ref<SortKey>('order')
const limit = ref(PAGE)
const toggling = reactive<Record<string, boolean>>({})
let loadId = 0

async function load(quiet = false) {
  const request = ++loadId
  if (!quiet) loading.value = true
  try {
    const result = await store.backend.rules()
    if (request !== loadId) return
    if (result.error) {
      error.value = result.error
      rules.value = []
    } else {
      rules.value = result.rules
      error.value = null
    }
  } catch (err) {
    if (request !== loadId) return
    error.value = err instanceof Error ? err.message : String(err)
    rules.value = []
  } finally {
    if (request === loadId) {
      loading.value = false
      loaded.value = true
    }
  }
}

const hasHits = computed(() =>
  rules.value.some((rule) => rule.hit_count != null || rule.last_hit != null),
)

const SORTS = computed<{ id: SortKey; label: string }[]>(() =>
  hasHits.value
    ? [
        { id: 'order', label: tr('默认') },
        { id: 'hits', label: tr('命中') },
      ]
    : [{ id: 'order', label: tr('默认') }],
)

watch(hasHits, (available) => {
  if (!available) sort.value = 'order'
})

function countsOf(values: string[]): [string, number][] {
  const counts = new Map<string, number>()
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1))
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || compareText(a[0], b[0]))
}

const kinds = computed(() => countsOf(rules.value.map((rule) => rule.kind)))
const proxies = computed(() => countsOf(rules.value.map((rule) => rule.proxy)))

const kindOptions = computed(() => [
  { value: 'all', get label() { return tr('全部类型') }, hint: String(rules.value.length) },
  ...kinds.value.map(([name, count]) => ({ value: name, label: name, hint: String(count) })),
])
const proxyOptions = computed(() => [
  { value: 'all', get label() { return tr('全部策略') }, hint: String(proxies.value.length) },
  ...proxies.value.map(([name, count]) => ({ value: name, label: name, hint: String(count) })),
])

const needle = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))
const onlyDisabled = ref(false)
const disabledCount = computed(() => rules.value.filter((rule) => rule.disabled).length)
watch(disabledCount, (count) => {
  if (count === 0) onlyDisabled.value = false
})
const isFiltered = computed(
  () => Boolean(needle.value) || kind.value !== 'all' || proxy.value !== 'all' || onlyDisabled.value,
)

function highlight(value: string) {
  return highlightTokens(value, query.value)
}

const filtered = computed(() => {
  const tokens = queryTokens.value
  const indexed = rules.value.map((rule, index) => ({ rule, index }))
  const list = indexed.filter(({ rule }) => {
    if (onlyDisabled.value && !rule.disabled) return false
    if (kind.value !== 'all' && rule.kind !== kind.value) return false
    if (proxy.value !== 'all' && rule.proxy !== proxy.value) return false
    if (!tokens.length) return true
    return matchesTokens(`${rule.kind} ${rule.payload} ${rule.proxy}`, tokens)
  })
  if (sort.value === 'hits') {
    list.sort((a, b) => (b.rule.hit_count ?? -1) - (a.rule.hit_count ?? -1) || a.index - b.index)
  }
  return list
})

/** The manual cap keeps a 300-row page fast; "显示更多" raises it a page at a time. */
const capped = computed(() => filtered.value.slice(0, limit.value))

const scroller = ref<HTMLElement | null>(null)
const virtual = useVirtualList(
  computed(() => capped.value.length),
  () => ROW_HEIGHT.value,
  8,
)
const visible = computed(() => capped.value.slice(virtual.window.value.start, virtual.window.value.end))

let suppressFilterReset = false
let pendingRestoreScrollTop: number | null = null

// A remounted list (empty state round trip) and a changed filter both start at the
// first row instead of the previous offset (R31).
watch(scroller, (el) => virtual.measure(el))
watch([query, kind, proxy, sort, onlyDisabled], () => {
  if (suppressFilterReset) return
  limit.value = PAGE
  virtual.reset(scroller.value)
})

function resetFilters() {
  query.value = ''
  kind.value = 'all'
  proxy.value = 'all'
  onlyDisabled.value = false
}

const labelOf = (rule: RuleRow) => rule.payload || rule.kind
const isRuleSetKind = (ruleKind: string) => /^rule-?set$/i.test(ruleKind.trim())
const isRuleSet = (rule: RuleRow) => isRuleSetKind(rule.kind) && Boolean(rule.payload.trim())

function ruleExpression(rule: RuleRow): string {
  return rule.payload ? `${rule.kind},${rule.payload},${rule.proxy}` : `${rule.kind},${rule.proxy}`
}

async function copyRuleRow(rule: RuleRow) {
  const expr = ruleExpression(rule)
  await store.copyText(expr, tr('已复制规则：{0}', { 0: expr }))
}

/** Policies that name a proxy group can be opened; DIRECT/REJECT and plain nodes stay labels. */
const groupNames = computed(() => new Set(snap.value.node_catalog.map((group) => group.name)))
const isGroup = (name: string) => groupNames.value.has(name)

// ── Static rule matcher panel (R2) ──
const matcherOpen = ref(false)
const matchExtraOpen = ref(false)
const matchTarget = ref('')
const matchPort = ref('')
const matchProcess = ref('')
const matchPending = ref(false)
const matchError = ref<string | null>(null)
const matchResult = shallowRef<RuleMatchResult | null>(null)
const matchInputRef = ref<HTMLInputElement | null>(null)
const highlightedRowIndex = ref<number | null>(null)
let highlightTimer: ReturnType<typeof setTimeout> | null = null
let matchGen = 0

function clearHighlight() {
  if (highlightTimer) {
    clearTimeout(highlightTimer)
    highlightTimer = null
  }
  highlightedRowIndex.value = null
}

function toggleMatcher() {
  if (!snap.value.kernel_running) return
  matcherOpen.value = !matcherOpen.value
  if (matcherOpen.value) {
    void nextTick(() => matchInputRef.value?.focus({ preventScroll: true }))
  }
}

function clearMatch() {
  ++matchGen
  matchTarget.value = ''
  matchPort.value = ''
  matchProcess.value = ''
  matchError.value = null
  matchResult.value = null
  matchPending.value = false
  clearHighlight()
  void nextTick(() => matchInputRef.value?.focus({ preventScroll: true }))
}

function parseOptionalPort(raw: string): { value: number | null; error: string | null } {
  const trimmed = raw.trim()
  if (!trimmed) return { value: null, error: null }
  if (!/^\d{1,5}$/.test(trimmed)) return { value: null, error: tr('目标端口无效（应为 1-65535）') }
  const port = Number(trimmed)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { value: null, error: tr('目标端口无效（应为 1-65535）') }
  }
  return { value: port, error: null }
}

async function runMatch() {
  if (!snap.value.kernel_running) {
    matchError.value = tr('内核未运行，连接后可测试规则匹配')
    return
  }
  const target = matchTarget.value.trim()
  if (!target) {
    matchError.value = tr('请输入要测试的域名或 IP')
    return
  }
  const parsedPort = parseOptionalPort(matchPort.value)
  if (parsedPort.error) {
    matchError.value = parsedPort.error
    return
  }
  const processName = matchProcess.value.trim() || null
  matchError.value = null
  matchPending.value = true
  const ticket = ++matchGen
  try {
    const result = await store.matchRule({
      target,
      dst_port: parsedPort.value,
      process: processName,
    })
    if (ticket !== matchGen) return
    matchResult.value = result
  } catch (err) {
    if (ticket !== matchGen) return
    matchError.value = tr(err instanceof Error ? err.message : String(err))
  } finally {
    if (ticket === matchGen) matchPending.value = false
  }
}

async function locateRuleRow(rowIndex: number, ruleKey?: string | null) {
  if (!rules.value.length) return
  const findPos = () =>
    filtered.value.findIndex((item) => item.index === rowIndex || (ruleKey != null && item.rule.key === ruleKey))
  let pos = findPos()
  if (pos < 0 && isFiltered.value) {
    resetFilters()
    store.toast(tr('已清空当前筛选以定位命中规则'), 'info')
    await nextTick()
    pos = findPos()
  }
  if (pos < 0) {
    store.toast(tr('未在当前规则列表中找到该行'), 'info')
    return
  }
  if (pos >= limit.value) {
    limit.value = Math.ceil((pos + 1) / PAGE) * PAGE
  }
  await nextTick()
  const targetTop = Math.max(0, pos * ROW_HEIGHT.value - ROW_HEIGHT.value * 2)
  if (scroller.value) {
    scroller.value.scrollTop = targetTop
    virtual.measure(scroller.value)
  } else {
    virtual.scrollTop.value = targetTop
  }
  clearHighlight()
  const resolvedIndex = filtered.value[pos]?.index ?? rowIndex
  highlightedRowIndex.value = resolvedIndex
  highlightTimer = setTimeout(() => {
    highlightedRowIndex.value = null
    highlightTimer = null
  }, 3200)
}

function saveRuleReturn(targetPage: 'resources' | 'proxies') {
  store.ruleReturn.value = {
    sessionId: store.connectionSessionId.value,
    profileId: snap.value.active_id,
    targetPage,
    query: query.value,
    kindFilter: String(kind.value),
    proxyFilter: String(proxy.value),
    disabledOnly: onlyDisabled.value,
    listScrollTop: scroller.value?.scrollTop ?? virtual.scrollTop.value,
    limit: limit.value,
    matcherOpen: matcherOpen.value,
    matchTarget: matchTarget.value,
    matchPort: matchPort.value,
    matchProcess: matchProcess.value,
    matchResult: matchResult.value,
  }
}

function openRuleSet(name: string) {
  const trimmed = name.trim()
  if (!trimmed) return
  saveRuleReturn('resources')
  store.openProvider('rule', trimmed)
}

function openProxyGroup(name: string) {
  const trimmed = name.trim()
  if (!trimmed) return
  saveRuleReturn('proxies')
  store.go('proxies', trimmed)
}

function onPolicyClick(policyName: string) {
  if (isGroup(policyName)) {
    openProxyGroup(policyName)
    return
  }
  proxy.value = proxy.value === policyName ? 'all' : policyName
}

const ctxMenu = ref<{ x: number; y: number; items: MenuItem[]; rule?: RuleRow } | null>(null)
let menuTriggerEl: HTMLElement | null = null

function closeCtxMenu() {
  ctxMenu.value = null
  if (menuTriggerEl?.isConnected) {
    menuTriggerEl.focus({ preventScroll: true })
  }
  menuTriggerEl = null
}

function openHeadMenu(event: MouseEvent) {
  if (props.compact || !ruleCols.customized.value) return
  event.preventDefault()
  menuTriggerEl = null
  ctxMenu.value = {
    x: event.clientX,
    y: event.clientY,
    items: [{ id: 'reset-cols', get label() { return tr('恢复默认列宽') }, icon: 'refresh' }],
  }
}

function buildRowMenuItems(rule: RuleRow): MenuItem[] {
  const items: MenuItem[] = [
    { id: 'copy', get label() { return tr('复制规则') }, icon: 'copy' },
    {
      id: 'filter-kind',
      label: kind.value === rule.kind ? tr('取消类型筛选') : tr('仅看 {0}', { 0: rule.kind }),
      icon: 'filter',
    },
    {
      id: 'filter-proxy',
      label: proxy.value === rule.proxy ? tr('取消策略筛选') : tr('仅看策略「{0}」', { 0: rule.proxy }),
      icon: 'filter',
    },
  ]
  if (isRuleSet(rule)) {
    items.push({ id: 'open-ruleset', label: tr('查看规则集「{0}」', { 0: rule.payload }), icon: 'database' })
  }
  if (isGroup(rule.proxy)) {
    items.push({ id: 'open-group', label: tr('前往代理组「{0}」', { 0: rule.proxy }), icon: 'globe' })
  }
  if (rule.key) {
    items.push({
      id: 'toggle',
      label: rule.disabled ? tr('恢复启用此规则') : tr('临时禁用此规则'),
      icon: rule.disabled ? 'play' : 'pause',
    })
  }
  return items
}

function openRowMenu(rule: RuleRow, event: MouseEvent) {
  if (props.compact) return
  event.preventDefault()
  menuTriggerEl = null
  ctxMenu.value = { x: event.clientX, y: event.clientY, items: buildRowMenuItems(rule), rule }
}

function openMobileRowMenu(rule: RuleRow, event: MouseEvent) {
  const el = event.currentTarget as HTMLElement | null
  menuTriggerEl = el
  const rect = el?.getBoundingClientRect()
  const x = rect ? rect.right : event.clientX
  const y = rect ? rect.bottom + 4 : event.clientY
  ctxMenu.value = { x, y, items: buildRowMenuItems(rule), rule }
}

function onContextSelect(item: MenuItem) {
  const target = ctxMenu.value?.rule
  closeCtxMenu()
  if (item.id === 'reset-cols') {
    ruleCols.resetAll()
    return
  }
  if (!target) return
  if (item.id === 'copy') void copyRuleRow(target)
  else if (item.id === 'filter-kind') kind.value = kind.value === target.kind ? 'all' : target.kind
  else if (item.id === 'filter-proxy') proxy.value = proxy.value === target.proxy ? 'all' : target.proxy
  else if (item.id === 'open-ruleset') openRuleSet(target.payload)
  else if (item.id === 'open-group') openProxyGroup(target.proxy)
  else if (item.id === 'toggle') void toggle(target)
}

function lastHitText(rule: RuleRow): string {
  if (!rule.last_hit) return ''
  const ms = Date.parse(rule.last_hit)
  return Number.isNaN(ms) ? '' : formatRelative(ms)
}

function hitText(rule: RuleRow): string {
  return rule.hit_count == null ? '—' : rule.hit_count.toLocaleString()
}

/**
 * Temporary disable/enable. The returned snapshot is merged in place so the
 * list, filters and scroll position survive; a failure leaves the row untouched
 * and reports the reason through a toast (R28).
 */
async function toggle(rule: RuleRow) {
  const key = rule.key
  if (!key || toggling[key]) return
  toggling[key] = true
  const disabling = !rule.disabled
  const context = loadId
  try {
    const result = await store.backend.setRuleDisabled(key, disabling)
    if (context !== loadId) return
    if (result.error) {
      store.toast(result.error, 'error')
      return
    }
    rules.value = result.rules
    store.toast(
      disabling ? tr('已临时禁用 {0}，重启后恢复', { 0: labelOf(rule) }) : tr('已恢复 {0}', { 0: labelOf(rule) }),
      'success',
    )
    if (matcherOpen.value && matchResult.value && matchTarget.value.trim()) {
      void runMatch()
    }
  } catch (err) {
    store.toast(tr('规则没有修改：{0}', { 0: err instanceof Error ? err.message : String(err) }), 'error')
  } finally {
    delete toggling[key]
  }
}

function consumeDiagnosticTarget(): boolean {
  const target = store.diagnosticTarget.value
  if (!target || target.kind !== 'rule-match') return false
  store.diagnosticTarget.value = null
  matcherOpen.value = true
  matchTarget.value = target.target
  matchPort.value = target.dstPort != null ? String(target.dstPort) : ''
  matchProcess.value = target.process ?? ''
  if (matchPort.value || matchProcess.value) {
    matchExtraOpen.value = true
  }
  matchError.value = null
  if (snap.value.kernel_running) {
    void runMatch()
  }
  return true
}

function restoreRuleReturn(): boolean {
  const saved = store.ruleReturn.value
  if (!saved) return false
  store.ruleReturn.value = null
  if (
    !snap.value.kernel_running ||
    saved.sessionId !== store.connectionSessionId.value ||
    saved.profileId !== snap.value.active_id
  ) {
    return false
  }
  suppressFilterReset = true
  query.value = saved.query
  kind.value = saved.kindFilter
  proxy.value = saved.proxyFilter
  onlyDisabled.value = saved.disabledOnly
  limit.value = Math.max(PAGE, saved.limit)
  matcherOpen.value = saved.matcherOpen
  matchTarget.value = saved.matchTarget
  matchPort.value = saved.matchPort
  matchProcess.value = saved.matchProcess
  if (saved.matchPort || saved.matchProcess) {
    matchExtraOpen.value = true
  }
  matchResult.value = saved.matchResult
  pendingRestoreScrollTop = saved.listScrollTop
  void nextTick(() => {
    suppressFilterReset = false
  })
  return true
}

watch(
  () => store.diagnosticTarget.value,
  (target) => {
    if (target?.kind === 'rule-match') {
      consumeDiagnosticTarget()
    }
  },
)

// A stopped kernel drops every row instead of keeping the previous session (R31).
watch(
  [() => snap.value.kernel_running, () => snap.value.active_id, () => store.current.value?.updated_ms],
  ([running]) => {
    ++loadId
    ++matchGen
    clearHighlight()
    matchResult.value = null
    matchError.value = null
    matchPending.value = false
    pendingRestoreScrollTop = null
    rules.value = []
    limit.value = PAGE
    resetFilters()
    if (running) {
      void load()
      return
    }
    rules.value = []
    error.value = null
    loading.value = false
    limit.value = PAGE
    resetFilters()
  },
)

onMounted(() => {
  const consumedTarget = consumeDiagnosticTarget()
  if (!consumedTarget) {
    restoreRuleReturn()
  }
  void load().then(async () => {
    await nextTick()
    if (pendingRestoreScrollTop != null && scroller.value) {
      scroller.value.scrollTop = pendingRestoreScrollTop
      pendingRestoreScrollTop = null
    }
    virtual.measure(scroller.value)
  })
})
onBeforeUnmount(() => {
  ++loadId
  ++matchGen
  clearHighlight()
})
</script>

<template>
  <div class="page rules">
    <header class="page-head">
      <div>
        <h1>{{ tr('规则') }}</h1>
        <p class="muted small">
          {{
            rules.length
              ? isFiltered
                ? tr('匹配 {0} / {1} 条规则，自上而下匹配', { 0: filtered.length, 1: rules.length })
                : tr('{0} 条规则，自上而下匹配', { 0: rules.length })
              : tr('运行中的内核按这些规则分流')
          }}
          <template v-if="rules.length && hasHits"> {{ tr('· 命中信息来自内核') }}</template>
        </p>
        <p v-if="rules.length && !hasHits" class="muted small" data-testid="rules-no-hits"> {{ tr('当前内核不提供命中信息，已隐藏命中列。') }} </p>
      </div>
      <div class="head-actions">
        <button
          type="button"
          class="btn ghost sm rule-matcher-toggle"
          :class="{ active: matcherOpen }"
          :disabled="!snap.kernel_running"
          :aria-expanded="matcherOpen"
          aria-controls="rule-matcher-panel"
          :title="!snap.kernel_running ? tr('内核未运行，连接后可测试规则匹配') : tr('测试域名或 IP 会命中哪条规则')"
          data-testid="rule-match-toggle"
          @click="toggleMatcher()"
        >
          <Icon name="locate" :size="14" />
          {{ tr('匹配测试') }}
        </button>
        <button
          v-if="!compact && ruleCols.customized.value"
          type="button"
          class="btn ghost sm"
          :title="tr('恢复默认列宽')"
          data-testid="reset-rule-cols"
          @click="ruleCols.resetAll()"
        > {{ tr('恢复列宽') }} </button>
        <button
          type="button"
          class="btn ghost sm"
          :disabled="loading"
          :aria-busy="loading || undefined"
          data-testid="refresh-rules"
          @click="load()"
        >
          <span v-if="loading" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="refresh" :size="15" />
          {{ loading ? tr('刷新中') : tr('刷新') }}
        </button>
      </div>
    </header>

    <Skeleton v-if="loading && !rules.length && snap.kernel_running" variant="list" :rows="8" />

    <div v-if="rules.length" class="toolbar rule-toolbar" data-testid="rule-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索规则内容或策略')" data-page-search />
        <span
          v-if="!compact && isFiltered"
          class="toolbar-count search-match-count small mono"
          data-testid="rule-match-count"
          aria-live="polite"
        >{{ filtered.length }} / {{ rules.length }}</span>
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          :aria-label="tr('清空搜索')"
          data-testid="clear-rule-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <SelectField
        v-model="kind"
        :options="kindOptions"
        :sheet="compact"
        size="sm"
        :label="tr('按类型筛选')"
        class="rule-filter"
        :class="{ filtered: kind !== 'all' }"
        data-testid="rule-kind-filter"
      />
      <SelectField
        v-model="proxy"
        :options="proxyOptions"
        :sheet="compact"
        size="sm"
        :label="tr('按策略筛选')"
        class="rule-filter"
        :class="{ filtered: proxy !== 'all' }"
        data-testid="rule-proxy-filter"
      />
      <button
        v-if="disabledCount > 0"
        type="button"
        class="chip-btn"
        :class="{ active: onlyDisabled }"
        :aria-pressed="onlyDisabled"
        data-testid="rule-disabled-filter"
        @click="onlyDisabled = !onlyDisabled"
      > {{ tr('已禁用') }} {{ disabledCount }}
      </button>
      <Segmented v-if="hasHits" v-model="sort" :options="SORTS" size="sm" :label="tr('排序')" />
      <button v-if="isFiltered" type="button" class="btn ghost sm" data-testid="reset-rule-toolbar" @click="resetFilters"> {{ tr('重置') }} </button>
    </div>

    <section v-if="matcherOpen" id="rule-matcher-panel" class="card rule-matcher" data-testid="rule-matcher-panel">
      <div class="rule-matcher-head">
        <div>
          <h2 class="rule-matcher-title">{{ tr('规则匹配测试') }}</h2>
          <p class="muted small">{{ tr('静态按顺序评估当前生效规则与本地已缓存规则集，不发起网络请求') }}</p>
        </div>
        <button
          type="button"
          class="icon-btn sm"
          :aria-label="tr('收起匹配测试')"
          data-testid="rule-match-close"
          @click="matcherOpen = false"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>

      <form class="rule-matcher-form" data-testid="rule-match-form" @submit.prevent="runMatch">
        <div class="rule-matcher-row">
          <input
            ref="matchInputRef"
            v-model="matchTarget"
            class="input mono grow"
            type="text"
            placeholder="example.com / 1.1.1.1 / host:443"
            spellcheck="false"
            autocomplete="off"
            autocapitalize="off"
            enterkeyhint="search"
            :disabled="!snap.kernel_running"
            :aria-label="tr('目标域名或 IP')"
            :aria-invalid="matchError ? 'true' : undefined"
            data-testid="rule-match-target"
            @input="matchError = null"
          />
          <button
            type="button"
            class="btn ghost sm"
            :class="{ active: matchExtraOpen || Boolean(matchPort || matchProcess) }"
            :aria-expanded="matchExtraOpen"
            data-testid="rule-match-extra-toggle"
            @click="matchExtraOpen = !matchExtraOpen"
          >
            <Icon name="sliders" :size="13" />
            {{ tr('端口/进程') }}
          </button>
          <button
            type="submit"
            class="btn primary sm"
            :disabled="!snap.kernel_running || matchPending"
            :aria-busy="matchPending || undefined"
            data-testid="rule-match-submit"
          >
            <span v-if="matchPending" class="spinner xs" aria-hidden="true" />
            <Icon v-else name="locate" :size="14" />
            {{ matchPending ? tr('匹配中') : tr('测试') }}
          </button>
          <button
            v-if="matchTarget || matchPort || matchProcess || matchResult || matchError"
            type="button"
            class="btn ghost sm"
            data-testid="rule-match-clear"
            @click="clearMatch()"
          >
            {{ tr('清空') }}
          </button>
        </div>

        <div v-if="matchExtraOpen" class="rule-matcher-extra" data-testid="rule-match-extra">
          <label class="rule-matcher-field">
            <span class="small muted">{{ tr('目标端口（可选）') }}</span>
            <input
              v-model="matchPort"
              class="input mono"
              type="text"
              inputmode="numeric"
              placeholder="443"
              :disabled="!snap.kernel_running"
              data-testid="rule-match-port"
              @input="matchError = null"
            />
          </label>
          <label class="rule-matcher-field grow">
            <span class="small muted">{{ tr('进程名或路径（可选）') }}</span>
            <input
              v-model="matchProcess"
              class="input mono"
              type="text"
              :placeholder="tr('如 curl 或 /usr/bin/curl')"
              spellcheck="false"
              autocomplete="off"
              :disabled="!snap.kernel_running"
              data-testid="rule-match-process"
              @input="matchError = null"
            />
          </label>
        </div>

        <p v-if="!snap.kernel_running" class="muted small rule-matcher-status" role="status" data-testid="rule-match-blocked">
          <Icon name="info" :size="13" /> {{ tr('内核未运行，连接后可测试规则匹配') }}
        </p>
        <p v-if="matchError" class="field-error small rule-matcher-status" role="alert" data-testid="rule-match-error">
          <Icon name="alert" :size="13" /> {{ matchError }}
        </p>
      </form>

      <div v-if="matchResult" class="rule-matcher-result" aria-live="polite" data-testid="rule-match-result">
        <p class="muted small rule-matcher-summary" data-testid="rule-match-summary">
          <span class="rule-matcher-summary-label">{{ tr('匹配结果') }}</span>
          <span class="mono ellipsis">{{ matchResult.normalized_host || matchResult.normalized_ip || matchTarget.trim() }}<template v-if="matchResult.effective_port != null">:{{ matchResult.effective_port }}</template><template v-if="matchResult.effective_process"> · {{ matchResult.effective_process }}</template></span>
        </p>

        <div v-if="matchResult.matched" class="rule-matcher-hit" data-testid="rule-match-hit">
          <div class="rule-matcher-hit-main">
            <span class="tag accent">{{ tr('命中规则') }}</span>
            <span class="mono small muted">#{{ matchResult.matched.row_index + 1 }}</span>
            <span class="tag">{{ matchResult.matched.kind }}</span>
            <span v-if="matchResult.matched.payload" class="mono ellipsis">{{ matchResult.matched.payload }}</span>
            <span class="muted" aria-hidden="true">→</span>
            <span class="rule-proxy" :data-policy="matchResult.matched.proxy.toUpperCase()">
              <span class="rule-proxy-badge">{{ matchResult.matched.proxy }}</span>
            </span>
          </div>
          <p v-if="matchResult.matched.sub_rule" class="rule-matcher-sub small" data-testid="rule-match-sub-rule">
            <span class="muted">{{ tr('命中规则集条目') }}：</span>
            <code class="mono">{{ matchResult.matched.sub_rule }}</code>
          </p>
          <div class="rule-matcher-actions">
            <button
              type="button"
              class="btn ghost sm"
              data-testid="rule-match-locate"
              @click="locateRuleRow(matchResult.matched.row_index, matchResult.matched.rule_key)"
            >
              <Icon name="locate" :size="13" />
              {{ tr('定位规则') }}
            </button>
            <button
              v-if="isRuleSetKind(matchResult.matched.kind) && matchResult.matched.payload"
              type="button"
              class="btn ghost sm"
              data-testid="rule-match-open-ruleset"
              @click="openRuleSet(matchResult.matched.payload)"
            >
              <Icon name="database" :size="13" />
              {{ tr('查看规则集') }}
            </button>
            <button
              v-if="isGroup(matchResult.matched.proxy)"
              type="button"
              class="btn ghost sm"
              data-testid="rule-match-open-group"
              @click="openProxyGroup(matchResult.matched.proxy)"
            >
              <Icon name="globe" :size="13" />
              {{ tr('前往代理组') }}
            </button>
          </div>
        </div>
        <p v-else class="muted small rule-matcher-miss" data-testid="rule-match-miss">
          <Icon name="info" :size="13" /> {{ tr('未静态命中任何规则') }}
        </p>

        <div v-if="matchResult.skipped_disabled.length" class="rule-matcher-section" data-testid="rule-match-skipped">
          <div class="rule-matcher-section-head small">
            <span class="tag warn">{{ tr('已跳过') }}</span>
            <span class="muted">{{ tr('已跳过 {0} 条临时禁用规则', { 0: matchResult.skipped_disabled.length }) }}</span>
          </div>
          <ul class="rule-matcher-list">
            <li
              v-for="(item, idx) in matchResult.skipped_disabled"
              :key="`skip-${item.row_index}-${idx}`"
              class="rule-matcher-item small"
              data-testid="rule-match-skipped-item"
            >
              <div class="rule-matcher-item-main">
                <span class="mono muted">#{{ item.row_index + 1 }}</span>
                <span class="tag">{{ item.kind }}</span>
                <span v-if="item.payload" class="mono ellipsis">{{ item.payload }}</span>
                <span class="muted" aria-hidden="true">→</span>
                <span class="mono">{{ item.proxy }}</span>
                <code v-if="item.sub_rule" class="mono muted">({{ item.sub_rule }})</code>
              </div>
              <button
                type="button"
                class="btn ghost sm"
                @click="locateRuleRow(item.row_index, item.rule_key)"
              >{{ tr('定位') }}</button>
            </li>
          </ul>
        </div>

        <div v-if="matchResult.preceding_uncertain.length" class="rule-matcher-section" data-testid="rule-match-uncertain">
          <div class="rule-matcher-section-head small">
            <span class="tag">{{ tr('待核验') }}</span>
            <span class="muted">{{ tr('前置待核验（{0}）', { 0: matchResult.preceding_uncertain.length }) }} · {{ tr('以下规则位于确认命中之前，静态条件下无法完全排除') }}</span>
          </div>
          <ul class="rule-matcher-list">
            <li
              v-for="(item, idx) in matchResult.preceding_uncertain"
              :key="`uncertain-${item.row_index}-${idx}`"
              class="rule-matcher-item small"
              data-testid="rule-match-uncertain-item"
            >
              <div class="rule-matcher-item-body">
                <div class="rule-matcher-item-main">
                  <span class="mono muted">#{{ item.row_index + 1 }}</span>
                  <span class="tag">{{ item.kind }}</span>
                  <span v-if="item.payload" class="mono ellipsis">{{ item.payload }}</span>
                  <span class="muted" aria-hidden="true">→</span>
                  <span class="mono">{{ item.proxy }}</span>
                </div>
                <p class="muted small rule-matcher-reason">{{ tr(item.reason) }}</p>
              </div>
              <div class="rule-matcher-item-actions">
                <button
                  type="button"
                  class="btn ghost sm"
                  @click="locateRuleRow(item.row_index, item.rule_key)"
                >{{ tr('定位') }}</button>
                <button
                  v-if="item.provider_name"
                  type="button"
                  class="btn ghost sm"
                  data-testid="rule-match-uncertain-provider"
                  @click="openRuleSet(item.provider_name)"
                >
                  <Icon name="database" :size="13" />
                  {{ tr('查看规则集') }}
                </button>
                <button
                  v-if="item.needs_dns"
                  type="button"
                  class="btn ghost sm"
                  data-testid="rule-match-uncertain-dns"
                  @click="store.dnsQueryOpen.value = true"
                >
                  <Icon name="search" :size="13" />
                  {{ tr('DNS 查询') }}
                </button>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </section>

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" icon="route" :title="tr('内核未运行')" :description="tr('连接后可以查看当前配置生效的分流规则。')">
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
          {{ store.hasProfiles.value ? (store.connecting.value ? tr('连接中') : tr('立即连接')) : tr('添加配置') }}
        </button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="loaded && error && !rules.length" variant="error" :title="tr('读取失败')" :description="error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-rules" @click="load()">{{ tr('重试') }}</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="loaded && !rules.length" variant="no-data" icon="route" :title="tr('没有规则')" :description="tr('当前配置没有可显示的分流规则。')">
      <template #action>
        <button type="button" class="btn ghost sm" @click="load()">{{ tr('刷新') }}</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="rules.length && !filtered.length" variant="no-match" :title="tr('没有匹配的规则')" :description="tr('换一个关键词或筛选条件，或清空当前筛选。')">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="clear-rule-filter" @click="resetFilters">{{ tr('清空筛选') }}</button>
      </template>
    </EmptyState>

    <div
      v-if="filtered.length"
      ref="scroller"
      class="card list-card rule-scroll"
      :class="{ 'custom-cols': !compact && ruleCols.customized.value }"
      :style="ruleScrollStyle"
      data-testid="rule-scroll"
      @scroll="virtual.onScroll"
    >
      <!-- Column captions: without them the hit count and last-hit time are bare numbers. -->
      <div
        v-if="!compact"
        class="rule-head"
        :aria-hidden="hasHits ? undefined : 'true'"
        data-testid="rule-head"
        @contextmenu="openHeadMenu"
      >
        <span class="rule-kind-cell rule-head-cell"> {{ tr('类型') }} <span
            class="col-resizer"
            :class="{ active: ruleCols.resizingId.value === 'kind' }"
            role="separator"
            aria-orientation="vertical"
            :title="tr('拖拽调整列宽，双击恢复默认')"
            data-testid="col-resize-rule-kind"
            @pointerdown="ruleCols.startResize('kind', $event)"
            @dblclick="ruleCols.resetColumn('kind', $event)"
            @click.stop
          />
        </span>
        <span class="rule-head-main rule-head-cell"> {{ tr('内容') }} <span
            class="col-resizer"
            :class="{ active: ruleCols.resizingId.value === 'payload' }"
            role="separator"
            aria-orientation="vertical"
            :title="tr('拖拽调整列宽，双击恢复默认')"
            data-testid="col-resize-rule-payload"
            @pointerdown="ruleCols.startResize('payload', $event)"
            @dblclick="ruleCols.resetColumn('payload', $event)"
            @click.stop
          />
        </span>
        <span class="rule-head-proxy rule-head-cell"> {{ tr('策略') }} <span
            class="col-resizer"
            :class="{ active: ruleCols.resizingId.value === 'proxy' }"
            role="separator"
            aria-orientation="vertical"
            :title="tr('拖拽调整列宽，双击恢复默认')"
            data-testid="col-resize-rule-proxy"
            @pointerdown="ruleCols.startResize('proxy', $event)"
            @dblclick="ruleCols.resetColumn('proxy', $event)"
            @click.stop
          />
        </span>
        <template v-if="hasHits">
          <span class="rule-hit rule-head-cell">
            <button
              type="button"
              class="th-sort num"
              :class="{ active: sort === 'hits' }"
              :aria-label="tr('按命中次数排序')"
              :title="sort === 'hits' ? tr('点击恢复默认顺序') : tr('点击按命中次数降序排列')"
              data-testid="rule-sort-hits"
              @click="sort = sort === 'hits' ? 'order' : 'hits'"
            > {{ tr('命中') }}<Icon v-if="sort === 'hits'" name="down" :size="11" />
            </button>
            <span
              class="col-resizer"
              :class="{ active: ruleCols.resizingId.value === 'hit' }"
              role="separator"
              aria-orientation="vertical"
              :title="tr('拖拽调整列宽，双击恢复默认')"
              data-testid="col-resize-rule-hit"
              @pointerdown="ruleCols.startResize('hit', $event)"
              @dblclick="ruleCols.resetColumn('hit', $event)"
              @click.stop
            />
          </span>
          <span class="rule-last-hit rule-head-cell"> {{ tr('最近命中') }} <span
              class="col-resizer"
              :class="{ active: ruleCols.resizingId.value === 'last' }"
              role="separator"
              aria-orientation="vertical"
              :title="tr('拖拽调整列宽，双击恢复默认')"
              data-testid="col-resize-rule-last"
              @pointerdown="ruleCols.startResize('last', $event)"
              @dblclick="ruleCols.resetColumn('last', $event)"
              @click.stop
            />
          </span>
        </template>
        <span class="rule-actions" />
      </div>
      <div v-if="virtual.offset.value" class="rule-spacer" aria-hidden="true" :style="{ height: `${virtual.offset.value}px` }" />
      <div
        v-for="({ rule, index }, position) in visible"
        :key="rule.key ?? `i${index}`"
        class="rule-row"
        :class="{ disabled: rule.disabled, highlighted: highlightedRowIndex === index }"
        :data-row-index="virtual.window.value.start + position"
        :data-rule-index="index"
        :data-rule-key="rule.key ?? undefined"
        :data-rule-disabled="rule.disabled ? 'true' : undefined"
        :data-rule-highlighted="highlightedRowIndex === index ? 'true' : undefined"
        data-testid="rule-row"
        @contextmenu="openRowMenu(rule, $event)"
      >
        <span class="rule-kind-cell">
          <button
            type="button"
            class="tag tag-btn"
            :class="{ accent: kind === rule.kind }"
            :title="kind === rule.kind ? tr('取消类型筛选') : tr('仅看 {0} 规则', { 0: rule.kind })"
            data-testid="rule-kind-tag"
            @click="kind = kind === rule.kind ? 'all' : rule.kind"
          >
            <template v-for="(part, partIdx) in highlight(rule.kind)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </button>
          <span v-if="rule.disabled" class="tag warn rule-off-tag" data-testid="rule-off-tag">{{ tr('已禁用') }}</span>
        </span>
        <span class="rule-payload mono ellipsis" :title="rule.payload">
          <template v-if="rule.payload">
            <span class="rule-payload-text ellipsis">
              <template v-for="(part, partIdx) in highlight(rule.payload)" :key="partIdx">
                <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
              </template>
            </span>
            <button
              v-if="isRuleSet(rule)"
              type="button"
              class="icon-btn xs rule-open-provider"
              :title="tr('查看规则集「{0}」详情', { 0: rule.payload })"
              :aria-label="tr('查看规则集 {0}', { 0: rule.payload })"
              data-testid="rule-open-provider"
              @click="openRuleSet(rule.payload)"
            >
              <Icon name="external" :size="12" />
            </button>
          </template>
          <template v-else>—</template>
        </span>
        <span class="rule-proxy" :data-policy="rule.proxy.toUpperCase()">
          <button
            type="button"
            class="rule-proxy-badge link"
            :class="{ filtered: !isGroup(rule.proxy) && proxy === rule.proxy }"
            :title="isGroup(rule.proxy) ? tr('前往代理组「{0}」', { 0: rule.proxy }) : proxy === rule.proxy ? tr('取消策略筛选') : tr('仅看策略「{0}」', { 0: rule.proxy })"
            :data-testid="isGroup(rule.proxy) ? 'rule-proxy-link' : 'rule-proxy-filter-tag'"
            @click="onPolicyClick(rule.proxy)"
          >
            <template v-for="(part, partIdx) in highlight(rule.proxy)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </button>
          <span v-if="rule.disabled" class="rule-flag small" data-rule-flag>{{ tr('临时，重启后恢复') }}</span>
          <span v-else-if="!rule.key" class="rule-flag small muted">{{ tr('内核注入，无法临时禁用') }}</span>
        </span>
        <template v-if="hasHits">
          <span class="rule-hit mono" :title="tr('命中 {0} 次', { 0: hitText(rule) })" data-rule-hit>{{ hitText(rule) }}</span>
          <span class="rule-last-hit small muted">{{ lastHitText(rule) }}</span>
        </template>
        <span class="rule-actions">
          <button
            type="button"
            class="icon-btn sm rule-copy"
            :aria-label="tr('复制规则 {0}', { 0: labelOf(rule) })"
            :title="tr('复制规则')"
            data-testid="rule-copy"
            @click="copyRuleRow(rule)"
          >
            <Icon name="copy" :size="13" />
          </button>
          <!-- Desktop reveals the action on hover/focus; disabled rows keep 「启用」 visible (R4). Phones use a compact icon. -->
          <button
            v-if="rule.key && compact"
            type="button"
            class="icon-btn sm rule-toggle"
            :class="{ active: rule.disabled }"
            :disabled="toggling[rule.key]"
            :aria-busy="toggling[rule.key] || undefined"
            :aria-label="rule.disabled ? tr('启用规则 {0}', { 0: labelOf(rule) }) : tr('临时禁用规则 {0}', { 0: labelOf(rule) })"
            :title="rule.disabled ? tr('启用') : tr('临时禁用')"
            data-testid="rule-toggle"
            @click="toggle(rule)"
          >
            <span v-if="toggling[rule.key]" class="spinner xs" aria-hidden="true" />
            <Icon v-else :name="rule.disabled ? 'play' : 'pause'" :size="14" />
          </button>
          <button
            v-else-if="rule.key"
            type="button"
            class="btn ghost sm rule-toggle"
            :class="{ pinned: rule.disabled || toggling[rule.key] }"
            :disabled="toggling[rule.key]"
            :aria-busy="toggling[rule.key] || undefined"
            :aria-label="rule.disabled ? tr('启用规则 {0}', { 0: labelOf(rule) }) : tr('临时禁用规则 {0}', { 0: labelOf(rule) })"
            data-testid="rule-toggle"
            @click="toggle(rule)"
          >
            {{ toggling[rule.key] ? (rule.disabled ? tr('恢复中') : tr('禁用中')) : rule.disabled ? tr('启用') : tr('禁用') }}
          </button>
          <span v-else-if="!compact" class="rule-toggle muted small">—</span>
          <button
            v-if="compact"
            type="button"
            class="icon-btn sm rule-row-more"
            aria-haspopup="menu"
            :aria-label="tr('更多操作')"
            :title="tr('更多操作')"
            data-testid="rule-row-menu"
            @click="openMobileRowMenu(rule, $event)"
          >
            <Icon name="more" :size="14" />
          </button>
        </span>
      </div>
      <div v-if="virtual.tail.value" class="rule-spacer" aria-hidden="true" :style="{ height: `${virtual.tail.value}px` }" />
      <button
        v-if="filtered.length > limit"
        type="button"
        class="btn ghost block"
        data-testid="show-more-rules"
        @click="limit += PAGE"
      > {{ tr('显示更多（还有') }} {{ filtered.length - limit }} {{ tr('条）') }} </button>
    </div>

    <ContextMenu
      :open="Boolean(ctxMenu)"
      :x="ctxMenu?.x ?? 0"
      :y="ctxMenu?.y ?? 0"
      :items="ctxMenu?.items ?? []"
      :label="tr('规则操作')"
      @select="onContextSelect"
      @close="closeCtxMenu"
    />
  </div>
</template>

<style scoped>
.rule-matcher {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px 16px;
}

.rule-matcher-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.rule-matcher-title {
  margin: 0;
  font-size: var(--text-md, 15px);
  font-weight: 600;
}

.rule-matcher-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rule-matcher-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.rule-matcher-row .input {
  min-width: 180px;
}

.rule-matcher-extra {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.rule-matcher-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 120px;
}

.rule-matcher-status {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0;
}

.rule-matcher-result {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.rule-matcher-summary {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  margin: 0;
}

.rule-matcher-summary-label {
  flex: none;
  font-weight: 600;
  color: var(--text-2);
}

.rule-matcher-hit {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 12px;
  border-radius: var(--radius-sm, 8px);
  background: var(--surface-2, rgba(127, 127, 127, 0.08));
  border: 1px solid var(--border);
}

.rule-matcher-hit-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.rule-matcher-sub {
  margin: 0;
  word-break: break-all;
}

.rule-matcher-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.rule-matcher-miss {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0;
}

.rule-matcher-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.rule-matcher-section-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.rule-matcher-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.rule-matcher-item {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm, 8px);
  border: 1px solid var(--border);
}

.rule-matcher-item-body {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
  flex: 1 1 200px;
}

.rule-matcher-item-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.rule-matcher-reason {
  margin: 0;
}

.rule-matcher-item-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.rule-row.highlighted {
  background: color-mix(in srgb, var(--accent) 14%, transparent);
  box-shadow: inset 3px 0 0 var(--accent);
}
</style>
