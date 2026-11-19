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
import type { RuleRow } from '../lib/types'

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

onMounted(() => {
  void nextTick(() => virtual.measure(scroller.value))
})

// A remounted list (empty state round trip) and a changed filter both start at the
// first row instead of the previous offset (R31).
watch(scroller, (el) => virtual.measure(el))
watch([query, kind, proxy, sort, onlyDisabled], () => {
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
const isRuleSet = (rule: RuleRow) => /^rule-?set$/i.test(rule.kind.trim()) && Boolean(rule.payload.trim())

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

function onPolicyClick(policyName: string) {
  if (isGroup(policyName)) {
    store.go('proxies', policyName)
    return
  }
  proxy.value = proxy.value === policyName ? 'all' : policyName
}

const ctxMenu = ref<{ x: number; y: number; items: MenuItem[]; rule?: RuleRow } | null>(null)

function openHeadMenu(event: MouseEvent) {
  if (props.compact || !ruleCols.customized.value) return
  event.preventDefault()
  ctxMenu.value = {
    x: event.clientX,
    y: event.clientY,
    items: [{ id: 'reset-cols', get label() { return tr('恢复默认列宽') }, icon: 'refresh' }],
  }
}

function openRowMenu(rule: RuleRow, event: MouseEvent) {
  if (props.compact) return
  event.preventDefault()
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
  ctxMenu.value = { x: event.clientX, y: event.clientY, items, rule }
}

function onContextSelect(item: MenuItem) {
  const target = ctxMenu.value?.rule
  ctxMenu.value = null
  if (item.id === 'reset-cols') {
    ruleCols.resetAll()
    return
  }
  if (!target) return
  if (item.id === 'copy') void copyRuleRow(target)
  else if (item.id === 'filter-kind') kind.value = kind.value === target.kind ? 'all' : target.kind
  else if (item.id === 'filter-proxy') proxy.value = proxy.value === target.proxy ? 'all' : target.proxy
  else if (item.id === 'open-ruleset') store.openProvider('rule', target.payload)
  else if (item.id === 'open-group') store.go('proxies', target.proxy)
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
  } catch (err) {
    store.toast(tr('规则没有修改：{0}', { 0: err instanceof Error ? err.message : String(err) }), 'error')
  } finally {
    delete toggling[key]
  }
}

// A stopped kernel drops every row instead of keeping the previous session (R31).
watch(
  [() => snap.value.kernel_running, () => snap.value.active_id, () => store.current.value?.updated_ms],
  ([running]) => {
    ++loadId
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

onMounted(() => void load())
onBeforeUnmount(() => { ++loadId })
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

    <div v-if="rules.length" class="toolbar rule-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索规则内容或策略')" data-page-search />
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
        :class="{ disabled: rule.disabled }"
        :data-row-index="virtual.window.value.start + position"
        :data-rule-key="rule.key ?? undefined"
        :data-rule-disabled="rule.disabled ? 'true' : undefined"
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
              @click="store.openProvider('rule', rule.payload)"
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
          <span v-else class="rule-toggle muted small">—</span>
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
      v-if="ctxMenu"
      :x="ctxMenu.x"
      :y="ctxMenu.y"
      :items="ctxMenu.items"
      :label="tr('规则操作')"
      @select="onContextSelect"
      @close="ctxMenu = null"
    />
  </div>
</template>
