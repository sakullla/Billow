<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import SelectField from '../components/SelectField.vue'
import Skeleton from '../components/Skeleton.vue'
import { formatRelative } from '../lib/format'
import { useStore } from '../lib/store'
import { useVirtualList } from '../lib/ui/virtual'
import type { RuleRow } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type SortKey = 'order' | 'hits'

const ROW_HEIGHT = computed(() => (props.compact ? 88 : 52))
const PAGE = 300

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
        { id: 'order', label: '默认' },
        { id: 'hits', label: '命中' },
      ]
    : [{ id: 'order', label: '默认' }],
)

watch(hasHits, (available) => {
  if (!available) sort.value = 'order'
})

function countsOf(values: string[]): [string, number][] {
  const counts = new Map<string, number>()
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1))
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

const kinds = computed(() => countsOf(rules.value.map((rule) => rule.kind)))
const proxies = computed(() => countsOf(rules.value.map((rule) => rule.proxy)))

const kindOptions = computed(() => [
  { value: 'all', label: '全部类型', hint: String(rules.value.length) },
  ...kinds.value.map(([name, count]) => ({ value: name, label: name, hint: String(count) })),
])
const proxyOptions = computed(() => [
  { value: 'all', label: '全部策略', hint: String(proxies.value.length) },
  ...proxies.value.map(([name, count]) => ({ value: name, label: name, hint: String(count) })),
])

const needle = computed(() => query.value.trim().toLowerCase())
const isFiltered = computed(() => Boolean(needle.value) || kind.value !== 'all' || proxy.value !== 'all')

interface HighlightPart {
  text: string
  hit: boolean
}

function highlight(value: string): HighlightPart[] {
  const q = needle.value
  if (!q || !value) return [{ text: value, hit: false }]
  const lower = value.toLowerCase()
  const parts: HighlightPart[] = []
  let idx = 0
  let found = lower.indexOf(q)
  while (found >= 0) {
    if (found > idx) parts.push({ text: value.slice(idx, found), hit: false })
    parts.push({ text: value.slice(found, found + q.length), hit: true })
    idx = found + q.length
    found = lower.indexOf(q, idx)
  }
  if (idx < value.length) parts.push({ text: value.slice(idx), hit: false })
  return parts.length ? parts : [{ text: value, hit: false }]
}

const filtered = computed(() => {
  const q = needle.value
  const indexed = rules.value.map((rule, index) => ({ rule, index }))
  const list = indexed.filter(({ rule }) => {
    if (kind.value !== 'all' && rule.kind !== kind.value) return false
    if (proxy.value !== 'all' && rule.proxy !== proxy.value) return false
    if (!q) return true
    return [rule.kind, rule.payload, rule.proxy].some((text) => text.toLowerCase().includes(q))
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
watch([query, kind, proxy, sort], () => {
  limit.value = PAGE
  virtual.reset(scroller.value)
})

function resetFilters() {
  query.value = ''
  kind.value = 'all'
  proxy.value = 'all'
}

const labelOf = (rule: RuleRow) => rule.payload || rule.kind

/** Policies that name a proxy group can be opened; DIRECT/REJECT and plain nodes stay labels. */
const groupNames = computed(() => new Set(snap.value.node_catalog.map((group) => group.name)))
const isGroup = (name: string) => groupNames.value.has(name)

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
      disabling ? `已临时禁用 ${labelOf(rule)}，重启后恢复` : `已恢复 ${labelOf(rule)}`,
      'success',
    )
  } catch (err) {
    store.toast(`规则没有修改：${err instanceof Error ? err.message : String(err)}`, 'error')
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
        <h1>规则</h1>
        <p class="muted small">
          {{
            rules.length
              ? isFiltered
                ? `匹配 ${filtered.length} / ${rules.length} 条规则，自上而下匹配`
                : `${rules.length} 条规则，自上而下匹配`
              : '运行中的内核按这些规则分流'
          }}
          <template v-if="rules.length && hasHits"> · 命中信息来自内核</template>
        </p>
        <p v-if="rules.length && !hasHits" class="muted small" data-testid="rules-no-hits">
          当前内核不提供命中信息，已隐藏命中列。
        </p>
      </div>
      <div class="head-actions">
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
          {{ loading ? '刷新中' : '刷新' }}
        </button>
      </div>
    </header>

    <Skeleton v-if="loading && !rules.length && snap.kernel_running" variant="list" :rows="8" />

    <div v-if="rules.length" class="toolbar rule-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索规则内容或策略" data-page-search />
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          aria-label="清空搜索"
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
        label="按类型筛选"
        class="rule-filter"
        :class="{ filtered: kind !== 'all' }"
        data-testid="rule-kind-filter"
      />
      <SelectField
        v-model="proxy"
        :options="proxyOptions"
        :sheet="compact"
        size="sm"
        label="按策略筛选"
        class="rule-filter"
        :class="{ filtered: proxy !== 'all' }"
        data-testid="rule-proxy-filter"
      />
      <Segmented v-if="hasHits" v-model="sort" :options="SORTS" size="sm" label="排序" />
      <button v-if="isFiltered" type="button" class="btn ghost sm" data-testid="reset-rule-toolbar" @click="resetFilters">
        重置
      </button>
    </div>

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" icon="route" title="内核未运行" description="连接后可以查看当前配置生效的分流规则。">
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
    <EmptyState v-else-if="loaded && error && !rules.length" variant="error" title="读取失败" :description="error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-rules" @click="load()">重试</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="loaded && !rules.length" variant="no-data" icon="route" title="没有规则" description="当前配置没有可显示的分流规则。">
      <template #action>
        <button type="button" class="btn ghost sm" @click="load()">刷新</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="rules.length && !filtered.length" variant="no-match" title="没有匹配的规则" description="换一个关键词或筛选条件，或清空当前筛选。">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="clear-rule-filter" @click="resetFilters">清空筛选</button>
      </template>
    </EmptyState>

    <div v-if="filtered.length" ref="scroller" class="card list-card rule-scroll" data-testid="rule-scroll" @scroll="virtual.onScroll">
      <!-- Column captions: without them the hit count and last-hit time are bare numbers. -->
      <div v-if="!compact" class="rule-head" aria-hidden="true" data-testid="rule-head">
        <span class="rule-index">#</span>
        <span class="rule-head-main">类型 · 内容</span>
        <span class="rule-head-proxy">策略</span>
        <template v-if="hasHits">
          <span class="rule-hit">命中</span>
          <span class="rule-last-hit">最近命中</span>
        </template>
        <span class="rule-toggle" />
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
      >
        <span class="rule-index mono muted">{{ index + 1 }}</span>
        <span class="tag">{{ rule.kind }}</span>
        <span v-if="rule.disabled" class="tag warn rule-off-tag" data-testid="rule-off-tag">已禁用</span>
        <span class="rule-payload mono ellipsis" :title="rule.payload">
          <template v-if="rule.payload">
            <template v-for="(part, partIdx) in highlight(rule.payload)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </template>
          <template v-else>—</template>
        </span>
        <span class="rule-proxy" :data-policy="rule.proxy.toUpperCase()">
          <component
            :is="isGroup(rule.proxy) ? 'button' : 'span'"
            class="rule-proxy-badge"
            :class="{ link: isGroup(rule.proxy) }"
            :type="isGroup(rule.proxy) ? 'button' : undefined"
            :title="isGroup(rule.proxy) ? `前往代理组「${rule.proxy}」` : undefined"
            :data-testid="isGroup(rule.proxy) ? 'rule-proxy-link' : undefined"
            @click="isGroup(rule.proxy) && store.go('proxies', rule.proxy)"
          >
            <template v-for="(part, partIdx) in highlight(rule.proxy)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </component>
          <span v-if="rule.disabled" class="rule-flag small" data-rule-flag>临时，重启后恢复</span>
          <span v-else-if="!rule.key" class="rule-flag small muted">内核注入，无法临时禁用</span>
        </span>
        <template v-if="hasHits">
          <span class="rule-hit mono" :title="`命中 ${hitText(rule)} 次`" data-rule-hit>{{ hitText(rule) }}</span>
          <span class="rule-last-hit small muted">{{ lastHitText(rule) }}</span>
        </template>
        <!-- Desktop reveals the action on hover/focus; disabled rows keep 「启用」 visible (R4). Phones use a compact icon. -->
        <button
          v-if="rule.key && compact"
          type="button"
          class="icon-btn sm rule-toggle"
          :class="{ active: rule.disabled }"
          :disabled="toggling[rule.key]"
          :aria-busy="toggling[rule.key] || undefined"
          :aria-label="rule.disabled ? `启用规则 ${labelOf(rule)}` : `临时禁用规则 ${labelOf(rule)}`"
          :title="rule.disabled ? '启用' : '临时禁用'"
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
          :aria-label="rule.disabled ? `启用规则 ${labelOf(rule)}` : `临时禁用规则 ${labelOf(rule)}`"
          data-testid="rule-toggle"
          @click="toggle(rule)"
        >
          {{ toggling[rule.key] ? (rule.disabled ? '恢复中' : '禁用中') : rule.disabled ? '启用' : '禁用' }}
        </button>
        <span v-else class="rule-toggle muted small">—</span>
      </div>
      <div v-if="virtual.tail.value" class="rule-spacer" aria-hidden="true" :style="{ height: `${virtual.tail.value}px` }" />
      <button
        v-if="filtered.length > limit"
        type="button"
        class="btn ghost block"
        data-testid="show-more-rules"
        @click="limit += PAGE"
      >
        显示更多（还有 {{ filtered.length - limit }} 条）
      </button>
    </div>
  </div>
</template>
