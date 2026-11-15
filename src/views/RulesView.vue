<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
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
const kind = ref('all')
const proxy = ref('all')
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

const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const indexed = rules.value.map((rule, index) => ({ rule, index }))
  const list = indexed.filter(({ rule }) => {
    if (kind.value !== 'all' && rule.kind !== kind.value) return false
    if (proxy.value !== 'all' && rule.proxy !== proxy.value) return false
    if (!needle) return true
    return [rule.kind, rule.payload, rule.proxy].some((text) => text.toLowerCase().includes(needle))
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
          {{ rules.length ? `${rules.length} 条规则，自上而下匹配` : '运行中的内核按这些规则分流' }}
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
      </div>
      <select v-model="kind" class="input sm rule-filter" aria-label="按类型筛选" data-testid="rule-kind-filter">
        <option value="all">全部类型 ({{ rules.length }})</option>
        <option v-for="[name, count] in kinds" :key="name" :value="name">{{ name }} ({{ count }})</option>
      </select>
      <select v-model="proxy" class="input sm rule-filter" aria-label="按策略筛选" data-testid="rule-proxy-filter">
        <option value="all">全部策略 ({{ proxies.length }})</option>
        <option v-for="[name, count] in proxies" :key="name" :value="name">{{ name }} ({{ count }})</option>
      </select>
      <Segmented v-if="hasHits" v-model="sort" :options="SORTS" size="sm" label="排序" />
    </div>

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" title="内核未运行" description="连接后可以查看当前配置生效的分流规则。">
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
    <EmptyState v-else-if="loaded && !rules.length" variant="no-data" title="没有规则" description="当前配置没有可显示的分流规则。">
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
        <span class="rule-payload mono ellipsis" :title="rule.payload">{{ rule.payload || '—' }}</span>
        <span class="rule-proxy">
          <span>{{ rule.proxy }}</span>
          <span v-if="rule.disabled" class="rule-flag small" data-rule-flag>临时，重启后恢复</span>
          <span v-else-if="!rule.key" class="rule-flag small muted">内核注入，无法临时禁用</span>
        </span>
        <template v-if="hasHits">
          <span class="rule-hit mono" :title="`命中 ${hitText(rule)} 次`" data-rule-hit>{{ hitText(rule) }}</span>
          <span class="rule-last-hit small muted">{{ lastHitText(rule) }}</span>
        </template>
        <button
          v-if="rule.key"
          type="button"
          class="btn ghost sm rule-toggle"
          :disabled="toggling[rule.key]"
          :aria-busy="toggling[rule.key] || undefined"
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
