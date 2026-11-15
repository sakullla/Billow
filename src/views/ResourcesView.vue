<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Skeleton from '../components/Skeleton.vue'
import { formatBytes, formatDate, formatRelative, usagePercent } from '../lib/format'
import { useStore } from '../lib/store'
import type { ProviderRow } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type Action = 'update' | 'healthcheck'
type RowState = 'pending' | 'error' | 'success'

interface RowProgress {
  state: RowState
  action: Action
  reason: string | null
  at: number | null
}

const providers = ref<ProviderRow[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
const loaded = ref(false)
const geoBusy = ref(false)
const progress = reactive<Record<string, RowProgress>>({})
const allRunning = reactive<Record<'proxy' | 'rule', boolean>>({ proxy: false, rule: false })
const allProgress = reactive<Record<'proxy' | 'rule', { done: number; total: number }>>({
  proxy: { done: 0, total: 0 },
  rule: { done: 0, total: 0 },
})

const proxySets = computed(() => providers.value.filter((item) => item.kind === 'proxy'))
const ruleSets = computed(() => providers.value.filter((item) => item.kind === 'rule'))

/** Inline providers carry their content in the config, so no fetch can update them (R28). */
const isInline = (row: ProviderRow) => row.vehicle.toLowerCase().includes('inline')

const keyOf = (row: ProviderRow) => `${row.kind}:${row.name}`
const stateOf = (row: ProviderRow) => progress[keyOf(row)] ?? null
const fruitless = (row: ProviderRow) => stateOf(row)?.state === 'pending'
const updatedMs = (row: ProviderRow) => {
  const ms = Date.parse(row.updated_at)
  return Number.isNaN(ms) || ms < 86_400_000 ? null : ms
}

async function load(quiet = false) {
  if (!quiet) loading.value = true
  try {
    const result = await store.backend.providers()
    if (result.error) {
      // A read failure must not leave last round's rows on screen (R29).
      error.value = result.error
      providers.value = []
    } else {
      providers.value = result.providers
      error.value = null
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
    providers.value = []
  } finally {
    loading.value = false
    loaded.value = true
  }
}

async function act(row: ProviderRow, action: Action, quiet = false) {
  const key = keyOf(row)
  progress[key] = { state: 'pending', action, reason: null, at: null }
  try {
    await store.backend.providerAction(row.kind, row.name, action)
    progress[key] = { state: 'success', action, reason: null, at: Date.now() }
    if (!quiet) {
      store.toast(action === 'update' ? `${row.name} 已更新` : `${row.name} 健康检查完成`, 'success')
    }
    return true
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    progress[key] = { state: 'error', action, reason, at: null }
    if (!quiet) store.toast(`${row.name}：${reason}`, 'error')
    return false
  }
}

async function single(row: ProviderRow, action: Action) {
  if (fruitless(row)) return
  const ok = await act(row, action)
  if (ok) await load(true)
  // A health check only touches its own row; no full page reload and no other row state.
  if (action === 'healthcheck') void store.refresh()
}

/** Sequential on purpose: each row paints 更新中/成功/失败 and the counter follows along (R28, R29). */
async function updateAll(rows: ProviderRow[], kind: 'proxy' | 'rule') {
  if (allRunning[kind]) return
  const updatable = rows.filter((row) => !isInline(row))
  allRunning[kind] = true
  allProgress[kind] = { done: 0, total: updatable.length }
  let failed = 0
  try {
    for (const row of updatable) {
      const ok = await act(row, 'update', true)
      if (!ok) failed += 1
      allProgress[kind] = { done: allProgress[kind].done + 1, total: updatable.length }
    }
    await load(true)
    const { done, total } = allProgress[kind]
    if (total) {
      store.toast(
        failed
          ? `更新完成：${done}/${total}，${failed} 个失败`
          : `已更新 ${done}/${total} 个${kind === 'proxy' ? '代理集' : '规则集'}`,
        failed ? 'error' : 'success',
      )
    }
  } finally {
    allRunning[kind] = false
  }
}

async function retry(row: ProviderRow) {
  const state = stateOf(row)
  if (!state || state.state !== 'error') return
  await single(row, state.action)
}

async function upgradeGeo() {
  geoBusy.value = true
  try {
    await store.backend.upgradeGeo()
    store.toast('GEO 数据库已更新', 'success')
  } catch (err) {
    store.toast(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    geoBusy.value = false
  }
}

const successText = (row: ProviderRow) => (stateOf(row)?.action === 'healthcheck' ? '检查通过' : '已更新')

// A stopped kernel drops the rows instead of showing the previous session (R31).
watch(
  () => snap.value.kernel_running,
  (running) => {
    if (running) {
      void load()
      return
    }
    providers.value = []
    error.value = null
    loading.value = false
  },
)

onMounted(() => void load())
</script>

<template>
  <div class="page resources">
    <header class="page-head">
      <div>
        <h1>外部资源</h1>
        <p class="muted small">配置中引用的代理集、规则集与 GEO 数据库</p>
      </div>
      <div class="head-actions">
        <button
          type="button"
          class="btn ghost sm"
          :disabled="loading"
          :aria-busy="loading || undefined"
          data-testid="refresh-providers"
          @click="load()"
        >
          <span v-if="loading" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="refresh" :size="15" />
          {{ loading ? '刷新中' : '刷新' }}
        </button>
      </div>
    </header>

    <section class="card">
      <div class="setting-row">
        <span class="row-icon"><Icon name="database" /></span>
        <div class="grow">
          <strong>GEO 数据库</strong>
          <p class="muted small">重新下载 GeoIP、GeoSite、MMDB 与 ASN 数据，地址取自配置中的 geox-url</p>
          <p v-if="!snap.kernel_running" class="muted small">连接后可更新</p>
        </div>
        <button
          type="button"
          class="btn sm"
          :disabled="!snap.kernel_running || geoBusy"
          :aria-busy="geoBusy || undefined"
          data-testid="upgrade-geo"
          @click="upgradeGeo"
        >
          <span v-if="geoBusy" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="download" :size="15" />
          {{ geoBusy ? '更新中' : '更新' }}
        </button>
      </div>
    </section>

    <Skeleton v-if="loading && !providers.length && snap.kernel_running" variant="card" :cards="2" />

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" title="内核未运行" description="连接后可以查看并更新配置中的 proxy-providers 与 rule-providers。">
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
    <EmptyState v-else-if="loaded && error && !providers.length" variant="error" title="读取失败" :description="error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-providers" @click="load()">重试</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="loaded && !providers.length && !loading" variant="no-data" title="这份配置没有使用外部资源" description="配置里的 proxy-providers 和 rule-providers 会显示在这里。">
      <template #action>
        <button type="button" class="btn ghost sm" @click="load()">刷新</button>
      </template>
    </EmptyState>

    <template v-for="section in [
      { kind: 'proxy' as const, title: '代理集', rows: proxySets },
      { kind: 'rule' as const, title: '规则集', rows: ruleSets },
    ]" :key="section.kind">
      <section v-if="section.rows.length" class="card provider-card">
        <header class="card-head">
          <h2>{{ section.title }} <span class="muted">{{ section.rows.length }}</span></h2>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="allRunning[section.kind]"
            :aria-busy="allRunning[section.kind] || undefined"
            :data-testid="`update-all-${section.kind}`"
            @click="updateAll(section.rows, section.kind)"
          >
            <span v-if="allRunning[section.kind]" class="spinner sm" aria-hidden="true" />
            <Icon v-else name="refresh" :size="15" />
            {{ allRunning[section.kind] ? `更新中 ${allProgress[section.kind].done}/${allProgress[section.kind].total}` : '全部更新' }}
          </button>
        </header>
        <div v-for="row in section.rows" :key="row.name" class="provider" :data-provider="row.name" :data-inline="isInline(row) ? 'true' : undefined">
          <div class="provider-main">
            <div class="provider-title">
              <strong class="ellipsis">{{ row.name }}</strong>
              <span class="tag">{{ row.vehicle || '—' }}</span>
              <span v-if="row.behavior" class="tag accent">{{ row.behavior }}</span>
              <span v-if="row.format" class="tag">{{ row.format }}</span>
            </div>
            <p class="muted small">
              {{ row.kind === 'proxy' ? `${row.count} 个节点` : `${row.count.toLocaleString()} 条规则` }}
              · 更新于 {{ formatRelative(updatedMs(row)) }}
              <template v-if="row.expire"> · {{ formatDate(row.expire) }} 到期</template>
            </p>
            <div v-if="usagePercent(row.used, row.total) != null" class="usage compact-usage">
              <div class="usage-bar"><span :style="{ width: `${usagePercent(row.used, row.total)}%` }" /></div>
              <span class="small mono muted">{{ formatBytes(row.used) }} / {{ formatBytes(row.total) }}</span>
            </div>
            <p v-if="isInline(row)" class="provider-note small" data-provider-inline>
              <Icon name="check" :size="13" />内联资源无需更新
            </p>
            <p v-if="stateOf(row)?.state === 'pending'" class="provider-note small muted" role="status" data-provider-state="pending">
              <span class="spinner sm" aria-hidden="true" />{{ stateOf(row)?.action === 'healthcheck' ? '检查中' : '更新中' }}
            </p>
            <p v-else-if="stateOf(row)?.state === 'success'" class="provider-note small muted" data-provider-state="success">
              <Icon name="check" :size="13" />{{ successText(row) }} · 刚刚
            </p>
            <p v-else-if="stateOf(row)?.state === 'error'" class="provider-note field-error small" role="alert" data-provider-state="error">
              <Icon name="alert" :size="13" />
              {{ stateOf(row)?.action === 'healthcheck' ? '健康检查失败' : '更新失败' }}：{{ stateOf(row)?.reason }}
              <button type="button" class="btn ghost sm" data-testid="retry-provider" @click="retry(row)">重试</button>
            </p>
          </div>
          <div class="provider-actions">
            <button
              v-if="row.kind === 'proxy'"
              type="button"
              class="icon-btn"
              :aria-label="`${row.name} 健康检查`"
              :title="`${row.name} 健康检查`"
              :disabled="fruitless(row)"
              @click="single(row, 'healthcheck')"
            >
              <span v-if="stateOf(row)?.state === 'pending' && stateOf(row)?.action === 'healthcheck'" class="spinner sm" />
              <Icon v-else name="zap" />
            </button>
            <button
              type="button"
              class="icon-btn"
              :aria-label="isInline(row) ? `${row.name} 无需更新` : `更新 ${row.name}`"
              :title="isInline(row) ? '内联资源无需更新' : `更新 ${row.name}`"
              :disabled="isInline(row) || fruitless(row)"
              @click="single(row, 'update')"
            >
              <span v-if="stateOf(row)?.state === 'pending' && stateOf(row)?.action === 'update'" class="spinner sm" />
              <Icon v-else name="refresh" />
            </button>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>
