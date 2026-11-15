<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import Skeleton from '../components/Skeleton.vue'
import { delayText, delayTone, formatBytes, formatDate, formatRelative, protocolLabel, usagePercent } from '../lib/format'
import { useStore } from '../lib/store'
import type { GeoFile, GeoSource, KernelSettings, ProviderDetail, ProviderRow } from '../lib/types'

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

const providers = shallowRef<ProviderRow[]>([])
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

let loadVersion = 0
let detailVersion = 0
let disposed = false

async function load(quiet = false) {
  const version = ++loadVersion
  if (!quiet) loading.value = true
  try {
    const result = await store.backend.providers()
    if (disposed || version !== loadVersion) return
    if (result.error) {
      // A read failure must not leave last round's rows on screen (R29).
      error.value = result.error
      providers.value = []
    } else {
      providers.value = result.providers
      error.value = null
    }
  } catch (err) {
    if (disposed || version !== loadVersion) return
    error.value = err instanceof Error ? err.message : String(err)
    providers.value = []
  } finally {
    if (!disposed && version === loadVersion) {
      loading.value = false
      loaded.value = true
    }
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
    await loadGeo()
  } catch (err) {
    store.toast(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    geoBusy.value = false
  }
}

// ── GEO databases: file state plus the three choices people actually make ──
const geoFiles = shallowRef<GeoFile[]>([])
const GEO_INTERVALS = [
  { id: '24', label: '每天' },
  { id: '72', label: '每 3 天' },
  { id: '168', label: '每周' },
] as const
const GEO_SOURCES: { id: GeoSource; label: string }[] = [
  { id: '', label: '跟随配置' },
  { id: 'github', label: 'GitHub' },
  { id: 'jsdelivr', label: 'jsDelivr 加速' },
]
const geoSettings = computed(() => snap.value.settings)
const geoInterval = computed(() => String(geoSettings.value.geo_update_interval ?? 24))
/** Files that exist, plus GeoIP/GeoSite even when missing: those are the ones rules depend on. */
const shownGeoFiles = computed(() => geoFiles.value.filter((file) => file.exists || file.key === 'geoip' || file.key === 'geosite'))

async function loadGeo() {
  try {
    geoFiles.value = await store.backend.geoFiles()
  } catch {
    geoFiles.value = []
  }
}

function saveGeo(patch: Partial<KernelSettings>) {
  void store.saveSettings({ ...snap.value.settings, ...patch })
}

// ── Provider detail sheet ──
const detail = shallowRef<{ row: ProviderRow; data: ProviderDetail | null; error: string | null } | null>(null)
const detailQuery = ref('')
const detailNeedle = computed(() => detailQuery.value.trim().toLowerCase())
const detailProxies = computed(() => {
  const rows = detail.value?.data?.proxies ?? []
  const needle = detailNeedle.value
  if (!needle) return rows
  return rows.filter((row) => row.name.toLowerCase().includes(needle) || [row.node_type, ...row.tags].some((tag) => tag.toLowerCase() === needle))
})
/** Rule lists can hold thousands of lines; the sheet renders a capped slice and says so. */
const RULE_PAGE = 400
const detailRules = computed(() => {
  const rows = detail.value?.data?.rules ?? []
  const needle = detailNeedle.value
  return needle ? rows.filter((rule) => rule.toLowerCase().includes(needle)) : rows
})

async function openDetail(row: ProviderRow) {
  const version = ++detailVersion
  detailQuery.value = ''
  detail.value = { row, data: null, error: null }
  try {
    const data = await store.backend.providerDetail(row.kind, row.name)
    if (!disposed && version === detailVersion && detail.value?.row === row) detail.value = { row, data, error: null }
  } catch (err) {
    if (!disposed && version === detailVersion && detail.value?.row === row) detail.value = { row, data: null, error: err instanceof Error ? err.message : String(err) }
  }
}

/** First token of a classical rule ("DOMAIN-SUFFIX,x") is its type; plain domain/IP lists have none. */
function ruleParts(rule: string): { type: string; rest: string } {
  const comma = rule.indexOf(',')
  const head = comma > 0 ? rule.slice(0, comma) : ''
  return /^[A-Z][A-Z0-9-]+$/.test(head) ? { type: head, rest: rule.slice(comma + 1) } : { type: '', rest: rule }
}

const successText = (row: ProviderRow) => (stateOf(row)?.action === 'healthcheck' ? '检查通过' : '已更新')

// A stopped kernel drops the rows instead of showing the previous session (R31).
watch(
  [() => snap.value.kernel_running, () => snap.value.active_id],
  ([running]) => {
    loadVersion++
    detailVersion++
    detail.value = null
    providers.value = []
    for (const key of Object.keys(progress)) delete progress[key]
    if (running) {
      void load()
      return
    }
    providers.value = []
    error.value = null
    loading.value = false
  },
)

onBeforeUnmount(() => {
  disposed = true
  loadVersion++
  detailVersion++
})

onMounted(() => {
  void load()
  void loadGeo()
})
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

    <section class="card geo-card" data-testid="geo-card">
      <header class="card-head">
        <div>
          <h2>GEO 数据库</h2>
          <p class="muted small">GeoIP / GeoSite 规则依赖的数据文件</p>
        </div>
        <button
          type="button"
          class="btn sm"
          :disabled="!snap.kernel_running || geoBusy"
          :aria-busy="geoBusy || undefined"
          :title="snap.kernel_running ? '立即重新下载' : '连接后可更新'"
          data-testid="upgrade-geo"
          @click="upgradeGeo"
        >
          <span v-if="geoBusy" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="download" :size="15" />
          {{ geoBusy ? '更新中' : snap.kernel_running ? '立即更新' : '连接后可更新' }}
        </button>
      </header>
      <ul v-if="shownGeoFiles.length" class="geo-files" data-testid="geo-files">
        <li v-for="file in shownGeoFiles" :key="file.key" :class="{ missing: !file.exists }" :title="file.file">
          <strong>{{ file.label }}</strong>
          <span class="muted small">
            {{ file.exists ? `${formatBytes(file.size)} · ${formatRelative(file.modified_ms)}` : '尚未下载' }}
          </span>
        </li>
      </ul>
      <div class="setting-row">
        <div class="grow">
          <strong>自动更新</strong>
          <p class="muted small">内核运行时按周期在后台下载新数据</p>
        </div>
        <Toggle
          :model-value="geoSettings.geo_auto_update === true"
          label="GEO 自动更新"
          data-testid="geo-auto-update"
          @update:model-value="(on) => saveGeo({ geo_auto_update: on, geo_update_interval: on ? Number(geoInterval) : geoSettings.geo_update_interval })"
        />
      </div>
      <div v-if="geoSettings.geo_auto_update" class="setting-row">
        <div class="grow"><strong>更新频率</strong></div>
        <Segmented
          :model-value="geoInterval"
          :options="GEO_INTERVALS"
          size="sm"
          label="更新频率"
          @update:model-value="(id) => saveGeo({ geo_update_interval: Number(id) })"
        />
      </div>
      <div class="setting-row">
        <div class="grow">
          <strong>下载源</strong>
          <p class="muted small">{{ geoSettings.geo_source ? 'MetaCubeX meta-rules-dat，覆盖配置中的 geox-url' : '使用配置中的 geox-url；没有写时用内核默认地址' }}</p>
        </div>
        <Segmented
          :model-value="geoSettings.geo_source"
          :options="GEO_SOURCES"
          size="sm"
          label="下载源"
          data-testid="geo-source"
          @update:model-value="(id) => saveGeo({ geo_source: id })"
        />
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
            <button
              type="button"
              class="provider-open"
              :aria-label="`查看 ${row.name} 的${row.kind === 'proxy' ? '节点' : '规则'}`"
              :data-testid="`open-provider-${row.name}`"
              @click="openDetail(row)"
            />
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

    <Modal
      v-if="detail"
      wide
      :title="detail.row.name"
      :subtitle="detail.row.kind === 'proxy'
        ? `代理集 · ${detail.data ? detail.data.total : detail.row.count} 个节点`
        : `规则集 · ${(detail.data?.total || detail.row.count).toLocaleString()} 条规则${detail.row.behavior ? ` · ${detail.row.behavior}` : ''}`"
      @close="detail = null"
    >
      <div class="provider-detail" data-testid="provider-detail">
        <p v-if="detail.data?.source && detail.data.source !== 'inline'" class="muted small mono ellipsis detail-source" :title="detail.data.source">{{ detail.data.source }}</p>
        <div v-if="detail.data && (detail.data.proxies.length || detail.data.rules.length)" class="search">
          <Icon name="search" :size="16" />
          <input v-model="detailQuery" type="search" :placeholder="detail.row.kind === 'proxy' ? '搜索节点、协议或 UDP' : '搜索规则'" />
        </div>
        <p v-if="detail.error" class="field-error" role="alert">{{ detail.error }}</p>
        <div v-else-if="!detail.data" class="detail-loading muted small"><span class="spinner xs" /> 正在读取…</div>
        <template v-else>
          <p v-if="detail.data.notice" class="banner info small" data-testid="provider-notice"><Icon name="info" :size="15" />{{ detail.data.notice }}</p>
          <ul v-if="detail.row.kind === 'proxy'" class="detail-list">
            <li v-for="proxy in detailProxies.slice(0, RULE_PAGE)" :key="proxy.name" class="detail-proxy">
              <span class="grow min0">
                <strong class="ellipsis">{{ proxy.name }}</strong>
                <span class="node-meta">
                  <span class="node-type">{{ protocolLabel(proxy.node_type) || proxy.node_type }}</span>
                  <span v-for="tag in proxy.tags" :key="tag" class="node-tag" :class="{ udp: tag === 'UDP' }">{{ tag }}</span>
                </span>
              </span>
              <span
                v-if="proxy.delay_ms != null || proxy.alive === false"
                class="delay"
                :class="delayTone(proxy.delay_ms, proxy.alive === false)"
              >{{ delayText(proxy.delay_ms, proxy.alive === false) }}</span>
            </li>
            <li v-if="detailProxies.length > RULE_PAGE" class="muted small empty-line">还有 {{ detailProxies.length - RULE_PAGE }} 个节点，输入关键词缩小范围</li>
            <li v-if="!detailProxies.length" class="muted small empty-line">{{ detailQuery ? '没有匹配的节点' : '这个代理集还没有节点' }}</li>
          </ul>
          <ol v-else-if="detail.data.rules.length" class="detail-list detail-rules mono">
            <li v-for="(rule, index) in detailRules.slice(0, RULE_PAGE)" :key="index">
              <span v-if="ruleParts(rule).type" class="rule-type">{{ ruleParts(rule).type }}</span>
              <span class="ellipsis">{{ ruleParts(rule).rest }}</span>
            </li>
            <li v-if="!detailRules.length" class="muted small empty-line">没有匹配的规则</li>
            <li v-else-if="detailRules.length > RULE_PAGE" class="muted small empty-line">
              还有 {{ (detailRules.length - RULE_PAGE).toLocaleString() }} 条，输入关键词缩小范围
            </li>
          </ol>
        </template>
      </div>
      <!-- The sheet's work action is primary; closing is the quiet way out. -->
      <template #footer>
        <button type="button" class="btn ghost" data-testid="close-provider-detail" @click="detail = null">关闭</button>
        <button
          v-if="detail.row.kind === 'proxy'"
          type="button"
          class="btn primary"
          :disabled="!snap.kernel_running || fruitless(detail.row)"
          :aria-busy="fruitless(detail.row) || undefined"
          @click="single(detail.row, 'healthcheck').then(() => detail && openDetail(detail.row))"
        >
          <span v-if="fruitless(detail.row)" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="zap" :size="15" />{{ fruitless(detail.row) ? '检查中' : '健康检查' }}
        </button>
        <button
          v-else-if="!isInline(detail.row)"
          type="button"
          class="btn primary"
          :disabled="!snap.kernel_running || fruitless(detail.row)"
          :aria-busy="fruitless(detail.row) || undefined"
          @click="single(detail.row, 'update').then(() => detail && openDetail(detail.row))"
        >
          <span v-if="fruitless(detail.row)" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="refresh" :size="15" />{{ fruitless(detail.row) ? '更新中' : '更新规则集' }}
        </button>
      </template>
    </Modal>
  </div>
</template>
