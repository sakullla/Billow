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
import {
  defaultGeoUrls,
  GEO_SOURCE_PRESETS,
  type GeoFile,
  type GeoSource,
  type GeoUrls,
  type KernelSettings,
  type ProviderDetail,
  type ProviderRow,
} from '../lib/types'

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
const geoError = ref<string | null>(null)
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

const geoBusyKey = ref<string | null>(null)
const lastFailedGeoKey = ref<string | undefined>(undefined)

// ── GEO databases: file state, mode, source preset, and per-database URLs ──
const geoFiles = shallowRef<GeoFile[]>([])
const GEO_INTERVALS = [
  { id: '24', label: '每天' },
  { id: '72', label: '每 3 天' },
  { id: '168', label: '每周' },
] as const
const GEO_SOURCES: { id: GeoSource; label: string }[] = [
  { id: '', label: '默认' },
  { id: 'github', label: 'GitHub' },
  { id: 'jsdelivr', label: 'jsDelivr' },
  { id: 'testingcf', label: 'CF' },
]
const GEODATA_MODES = [
  { id: '', label: '默认' },
  { id: 'db', label: 'MMDB' },
  { id: 'dat', label: 'DAT' },
] as const
const GEO_URL_FIELDS: { key: keyof GeoUrls; label: string }[] = [
  { key: 'geoip', label: 'GeoIP' },
  { key: 'mmdb', label: 'MMDB' },
  { key: 'geosite', label: 'GeoSite' },
  { key: 'asn', label: 'ASN' },
]
const geoOpen = ref(false)
const geoSettings = computed(() => snap.value.settings)
const geoMissing = computed(() => geoFiles.value.filter((file) => !file.exists).length)
const geoLatest = computed(() =>
  geoFiles.value.reduce<number | null>((latest, file) => (file.exists && file.modified_ms && (!latest || file.modified_ms > latest) ? file.modified_ms : latest), null),
)
/** One plain sentence instead of four cards: ready or not, how fresh, and whether it maintains itself. */
const geoSummary = computed(() => {
  if (!geoFiles.value.length) return '分流规则依赖的地域与域名数据'
  const parts = [
    geoMissing.value ? `${geoMissing.value} 个尚未下载` : '全部就绪',
  ]
  if (geoLatest.value) parts.push(`${formatRelative(geoLatest.value)}更新`)
  parts.push(geoSettings.value.geo_auto_update ? '自动更新' : '手动更新')
  return parts.join(' · ')
})
const geoInterval = computed(() => String(geoSettings.value.geo_update_interval ?? 24))
const geodataModeId = computed(() => {
  const mode = geoSettings.value.geodata_mode
  return mode == null ? '' : mode ? 'dat' : 'db'
})
const shownGeoFiles = computed(() => geoFiles.value)

const geoUrlsDraft = reactive<GeoUrls>(defaultGeoUrls())
const geoUrlFocused = ref(false)
let lastSyncedGeoUrls = ''
watch(
  () => snap.value.settings.geo_urls,
  (urls) => {
    const serialized = JSON.stringify(urls)
    if (serialized === lastSyncedGeoUrls) return
    lastSyncedGeoUrls = serialized
    if (!geoUrlFocused.value) {
      geoUrlsDraft.geoip = urls.geoip
      geoUrlsDraft.mmdb = urls.mmdb
      geoUrlsDraft.geosite = urls.geosite
      geoUrlsDraft.asn = urls.asn
    }
  },
  { immediate: true, deep: true },
)

const normalizedGeoUrlsDraft = computed<GeoUrls>(() => ({
  geoip: geoUrlsDraft.geoip.trim(),
  mmdb: geoUrlsDraft.mmdb.trim(),
  geosite: geoUrlsDraft.geosite.trim(),
  asn: geoUrlsDraft.asn.trim(),
}))
const geoUrlsDirty = computed(
  () => JSON.stringify(normalizedGeoUrlsDraft.value) !== JSON.stringify(snap.value.settings.geo_urls),
)
const hasCustomGeoUrls = computed(() =>
  Object.values(normalizedGeoUrlsDraft.value).some((url) => url.length > 0),
)

function geoUrlPlaceholder(key: keyof GeoUrls): string {
  const src = geoSettings.value.geo_source || 'github'
  const preset = GEO_SOURCE_PRESETS[src === 'jsdelivr' || src === 'testingcf' ? src : 'github']
  return preset[key]
}

async function commitGeoUrls() {
  if (!geoUrlsDirty.value) return
  const nextUrls = { ...normalizedGeoUrlsDraft.value }
  lastSyncedGeoUrls = JSON.stringify(nextUrls)
  geoError.value = null
  await store.saveSettings({ ...snap.value.settings, geo_urls: nextUrls })
}

function resetGeoUrls() {
  const empty = defaultGeoUrls()
  geoUrlsDraft.geoip = empty.geoip
  geoUrlsDraft.mmdb = empty.mmdb
  geoUrlsDraft.geosite = empty.geosite
  geoUrlsDraft.asn = empty.asn
  lastSyncedGeoUrls = JSON.stringify(empty)
  void store.saveSettings({ ...snap.value.settings, geo_urls: empty })
}

async function loadGeo() {
  try {
    geoFiles.value = await store.backend.geoFiles()
  } catch {
    geoFiles.value = []
  }
}

function saveGeo(patch: Partial<KernelSettings>) {
  if (patch.geo_source !== undefined || patch.geo_urls !== undefined) geoError.value = null
  void store.saveSettings({ ...snap.value.settings, ...patch })
}

async function upgradeGeo(key?: string) {
  if (geoBusy.value) return
  geoBusy.value = true
  geoBusyKey.value = key ?? 'all'
  geoError.value = null
  try {
    if (geoUrlsDirty.value) await commitGeoUrls()
    const updated = await store.backend.upgradeGeo(key)
    geoError.value = null
    lastFailedGeoKey.value = undefined
    if (Array.isArray(updated)) {
      geoFiles.value = updated
    } else {
      await loadGeo()
    }
    const label = key ? (shownGeoFiles.value.find((f) => f.key === key)?.label ?? key.toUpperCase()) : 'GEO'
    store.toast(`${label} 数据库已更新`, 'success')
  } catch (err) {
    lastFailedGeoKey.value = key
    geoError.value = err instanceof Error ? err.message : String(err)
  } finally {
    geoBusy.value = false
    geoBusyKey.value = null
  }
}

async function switchJsdelivrAndUpgrade() {
  if (geoBusy.value) return
  geoError.value = null
  await store.saveSettings({ ...snap.value.settings, geo_source: 'jsdelivr' })
  await upgradeGeo(lastFailedGeoKey.value)
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

// A stopped kernel drops the rows instead of showing the previous session (R31),
// while hot-reloads that keep kernel_running=true preserve the existing provider list.
watch(
  [() => snap.value.kernel_running, () => snap.value.active_id],
  ([running, activeId], [prevRunning, prevActiveId]) => {
    if (running && prevRunning && activeId === prevActiveId) return
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
        <h1>资源</h1>
        <p class="muted small">配置引用的代理集与规则集</p>
      </div>
      <div v-if="snap.kernel_running" class="head-actions">
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

    <Skeleton v-if="loading && !providers.length && snap.kernel_running" variant="card" :cards="2" />

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" icon="database" title="内核未运行" description="连接后可以查看并更新配置中的 proxy-providers 与 rule-providers。">
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
          <h2>{{ section.title }} <span class="count-pill">{{ section.rows.length }}</span></h2>
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
              <span class="provider-glyph" :class="row.kind" aria-hidden="true">
                <Icon :name="row.kind === 'proxy' ? 'globe' : isInline(row) ? 'code' : 'route'" :size="16" />
              </span>
              <div class="min0 grow">
                <strong class="ellipsis">{{ row.name }}</strong>
                <p class="muted small provider-meta">
                  <span>{{ row.kind === 'proxy' ? `${row.count} 个节点` : `${row.count.toLocaleString()} 条规则` }}</span>
                  <span v-if="row.behavior">{{ row.behavior }}</span>
                  <span v-if="isInline(row)" data-provider-inline>内联 · 无需更新</span>
                  <span v-else>{{ formatRelative(updatedMs(row)) }}更新</span>
                  <span v-if="row.expire">{{ formatDate(row.expire) }} 到期</span>
                </p>
              </div>
            </div>
            <div v-if="usagePercent(row.used, row.total) != null" class="usage compact-usage">
              <div class="usage-bar"><span :style="{ width: `${usagePercent(row.used, row.total)}%` }" /></div>
              <span class="small mono muted">{{ formatBytes(row.used) }} / {{ formatBytes(row.total) }}</span>
            </div>
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
            <span class="provider-chevron" aria-hidden="true"><Icon name="chevron-right" :size="15" /></span>
          </div>
        </div>
      </section>
    </template>


    <!-- GEO data is plumbing: one quiet strip with a single action; everything else lives behind 设置. -->
    <section class="card geo-card" data-testid="geo-card">
      <div class="geo-strip">
        <span class="geo-glyph" :class="{ warn: geoMissing > 0 }" aria-hidden="true"><Icon name="globe" :size="18" /></span>
        <div class="grow min0">
          <strong>GEO 数据库</strong>
          <p class="muted small ellipsis" data-testid="geo-summary">{{ geoSummary }}</p>
        </div>
        <button
          type="button"
          class="icon-btn"
          title="GEO 设置"
          aria-label="GEO 设置"
          data-testid="open-geo-settings"
          @click="geoOpen = true"
        >
          <Icon name="sliders" :size="16" />
        </button>
        <button
          type="button"
          class="btn sm"
          :disabled="geoBusy"
          :aria-busy="geoBusy || undefined"
          title="下载并更新全部 GEO 数据库"
          data-testid="upgrade-geo"
          @click="upgradeGeo()"
        >
          <span v-if="geoBusy" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="download" :size="15" />
          {{ geoBusy ? '更新中' : '更新' }}
        </button>
      </div>
      <ul v-if="shownGeoFiles.length" class="geo-chips" data-testid="geo-files">
        <li v-for="file in shownGeoFiles" :key="file.key" :class="{ missing: !file.exists }" :title="file.file">
          <span class="geo-chip-dot" aria-hidden="true" />
          <strong>{{ file.label }}</strong>
          <span class="muted">{{ file.exists ? formatBytes(file.size) : '未下载' }}</span>
        </li>
      </ul>
      <div v-if="geoError" class="geo-alert" role="alert" data-testid="geo-error">
        <Icon name="alert" :size="15" />
        <span class="geo-alert-text small">{{ geoError }}</span>
        <div class="geo-alert-actions">
          <button
            v-if="geoSettings.geo_source !== 'jsdelivr'"
            type="button"
            class="btn primary sm"
            :disabled="geoBusy"
            data-testid="geo-switch-jsdelivr"
            @click="switchJsdelivrAndUpgrade"
          >
            切换 jsDelivr 重试
          </button>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="geoBusy"
            data-testid="geo-retry"
            @click="upgradeGeo(lastFailedGeoKey)"
          >
            重试
          </button>
        </div>
      </div>
    </section>

    <Modal v-if="geoOpen" title="GEO 数据库" subtitle="GEOIP、GEOSITE 规则使用的地域与域名数据" @close="geoOpen = false">
      <div class="geo-sheet" data-testid="geo-settings">
        <ul class="geo-file-list" data-testid="geo-file-list">
          <li v-for="file in shownGeoFiles" :key="file.key" :class="{ missing: !file.exists }">
            <span class="geo-chip-dot" aria-hidden="true" />
            <div class="grow min0">
              <strong>{{ file.label }}</strong>
              <span class="muted small mono">{{ file.file }}</span>
            </div>
            <span class="muted small geo-file-meta">
              {{ file.exists ? `${formatBytes(file.size)} · ${formatRelative(file.modified_ms)}` : '尚未下载' }}
            </span>
            <button
              type="button"
              class="icon-btn sm"
              :disabled="geoBusy"
              :title="`更新 ${file.label}`"
              :aria-label="`更新 ${file.label}`"
              :data-testid="`upgrade-geo-${file.key}`"
              @click="upgradeGeo(file.key)"
            >
              <span v-if="geoBusy && (geoBusyKey === file.key || geoBusyKey === 'all')" class="spinner xs" aria-hidden="true" />
              <Icon v-else name="download" :size="14" />
            </button>
          </li>
        </ul>

        <div class="geo-options">
          <div class="setting-row">
            <div class="grow">
              <strong>自动更新</strong>
              <p class="muted small">内核运行时在后台定期同步</p>
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
              <p class="muted small">{{ geoSettings.geo_source ? '下载慢或失败时可换用加速镜像' : '沿用配置中的 geox-url' }}</p>
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
          <div class="setting-row">
            <div class="grow">
              <strong>GeoIP 格式</strong>
              <p class="muted small">{{ geodataModeId === 'dat' ? '使用 GeoIP.dat' : geodataModeId === 'db' ? '使用 Country.mmdb' : '沿用配置中的 geodata-mode' }}</p>
            </div>
            <Segmented
              :model-value="geodataModeId"
              :options="GEODATA_MODES"
              size="sm"
              label="GeoIP 格式"
              data-testid="geodata-mode"
              @update:model-value="(id) => saveGeo({ geodata_mode: id === '' ? null : id === 'dat' })"
            />
          </div>
        </div>

        <details class="geo-advanced" data-testid="geo-urls-section" :open="hasCustomGeoUrls || undefined">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span class="grow">自定义下载地址</span>
            <span v-if="hasCustomGeoUrls" class="tag accent sm">已自定义</span>
          </summary>
          <p class="muted small">留空则使用上方下载源。</p>
          <div class="geo-url-list">
            <label v-for="item in GEO_URL_FIELDS" :key="item.key" class="geo-url-row" :for="`geo-url-${item.key}`">
              <span class="geo-url-label">{{ item.label }}</span>
              <input
                :id="`geo-url-${item.key}`"
                v-model="geoUrlsDraft[item.key]"
                type="url"
                class="input sm mono"
                spellcheck="false"
                :placeholder="geoUrlPlaceholder(item.key)"
                :aria-label="`${item.label} 下载地址`"
                :data-testid="`geo-url-${item.key}`"
                @focus="geoUrlFocused = true"
                @blur="geoUrlFocused = false; commitGeoUrls()"
                @keydown.enter="($event.target as HTMLInputElement).blur()"
              />
            </label>
          </div>
          <div v-if="geoUrlsDirty || hasCustomGeoUrls" class="geo-url-actions">
            <button
              v-if="hasCustomGeoUrls && !geoUrlsDirty"
              type="button"
              class="btn ghost sm"
              data-testid="reset-geo-urls"
              @click="resetGeoUrls"
            >
              恢复默认
            </button>
            <button
              v-if="geoUrlsDirty"
              type="button"
              class="btn primary sm"
              data-testid="save-geo-urls"
              @mousedown.prevent
              @click="commitGeoUrls"
            >
              保存地址
            </button>
          </div>
        </details>
      </div>
    </Modal>

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
        <div v-if="detail.data?.source && detail.data.source !== 'inline'" class="detail-source-row">
          <p class="muted small mono ellipsis detail-source grow" :title="detail.data.source">{{ detail.data.source }}</p>
          <button
            type="button"
            class="icon-btn sm"
            title="复制来源地址"
            aria-label="复制来源地址"
            data-testid="copy-provider-source"
            @click="store.copyText(detail.data.source, '已复制来源地址')"
          >
            <Icon name="copy" :size="13" />
          </button>
        </div>
        <div v-if="detail.data && (detail.data.proxies.length || detail.data.rules.length)" class="search">
          <Icon name="search" :size="16" />
          <input v-model="detailQuery" type="search" :placeholder="detail.row.kind === 'proxy' ? '搜索节点、协议或 UDP' : '搜索规则'" />
          <span v-if="detailNeedle" class="small muted mono">
            {{ detail.row.kind === 'proxy' ? detailProxies.length : detailRules.length }}
          </span>
          <button
            v-if="detailQuery"
            type="button"
            class="icon-btn sm"
            aria-label="清空搜索"
            data-testid="clear-provider-search"
            @click="detailQuery = ''"
          >
            <Icon name="x" :size="14" />
          </button>
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
