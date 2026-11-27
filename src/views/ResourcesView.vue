<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, inject, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import Skeleton from '../components/Skeleton.vue'
import { delayText, delayTone, formatBytes, formatDate, formatRelative, protocolLabel, usagePercent } from '../lib/format'
import { runPool } from '../lib/pool'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
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
const connectionBack = inject<(() => void) | null>('connectionBack', null)
const ruleBack = inject<(() => void) | null>('ruleBack', null)

function closeProviderDetail() {
  const closedName = detail.value?.row.name ?? null
  detail.value = null
  if (
    typeof window !== 'undefined' &&
    window.matchMedia?.('(pointer: coarse)').matches !== true
  ) {
    void nextTick(() => {
      if (document.activeElement && document.activeElement !== document.body) return
      const target =
        document.querySelector<HTMLElement>('[data-testid="connection-return"]') ??
        document.querySelector<HTMLElement>('[data-testid="rule-return"]') ??
        document.querySelector<HTMLElement>('[data-testid="page-back"]') ??
        (closedName ? document.querySelector<HTMLElement>(`[data-testid="open-provider-${CSS.escape(closedName)}"]`) : null)
      target?.focus({ preventScroll: true })
    })
  }
}

async function returnToConnection() {
  detail.value = null
  await nextTick()
  if (connectionBack) connectionBack()
  else store.go('connections')
}

async function returnToRule() {
  detail.value = null
  await nextTick()
  if (ruleBack) ruleBack()
  else store.go('rules')
}

type Action = 'update' | 'healthcheck'
type RowState = 'pending' | 'error' | 'success'
type ProviderFilter = 'all' | 'proxy' | 'rule' | 'failed'

interface RowProgress {
  state: RowState
  action: Action
  reason: string | null
  at: number | null
}

interface BatchState {
  running: boolean
  action: Action | null
  done: number
  total: number
}

const providers = shallowRef<ProviderRow[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
const loaded = ref(false)
const geoBusy = ref(false)
const geoError = ref<string | null>(null)
const progress = reactive<Record<string, RowProgress>>({})
const batchState = reactive<Record<'proxy' | 'rule', BatchState>>({
  proxy: { running: false, action: null, done: 0, total: 0 },
  rule: { running: false, action: null, done: 0, total: 0 },
})

const proxySets = computed(() => providers.value.filter((item) => item.kind === 'proxy'))
const ruleSets = computed(() => providers.value.filter((item) => item.kind === 'rule'))

const query = ref('')
const providerFilter = ref<ProviderFilter>('all')
const needle = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))
const isFiltered = computed(() => Boolean(needle.value) || providerFilter.value !== 'all')
const failedTotal = computed(() => providers.value.filter((row) => stateOf(row)?.state === 'error').length)
const PROVIDER_FILTER_OPTIONS = computed(() => [
  { id: 'all' as const, label: tr('全部') },
  { id: 'proxy' as const, label: tr('代理集') },
  { id: 'rule' as const, label: tr('规则集') },
  { id: 'failed' as const, label: failedTotal.value > 0 ? `${tr('异常')} (${failedTotal.value})` : tr('异常') },
])
const matchesQuery = (row: ProviderRow) =>
  !queryTokens.value.length || matchesTokens(`${row.name} ${row.behavior} ${row.format}`, queryTokens.value)
const matchesFilter = (row: ProviderRow) => {
  if (providerFilter.value === 'proxy' && row.kind !== 'proxy') return false
  if (providerFilter.value === 'rule' && row.kind !== 'rule') return false
  if (providerFilter.value === 'failed' && stateOf(row)?.state !== 'error') return false
  return true
}
const matches = (row: ProviderRow) => matchesFilter(row) && matchesQuery(row)
const sections = computed(() => [
  { kind: 'proxy' as const, get title() { return tr('代理集') }, all: proxySets.value, rows: proxySets.value.filter(matches) },
  { kind: 'rule' as const, get title() { return tr('规则集') }, all: ruleSets.value, rows: ruleSets.value.filter(matches) },
])
const visibleCount = computed(() => sections.value.reduce((sum, section) => sum + section.rows.length, 0))
const noMatch = computed(() => isFiltered.value && providers.value.length > 0 && visibleCount.value === 0)

function resetFilters() {
  query.value = ''
  providerFilter.value = 'all'
}

/** Sections fold away once they are just plumbing; the choice survives restarts. */
const COLLAPSE_KEY = 'billow.resources.collapsed'
function readCollapsed(): Record<'proxy' | 'rule', boolean> {
  try {
    const raw = JSON.parse(localStorage.getItem(COLLAPSE_KEY) ?? '{}') as Record<string, unknown>
    return { proxy: raw.proxy === true, rule: raw.rule === true }
  } catch {
    return { proxy: false, rule: false }
  }
}
const collapsed = reactive(readCollapsed())
function toggleSection(kind: 'proxy' | 'rule') {
  collapsed[kind] = !collapsed[kind]
  try {
    localStorage.setItem(COLLAPSE_KEY, JSON.stringify(collapsed))
  } catch {
    // Storage is optional; the fold still applies for this session.
  }
}
/** Active search or category/status filter always reveals matching sections, folded or not. */
const isOpen = (kind: 'proxy' | 'rule') => !collapsed[kind] || isFiltered.value

/** One-line digest for a folded section: freshest update and anything needing attention. */
function sectionSummary(rows: ProviderRow[]): string {
  const parts: string[] = []
  const failed = rows.filter((row) => stateOf(row)?.state === 'error')
  if (failed.length) {
    const allHealthcheck = failed.every((row) => stateOf(row)?.action === 'healthcheck')
    parts.push(allHealthcheck ? tr('{0} 个检查失败', { 0: failed.length }) : tr('{0} 个更新失败', { 0: failed.length }))
  }
  const latest = rows.reduce<number | null>((max, row) => {
    const ms = updatedMs(row)
    return ms != null && (max == null || ms > max) ? ms : max
  }, null)
  if (latest != null) parts.push(tr('最近更新 {0}', { 0: formatRelative(latest) }))
  return parts.join(' · ')
}

/** Inline providers carry their content in the config, so no fetch can update them (R28). */
const isInline = (row: ProviderRow) => row.vehicle.toLowerCase().includes('inline')

const keyOf = (row: ProviderRow) => `${row.kind}:${row.name}`
const stateOf = (row: ProviderRow) => progress[keyOf(row)] ?? null
const fruitless = (row: ProviderRow) => stateOf(row)?.state === 'pending'
const hasPendingInKind = (kind: 'proxy' | 'rule') =>
  Object.entries(progress).some(([key, value]) => key.startsWith(`${kind}:`) && value.state === 'pending')
const sectionBusy = (kind: 'proxy' | 'rule') =>
  batchState[kind].running || hasPendingInKind(kind)
const updatedMs = (row: ProviderRow) => {
  const ms = Date.parse(row.updated_at)
  return Number.isNaN(ms) || ms < 86_400_000 ? null : ms
}

let loadVersion = 0
let detailVersion = 0
let batchEpoch = 0
let disposed = false

async function load(quiet = false) {
  if (disposed) return
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
      consumeFocusProvider()
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

async function act(row: ProviderRow, action: Action, quiet = false, expectedEpoch = batchEpoch) {
  if (fruitless(row)) return false
  const key = keyOf(row)
  progress[key] = { state: 'pending', action, reason: null, at: null }
  try {
    await store.backend.providerAction(row.kind, row.name, action)
    if (disposed || expectedEpoch !== batchEpoch) return false
    progress[key] = { state: 'success', action, reason: null, at: Date.now() }
    if (!quiet) {
      store.toast(action === 'update' ? tr('{0} 已更新', { 0: row.name }) : tr('{0} 健康检查完成', { 0: row.name }), 'success')
    }
    return true
  } catch (err) {
    if (disposed || expectedEpoch !== batchEpoch) return false
    const reason = err instanceof Error ? err.message : String(err)
    progress[key] = { state: 'error', action, reason, at: null }
    if (!quiet) store.toast(`${row.name}：${reason}`, 'error')
    return false
  }
}

async function single(row: ProviderRow, action: Action): Promise<boolean> {
  if (!snap.value.kernel_running || sectionBusy(row.kind)) return false
  const epoch = batchEpoch
  const ok = await act(row, action, false, epoch)
  if (disposed || epoch !== batchEpoch) return false
  if (ok) await load(true)
  // A health check only touches its own row; no full page reload and no other row state.
  if (action === 'healthcheck') void store.refresh()
  return ok
}

async function runDetailAction(action: Action) {
  const row = detail.value?.row
  if (!row) return
  const ok = await single(row, action)
  if (!ok || disposed) return
  const current = detail.value?.row
  if (current && current.kind === row.kind && current.name === row.name) {
    await openDetail(current)
  }
}

const failedRows = (rows: ProviderRow[]) =>
  rows.filter((row) => {
    const state = stateOf(row)
    if (!state || state.state !== 'error') return false
    return state.action === 'healthcheck' || !isInline(row)
  })

/**
 * Bounded concurrent pool: runs update or healthcheck across up to 3 proxy providers
 * or 4 rule providers in parallel while keeping per-row state isolated, mutually
 * excluding concurrent batches per section, and safely invalidating on profile switch / stop.
 */
async function runBatch(
  rows: ProviderRow[],
  kind: 'proxy' | 'rule',
  action: Action,
  onlyFailed = false,
) {
  if (!snap.value.kernel_running || sectionBusy(kind)) return
  const targets: { row: ProviderRow; action: Action }[] = onlyFailed
    ? failedRows(rows).map((row) => ({ row, action: stateOf(row)?.action ?? action }))
    : rows
        .filter((row) => action === 'healthcheck' || !isInline(row))
        .map((row) => ({ row, action }))
  if (!targets.length) return

  const epoch = batchEpoch
  const allHealthcheck = targets.every((item) => item.action === 'healthcheck')
  const anyHealthcheck = targets.some((item) => item.action === 'healthcheck')
  const displayAction: Action = allHealthcheck ? 'healthcheck' : 'update'

  batchState[kind].running = true
  batchState[kind].action = displayAction
  batchState[kind].done = 0
  batchState[kind].total = targets.length
  try {
    const { done, failed } = await runPool(
      targets,
      {
        concurrency: kind === 'rule' ? 4 : 3,
        shouldStop: () => disposed || epoch !== batchEpoch || !snap.value.kernel_running,
        onProgress: (completed) => {
          if (disposed || epoch !== batchEpoch) return
          batchState[kind].done = completed
        },
      },
      (item) => act(item.row, item.action, true, epoch),
    )
    if (disposed || epoch !== batchEpoch) return
    if (snap.value.kernel_running) {
      await load(true)
      if (anyHealthcheck && !disposed && epoch === batchEpoch) void store.refresh()
    }
    const total = targets.length
    if (!disposed && epoch === batchEpoch && total) {
      if (allHealthcheck) {
        store.toast(
          failed
            ? tr('健康检查完成：{0}/{1}，{2} 个失败', { 0: done, 1: total, 2: failed })
            : tr('已完成 {0}/{1} 个代理集健康检查', { 0: done, 1: total }),
          failed ? 'error' : 'success',
        )
      } else {
        store.toast(
          failed
            ? tr('更新完成：{0}/{1}，{2} 个失败', { 0: done, 1: total, 2: failed })
            : tr('已更新 {0}/{1} 个{2}', { 0: done, 1: total, 2: kind === 'proxy' ? tr('代理集') : tr('规则集') }),
          failed ? 'error' : 'success',
        )
      }
    }
  } finally {
    if (epoch === batchEpoch) {
      batchState[kind].running = false
      batchState[kind].action = null
    }
  }
}

async function retryFailed(rows: ProviderRow[], kind: 'proxy' | 'rule') {
  const firstFailed = failedRows(rows)[0]
  if (!firstFailed) return
  await runBatch(rows, kind, stateOf(firstFailed)?.action ?? 'update', true)
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
  { id: '24', get label() { return tr('每天') } },
  { id: '72', get label() { return tr('每 3 天') } },
  { id: '168', get label() { return tr('每周') } },
] as const
const GEO_SOURCES: { id: GeoSource; label: string }[] = [
  { id: '', get label() { return tr('默认') } },
  { id: 'github', label: 'GitHub' },
  { id: 'jsdelivr', label: 'jsDelivr' },
  { id: 'testingcf', label: 'CF' },
]
const GEODATA_MODES = [
  { id: '', get label() { return tr('默认') } },
  { id: 'db', label: 'MMDB' },
  { id: 'dat', label: 'DAT' },
] as const
/** mihomo defaults to the low-memory loader; 标准 reads each file whole. */
const GEODATA_LOADERS = [
  { id: '', get label() { return tr('默认') } },
  { id: 'memconservative', get label() { return tr('低内存') } },
  { id: 'standard', get label() { return tr('标准') } },
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
  if (!geoFiles.value.length) return tr('分流规则依赖的地域与域名数据')
  const parts = [
    geoMissing.value ? tr('{0} 个尚未下载', { 0: geoMissing.value }) : tr('全部就绪'),
  ]
  if (geoLatest.value) parts.push(tr('{0}更新', { 0: formatRelative(geoLatest.value) }))
  parts.push(geoSettings.value.geo_auto_update ? tr('自动更新') : tr('手动更新'))
  return parts.join(' · ')
})
const geoInterval = computed(() => String(geoSettings.value.geo_update_interval ?? 24))
const geodataModeId = computed(() => {
  const mode = geoSettings.value.geodata_mode
  return mode == null ? '' : mode ? 'dat' : 'db'
})
const shownGeoFiles = computed(() => geoFiles.value)
const geodataLoaderId = computed(() => geoSettings.value.geodata_loader ?? '')
const geodataLoaderHint = computed(() => {
  if (geodataLoaderId.value === 'standard') return tr('一次读入整个 GEO 文件，内存占用更高')
  if (geodataLoaderId.value === 'memconservative') return tr('按需读取 GEO 文件，适合手机与路由器')
  return tr('沿用配置；未设置时内核默认低内存模式')
})

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

let geoLoadVersion = 0
async function loadGeo() {
  if (disposed) return
  const version = ++geoLoadVersion
  try {
    const files = await store.backend.geoFiles()
    if (!disposed && version === geoLoadVersion) geoFiles.value = files
  } catch {
    if (!disposed && version === geoLoadVersion) geoFiles.value = []
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
    store.toast(tr('{0} 数据库已更新', { 0: label }), 'success')
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
const detailTokens = computed(() => splitQueryTokens(detailQuery.value))
const detailProxies = computed(() => {
  const rows = detail.value?.data?.proxies ?? []
  if (!detailTokens.value.length) return rows
  return rows.filter((row) =>
    matchesTokens(`${row.name} ${row.node_type} ${protocolLabel(row.node_type)} ${row.tags.join(' ')}`, detailTokens.value),
  )
})
/** Rule lists can hold thousands of lines; start at 400 rows and expand progressively via "Show more". */
const RULE_PAGE = 400
const detailLimit = ref(RULE_PAGE)
/** The backend previews the first rows of a large set; searching it must ask for all of them. */
const detailPartial = computed(() => {
  const data = detail.value?.data
  return !!data && data.kind === 'rule' && data.total > data.rules.length
})
const detailSearch = shallowRef<{ query: string; data: ProviderDetail | null; error: string | null; pending: boolean } | null>(null)
let searchTimer: ReturnType<typeof setTimeout> | null = null
let searchVersion = 0
watch(detailNeedle, () => {
  detailLimit.value = RULE_PAGE
})
watch([detailNeedle, detailPartial], ([needle, partial]) => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = null
  const version = ++searchVersion
  if (!needle || !partial || !detail.value) {
    detailSearch.value = null
    return
  }
  const row = detail.value.row
  // Earlier matches stay visible until the new ones arrive.
  detailSearch.value = { query: needle, data: detailSearch.value?.data ?? null, error: null, pending: true }
  searchTimer = setTimeout(async () => {
    searchTimer = null
    try {
      const data = await store.backend.providerDetail(row.kind, row.name, needle)
      if (!disposed && version === searchVersion) detailSearch.value = { query: needle, data, error: null, pending: false }
    } catch (err) {
      if (!disposed && version === searchVersion) detailSearch.value = { query: needle, data: null, error: err instanceof Error ? err.message : String(err), pending: false }
    }
  }, 250)
})
/** Still waiting for the full-set search of the current text. */
const detailSearching = computed(() => !!detailSearch.value?.pending)
const detailRules = computed(() => {
  const needle = detailNeedle.value
  if (needle && detailPartial.value) return detailSearch.value?.data?.rules ?? []
  const rows = detail.value?.data?.rules ?? []
  return detailTokens.value.length ? rows.filter((rule) => matchesTokens(rule, detailTokens.value)) : rows
})
/** Matches across the whole set, which can exceed the rows sent back. */
const detailRuleCount = computed(() =>
  detailNeedle.value && detailPartial.value ? detailSearch.value?.data?.total ?? 0 : detailRules.value.length,
)
const detailNotice = computed(() =>
  detailNeedle.value && detailPartial.value ? detailSearch.value?.error ?? detailSearch.value?.data?.notice ?? null : detail.value?.data?.notice ?? null,
)
/** MrsRule → MRS, YamlRule → YAML: the file format named the way configs write it. */
function ruleFormat(row: ProviderRow): string {
  return row.format.replace(/Rule$/, '').toUpperCase()
}

async function openDetail(row: ProviderRow) {
  const version = ++detailVersion
  detailQuery.value = ''
  detailLimit.value = RULE_PAGE
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

function highlightDetail(value: string) {
  return highlightTokens(value, detailQuery.value)
}

function consumeFocusProvider() {
  const req = store.focusProvider.value
  if (!req || !providers.value.length) return
  const lower = req.name.toLowerCase()
  const target =
    providers.value.find((row) => row.kind === req.kind && row.name === req.name) ??
    providers.value.find((row) => row.kind === req.kind && row.name.toLowerCase() === lower) ??
    providers.value.find((row) => row.name.toLowerCase() === lower)
  store.focusProvider.value = null
  if (!target) {
    store.toast(tr('未找到资源「{0}」', { 0: req.name }), 'info')
    return
  }
  if (collapsed[target.kind]) collapsed[target.kind] = false
  if (providerFilter.value !== 'all' && !matchesFilter(target)) providerFilter.value = 'all'
  if (query.value && !matchesQuery(target)) query.value = ''
  void openDetail(target)
}

watch(() => store.focusProvider.value, () => consumeFocusProvider())

const successText = (row: ProviderRow) => (stateOf(row)?.action === 'healthcheck' ? tr('检查通过') : tr('已更新'))

// A stopped kernel drops the rows instead of showing the previous session (R31),
// while hot-reloads that keep kernel_running=true preserve the existing provider list.
watch(
  [() => snap.value.kernel_running, () => snap.value.active_id],
  ([running, activeId], [prevRunning, prevActiveId]) => {
    if (running && prevRunning && activeId === prevActiveId) return
    loadVersion++
    detailVersion++
    batchEpoch++
    batchState.proxy = { running: false, action: null, done: 0, total: 0 }
    batchState.rule = { running: false, action: null, done: 0, total: 0 }
    detail.value = null
    providers.value = []
    providerFilter.value = 'all'
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
  if (searchTimer) clearTimeout(searchTimer)
  disposed = true
  loadVersion++
  detailVersion++
  batchEpoch++
  if (store.focusProvider.value) store.focusProvider.value = null
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
        <h1>{{ tr('资源') }}</h1>
        <p class="muted small">{{ tr('配置引用的代理集与规则集') }}</p>
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
          {{ loading ? tr('刷新中') : tr('刷新') }}
        </button>
      </div>
    </header>

    <div v-if="snap.kernel_running && providers.length" class="toolbar res-toolbar" data-testid="provider-toolbar">
      <div class="search provider-search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('筛选代理集与规则集')" data-page-search data-testid="provider-search" />
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <span class="small muted mono search-count" data-testid="provider-count">
          {{ isFiltered ? `${visibleCount}/${providers.length}` : providers.length }}
        </span>
        <button v-if="query" type="button" class="icon-btn sm" :aria-label="tr('清空筛选')" @click="query = ''">
          <Icon name="x" :size="14" />
        </button>
      </div>
      <div class="toolbar-options">
        <Segmented
          v-model="providerFilter"
          :options="PROVIDER_FILTER_OPTIONS"
          size="sm"
          :label="tr('资源筛选')"
          data-testid="provider-filter"
        />
        <button
          v-if="isFiltered"
          type="button"
          class="btn ghost sm"
          data-testid="reset-provider-filters"
          @click="resetFilters"
        >
          {{ tr('重置筛选') }}
        </button>
      </div>
    </div>

    <Skeleton v-if="loading && !providers.length && snap.kernel_running" variant="card" :cards="2" />

    <EmptyState v-if="!snap.kernel_running" variant="unavailable" icon="database" :title="tr('内核未运行')" :description="tr('连接后可以查看并更新配置中的 proxy-providers 与 rule-providers。')">
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
    <EmptyState v-else-if="loaded && error && !providers.length" variant="error" :title="tr('读取失败')" :description="error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-providers" @click="load()">{{ tr('重试') }}</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="loaded && !providers.length && !loading" variant="no-data" :title="tr('这份配置没有使用外部资源')" :description="tr('配置里的 proxy-providers 和 rule-providers 会显示在这里。')">
      <template #action>
        <button type="button" class="btn ghost sm" @click="load()">{{ tr('刷新') }}</button>
      </template>
    </EmptyState>

    <div v-if="noMatch" class="empty-line muted" data-testid="provider-no-match">
      <span v-if="needle">{{ tr('没有名称匹配「') }}{{ query.trim() }}{{ tr('」的资源') }}</span>
      <span v-else-if="providerFilter === 'failed'">{{ tr('当前没有异常的外部资源') }}</span>
      <span v-else>{{ tr('当前筛选条件下没有外部资源') }}</span>
      <button type="button" class="btn ghost sm" @click="resetFilters">{{ tr('重置筛选') }}</button>
    </div>

    <template v-for="section in sections" :key="section.kind">
      <section v-if="section.rows.length" class="card provider-card" :class="{ folded: !isOpen(section.kind) }" :data-section="section.kind">
        <header class="card-head provider-head">
          <button
            type="button"
            class="provider-fold"
            :aria-expanded="isOpen(section.kind)"
            :disabled="isFiltered"
            :data-testid="`fold-${section.kind}`"
            @click="toggleSection(section.kind)"
          >
            <Icon name="chevron-right" :size="15" class="fold-chevron" />
            <h2>{{ section.title }}</h2>
            <span class="count-pill">{{ isFiltered ? `${section.rows.length}/${section.all.length}` : section.all.length }}</span>
            <span v-if="!isOpen(section.kind)" class="muted small ellipsis provider-fold-summary">{{ sectionSummary(section.all) }}</span>
          </button>
          <div class="card-head-actions">
            <button
              v-if="!batchState[section.kind].running && failedRows(section.all).length > 0"
              type="button"
              class="btn ghost sm danger-text"
              :disabled="sectionBusy(section.kind)"
              :data-testid="`retry-failed-${section.kind}`"
              @click="retryFailed(section.all, section.kind)"
            >
              <Icon name="refresh" :size="14" />{{ tr('重试失败 (') }}{{ failedRows(section.all).length }})
            </button>
            <button
              v-if="section.kind === 'proxy'"
              type="button"
              class="btn ghost sm"
              :disabled="sectionBusy('proxy')"
              :aria-busy="(batchState.proxy.running && batchState.proxy.action === 'healthcheck') || undefined"
              data-testid="healthcheck-all-proxy"
              @click="runBatch(section.all, 'proxy', 'healthcheck')"
            >
              <span v-if="batchState.proxy.running && batchState.proxy.action === 'healthcheck'" class="spinner sm" aria-hidden="true" />
              <Icon v-else name="zap" :size="15" />
              {{ batchState.proxy.running && batchState.proxy.action === 'healthcheck'
                ? tr('检查中 {0}/{1}', { 0: batchState.proxy.done, 1: batchState.proxy.total })
                : tr('全部健康检查') }}
            </button>
            <button
              type="button"
              class="btn ghost sm"
              :disabled="sectionBusy(section.kind)"
              :aria-busy="(batchState[section.kind].running && batchState[section.kind].action === 'update') || undefined"
              :data-testid="`update-all-${section.kind}`"
              @click="runBatch(section.all, section.kind, 'update')"
            >
              <span v-if="batchState[section.kind].running && batchState[section.kind].action === 'update'" class="spinner sm" aria-hidden="true" />
              <Icon v-else name="refresh" :size="15" />
              {{ batchState[section.kind].running && batchState[section.kind].action === 'update'
                ? tr('更新中 {0}/{1}', { 0: batchState[section.kind].done, 1: batchState[section.kind].total })
                : tr('全部更新') }}
            </button>
          </div>
        </header>
        <div v-if="isOpen(section.kind)" class="provider-list" :class="{ multi: section.rows.length >= 6 }">
        <div
          v-for="row in section.rows"
          :key="row.name"
          class="provider"
          :data-provider="row.name"
          :data-inline="isInline(row) ? 'true' : undefined"
          :data-busy="stateOf(row) && stateOf(row)?.state !== 'success' ? 'true' : undefined"
        >
          <div class="provider-main">
            <button
              type="button"
              class="provider-open"
              :aria-label="tr('查看 {0} 的{1}', { 0: row.name, 1: row.kind === 'proxy' ? tr('节点') : tr('规则') })"
              :data-testid="`open-provider-${row.name}`"
              @click="openDetail(row)"
            />
            <div class="provider-title">
              <span class="provider-glyph" :class="row.kind" aria-hidden="true">
                <Icon :name="row.kind === 'proxy' ? 'globe' : isInline(row) ? 'code' : 'route'" :size="16" />
              </span>
              <div class="min0 grow">
                <strong class="ellipsis">
                  <template v-for="(part, partIdx) in highlightTokens(row.name, query)" :key="partIdx">
                    <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                  </template>
                </strong>
                <p class="muted small provider-meta">
                  <span>{{ row.kind === 'proxy' ? tr('{0} 个节点', { 0: row.count }) : tr('{0} 条规则', { 0: row.count.toLocaleString() }) }}</span>
                  <span v-if="row.behavior">{{ row.behavior }}</span>
                  <span v-if="isInline(row)" data-provider-inline>{{ tr('内联 · 无需更新') }}</span>
                  <span
                    v-else-if="stateOf(row)?.state === 'pending'"
                    class="provider-state-inline pending"
                    role="status"
                    data-provider-state="pending"
                  >
                    {{ stateOf(row)?.action === 'healthcheck' ? tr('检查中') : tr('更新中') }}
                  </span>
                  <span
                    v-else-if="stateOf(row)?.state === 'success'"
                    class="provider-state-inline success"
                    data-provider-state="success"
                  >
                    <Icon name="check" :size="12" />{{ successText(row) }}
                  </span>
                  <span v-else>{{ formatRelative(updatedMs(row)) }}{{ tr('更新') }}</span>
                  <span v-if="row.expire">{{ formatDate(row.expire) }} {{ tr('到期') }}</span>
                </p>
              </div>
            </div>
            <div v-if="usagePercent(row.used, row.total) != null" class="usage compact-usage">
              <div class="usage-bar"><span :style="{ width: `${usagePercent(row.used, row.total)}%` }" /></div>
              <span class="small mono muted">{{ formatBytes(row.used) }} / {{ formatBytes(row.total) }}</span>
            </div>
            <p v-if="stateOf(row)?.state === 'error'" class="provider-note field-error small" role="alert" data-provider-state="error">
              <Icon name="alert" :size="13" />
              {{ stateOf(row)?.action === 'healthcheck' ? tr('健康检查失败') : tr('更新失败') }}：{{ stateOf(row)?.reason }}
              <button type="button" class="btn ghost sm" :disabled="sectionBusy(row.kind)" data-testid="retry-provider" @click="retry(row)">{{ tr('重试') }}</button>
            </p>
          </div>
          <div class="provider-actions">
            <button
              v-if="row.kind === 'proxy'"
              type="button"
              class="icon-btn"
              :aria-label="tr('{0} 健康检查', { 0: row.name })"
              :title="tr('{0} 健康检查', { 0: row.name })"
              :disabled="sectionBusy(row.kind)"
              @click="single(row, 'healthcheck')"
            >
              <span v-if="stateOf(row)?.state === 'pending' && stateOf(row)?.action === 'healthcheck'" class="spinner sm" />
              <Icon v-else name="zap" />
            </button>
            <button
              type="button"
              class="icon-btn"
              :aria-label="isInline(row) ? tr('{0} 无需更新', { 0: row.name }) : tr('更新 {0}', { 0: row.name })"
              :title="isInline(row) ? tr('内联资源无需更新') : tr('更新 {0}', { 0: row.name })"
              :disabled="isInline(row) || sectionBusy(row.kind)"
              @click="single(row, 'update')"
            >
              <span v-if="stateOf(row)?.state === 'pending' && stateOf(row)?.action === 'update'" class="spinner sm" />
              <Icon v-else name="refresh" />
            </button>
            <span class="provider-chevron" aria-hidden="true"><Icon name="chevron-right" :size="15" /></span>
          </div>
        </div>
        </div>
      </section>
    </template>


    <!-- GEO data is plumbing: one quiet strip with a single action; everything else lives behind 设置. -->
    <section class="card geo-card" data-testid="geo-card">
      <div class="geo-strip">
        <span class="geo-glyph" :class="{ warn: geoMissing > 0 }" aria-hidden="true"><Icon name="globe" :size="18" /></span>
        <div class="grow min0">
          <strong>{{ tr('GEO 数据库') }}</strong>
          <p class="muted small ellipsis" data-testid="geo-summary">{{ geoSummary }}</p>
        </div>
        <button
          type="button"
          class="icon-btn"
          :title="tr('GEO 设置')"
          :aria-label="tr('GEO 设置')"
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
          :title="tr('下载并更新全部 GEO 数据库')"
          data-testid="upgrade-geo"
          @click="upgradeGeo()"
        >
          <span v-if="geoBusy" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="download" :size="15" />
          {{ geoBusy ? tr('更新中') : tr('更新') }}
        </button>
      </div>
      <ul v-if="shownGeoFiles.length" class="geo-chips" data-testid="geo-files">
        <li v-for="file in shownGeoFiles" :key="file.key" :class="{ missing: !file.exists }" :title="file.file">
          <strong>{{ file.label }}</strong>
          <span class="muted">{{ file.exists ? formatBytes(file.size) : tr('未下载') }}</span>
        </li>
      </ul>
      <div v-if="geoError" class="geo-alert" role="alert" data-testid="geo-error">
        <Icon name="alert" :size="15" />
        <span class="geo-alert-text small">{{ tr(geoError) }}</span>
        <div class="geo-alert-actions">
          <button
            v-if="geoSettings.geo_source !== 'jsdelivr'"
            type="button"
            class="btn primary sm"
            :disabled="geoBusy"
            data-testid="geo-switch-jsdelivr"
            @click="switchJsdelivrAndUpgrade"
          > {{ tr('切换 jsDelivr 重试') }} </button>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="geoBusy"
            data-testid="geo-retry"
            @click="upgradeGeo(lastFailedGeoKey)"
          > {{ tr('重试') }} </button>
        </div>
      </div>
    </section>

    <Modal :open="geoOpen" :title="tr('GEO 数据库')" :subtitle="tr('GEOIP、GEOSITE 规则使用的地域与域名数据')" @close="geoOpen = false">
      <div class="geo-sheet" data-testid="geo-settings">
        <ul class="geo-file-list" data-testid="geo-file-list">
          <li v-for="file in shownGeoFiles" :key="file.key" :class="{ missing: !file.exists }">
            <div class="grow min0">
              <strong>{{ file.label }}</strong>
              <span class="muted small mono">{{ file.file }}</span>
            </div>
            <span class="muted small geo-file-meta">
              {{ file.exists ? `${formatBytes(file.size)} · ${formatRelative(file.modified_ms)}` : tr('尚未下载') }}
            </span>
            <button
              type="button"
              class="icon-btn sm"
              :disabled="geoBusy"
              :title="tr('更新 {0}', { 0: file.label })"
              :aria-label="tr('更新 {0}', { 0: file.label })"
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
              <strong>{{ tr('自动更新') }}</strong>
              <p class="muted small">{{ tr('内核运行时在后台定期同步') }}</p>
            </div>
            <Toggle
              :model-value="geoSettings.geo_auto_update === true"
              :label="tr('GEO 自动更新')"
              data-testid="geo-auto-update"
              @update:model-value="(on) => saveGeo({ geo_auto_update: on, geo_update_interval: on ? Number(geoInterval) : geoSettings.geo_update_interval })"
            />
          </div>
          <div v-if="geoSettings.geo_auto_update" class="setting-row">
            <div class="grow"><strong>{{ tr('更新频率') }}</strong></div>
            <Segmented
              :model-value="geoInterval"
              :options="GEO_INTERVALS"
              size="sm"
              :label="tr('更新频率')"
              @update:model-value="(id) => saveGeo({ geo_update_interval: Number(id) })"
            />
          </div>
          <div class="setting-row">
            <div class="grow">
              <strong>{{ tr('下载源') }}</strong>
              <p class="muted small">{{ geoSettings.geo_source ? tr('下载慢或失败时可换用加速镜像') : tr('沿用配置中的 geox-url') }}</p>
            </div>
            <Segmented
              :model-value="geoSettings.geo_source"
              :options="GEO_SOURCES"
              size="sm"
              :label="tr('下载源')"
              data-testid="geo-source"
              @update:model-value="(id) => saveGeo({ geo_source: id })"
            />
          </div>
          <div class="setting-row">
            <div class="grow">
              <strong>{{ tr('GeoIP 格式') }}</strong>
              <p class="muted small">{{ geodataModeId === 'dat' ? tr('使用 GeoIP.dat') : geodataModeId === 'db' ? tr('使用 Country.mmdb') : tr('沿用配置中的 geodata-mode') }}</p>
            </div>
            <Segmented
              :model-value="geodataModeId"
              :options="GEODATA_MODES"
              size="sm"
              :label="tr('GeoIP 格式')"
              data-testid="geodata-mode"
              @update:model-value="(id) => saveGeo({ geodata_mode: id === '' ? null : id === 'dat' })"
            />
          </div>
          <div class="setting-row">
            <div class="grow">
              <strong>{{ tr('加载方式') }}</strong>
              <p class="muted small">{{ geodataLoaderHint }}</p>
            </div>
            <Segmented
              :model-value="geodataLoaderId"
              :options="GEODATA_LOADERS"
              size="sm"
              :label="tr('GEO 加载方式')"
              data-testid="geodata-loader"
              @update:model-value="(id) => saveGeo({ geodata_loader: id === '' ? null : id })"
            />
          </div>
        </div>

        <details class="geo-advanced" data-testid="geo-urls-section" :open="hasCustomGeoUrls || undefined">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span class="grow">{{ tr('自定义下载地址') }}</span>
            <span v-if="hasCustomGeoUrls" class="tag accent sm">{{ tr('已自定义') }}</span>
          </summary>
          <p class="muted small">{{ tr('留空则使用上方下载源。') }}</p>
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
                :aria-label="tr('{0} 下载地址', { 0: item.label })"
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
            > {{ tr('恢复默认') }} </button>
            <button
              v-if="geoUrlsDirty"
              type="button"
              class="btn primary sm"
              data-testid="save-geo-urls"
              @mousedown.prevent
              @click="commitGeoUrls"
            > {{ tr('保存地址') }} </button>
          </div>
        </details>
      </div>
    </Modal>

    <Modal
      :open="Boolean(detail)"
      wide
      :title="detail?.row.name ?? ''"
      :subtitle="detail ? (detail.row.kind === 'proxy'
        ? tr('代理集 · {0} 个节点', { 0: detail.data ? detail.data.total : detail.row.count })
        : tr('规则集 · {0} 条规则{1}{2}', { 0: (detail.data?.total || detail.row.count).toLocaleString(), 1: detail.row.behavior ? ` · ${detail.row.behavior}` : '', 2: ruleFormat(detail.row) ? ` · ${ruleFormat(detail.row)}` : '' })) : ''"
      @close="closeProviderDetail"
    >
      <div v-if="detail" class="provider-detail" data-testid="provider-detail">
        <div v-if="detail.data?.source && detail.data.source !== 'inline'" class="detail-source-row">
          <p class="muted small mono ellipsis detail-source grow" :title="detail.data.source">{{ detail.data.source }}</p>
          <button
            type="button"
            class="icon-btn sm"
            :title="tr('复制来源地址')"
            :aria-label="tr('复制来源地址')"
            data-testid="copy-provider-source"
            @click="store.copyText(detail.data.source, tr('已复制来源地址'))"
          >
            <Icon name="copy" :size="13" />
          </button>
        </div>
        <div v-if="detail.data && (detail.data.proxies.length || detail.data.rules.length)" class="search">
          <Icon name="search" :size="16" />
          <input v-model="detailQuery" type="search" :placeholder="detail.row.kind === 'proxy' ? tr('搜索节点、协议或 UDP') : tr('搜索规则')" />
          <span v-if="detailNeedle && detailSearching" class="spinner xs" :aria-label="tr('正在搜索全部规则')" />
          <span v-else-if="detailNeedle" class="small muted mono" data-testid="provider-match-count">
            {{ (detail.row.kind === 'proxy' ? detailProxies.length : detailRuleCount).toLocaleString() }}
          </span>
          <button
            v-if="detailQuery"
            type="button"
            class="icon-btn sm"
            :aria-label="tr('清空搜索')"
            data-testid="clear-provider-search"
            @click="detailQuery = ''"
          >
            <Icon name="x" :size="14" />
          </button>
        </div>
        <p v-if="detail.error" class="field-error" role="alert">{{ tr(detail.error) }}</p>
        <div v-else-if="!detail.data" class="detail-loading muted small"><span class="spinner xs" /> {{ tr('正在读取…') }}</div>
        <template v-else>
          <p v-if="detailNotice" class="banner info small" data-testid="provider-notice"><Icon name="info" :size="15" />{{ tr(detailNotice) }}</p>
          <ul v-if="detail.row.kind === 'proxy'" class="detail-list">
            <li v-for="proxy in detailProxies.slice(0, detailLimit)" :key="proxy.name" class="detail-proxy">
              <span class="grow min0">
                <strong class="ellipsis">
                  <template v-for="(part, partIdx) in highlightDetail(proxy.name)" :key="partIdx">
                    <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                  </template>
                </strong>
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
              <button
                type="button"
                class="icon-btn xs detail-copy-btn"
                :title="tr('复制节点名')"
                :aria-label="tr('复制节点名')"
                data-testid="copy-detail-proxy"
                @click="store.copyText(proxy.name, tr('已复制节点名'))"
              >
                <Icon name="copy" :size="13" />
              </button>
            </li>
            <li v-if="detailProxies.length > detailLimit" class="detail-more-row">
              <button
                type="button"
                class="btn ghost sm"
                data-testid="detail-show-more"
                @click="detailLimit += RULE_PAGE"
              >
                {{ tr('显示更多（还有 {0} 个节点）', { 0: (detailProxies.length - detailLimit).toLocaleString() }) }}
              </button>
            </li>
            <li v-if="!detailProxies.length" class="muted small empty-line">{{ detailQuery ? tr('没有匹配的节点') : tr('这个代理集还没有节点') }}</li>
          </ul>
          <ol v-else-if="detail.data.rules.length" class="detail-list detail-rules mono">
            <li v-for="(rule, index) in detailRules.slice(0, detailLimit)" :key="index">
              <span v-if="ruleParts(rule).type" class="rule-type">{{ ruleParts(rule).type }}</span>
              <span class="ellipsis grow">
                <template v-for="(part, partIdx) in highlightDetail(ruleParts(rule).rest)" :key="partIdx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <button
                type="button"
                class="icon-btn xs detail-copy-btn"
                :title="tr('复制规则')"
                :aria-label="tr('复制规则')"
                data-testid="copy-detail-rule"
                @click="store.copyText(rule, tr('已复制规则'))"
              >
                <Icon name="copy" :size="13" />
              </button>
            </li>
            <li v-if="!detailRules.length" class="muted small empty-line">{{ detailSearching ? tr('正在搜索全部 {0} 条…', { 0: detail.data.total.toLocaleString() }) : tr('没有匹配的规则') }}</li>
            <li v-else-if="detailRules.length > detailLimit" class="detail-more-row">
              <button
                type="button"
                class="btn ghost sm"
                data-testid="detail-show-more"
                @click="detailLimit += RULE_PAGE"
              >
                {{ tr('显示更多（还有 {0} 条）', { 0: (detailRules.length - detailLimit).toLocaleString() }) }}
              </button>
            </li>
            <li v-else-if="detailPartial && !detailNeedle" class="muted small empty-line" data-testid="detail-preview-cap">
              {{ tr('共 {0} 条，当前已展开全部 {1} 条预览；输入关键词可搜索整份规则集', { 0: detail.data.total.toLocaleString(), 1: detailRules.length.toLocaleString() }) }}
            </li>
          </ol>
        </template>
      </div>
      <!-- The sheet's work action is primary; closing is the quiet way out. -->
      <template #footer>
        <button
          v-if="store.connectionReturn.value?.targetPage === 'resources'"
          type="button"
          class="btn ghost"
          data-testid="provider-return-connection"
          @click="returnToConnection"
        >
          <Icon name="chevron-left" :size="15" />{{ tr('返回连接') }} </button>
        <button
          v-else-if="store.ruleReturn.value && store.ruleReturn.value.targetPage === 'resources'"
          type="button"
          class="btn ghost"
          data-testid="provider-return-rule"
          @click="returnToRule"
        >
          <Icon name="chevron-left" :size="15" />{{ tr('返回规则') }} </button>
        <button type="button" class="btn ghost" data-testid="close-provider-detail" @click="closeProviderDetail">{{ tr('关闭') }}</button>
        <button
          v-if="detail && detail.row.kind === 'proxy'"
          type="button"
          class="btn primary"
          :disabled="!snap.kernel_running || sectionBusy(detail.row.kind)"
          :aria-busy="fruitless(detail.row) || undefined"
          @click="runDetailAction('healthcheck')"
        >
          <span v-if="fruitless(detail.row)" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="zap" :size="15" />{{ fruitless(detail.row) ? tr('检查中') : tr('健康检查') }}
        </button>
        <button
          v-else-if="detail && !isInline(detail.row)"
          type="button"
          class="btn primary"
          :disabled="!snap.kernel_running || sectionBusy(detail.row.kind)"
          :aria-busy="fruitless(detail.row) || undefined"
          @click="runDetailAction('update')"
        >
          <span v-if="fruitless(detail.row)" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="refresh" :size="15" />{{ fruitless(detail.row) ? tr('更新中') : tr('更新规则集') }}
        </button>
      </template>
    </Modal>
  </div>
</template>
