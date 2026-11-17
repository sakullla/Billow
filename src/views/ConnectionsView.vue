<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue'
import ChainPath from '../components/ChainPath.vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import { formatBytes, formatClock, formatDuration, formatSpeed } from '../lib/format'
import { useStore } from '../lib/store'
import { useVirtualList } from '../lib/ui/virtual'
import type { ConnectionRow } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type SortKey = 'time' | 'speed' | 'download' | 'upload' | 'host'
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'time', label: '时间' },
  { id: 'speed', label: '速度' },
  { id: 'download', label: '下载' },
  { id: 'upload', label: '上传' },
  { id: 'host', label: '主机' },
]

const TABLE_ROW = 40
const CARD_ROW = 100

const query = ref('')
const sortKey = ref<SortKey>('time')
const sortDir = ref<'asc' | 'desc'>('desc')

function setSort(key: SortKey) {
  sortKey.value = key
  sortDir.value = key === 'host' ? 'asc' : 'desc'
}

function toggleColumnSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'desc' ? 'asc' : 'desc'
  } else {
    setSort(key)
  }
}

function ariaSortOf(key: SortKey): 'ascending' | 'descending' | 'none' {
  if (sortKey.value !== key) return 'none'
  return sortDir.value === 'asc' ? 'ascending' : 'descending'
}
const paused = ref(false)
const pausedAt = ref<number | null>(null)
const frozenRows = shallowRef<ConnectionRow[]>([])
const frozenIds = shallowRef(new Set<string>())
const frozenTotal = ref(0)
const frozenUp = ref<number | null>(null)
const frozenDown = ref<number | null>(null)
const selecting = ref<string | null>(null)
const selectedHost = ref('')
const selectedLast = shallowRef<ConnectionRow | null>(null)
const selectedAt = ref(Date.now())
const confirmAll = ref(false)
const rates = shallowRef(new Map<string, { up: number; down: number }>())
let previous = new Map<string, { upload: number; download: number; at: number }>()

const idOf = (row: ConnectionRow) => row.id || `${row.host}|${row.source}`

watch(
  () => snap.value.connections,
  (rows) => {
    const now = Date.now()
    const next = new Map<string, { upload: number; download: number; at: number }>()
    const speed = new Map<string, { up: number; down: number }>()
    for (const row of rows) {
      const key = idOf(row)
      const before = previous.get(key)
      next.set(key, { upload: row.upload, download: row.download, at: now })
      if (before) {
        const seconds = Math.max(0.25, (now - before.at) / 1000)
        speed.set(key, {
          up: Math.max(0, (row.upload - before.upload) / seconds),
          down: Math.max(0, (row.download - before.download) / seconds),
        })
      }
    }
    previous = next
    rates.value = speed
  },
  { immediate: true },
)

const rateOf = (row: ConnectionRow) => rates.value.get(idOf(row)) ?? { up: 0, down: 0 }

function pause() {
  frozenRows.value = snap.value.connections
  frozenIds.value = new Set(snap.value.connections.map(idOf))
  frozenTotal.value = snap.value.connection_total || snap.value.connections.length
  frozenUp.value = snap.value.upload_total
  frozenDown.value = snap.value.download_total
  pausedAt.value = Date.now()
  paused.value = true
}

function resume() {
  paused.value = false
  pausedAt.value = null
  frozenRows.value = []
  frozenIds.value = new Set()
}

function togglePause() {
  if (paused.value) resume()
  else pause()
}

/** The list source: a frozen copy while paused, the live snapshot otherwise (R28). */
const sourceRows = computed(() => (paused.value ? frozenRows.value : snap.value.connections))

/** New ids that arrived after the freeze, so the pause screen can say how far behind it is. */
const newCount = computed(() => {
  if (!paused.value) return 0
  return snap.value.connections.filter((row) => !frozenIds.value.has(idOf(row))).length
})

const rows = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const list = needle
    ? sourceRows.value.filter((row) =>
        [row.host, row.destination, row.process, row.rule, row.rule_payload, row.chains.join(' '), row.network]
          .some((text) => text.toLowerCase().includes(needle)),
      )
    : [...sourceRows.value]
  const dir = sortDir.value === 'asc' ? -1 : 1
  switch (sortKey.value) {
    case 'speed':
      list.sort((a, b) => dir * (rateOf(b).down + rateOf(b).up - (rateOf(a).down + rateOf(a).up)))
      break
    case 'download':
      list.sort((a, b) => dir * (b.download - a.download))
      break
    case 'upload':
      list.sort((a, b) => dir * (b.upload - a.upload))
      break
    case 'host':
      list.sort((a, b) => (sortDir.value === 'asc' ? 1 : -1) * a.host.localeCompare(b.host))
      break
    default:
      list.sort((a, b) => dir * (Date.parse(b.start || '0') - Date.parse(a.start || '0')))
  }
  return list
})

const tableScroll = ref<HTMLElement | null>(null)
const cardScroll = ref<HTMLElement | null>(null)
const table = useVirtualList(computed(() => rows.value.length), TABLE_ROW, 6)
const cards = useVirtualList(computed(() => rows.value.length), CARD_ROW, 4)
const tableRows = computed(() => rows.value.slice(table.window.value.start, table.window.value.end))
const cardRows = computed(() => rows.value.slice(cards.window.value.start, cards.window.value.end))

onMounted(() => {
  void nextTick(() => {
    table.measure(tableScroll.value)
    cards.measure(cardScroll.value)
  })
})

// Empty/error states unmount the list, so a remount must not reuse the old offset
// or window index; a filter or sort change returns to the first row (R31).
watch(tableScroll, (el) => table.measure(el))
watch(cardScroll, (el) => cards.measure(el))
watch([query, sortKey, sortDir], () => {
  table.reset(tableScroll.value)
  cards.reset(cardScroll.value)
})

// Totals and the count stay frozen with the list; only the live source moves.
const displayTotal = computed(() =>
  paused.value ? frozenTotal.value : snap.value.connection_total || snap.value.connections.length,
)
const displayUp = computed(() => (paused.value ? frozenUp.value : snap.value.upload_total))
const displayDown = computed(() => (paused.value ? frozenDown.value : snap.value.download_total))
const hiddenRows = computed(() => Math.max(0, displayTotal.value - sourceRows.value.length))

const detailRow = computed(() => snap.value.connections.find((row) => idOf(row) === selecting.value) ?? null)
const detailSource = computed(() => detailRow.value ?? selectedLast.value)
const detailGone = computed(() => selecting.value !== null && !detailRow.value)

watch(detailRow, (row) => {
  if (!row) return
  selectedLast.value = row
  selectedAt.value = Date.now()
})

// A dropped session or a restarted kernel invalidates the frozen rows and the open detail (R31).
watch(
  () => [snap.value.connected, snap.value.kernel_running] as const,
  ([connected]) => {
    if (connected) return
    resume()
    frozenRows.value = []
    frozenIds.value = new Set()
    if (selecting.value !== null) {
      selectedLast.value = null
      selecting.value = null
      selectedHost.value = ''
    }
  },
)

/** Mihomo lists chains from the server back to the rule's target; people read them forwards. */
function hopsOf(row: ConnectionRow): string[] {
  return row.chains.length ? [...row.chains].reverse() : [row.outbound]
}

const detail = computed(() => {
  const row = detailSource.value
  if (!row) return []
  const at = detailRow.value ? Date.now() : selectedAt.value
  const entries: [string, string][] = [
    ['主机', row.host],
    ['目标地址', row.destination],
    ['来源', row.source],
    ['进程', row.process],
    ['网络', `${row.network.toUpperCase()}${row.conn_type ? ` · ${row.conn_type}` : ''}`],
    ['规则', row.rule ? `${row.rule}${row.rule_payload ? ` (${row.rule_payload})` : ''}` : ''],
    ['代理链', hopsOf(row).join(' → ')],
    ['下载', formatBytes(row.download)],
    ['上传', formatBytes(row.upload)],
    ['持续', formatDuration(row.start, at)],
  ]
  return entries.filter(([, value]) => value)
})

function openDetail(row: ConnectionRow) {
  selecting.value = idOf(row)
  selectedHost.value = row.host
  selectedLast.value = row
  selectedAt.value = Date.now()
}

function closeDetail() {
  selecting.value = null
  selectedHost.value = ''
  selectedLast.value = null
}

async function copySummary() {
  const row = detailSource.value
  if (!row) return
  const at = detailRow.value ? Date.now() : selectedAt.value
  const text = [
    `主机: ${row.host}`,
    row.destination ? `目标地址: ${row.destination}` : '',
    row.process ? `进程: ${row.process}` : '',
    `规则: ${row.rule}${row.rule_payload ? ` (${row.rule_payload})` : ''}`,
    `代理链: ${hopsOf(row).join(' → ')}`,
    `下载: ${formatBytes(row.download)}`,
    `上传: ${formatBytes(row.upload)}`,
    `持续: ${formatDuration(row.start, at)}`,
  ].filter(Boolean)
  await store.copyText(text.join('\n'), '已复制连接摘要')
}

async function closeOne(row: ConnectionRow) {
  await store.closeConnection(row.id)
}

async function disconnectAll() {
  confirmAll.value = false
  const result = await store.closeConnection(null)
  if (result) store.toast('已断开全部连接', 'success')
}

function resetFilters() {
  query.value = ''
}

function filterBy(value: string) {
  if (!value) return
  query.value = value
  closeDetail()
}

function speedDisplay(row: ConnectionRow): { text: string; idle: boolean; upOnly: boolean; title: string } {
  const r = rateOf(row)
  const total = r.down + r.up
  if (total < 1) {
    return { text: formatSpeed(0), idle: true, upOnly: false, title: '当前无活动传输' }
  }
  if (r.down < 1 && r.up >= 1) {
    return {
      text: `↑ ${formatSpeed(r.up)}`,
      idle: false,
      upOnly: true,
      title: `上传 ${formatSpeed(r.up)} · 下载 ${formatSpeed(r.down)}`,
    }
  }
  return {
    text: formatSpeed(r.down),
    idle: false,
    upOnly: false,
    title: r.up >= 1 ? `下载 ${formatSpeed(r.down)} · 上传 ${formatSpeed(r.up)}` : `下载 ${formatSpeed(r.down)}`,
  }
}
</script>

<template>
  <div class="page connections">
    <header class="page-head">
      <div>
        <h1>连接</h1>
        <p class="muted small mono" data-testid="connection-summary">
          <template v-if="!snap.connected">未连接</template>
          <template v-else>
            {{ displayTotal }} 个活动连接
            <template v-if="query.trim()"> · 匹配 {{ rows.length }} 条</template>
            <template v-if="hiddenRows"> · 显示前 {{ sourceRows.length }} 条</template>
            <template v-if="paused"> · 暂停于 {{ formatClock(pausedAt ?? 0) }}</template>
            <template v-if="paused && newCount"> · <span data-testid="new-connections">{{ newCount }} 条新连接</span></template>
            · <span title="本次累计下载"><Icon name="down" :size="11" />{{ formatBytes(displayDown) }}</span>
            · <span title="本次累计上传"><Icon name="up" :size="11" />{{ formatBytes(displayUp) }}</span>
          </template>
        </p>
      </div>
      <!-- Nothing to pause or close while disconnected; the empty state owns the next step. -->
      <div v-if="snap.connected" class="head-actions">
        <button
          type="button"
          class="btn ghost sm"
          :class="{ active: paused }"
          :disabled="!snap.connected"
          :aria-pressed="paused"
          data-testid="pause-connections"
          @click="togglePause"
        >
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? '继续' : '暂停' }}
        </button>
        <button
          type="button"
          class="btn ghost sm danger-text"
          :disabled="!snap.connections.length"
          data-testid="disconnect-all"
          @click="confirmAll = true"
        >
          <Icon name="x" :size="15" />全部断开
        </button>
      </div>
    </header>

    <div v-if="snap.connected && snap.connections.length" class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="按主机、进程、规则或节点筛选" data-testid="connection-search" data-page-search />
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          aria-label="清空筛选"
          data-testid="clear-connection-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <!-- The desktop table sorts from its column headers; phone cards have none, so they keep the switch. -->
      <Segmented
        v-if="compact"
        :model-value="sortKey"
        :options="SORTS"
        size="sm"
        label="排序"
        data-testid="connection-sort"
        @update:model-value="setSort"
      />
    </div>

    <EmptyState v-if="!snap.connected" variant="unavailable" icon="activity" title="未连接" description="连接后这里会实时显示经过 Billow 的连接。">
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
    <EmptyState v-else-if="snap.connections_error" variant="error" title="读取失败" :description="snap.connections_error">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="retry-connections" @click="store.refresh()">重试</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="!rows.length && query" variant="no-match" title="没有匹配的连接" description="换一个关键词，或清空当前筛选。">
      <template #action>
        <button type="button" class="btn ghost sm" data-testid="clear-connection-filter" @click="resetFilters">清空筛选</button>
      </template>
    </EmptyState>
    <EmptyState v-else-if="!rows.length" variant="no-data" icon="activity" title="没有当前连接" description="应用发起连接后会出现在这里。">
      <template #action>
        <button type="button" class="btn ghost sm" @click="store.refresh()">刷新</button>
      </template>
    </EmptyState>

    <div v-else-if="!compact" ref="tableScroll" class="card table-card conn-table" data-testid="connection-scroll" @scroll="table.onScroll">
      <table class="table virtual">
        <thead>
          <tr>
            <th :aria-sort="ariaSortOf('host')">
              <button type="button" class="th-sort" :class="{ active: sortKey === 'host' }" @click="toggleColumnSort('host')">
                主机
                <Icon v-if="sortKey === 'host'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
            </th>
            <th class="col-process">进程</th>
            <th>规则</th>
            <th>代理链</th>
            <th class="num" :aria-sort="ariaSortOf('speed')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'speed' }" @click="toggleColumnSort('speed')">
                速度
                <Icon v-if="sortKey === 'speed'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
            </th>
            <th class="num col-down" :aria-sort="ariaSortOf('download')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'download' }" @click="toggleColumnSort('download')">
                下载
                <Icon v-if="sortKey === 'download'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
            </th>
            <th class="num col-up" :aria-sort="ariaSortOf('upload')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'upload' }" @click="toggleColumnSort('upload')">
                上传
                <Icon v-if="sortKey === 'upload'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
            </th>
            <th class="num" :aria-sort="ariaSortOf('time')">
              <button type="button" class="th-sort num" :class="{ active: sortKey === 'time' }" @click="toggleColumnSort('time')">
                时长
                <Icon v-if="sortKey === 'time'" :name="sortDir === 'asc' ? 'up' : 'down'" :size="11" />
              </button>
            </th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-if="table.offset.value" class="v-spacer" aria-hidden="true" :style="{ height: `${table.offset.value}px` }">
            <td colspan="9" />
          </tr>
          <tr
            v-for="(row, index) in tableRows"
            :key="idOf(row)"
            :data-row-index="table.window.value.start + index"
            :data-connection-id="idOf(row)"
            tabindex="0"
            data-testid="connection-row"
            @click="openDetail(row)"
            @keydown.enter.prevent="openDetail(row)"
            @keydown.space.prevent="openDetail(row)"
          >
            <td>
              <div class="cell-host">
                <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
                <span class="ellipsis" :title="row.host">{{ row.host }}</span>
              </div>
            </td>
            <td class="muted ellipsis col-process" :title="row.process || undefined">{{ row.process || '—' }}</td>
            <td class="ellipsis" :title="row.rule_payload ? `${row.rule} ${row.rule_payload}` : row.rule"><span class="muted">{{ row.rule }}</span><span v-if="row.rule_payload" class="rule-payload-inline">{{ row.rule_payload }}</span></td>
            <td><ChainPath :hops="hopsOf(row)" pill fold /></td>
            <td
              class="num mono"
              :class="{ muted: speedDisplay(row).idle, 'conn-rate-up': speedDisplay(row).upOnly }"
              :title="speedDisplay(row).title"
            >
              {{ speedDisplay(row).text }}
            </td>
            <td class="num mono col-down">{{ formatBytes(row.download) }}</td>
            <td class="num mono muted col-up">{{ formatBytes(row.upload) }}</td>
            <td class="num muted">{{ formatDuration(row.start) }}</td>
            <td class="num">
              <button type="button" class="icon-btn sm conn-close" :aria-label="`断开 ${row.host}`" title="断开" @click.stop="closeOne(row)">
                <Icon name="x" :size="14" />
              </button>
            </td>
          </tr>
          <tr v-if="table.tail.value" class="v-spacer" aria-hidden="true" :style="{ height: `${table.tail.value}px` }">
            <td colspan="9" />
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else ref="cardScroll" class="conn-list-scroll" data-testid="connection-scroll" @scroll="cards.onScroll">
      <ul class="conn-list">
        <li v-if="cards.offset.value" class="v-spacer" aria-hidden="true" :style="{ height: `${cards.offset.value}px` }" />
        <li
          v-for="(row, index) in cardRows"
          :key="idOf(row)"
          :data-row-index="cards.window.value.start + index"
          :data-connection-id="idOf(row)"
          class="card conn"
          tabindex="0"
          data-testid="connection-row"
          @click="openDetail(row)"
          @keydown.enter.prevent="openDetail(row)"
          @keydown.space.prevent="openDetail(row)"
        >
          <div class="conn-top">
            <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
            <strong class="ellipsis grow">{{ row.host }}</strong>
            <span class="mono small" :class="{ muted: speedDisplay(row).idle, 'conn-rate-up': speedDisplay(row).upOnly }">
              {{ speedDisplay(row).text }}
            </span>
            <button type="button" class="icon-btn sm" :aria-label="`断开 ${row.host}`" title="断开" @click.stop="closeOne(row)">
              <Icon name="x" :size="14" />
            </button>
          </div>
          <div class="conn-meta small muted">
            <ChainPath :hops="hopsOf(row)" pill fold />
            <span v-if="row.process" class="ellipsis conn-process">{{ row.process }}</span>
          </div>
          <div class="conn-meta small muted" data-testid="connection-traffic">
            <span class="mono">↓{{ formatBytes(row.download) }}</span>
            <span class="mono">↑{{ formatBytes(row.upload) }}</span>
            <span class="grow" />
            <span>{{ formatDuration(row.start) }}</span>
          </div>
        </li>
        <li v-if="cards.tail.value" class="v-spacer" aria-hidden="true" :style="{ height: `${cards.tail.value}px` }" />
      </ul>
    </div>

    <Modal v-if="selecting !== null" title="连接详情" :subtitle="selectedHost" @close="closeDetail">
      <p v-if="detailGone" class="detail-status" role="status" data-testid="detail-disconnected">
        <Icon name="x" :size="14" />已断开
      </p>
      <dl class="detail">
        <template v-for="[label, value] in detail" :key="label">
          <dt>{{ label }}</dt>
          <dd v-if="label === '代理链' && detailSource" data-testid="detail-chain"><ChainPath :hops="hopsOf(detailSource)" variant="steps" /></dd>
          <dd v-else class="mono">{{ value }}</dd>
        </template>
      </dl>
      <div v-if="detailSource" class="chips conn-detail-chips">
        <button
          type="button"
          class="chip"
          data-testid="copy-conn-host"
          @click="store.copyText(detailSource.host || detailSource.destination, '已复制目标主机')"
        >
          <Icon name="copy" :size="13" />复制主机
        </button>
        <button
          v-if="detailSource.host"
          type="button"
          class="chip"
          data-testid="filter-conn-host"
          @click="filterBy(detailSource.host)"
        >
          <Icon name="filter" :size="13" />筛选此主机
        </button>
        <button
          v-if="detailSource.process"
          type="button"
          class="chip"
          data-testid="filter-conn-process"
          @click="filterBy(detailSource.process)"
        >
          <Icon name="filter" :size="13" />筛选 {{ detailSource.process }}
        </button>
      </div>
      <template #footer>
        <button type="button" class="btn ghost" @click="closeDetail">关闭</button>
        <button type="button" class="btn ghost" data-testid="copy-connection" :disabled="!detailSource" @click="copySummary">
          <Icon name="copy" :size="15" />复制摘要
        </button>
        <button
          type="button"
          class="btn danger"
          data-testid="disconnect-connection"
          :disabled="!detailRow"
          @click="detailRow && closeOne(detailRow)"
        >
          断开连接
        </button>
      </template>
    </Modal>

    <Modal v-if="confirmAll" title="断开全部连接" @close="confirmAll = false">
      <p class="small">将断开当前 {{ displayTotal }} 个活动连接，已建立的连接会立即中断。</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="cancel-disconnect-all" @click="confirmAll = false">取消</button>
        <button type="button" class="btn danger" data-testid="confirm-disconnect-all" @click="disconnectAll">断开全部</button>
      </template>
    </Modal>
  </div>
</template>
