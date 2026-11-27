<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import DailyBars from './DailyBars.vue'
import EmptyState from './EmptyState.vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import Segmented from './Segmented.vue'
import { formatBytes } from '../lib/format'
import { t } from '../lib/i18n'
import { useStore } from '../lib/store'
import { useVirtualList } from '../lib/ui/virtual'
import { localDateKey, shiftDateKey, type TrafficGrouping, type TrafficRange } from '../lib/types'

/**
 * Traffic stats (R43): the switch state, today / 7 / 30 / custom ranges inside
 * the retention window, grouping by profile, group or node, daily bars and
 * clear-all. With recording off the dialog only explains how to turn it on.
 */
const emit = defineEmits<{ close: [] }>()
const store = useStore()

const grouping = ref<TrafficGrouping>('profile')
const range = ref<TrafficRange>(store.trafficStatsRange.value.range)
const from = ref(store.trafficStatsRange.value.from ?? '')
const to = ref(store.trafficStatsRange.value.to ?? '')
const confirmingClear = ref(false)

const view = computed(() => store.trafficStats.value)
const busy = computed(() => store.trafficStatsBusy.value)
const enabled = computed(() => view.value?.enabled ?? false)
const retention = computed(() => view.value?.retention_days ?? 90)
const today = computed(() => view.value?.today ?? localDateKey())
const minDate = computed(() => shiftDateKey(today.value, -(retention.value - 1)))

const rangeOptions = computed(() => [
  { id: 'today' as TrafficRange, label: t('traffic.range.today') },
  { id: '7d' as TrafficRange, label: t('traffic.range.7d') },
  { id: '30d' as TrafficRange, label: t('traffic.range.30d') },
  { id: 'custom' as TrafficRange, label: t('traffic.range.custom') },
])

const groupingOptions = computed(() => [
  { id: 'profile' as TrafficGrouping, label: t('traffic.group.profile') },
  { id: 'group' as TrafficGrouping, label: t('traffic.group.group') },
  { id: 'node' as TrafficGrouping, label: t('traffic.group.node') },
])

interface GroupRow {
  key: string
  label: string
  upload: number
  download: number
}

/**
 * One row per label. DIRECT/REJECT always stays its own "直连" row, so R43's
 * separate Direct line is visible in every grouping; the totals still match.
 */
const rows = computed<GroupRow[]>(() => {
  const groups = new Map<string, GroupRow>()
  for (const entry of view.value?.entries ?? []) {
    let label: string
    let key: string
    if (entry.direct) {
      label = t('traffic.direct')
      key = `${grouping.value}:direct`
    } else if (grouping.value === 'profile') {
      label = entry.profile || t('traffic.unknown')
      key = `profile:${entry.profile}`
    } else {
      label = (grouping.value === 'group' ? entry.group : entry.node) || t('traffic.unknown')
      key = `${grouping.value}:${label}`
    }
    const row = groups.get(key) ?? { key, label, upload: 0, download: 0 }
    row.upload += entry.upload
    row.download += entry.download
    groups.set(key, row)
  }
  return [...groups.values()]
    .filter((row) => row.upload > 0 || row.download > 0)
    .sort((left, right) => right.upload + right.download - (left.upload + left.download))
})

const tableBody = ref<HTMLTableSectionElement | null>(null)
const rowHeight = ref(44)
const windowed = computed(() => rows.value.length > 80)
const list = useVirtualList(computed(() => rows.value.length), () => rowHeight.value)
const visibleRows = computed(() => windowed.value
  ? rows.value.slice(list.window.value.start, list.window.value.end)
  : rows.value)

watch([tableBody, rows], ([body], _, onCleanup) => {
  if (!body || !windowed.value) return
  const scroller = body.closest<HTMLElement>('.modal-body')
  if (!scroller) return
  let contentTop = 0
  const onScroll = () => list.measure(scroller, contentTop)
  const measure = () => {
    const row = body.querySelector<HTMLElement>('tr[data-key]')
    const height = row?.getBoundingClientRect().height
    if (height) rowHeight.value = height
    const top = body.getBoundingClientRect().top - scroller.getBoundingClientRect().top
    contentTop = scroller.scrollTop + top - scroller.clientTop
    onScroll()
  }
  measure()
  scroller.addEventListener('scroll', onScroll, { passive: true })
  const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
  observer?.observe(scroller)
  observer?.observe(body)
  onCleanup(() => {
    observer?.disconnect()
    scroller.removeEventListener('scroll', onScroll)
  })
}, { flush: 'post' })

const totals = computed(() =>
  rows.value.reduce((sum, row) => {
    sum.upload += row.upload
    sum.download += row.download
    return sum
  }, { upload: 0, download: 0 }),
)

/** Width of each row's share bar, relative to the largest row so small rows stay visible. */
const topRow = computed(() => {
  const first = rows.value[0]
  return first ? Math.max(1, first.upload + first.download) : 1
})
function rowShare(row: GroupRow): string {
  return `${Math.max(1.5, ((row.upload + row.download) / topRow.value) * 100)}%`
}

const groupingLabel = computed(
  () => groupingOptions.value.find((option) => option.id === grouping.value)?.label ?? '',
)

/** Every day of the range, including empty ones, so the bar chart keeps its axis. */
const days = computed<{ date: string; upload: number; download: number }[]>(() => {
  const current = view.value
  if (!current) return []
  const sums = new Map<string, { upload: number; download: number }>()
  for (const entry of current.entries) {
    const sum = sums.get(entry.date) ?? { upload: 0, download: 0 }
    sum.upload += entry.upload
    sum.download += entry.download
    sums.set(entry.date, sum)
  }
  const out: { date: string; upload: number; download: number }[] = []
  let date = current.from
  for (let guard = 0; date <= current.to && guard < 400; guard += 1) {
    const sum = sums.get(date)
    out.push({ date, upload: sum?.upload ?? 0, download: sum?.download ?? 0 })
    date = shiftDateKey(date, 1)
  }
  return out
})

/** A one-day range has nothing to compare, so the daily chart only shows for longer ranges. */
const showsDaily = computed(
  () => days.value.length > 1 && days.value.some((day) => day.upload > 0 || day.download > 0),
)

function load(): Promise<unknown> {
  return store.loadTrafficStats(range.value, from.value || null, to.value || null)
}

async function chooseRange(next: TrafficRange) {
  range.value = next
  if (next === 'custom') {
    from.value = from.value || view.value?.from || minDate.value
    to.value = to.value || view.value?.to || today.value
    if (from.value !== to.value) await load()
    return
  }
  from.value = ''
  to.value = ''
  await load()
}

function applyCustom() {
  if (range.value !== 'custom') return
  void load()
}

function enable() {
  void store.setTrafficRecording(true)
}

async function clearAll() {
  confirmingClear.value = false
  await store.clearTrafficHistory()
}

onMounted(() => {
  void load()
})
onBeforeUnmount(store.releaseTrafficStats)
</script>


<template>
  <Modal :title="t('traffic.title')" wide @close="emit('close')">
    <div class="traffic-stats" data-testid="traffic-stats">
      <p v-if="store.trafficStatsError.value" class="field-error small" role="alert" data-testid="traffic-error">
        <Icon name="alert" :size="13" />
        {{ t('traffic.loadError', { reason: store.trafficStatsError.value }) }}
      </p>

      <!-- Nothing recorded yet: only the switch is offered (R43). -->
      <template v-if="view && (enabled || view.entries.length)">
        <!-- Recording is off but earlier rows exist: they stay readable and clearable. -->
        <div v-if="!enabled" class="traffic-off-banner" data-testid="traffic-off">
          <Icon name="pause" :size="15" class="muted" />
          <span class="grow min0 small">
            <strong>{{ t('traffic.off') }}</strong>
            <span class="muted"> · {{ t('traffic.offShort') }}</span>
          </span>
          <button type="button" class="btn ghost sm accent-text" :disabled="busy" data-testid="traffic-enable" @click="enable">
            {{ t('traffic.enable') }}
          </button>
        </div>

        <div class="traffic-controls">
          <Segmented
            :model-value="range"
            :options="rangeOptions"
            :label="t('traffic.rangeLabel')"
            size="sm"
            data-testid="traffic-range"
            @update:model-value="chooseRange"
          />
          <Segmented
            :model-value="grouping"
            :options="groupingOptions"
            :label="t('traffic.groupingLabel')"
            size="sm"
            data-testid="traffic-grouping"
            @update:model-value="(value) => (grouping = value)"
          />
        </div>

        <div v-if="range === 'custom'" class="traffic-dates" data-testid="traffic-custom">
          <input
            v-model="from"
            class="input"
            type="date"
            :min="minDate"
            :max="to || today"
            :aria-label="t('traffic.from')"
            data-testid="traffic-from"
            @change="applyCustom"
          />
          <span class="muted" aria-hidden="true">–</span>
          <input
            v-model="to"
            class="input"
            type="date"
            :min="from || minDate"
            :max="today"
            :aria-label="t('traffic.to')"
            data-testid="traffic-to"
            @change="applyCustom"
          />
        </div>

        <template v-if="rows.length">
          <div class="traffic-summary" data-testid="traffic-totals">
            <div class="traffic-summary-main">
              <span class="muted small">{{ t('traffic.total') }}</span>
              <strong class="traffic-summary-value" data-testid="traffic-total-all">{{ formatBytes(totals.upload + totals.download) }}</strong>
            </div>
            <div class="traffic-summary-split small">
              <Icon name="down" :size="12" class="traffic-icon down" aria-hidden="true" />
              <span class="muted">{{ t('traffic.download') }}</span>
              <span class="mono" data-testid="traffic-total-download">{{ formatBytes(totals.download) }}</span>
              <Icon name="up" :size="12" class="traffic-icon up" aria-hidden="true" />
              <span class="muted">{{ t('traffic.upload') }}</span>
              <span class="mono" data-testid="traffic-total-upload">{{ formatBytes(totals.upload) }}</span>
            </div>
          </div>

          <DailyBars v-if="showsDaily" :days="days" />

          <table class="traffic-table small" :aria-rowcount="rows.length + 1">
            <thead>
              <tr>
                <th>{{ groupingLabel }}</th>
                <th class="num">{{ t('traffic.download') }}</th>
                <th class="num">{{ t('traffic.upload') }}</th>
                <th class="num">{{ t('traffic.total') }}</th>
              </tr>
            </thead>
            <tbody ref="tableBody">
              <tr v-if="windowed && list.offset.value" aria-hidden="true">
                <td class="traffic-spacer" colspan="4" :style="{ height: list.offset.value + 'px' }" />
              </tr>
              <tr v-for="(row, index) in visibleRows" :key="row.key" data-testid="traffic-row" :data-key="row.key"
                :aria-rowindex="(windowed ? list.window.value.start : 0) + index + 2">
                <td class="traffic-label">
                  <span class="traffic-label-text" :class="{ muted: row.key.endsWith(':direct') }" :title="row.label">{{ row.label }}</span>
                  <span class="traffic-share" aria-hidden="true"><span :style="{ width: rowShare(row) }" /></span>
                </td>
                <td class="num mono">{{ formatBytes(row.download) }}</td>
                <td class="num mono">{{ formatBytes(row.upload) }}</td>
                <td class="num mono strong">{{ formatBytes(row.upload + row.download) }}</td>
              </tr>
              <tr v-if="windowed && list.tail.value" aria-hidden="true">
                <td class="traffic-spacer" colspan="4" :style="{ height: list.tail.value + 'px' }" />
              </tr>
            </tbody>
          </table>
        </template>

        <EmptyState
          v-else
          compact
          icon="activity"
          :title="t('traffic.empty')"
          :description="enabled ? t('traffic.emptyDetail') : t('traffic.offShort')"
          data-testid="traffic-empty"
        />
      </template>

      <!-- Fresh install (or a cleared view while recording is off): how to start. -->
      <EmptyState
        v-else-if="view"
        icon="activity"
        :title="t('traffic.off')"
        :description="t('traffic.offDetail')"
        data-testid="traffic-off"
      >
        <template #action>
          <button type="button" class="btn primary sm" :disabled="busy" data-testid="traffic-enable" @click="enable">
            {{ t('traffic.enable') }}
          </button>
        </template>
      </EmptyState>

      <EmptyState v-else variant="loading" compact :title="t('traffic.loading')" description="" data-testid="traffic-loading" />
    </div>

    <template v-if="view && (enabled || view.entries.length)" #footer>
      <div v-if="!confirmingClear" class="traffic-foot">
        <span class="muted small" data-testid="traffic-retention">{{ t('settings.traffic.retention', { days: retention }) }}</span>
        <button
          v-if="view.entries.length"
          type="button"
          class="btn ghost sm danger-text"
          :disabled="busy"
          data-testid="traffic-clear"
          @click="confirmingClear = true"
        >
          <Icon name="trash" :size="14" />{{ t('traffic.clear') }}
        </button>
      </div>
      <div v-else class="traffic-foot" role="alertdialog" data-testid="traffic-clear-confirm-box">
        <span class="small">{{ t('traffic.clearConfirm') }}</span>
        <span class="traffic-foot-actions">
          <button type="button" class="btn ghost sm" data-testid="traffic-clear-cancel" @click="confirmingClear = false">
            {{ t('traffic.clearCancel') }}
          </button>
          <button type="button" class="btn danger sm" data-testid="traffic-clear-confirm" @click="clearAll">
            {{ t('traffic.clearConfirmAction') }}
          </button>
        </span>
      </div>
    </template>
  </Modal>
</template>

<style scoped>
.traffic-stats {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.traffic-off-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 6px 6px 12px;
  border-radius: var(--radius-control);
  background: var(--sunken);
}

.accent-text {
  color: var(--accent-ink);
}

.traffic-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: space-between;
}

.traffic-dates {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: -6px;
}

.traffic-dates .input {
  width: auto;
  min-width: 0;
  flex: 0 1 170px;
}

.traffic-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: 8px 20px;
}

.traffic-summary-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.traffic-summary-value {
  font-size: var(--text-2xl);
  font-weight: 700;
  line-height: 1.1;
  letter-spacing: -0.02em;
  font-variant-numeric: tabular-nums;
}

.traffic-summary-split {
  display: flex;
  align-items: center;
  gap: 6px;
  padding-bottom: 3px;
}

.traffic-summary-split .mono {
  margin-right: 10px;
  color: var(--text);
}

.traffic-summary-split .mono:last-child {
  margin-right: 0;
}

.traffic-icon {
  flex: none;
}

.traffic-icon.down {
  color: var(--data-down);
}

.traffic-icon.up {
  color: var(--data-up);
}

.traffic-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}

.traffic-table th,
.traffic-table td {
  padding: 8px 6px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.traffic-table th:first-child,
.traffic-table td:first-child {
  padding-left: 0;
}

.traffic-table td.traffic-spacer {
  padding: 0;
  border: 0;
}

.traffic-table th:last-child,
.traffic-table td:last-child {
  padding-right: 0;
}

.traffic-table tbody tr:last-child td {
  border-bottom: 0;
}

.traffic-table th {
  font-weight: 560;
  color: var(--muted);
  font-size: var(--text-xs);
}

.traffic-table th:first-child {
  width: 46%;
}

.traffic-table .num {
  text-align: right;
  white-space: nowrap;
  color: var(--text-2);
}

.traffic-table .num.strong {
  color: var(--text);
  font-weight: 600;
}

.traffic-label {
  min-width: 0;
}

.traffic-label-text {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 560;
}

.traffic-share {
  display: block;
  height: 3px;
  margin-top: 5px;
  border-radius: 2px;
  background: var(--sunken);
  overflow: hidden;
}

.traffic-share > span {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: var(--data-down);
  opacity: 0.7;
}

.traffic-foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
}

.traffic-foot-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

/* Phone sheets stretch footer buttons; this footer keeps its quiet, compact actions. */
.traffic-foot .btn {
  flex: none;
}
</style>
