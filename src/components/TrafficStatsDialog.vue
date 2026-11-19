<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import DailyBars from './DailyBars.vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import Segmented from './Segmented.vue'
import { formatBytes } from '../lib/format'
import { t } from '../lib/i18n'
import { useStore } from '../lib/store'
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
 * One row per label. Grouping by profile keeps DIRECT traffic under its profile;
 * grouping by group or node folds every built-in policy into "Direct".
 */
const rows = computed<GroupRow[]>(() => {
  const groups = new Map<string, GroupRow>()
  for (const entry of view.value?.entries ?? []) {
    let label: string
    let key: string
    if (grouping.value === 'profile') {
      label = entry.profile || t('traffic.unknown')
      key = `profile:${entry.profile}`
    } else if (entry.direct) {
      label = t('traffic.direct')
      key = `${grouping.value}:direct`
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

const totals = computed(() =>
  rows.value.reduce(
    (sum, row) => ({ upload: sum.upload + row.upload, download: sum.download + row.download }),
    { upload: 0, download: 0 },
  ),
)

/** Every day of the range, including empty ones, so the bar chart keeps its axis. */
const days = computed(() => {
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
</script>

<template>
  <Modal :title="t('traffic.title')" :subtitle="t('traffic.subtitle')" wide @close="emit('close')">
    <div class="traffic-stats" data-testid="traffic-stats">
      <p v-if="store.trafficStatsError.value" class="field-error small" role="alert" data-testid="traffic-error">
        <Icon name="alert" :size="13" />
        {{ t('traffic.loadError', { reason: store.trafficStatsError.value }) }}
      </p>

      <!-- Nothing recorded yet: only the switch is offered (R43). -->
      <template v-if="view && (enabled || view.entries.length)">
        <!-- Recording is off but earlier rows exist: they stay readable and clearable. -->
        <div v-if="!enabled" class="traffic-off-banner" data-testid="traffic-off">
          <span class="traffic-off-icon sm"><Icon name="pause" :size="16" /></span>
          <div class="grow min0">
            <strong>{{ t('traffic.off') }}</strong>
            <p class="muted small">{{ t('traffic.offDetail') }}</p>
          </div>
          <button type="button" class="btn primary sm" :disabled="busy" data-testid="traffic-enable" @click="enable">
            <Icon name="play" :size="14" />{{ t('traffic.enable') }}
          </button>
        </div>

        <div class="traffic-controls">
          <Segmented
            :model-value="range"
            :options="rangeOptions"
            :label="t('traffic.title')"
            size="sm"
            data-testid="traffic-range"
            @update:model-value="chooseRange"
          />
          <Segmented
            :model-value="grouping"
            :options="groupingOptions"
            :label="t('traffic.group.profile')"
            size="sm"
            data-testid="traffic-grouping"
            @update:model-value="(value) => (grouping = value)"
          />
        </div>

        <div v-if="range === 'custom'" class="traffic-dates" data-testid="traffic-custom">
          <label class="field">
            <span>{{ t('traffic.from') }}</span>
            <input
              v-model="from"
              class="input"
              type="date"
              :min="minDate"
              :max="today"
              data-testid="traffic-from"
              @change="applyCustom"
            />
          </label>
          <label class="field">
            <span>{{ t('traffic.to') }}</span>
            <input
              v-model="to"
              class="input"
              type="date"
              :min="minDate"
              :max="today"
              data-testid="traffic-to"
              @change="applyCustom"
            />
          </label>
          <p class="muted small traffic-retention">
            {{ t('settings.traffic.retention', { days: retention }) }}
          </p>
        </div>

        <div class="traffic-totals" data-testid="traffic-totals">
          <div class="traffic-total">
            <span class="muted small">{{ t('traffic.download') }}</span>
            <strong class="mono" data-testid="traffic-total-download">{{ formatBytes(totals.download) }}</strong>
          </div>
          <div class="traffic-total">
            <span class="muted small">{{ t('traffic.upload') }}</span>
            <strong class="mono" data-testid="traffic-total-upload">{{ formatBytes(totals.upload) }}</strong>
          </div>
          <div class="traffic-total">
            <span class="muted small">{{ t('traffic.total') }}</span>
            <strong class="mono" data-testid="traffic-total-all">{{ formatBytes(totals.upload + totals.download) }}</strong>
          </div>
        </div>

        <section class="traffic-section">
          <h3>{{ t('traffic.daily') }}</h3>
          <DailyBars v-if="days.some((day) => day.upload > 0 || day.download > 0)" :days="days" />
          <p v-else class="muted small" data-testid="traffic-empty">{{ t('traffic.empty') }}</p>
        </section>

        <table v-if="rows.length" class="traffic-table small">
          <thead>
            <tr>
              <th>{{ grouping === 'profile' ? t('traffic.group.profile') : grouping === 'group' ? t('traffic.group.group') : t('traffic.group.node') }}</th>
              <th class="num">{{ t('traffic.upload') }}</th>
              <th class="num">{{ t('traffic.download') }}</th>
              <th class="num">{{ t('traffic.total') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in rows" :key="row.key" data-testid="traffic-row" :data-key="row.key">
              <td class="traffic-label">
                <span v-if="row.label === t('traffic.direct')" class="tag sm">{{ row.label }}</span>
                <span v-else>{{ row.label }}</span>
              </td>
              <td class="num mono">{{ formatBytes(row.upload) }}</td>
              <td class="num mono">{{ formatBytes(row.download) }}</td>
              <td class="num mono">{{ formatBytes(row.upload + row.download) }}</td>
            </tr>
          </tbody>
        </table>

        <footer class="traffic-actions">
          <div v-if="!confirmingClear">
            <button
              type="button"
              class="btn ghost sm danger"
              :disabled="busy || (!rows.length && !view.entries.length)"
              data-testid="traffic-clear"
              @click="confirmingClear = true"
            >
              <Icon name="trash" :size="14" />{{ t('traffic.clear') }}
            </button>
          </div>
          <div v-else class="traffic-confirm" role="alertdialog" data-testid="traffic-clear-confirm-box">
            <span class="small">{{ t('traffic.clearConfirm') }}</span>
            <button type="button" class="btn ghost sm" data-testid="traffic-clear-cancel" @click="confirmingClear = false">
              {{ t('traffic.clearCancel') }}
            </button>
            <button type="button" class="btn danger sm" data-testid="traffic-clear-confirm" @click="clearAll">
              {{ t('traffic.clearConfirmAction') }}
            </button>
          </div>
        </footer>
      </template>

      <!-- Fresh install (or a cleared view while recording is off): how to start. -->
      <div v-else-if="view" class="traffic-off" data-testid="traffic-off">
        <span class="traffic-off-icon"><Icon name="pause" :size="20" /></span>
        <strong>{{ t('traffic.off') }}</strong>
        <p class="muted small">{{ t('traffic.offDetail') }}</p>
        <button type="button" class="btn primary sm" :disabled="busy" data-testid="traffic-enable" @click="enable">
          <Icon name="play" :size="14" />{{ t('traffic.enable') }}
        </button>
        <p class="muted small" data-testid="traffic-retention">
          {{ t('settings.traffic.retention', { days: retention }) }}
        </p>
      </div>

      <p v-else class="muted small" data-testid="traffic-loading">{{ t('traffic.loading') }}</p>
    </div>
  </Modal>
</template>

<style scoped>
.traffic-stats {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.traffic-off {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 26px 16px;
  text-align: center;
  border: 1px dashed var(--border);
  border-radius: 12px;
}

.traffic-off-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface-2, rgba(127, 127, 127, 0.06));
}

.traffic-off-banner p {
  margin: 2px 0 0;
}

.traffic-off-icon.sm {
  width: 30px;
  height: 30px;
  flex: none;
}

.traffic-off-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  color: var(--muted);
  background: var(--surface-2, rgba(127, 127, 127, 0.08));
}

.traffic-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: space-between;
}

.traffic-dates {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 10px;
}

.traffic-dates .field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.traffic-retention {
  margin: 0 0 4px;
}

.traffic-totals {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.traffic-total {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface-2, rgba(127, 127, 127, 0.06));
}

.traffic-total strong {
  font-size: 16px;
}

.traffic-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.traffic-section h3 {
  margin: 0;
  font-size: 13px;
  color: var(--muted);
  font-weight: 500;
}

.traffic-table {
  width: 100%;
  border-collapse: collapse;
}

.traffic-table th,
.traffic-table td {
  padding: 7px 8px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.traffic-table th {
  font-weight: 500;
  color: var(--muted);
}

.traffic-table .num {
  text-align: right;
  white-space: nowrap;
}

.traffic-label {
  word-break: break-word;
}

.traffic-actions {
  display: flex;
  justify-content: flex-end;
}

.traffic-confirm {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  justify-content: flex-end;
}
</style>
