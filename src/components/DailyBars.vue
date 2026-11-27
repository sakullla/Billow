<script setup lang="ts">
import { computed } from 'vue'
import { formatBytes } from '../lib/format'
import { t } from '../lib/i18n'

/**
 * Daily traffic bars for the stats dialog (R43): one column per local day,
 * download below and upload on top, scaled to the busiest day in the range.
 * Empty days keep a hairline baseline so a 30-day range does not collapse,
 * without painting thirty grey tracks.
 */
const props = withDefaults(
  defineProps<{
    days: { date: string; upload: number; download: number }[]
    height?: number
  }>(),
  { height: 112 },
)

const peak = computed(() => Math.max(1, ...props.days.map((day) => day.upload + day.download)))
const label = computed(() => {
  const upload = props.days.reduce((sum, day) => sum + day.upload, 0)
  const download = props.days.reduce((sum, day) => sum + day.download, 0)
  return `${t('traffic.daily')}: ${t('traffic.download')} ${formatBytes(download)}, ${t('traffic.upload')} ${formatBytes(upload)}`
})

/** Share of the column height; any non-zero day gets at least a visible sliver. */
function share(value: number): string {
  if (value <= 0) return '0%'
  return `${Math.max(3, (value / peak.value) * 100)}%`
}

/** Only the ends and a few stops get a date label, or 30+ days would smear. */
function showsLabel(index: number): boolean {
  const count = props.days.length
  if (count <= 8) return true
  const step = Math.ceil(count / 5)
  return index === 0 || index === count - 1 || (index % step === 0 && count - 1 - index >= step / 2)
}

function shortDate(date: string): string {
  const [, month, day] = date.split('-')
  return month && day ? `${Number(month)}/${Number(day)}` : date
}

function title(day: { date: string; upload: number; download: number }): string {
  return `${day.date}\n${t('traffic.download')} ${formatBytes(day.download)} · ${t('traffic.upload')} ${formatBytes(day.upload)}`
}
</script>

<template>
  <div class="daily-bars" role="img" :aria-label="label" data-testid="traffic-daily-bars">
    <div class="daily-bars-plot" :style="{ height: `${height}px` }">
      <div
        v-for="day in days"
        :key="day.date"
        class="daily-bar"
        :class="{ empty: day.upload + day.download <= 0 }"
        :title="title(day)"
        data-testid="traffic-daily-bar"
      >
        <span class="daily-bar-stack" :style="{ height: share(day.upload + day.download) }">
          <span class="daily-bar-up" :style="{ flexGrow: day.upload }" />
          <span class="daily-bar-down" :style="{ flexGrow: day.download }" />
        </span>
      </div>
    </div>
    <div class="daily-bars-axis" aria-hidden="true">
      <span v-for="(day, index) in days" :key="day.date" class="daily-bar-label">
        {{ showsLabel(index) ? shortDate(day.date) : '' }}
      </span>
    </div>
  </div>
</template>

<style scoped>
.daily-bars {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
}

.daily-bars-plot {
  display: flex;
  align-items: flex-end;
  gap: 3px;
  border-bottom: 1px solid var(--border);
}

.daily-bar {
  flex: 1 1 0;
  min-width: 2px;
  height: 100%;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  border-radius: 4px 4px 0 0;
  transition: background var(--dur-fast) var(--ease);
}

.daily-bar:hover {
  background: var(--hover);
}

.daily-bar-stack {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 28px;
  min-height: 0;
  border-radius: 4px 4px 1px 1px;
  overflow: hidden;
}

.daily-bar-down {
  flex-basis: 0;
  min-height: 0;
  background: var(--data-down);
}

.daily-bar-up {
  flex-basis: 0;
  min-height: 0;
  background: var(--data-up);
}

.daily-bars-axis {
  display: flex;
  gap: 3px;
}

.daily-bar-label {
  flex: 1 1 0;
  min-width: 2px;
  font-size: var(--text-xs);
  line-height: 1;
  color: var(--muted);
  text-align: center;
  white-space: nowrap;
  overflow: visible;
  font-variant-numeric: tabular-nums;
}
</style>
