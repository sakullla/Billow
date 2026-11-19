<script setup lang="ts">
import { computed } from 'vue'
import { formatBytes } from '../lib/format'
import { t } from '../lib/i18n'

/**
 * Daily traffic bars for the stats dialog (R43): one column per local day,
 * download below and upload on top, scaled to the busiest day in the range.
 * Empty days stay visible so a 30-day range does not silently collapse.
 */
const props = withDefaults(
  defineProps<{
    days: { date: string; upload: number; download: number }[]
    height?: number
  }>(),
  { height: 120 },
)

const peak = computed(() => Math.max(1, ...props.days.map((day) => day.upload + day.download)))
const label = computed(() => {
  const upload = props.days.reduce((sum, day) => sum + day.upload, 0)
  const download = props.days.reduce((sum, day) => sum + day.download, 0)
  return `${t('traffic.daily')}: ${t('traffic.download')} ${formatBytes(download)}, ${t('traffic.upload')} ${formatBytes(upload)}`
})

function share(value: number): string {
  if (value <= 0) return '0%'
  return `${Math.max(2, (value / peak.value) * 100)}%`
}

/** Only the ends and a couple of stops get a date label, or 90 days would smear. */
function showsLabel(index: number): boolean {
  const count = props.days.length
  if (count <= 8) return true
  const step = Math.ceil(count / 5)
  return index === 0 || index === count - 1 || index % step === 0
}

function shortDate(date: string): string {
  const [, month, day] = date.split('-')
  return month && day ? `${Number(month)}/${Number(day)}` : date
}

function title(day: { date: string; upload: number; download: number }): string {
  return `${day.date} · ${t('traffic.download')} ${formatBytes(day.download)} · ${t('traffic.upload')} ${formatBytes(day.upload)}`
}
</script>

<template>
  <div class="daily-bars" :style="{ height: `${height}px` }" role="img" :aria-label="label" data-testid="traffic-daily-bars">
    <div v-for="(day, index) in days" :key="day.date" class="daily-bar" :title="title(day)" data-testid="traffic-daily-bar">
      <div class="daily-bar-track">
        <span class="daily-bar-down" :style="{ height: share(day.download) }" />
        <span class="daily-bar-up" :style="{ height: share(day.upload) }" />
      </div>
      <span v-if="showsLabel(index)" class="daily-bar-label">{{ shortDate(day.date) }}</span>
      <span v-else class="daily-bar-label" aria-hidden="true" />
    </div>
  </div>
</template>

<style scoped>
.daily-bars {
  display: flex;
  align-items: stretch;
  gap: 2px;
  width: 100%;
}

.daily-bar {
  flex: 1 1 0;
  min-width: 2px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.daily-bar-track {
  flex: 1;
  display: flex;
  flex-direction: column-reverse;
  justify-content: flex-start;
  border-radius: 3px;
  background: var(--surface-2, rgba(127, 127, 127, 0.08));
  overflow: hidden;
}

.daily-bar-down {
  display: block;
  width: 100%;
  background: var(--data-down);
  opacity: 0.75;
}

.daily-bar-up {
  display: block;
  width: 100%;
  background: var(--data-up);
  opacity: 0.85;
}

.daily-bar-label {
  font-size: 10px;
  line-height: 1;
  color: var(--muted);
  text-align: center;
  white-space: nowrap;
  min-height: 10px;
}
</style>
