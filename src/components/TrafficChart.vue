<script setup lang="ts">
import { computed } from 'vue'
import { formatSpeed } from '../lib/format'

const props = defineProps<{ up: number[]; down: number[]; height?: number }>()

const W = 600
const H = computed(() => props.height ?? 140)

const peak = computed(() => {
  const max = Math.max(1, ...props.up, ...props.down)
  // Round the scale up to a tidy step so the grid label does not jitter every second.
  const steps = [1, 2, 5]
  let unit = 1024
  while (true) {
    for (const step of steps) {
      if (step * unit >= max) return step * unit
    }
    unit *= 10
  }
})

function line(values: number[]): string {
  if (values.length < 2) return ''
  const dx = W / (values.length - 1)
  const h = H.value - 6
  return values
    .map((value, index) => {
      const x = index * dx
      const y = H.value - 2 - (value / peak.value) * h
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}

function area(values: number[]): string {
  const path = line(values)
  return path ? `${path} L${W},${H.value} L0,${H.value} Z` : ''
}

const downLine = computed(() => line(props.down))
const upLine = computed(() => line(props.up))
const downArea = computed(() => area(props.down))
const upArea = computed(() => area(props.up))
</script>

<template>
  <div class="chart">
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" :height="H" role="img" aria-label="最近一分钟流量">
      <line v-for="i in 3" :key="i" x1="0" :x2="W" :y1="(H / 4) * i" :y2="(H / 4) * i" class="chart-grid" />
      <path :d="downArea" class="chart-area down" />
      <path :d="upArea" class="chart-area up" />
      <path :d="downLine" class="chart-line down" vector-effect="non-scaling-stroke" />
      <path :d="upLine" class="chart-line up" vector-effect="non-scaling-stroke" />
    </svg>
    <span class="chart-peak">{{ formatSpeed(peak) }}</span>
  </div>
</template>
