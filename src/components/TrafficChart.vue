<script setup lang="ts">
import { computed, ref, useId } from 'vue'
import { formatSpeed } from '../lib/format'

const props = defineProps<{ up: number[]; down: number[]; height?: number }>()

const W = 600
const H = computed(() => props.height ?? 140)
const uid = useId()
const chartEl = ref<HTMLElement | null>(null)
const hoverIndex = ref<number | null>(null)

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

function pointsOf(values: number[]): { x: number; y: number }[] {
  if (values.length < 2) return []
  const dx = W / (values.length - 1)
  const h = H.value - 8
  return values.map((value, index) => ({
    x: index * dx,
    y: H.value - 3 - Math.min(1, Math.max(0, value / peak.value)) * h,
  }))
}

/** Monotone cubic Hermite curve: smooth without overshooting zero or peaks. */
function smoothLine(values: number[]): string {
  const pts = pointsOf(values)
  const n = pts.length
  if (n < 2) return ''
  if (n === 2) {
    return `M${pts[0]!.x.toFixed(1)},${pts[0]!.y.toFixed(1)} L${pts[1]!.x.toFixed(1)},${pts[1]!.y.toFixed(1)}`
  }
  const dx: number[] = []
  const dy: number[] = []
  const m: number[] = []
  for (let i = 0; i < n - 1; i++) {
    const dxi = pts[i + 1]!.x - pts[i]!.x
    const dyi = pts[i + 1]!.y - pts[i]!.y
    dx.push(dxi)
    dy.push(dyi)
    m.push(dxi > 0 ? dyi / dxi : 0)
  }
  const tangents: number[] = [m[0]!]
  for (let i = 1; i < n - 1; i++) {
    if (m[i - 1]! * m[i]! <= 0) tangents.push(0)
    else tangents.push((m[i - 1]! + m[i]!) / 2)
  }
  tangents.push(m[n - 2]!)
  for (let i = 0; i < n - 1; i++) {
    const slope = m[i]!
    if (slope === 0) {
      tangents[i] = 0
      tangents[i + 1] = 0
    } else {
      const a = tangents[i]! / slope
      const b = tangents[i + 1]! / slope
      const hypot = Math.hypot(a, b)
      if (hypot > 3) {
        const scale = 3 / hypot
        tangents[i] = scale * a * slope
        tangents[i + 1] = scale * b * slope
      }
    }
  }
  const parts = [`M${pts[0]!.x.toFixed(1)},${pts[0]!.y.toFixed(1)}`]
  for (let i = 0; i < n - 1; i++) {
    const p0 = pts[i]!
    const p1 = pts[i + 1]!
    const step = dx[i]! / 3
    const c1x = p0.x + step
    const c1y = p0.y + tangents[i]! * step
    const c2x = p1.x - step
    const c2y = p1.y - tangents[i + 1]! * step
    parts.push(`C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p1.x.toFixed(1)},${p1.y.toFixed(1)}`)
  }
  return parts.join(' ')
}

function area(values: number[]): string {
  const path = smoothLine(values)
  return path ? `${path} L${W},${H.value} L0,${H.value} Z` : ''
}

function last(values: number[]): number {
  return values[values.length - 1] ?? 0
}

const downLine = computed(() => smoothLine(props.down))
const upLine = computed(() => smoothLine(props.up))
const downArea = computed(() => area(props.down))
const upArea = computed(() => area(props.up))

const sampleCount = computed(() => Math.min(props.down.length, props.up.length))

const inspected = computed(() => {
  const idx = hoverIndex.value
  const count = sampleCount.value
  if (idx == null || count < 2) return null
  const clamped = Math.min(Math.max(0, idx), count - 1)
  const downVal = props.down[clamped] ?? 0
  const upVal = props.up[clamped] ?? 0
  const ratioX = clamped / (count - 1)
  const h = H.value - 8
  const downY = H.value - 3 - Math.min(1, Math.max(0, downVal / peak.value)) * h
  const upY = H.value - 3 - Math.min(1, Math.max(0, upVal / peak.value)) * h
  const secsAgo = count - 1 - clamped
  return {
    xPct: ratioX * 100,
    svgX: ratioX * W,
    downY,
    upY,
    downVal,
    upVal,
    when: secsAgo === 0 ? '当前' : `${secsAgo} 秒前`,
  }
})

function onPointerMove(event: PointerEvent) {
  const el = chartEl.value
  const count = sampleCount.value
  if (!el || count < 2) return
  const rect = el.getBoundingClientRect()
  if (rect.width <= 0) return
  const ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width))
  hoverIndex.value = Math.round(ratio * (count - 1))
}

function onPointerLeave() {
  hoverIndex.value = null
}

// The chart is the summary of the last minute, so the accessible name carries the numbers.
const label = computed(
  () =>
    `最近一分钟流量，峰值 ${formatSpeed(peak.value)}，当前下载 ${formatSpeed(last(props.down))}，上传 ${formatSpeed(last(props.up))}`,
)
</script>

<template>
  <div
    ref="chartEl"
    class="chart"
    @pointermove="onPointerMove"
    @pointerleave="onPointerLeave"
    @pointercancel="onPointerLeave"
  >
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" :height="H" role="img" :aria-label="label">
      <title>{{ label }}</title>
      <defs>
        <linearGradient :id="`${uid}-down`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--data-down)" stop-opacity="0.22" />
          <stop offset="100%" stop-color="var(--data-down)" stop-opacity="0.01" />
        </linearGradient>
        <linearGradient :id="`${uid}-up`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--data-up)" stop-opacity="0.18" />
          <stop offset="100%" stop-color="var(--data-up)" stop-opacity="0.01" />
        </linearGradient>
      </defs>
      <line v-for="i in 3" :key="i" x1="0" :x2="W" :y1="(H / 4) * i" :y2="(H / 4) * i" class="chart-grid" />
      <path :d="downArea" :fill="`url(#${uid}-down)`" class="chart-area down" />
      <path :d="upArea" :fill="`url(#${uid}-up)`" class="chart-area up" />
      <path :d="downLine" class="chart-line down" vector-effect="non-scaling-stroke" stroke-linecap="round" />
      <path :d="upLine" class="chart-line up" vector-effect="non-scaling-stroke" stroke-linecap="round" />
      <line
        v-if="inspected"
        :x1="inspected.svgX"
        :x2="inspected.svgX"
        y1="2"
        :y2="H - 2"
        class="chart-cursor"
        vector-effect="non-scaling-stroke"
      />
    </svg>
    <template v-if="inspected">
      <span class="chart-dot down" :style="{ left: `${inspected.xPct}%`, top: `${inspected.downY}px` }" aria-hidden="true" />
      <span class="chart-dot up" :style="{ left: `${inspected.xPct}%`, top: `${inspected.upY}px` }" aria-hidden="true" />
      <div
        class="chart-tooltip mono"
        :class="{ right: inspected.xPct > 62 }"
        data-testid="chart-tooltip"
        aria-hidden="true"
      >
        <span class="muted">{{ inspected.when }}</span>
        <span class="up">↑ {{ formatSpeed(inspected.upVal) }}</span>
        <span class="down">↓ {{ formatSpeed(inspected.downVal) }}</span>
      </div>
    </template>
    <span class="chart-peak">{{ formatSpeed(peak) }}</span>
  </div>
</template>
