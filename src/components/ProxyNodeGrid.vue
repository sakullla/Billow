<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { NodeItem } from '../lib/types'

const props = defineProps<{ nodes: NodeItem[]; dense: boolean; list?: boolean; compact?: boolean }>()
const root = ref<HTMLElement | null>(null)
const header = ref<HTMLElement | null>(null)
const columns = ref(1)
const top = ref(0)
const viewport = ref(600)
const gap = computed(() => props.compact ? (props.dense ? 7 : 0) : props.list ? 0 : props.dense ? 6 : 9)
const height = computed(() => props.compact ? (props.dense ? 56 : 76) : props.list ? 46 : props.dense ? 42 : 68)
const stride = computed(() => height.value + gap.value)
// Small groups retain their natural wrapping and keyboard order.
const virtual = computed(() => props.nodes.length > 80)
const rows = computed(() => Math.ceil(props.nodes.length / columns.value))
const range = computed(() => {
  if (!virtual.value) return { start: 0, end: rows.value }
  const start = Math.min(Math.max(0, Math.floor(top.value / stride.value) - 3), Math.max(0, rows.value - 1))
  const end = Math.min(rows.value, Math.max(start + 1, Math.ceil((top.value + viewport.value) / stride.value) + 3))
  return { start, end }
})
const visible = computed(() => virtual.value
  ? props.nodes.slice(range.value.start * columns.value, range.value.end * columns.value) : props.nodes)
const before = computed(() => Math.max(0, range.value.start * stride.value - gap.value))
const after = computed(() => Math.max(0, (rows.value - range.value.end) * stride.value - gap.value))
let scroller: HTMLElement | null = null
let observer: ResizeObserver | null = null
let frame: number | null = null
let disposed = false
let mounted = false

function measure() {
  const el = root.value
  if (!virtual.value || !el || !scroller) return
  const style = getComputedStyle(el)
  columns.value = Math.max(1, style.gridTemplateColumns.split(' ').filter(Boolean).length)
  const contentTop = header.value ? header.value.getBoundingClientRect().bottom + gap.value
    : el.getBoundingClientRect().top + (parseFloat(style.paddingTop) || 0)
  top.value = scroller.getBoundingClientRect().top - contentTop
  viewport.value = scroller.clientHeight || 600
}

function schedule() {
  if (disposed || !virtual.value || frame !== null) return
  frame = requestAnimationFrame(() => { frame = null; measure() })
}

async function reveal(name: string) {
  const index = props.nodes.findIndex((node) => node.name === name)
  if (!virtual.value || index < 0 || !root.value || !scroller) return
  measure()
  const row = Math.floor(index / columns.value)
  scroller.scrollTop += row * stride.value - top.value - viewport.value / 2 + height.value / 2
  measure()
  await nextTick()
}

// Tab across a window boundary must reach the next node, not skip the unseen rows.
async function onKeydown(event: KeyboardEvent) {
  if (!virtual.value || event.key !== 'Tab' || !root.value) return
  const buttons = [...root.value.querySelectorAll<HTMLButtonElement>('button:not(:disabled):not([tabindex="-1"])')]
  const backward = event.shiftKey
  if (event.target !== (backward ? buttons[0] : buttons[buttons.length - 1])) return
  const index = backward ? range.value.start * columns.value - 1 : range.value.end * columns.value
  const node = props.nodes[index]
  if (!node) return
  event.preventDefault()
  await reveal(node.name)
  if (disposed) return
  const row = root.value?.querySelector(`[data-node="${CSS.escape(node.name)}"]`)
  const targets = row?.querySelectorAll<HTMLButtonElement>('button:not(:disabled):not([tabindex="-1"])')
  if (targets?.length) targets[backward ? targets.length - 1 : 0]?.focus({ preventScroll: true })
}

function observe() {
  if (!virtual.value || scroller) return
  scroller = root.value?.closest<HTMLElement>('.main') ?? null
  scroller?.addEventListener('scroll', schedule, { passive: true })
  window.addEventListener('resize', schedule)
  if (typeof ResizeObserver !== 'undefined' && scroller) {
    observer = new ResizeObserver(schedule)
    observer.observe(scroller)
    // Other groups expanding changes this grid's position without resizing it.
    if (scroller.firstElementChild) observer.observe(scroller.firstElementChild)
  }
  measure()
}
function disconnect() {
  observer?.disconnect()
  observer = null
  scroller?.removeEventListener('scroll', schedule)
  scroller = null
  window.removeEventListener('resize', schedule)
  if (frame !== null) cancelAnimationFrame(frame)
  frame = null
}
onMounted(() => { mounted = true; observe() })
watch(virtual, (enabled) => {
  if (!mounted) return
  if (enabled) observe()
  else disconnect()
}, { flush: 'post' })
watch(() => [props.nodes, props.dense, props.list, props.compact], () => { void nextTick(schedule) })
onBeforeUnmount(() => {
  disposed = true
  disconnect()
})
defineExpose({ reveal })
</script>

<template>
  <div ref="root" class="nodes" :class="{ dense, list, 'windowed-nodes': virtual }" :style="virtual ? { '--node-height': `${height}px` } : undefined" @keydown="onKeydown">
    <div v-if="$slots.header" ref="header" class="node-grid-header"><slot name="header" /></div>
    <div v-if="range.start > 0" class="node-spacer" :style="{ height: `${before}px` }" aria-hidden="true" />
    <slot :nodes="visible" />
    <div v-if="range.end < rows" class="node-spacer" :style="{ height: `${after}px` }" aria-hidden="true" />
  </div>
</template>

<style scoped>
.node-grid-header { grid-column: 1 / -1; display: grid; gap: inherit; }
.node-spacer { grid-column: 1 / -1; pointer-events: none; }
.windowed-nodes :deep(.node) { height: var(--node-height); min-height: var(--node-height); }
</style>
