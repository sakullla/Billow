import { computed, ref, watch, type Ref } from 'vue'

/**
 * Variable-row-height windowing for lists whose rows can wrap or vary in height
 * (for example LogsView under word wrap). Unmeasured rows use `estimateHeight`
 * so the first paint is immediately usable, while mounted rows feed their real
 * measured heights back via `setItemHeight`.
 */
export const FALLBACK_DYNAMIC_VIEWPORT = 600

export interface DynamicVirtualRange {
  start: number
  end: number
}

export interface DynamicVirtualOptions {
  /** Fallback row height in px before a row is measured. Defaults to 32. */
  estimateHeight?: number | (() => number)
  /** Extra rows rendered above and below the viewport. Defaults to 6. */
  overscan?: number
  /** Optional stable key per index so measured heights survive ring-buffer shifts. */
  keyOf?: (index: number) => string | number
}

interface DynamicLayout {
  offsets: Float64Array
  totalHeight: number
}

function findIndexAtOffset(offsets: Float64Array, total: number, y: number): number {
  if (total <= 0) return 0
  if (y <= 0) return 0
  let lo = 0
  let hi = total - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (offsets[mid]! <= y) lo = mid
    else hi = mid - 1
  }
  return lo
}

function findEndIndex(offsets: Float64Array, total: number, bottomY: number): number {
  if (total <= 0) return 0
  let lo = 0
  let hi = total
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (offsets[mid]! < bottomY) lo = mid + 1
    else hi = mid
  }
  return lo
}

export function useDynamicVirtualList(
  count: Ref<number>,
  options: DynamicVirtualOptions = {},
) {
  const estimateOpt = options.estimateHeight
  const estimateFn =
    typeof estimateOpt === 'function'
      ? estimateOpt
      : () => Math.max(1, estimateOpt ?? 32)
  const overscan = Math.max(0, options.overscan ?? 6)
  const keyOf = options.keyOf

  const scrollTop = ref(0)
  const measuredViewport = ref(0)
  const version = ref(0)
  const heights = new Map<string | number, number>()

  const viewport = computed(() =>
    measuredViewport.value > 0 ? measuredViewport.value : FALLBACK_DYNAMIC_VIEWPORT,
  )

  function itemKey(index: number): string | number {
    return keyOf ? keyOf(index) : index
  }

  function currentEstimate(): number {
    const est = estimateFn()
    return Number.isFinite(est) && est > 0 ? est : 32
  }

  const layout = computed<DynamicLayout>(() => {
    // Depend on version so height updates and invalidations recompute prefix sums.
    void version.value
    const total = Math.max(0, count.value)
    const est = currentEstimate()
    const offsets = new Float64Array(total + 1)
    let acc = 0
    for (let i = 0; i < total; i++) {
      offsets[i] = acc
      acc += heights.get(itemKey(i)) ?? est
    }
    offsets[total] = acc
    return { offsets, totalHeight: acc }
  })

  const totalHeight = computed(() => layout.value.totalHeight)

  const window = computed<DynamicVirtualRange>(() => {
    const total = Math.max(0, count.value)
    if (total <= 0) return { start: 0, end: 0 }
    const { offsets, totalHeight: full } = layout.value
    const vp = viewport.value
    // Clamp effective scroll so shrinking lists never strand the window past the end.
    const maxScroll = Math.max(0, full - vp)
    const effectiveScroll = Math.max(0, Math.min(scrollTop.value, maxScroll))
    const firstVisible = findIndexAtOffset(offsets, total, effectiveScroll)
    const lastVisible = findEndIndex(offsets, total, effectiveScroll + vp)
    const start = Math.max(0, firstVisible - overscan)
    const end = Math.min(total, Math.max(start + 1, lastVisible + overscan))
    return { start, end }
  })

  /** Spacer height above the mounted window. */
  const offset = computed(() => layout.value.offsets[window.value.start] ?? 0)
  /** Spacer height below the mounted window. */
  const tail = computed(() =>
    Math.max(0, layout.value.totalHeight - (layout.value.offsets[window.value.end] ?? 0)),
  )

  watch(count, (next, previous) => {
    if (next > 0 && previous === 0) scrollTop.value = 0
    if (keyOf && heights.size > Math.max(2048, next * 2)) {
      const live = new Set<string | number>()
      for (let i = 0; i < next; i++) live.add(keyOf(i))
      for (const key of heights.keys()) {
        if (!live.has(key)) heights.delete(key)
      }
    }
  })

  function offsetOf(index: number): number {
    const total = Math.max(0, count.value)
    if (total === 0) return 0
    const clamped = Math.max(0, Math.min(index, total))
    return layout.value.offsets[clamped] ?? 0
  }

  function heightOf(index: number): number {
    if (index < 0 || index >= count.value) return currentEstimate()
    return heights.get(itemKey(index)) ?? currentEstimate()
  }

  /**
   * Record a newly measured row height. When `follow` is false and the row lies
   * strictly above the current scroll anchor, `scrollTop` is shifted by `delta`
   * so visible rows stay visually pinned. When `follow` is true, the container
   * stays pinned to the bottom.
   */
  function setItemHeight(
    index: number,
    height: number,
    el?: HTMLElement | null,
    opts?: { follow?: boolean },
  ): number {
    if (index < 0 || index >= count.value) return 0
    if (!Number.isFinite(height) || height <= 0) return 0
    const next = Math.max(1, Math.round(height))
    const key = itemKey(index)
    const prev = heights.get(key) ?? currentEstimate()
    if (Math.abs(next - prev) < 0.5) return 0

    const itemTopBefore = layout.value.offsets[index] ?? 0
    const delta = next - prev
    heights.set(key, next)
    version.value += 1

    if (opts?.follow) {
      if (el) scrollToBottom(el)
    } else if (el && itemTopBefore < scrollTop.value) {
      const adjusted = Math.max(0, scrollTop.value + delta)
      scrollTop.value = adjusted
      el.scrollTop = adjusted
    }
    return delta
  }

  /**
   * Drop all cached row measurements (for example after toggling word wrap or
   * changing viewport width). Pass `keepScroll: true` when reading history so
   * the viewport is not forced back to the top or bottom.
   */
  function invalidate(el?: HTMLElement | null, opts?: { keepScroll?: boolean }) {
    heights.clear()
    version.value += 1
    if (!opts?.keepScroll) {
      scrollTop.value = 0
      if (el) el.scrollTop = 0
    }
  }

  function onScroll(event: Event) {
    const el = event.currentTarget as HTMLElement | null
    if (!el) return
    scrollTop.value = el.scrollTop
    if (el.clientHeight > 0) measuredViewport.value = el.clientHeight
  }

  function measure(el: HTMLElement | null, contentTop = 0) {
    if (!el) return
    scrollTop.value = Math.max(0, el.scrollTop - contentTop)
    if (el.clientHeight > 0) measuredViewport.value = el.clientHeight
  }

  function reset(el: HTMLElement | null = null) {
    scrollTop.value = 0
    if (el) el.scrollTop = 0
  }

  function scrollToIndex(
    index: number,
    el: HTMLElement | null,
    align: 'start' | 'center' | 'end' = 'start',
  ) {
    const total = Math.max(0, count.value)
    if (total <= 0) return
    const clamped = Math.max(0, Math.min(index, total - 1))
    const itemTop = offsetOf(clamped)
    const itemH = heightOf(clamped)
    const vp = viewport.value
    let target = itemTop
    if (align === 'center') target = itemTop - (vp - itemH) / 2
    else if (align === 'end') target = itemTop + itemH - vp
    const maxScroll = Math.max(0, totalHeight.value - vp)
    const nextScroll = Math.max(0, Math.min(target, maxScroll))
    scrollTop.value = nextScroll
    if (el) el.scrollTop = nextScroll
  }

  function scrollToBottom(el: HTMLElement | null) {
    const vp = el && el.clientHeight > 0 ? el.clientHeight : viewport.value
    if (el && el.clientHeight > 0) measuredViewport.value = el.clientHeight
    const computedBottom = Math.max(0, totalHeight.value - vp)
    const domBottom = el ? Math.max(0, el.scrollHeight - el.clientHeight) : 0
    const nextScroll = Math.max(computedBottom, domBottom)
    scrollTop.value = nextScroll
    if (el) el.scrollTop = nextScroll
  }

  function isNearBottom(el: HTMLElement | null, threshold = 24): boolean {
    if (!el) return true
    const remaining = el.scrollHeight - el.scrollTop - el.clientHeight
    return remaining <= threshold
  }

  return {
    window,
    offset,
    tail,
    totalHeight,
    scrollTop,
    offsetOf,
    heightOf,
    setItemHeight,
    invalidate,
    onScroll,
    measure,
    reset,
    scrollToIndex,
    scrollToBottom,
    isNearBottom,
  }
}
