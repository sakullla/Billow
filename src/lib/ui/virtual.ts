import { computed, ref, watch, type Ref } from 'vue'

/**
 * Fixed-row-height windowing shared by the connection table, the phone
 * connection cards and the rule list (R31). Only the rows inside the viewport
 * plus `overscan` on each side are mounted, so 500 connections cost ~30 nodes
 * instead of 500.
 *
 * The container measures itself on scroll; before the first measurement (or in
 * a test document without layout) a screenful of rows is still rendered so the
 * first paint is never empty.
 */
export const FALLBACK_VIEWPORT = 600

export interface VirtualRange {
  start: number
  end: number
}

export function useVirtualList(
  count: Ref<number>,
  rowHeight: number | (() => number),
  overscan = 6,
) {
  const stride = typeof rowHeight === 'function' ? rowHeight : () => rowHeight
  const scrollTop = ref(0)
  const measured = ref(0)

  const viewport = computed(() => (measured.value > 0 ? measured.value : FALLBACK_VIEWPORT))

  const window = computed<VirtualRange>(() => {
    const total = count.value
    if (total <= 0) return { start: 0, end: 0 }
    // Never start past the last full screen, so a shrinking list cannot strand the
    // window below the content with a blank viewport (R31).
    const perScreen = Math.max(1, Math.floor(viewport.value / stride()))
    const visible = Math.ceil(viewport.value / stride()) + overscan * 2
    const start = Math.min(
      Math.max(0, Math.floor(scrollTop.value / stride()) - overscan),
      Math.max(0, total - perScreen),
    )
    return { start, end: Math.min(total, start + visible) }
  })

  /** Height of the rows above the window, kept as a spacer so the scrollbar matches the full list. */
  const offset = computed(() => window.value.start * stride())
  /** Height of the rows below the window. */
  const tail = computed(() => Math.max(0, count.value - window.value.end) * stride())

  // An empty list unmounts the container; when rows come back the window must
  // start at the top even if the old offset was never re-measured (R31).
  watch(count, (next, previous) => {
    if (next > 0 && previous === 0) scrollTop.value = 0
  })

  function onScroll(event: Event) {
    const el = event.currentTarget as HTMLElement | null
    if (!el) return
    scrollTop.value = el.scrollTop
    measured.value = el.clientHeight
  }

  /** Re-read the container after mount or when the row set changes size. */
  function measure(el: HTMLElement | null, contentTop = 0) {
    if (!el) return
    scrollTop.value = Math.max(0, el.scrollTop - contentTop)
    measured.value = el.clientHeight
  }

  /**
   * Return the window to the top. Filters, a remounted container and a reconnect
   * must not keep the previous scroll offset (R31).
   */
  function reset(el: HTMLElement | null = null) {
    scrollTop.value = 0
    if (el) el.scrollTop = 0
  }

  return { window, offset, tail, onScroll, measure, reset, scrollTop }
}
