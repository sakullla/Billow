import { computed, onBeforeUnmount, reactive, ref } from 'vue'

export interface ColumnSpec {
  id: string
  defaultWidth: number
  minWidth: number
  maxWidth?: number
}

const STORAGE_PREFIX = 'billow:cols:'

function clampWidth(value: number, spec: ColumnSpec): number {
  const max = spec.maxWidth ?? 960
  return Math.round(Math.min(max, Math.max(spec.minWidth, value)))
}

/**
 * Draggable column width state persisted per table (`billow:cols:<key>`).
 * Dragging a divider resizes that column smoothly; double-clicking resets it.
 */
export function useColumnResize(storageKey: string, specs: readonly ColumnSpec[]) {
  const byId = new Map(specs.map((spec) => [spec.id, spec]))
  const widths = reactive<Record<string, number>>(
    Object.fromEntries(specs.map((spec) => [spec.id, spec.defaultWidth])),
  )
  const resizingId = ref<string | null>(null)
  const customized = computed(() =>
    specs.some((spec) => widths[spec.id] !== spec.defaultWidth),
  )
  let cleanupDrag: (() => void) | null = null

  try {
    const raw = localStorage.getItem(`${STORAGE_PREFIX}${storageKey}`)
    if (raw) {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      for (const spec of specs) {
        const saved = parsed[spec.id]
        if (typeof saved === 'number' && Number.isFinite(saved)) {
          widths[spec.id] = clampWidth(saved, spec)
        }
      }
    }
  } catch {
    /* ignore unavailable storage */
  }

  function persist() {
    try {
      localStorage.setItem(`${STORAGE_PREFIX}${storageKey}`, JSON.stringify({ ...widths }))
    } catch {
      /* ignore unavailable storage */
    }
  }

  function stopDrag() {
    cleanupDrag?.()
    cleanupDrag = null
  }

  function startResize(id: string, event: PointerEvent | MouseEvent) {
    const spec = byId.get(id)
    if (!spec) return
    event.preventDefault()
    event.stopPropagation()
    stopDrag()

    const startX = event.clientX
    const startWidth = widths[id] ?? spec.defaultWidth
    resizingId.value = id
    document.documentElement.setAttribute('data-col-resizing', 'true')

    const onMove = (moveEvent: PointerEvent | MouseEvent) => {
      const next = clampWidth(startWidth + (moveEvent.clientX - startX), spec)
      if (widths[id] !== next) widths[id] = next
    }
    const onEnd = () => {
      stopDrag()
      persist()
    }

    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onEnd)
    window.addEventListener('pointercancel', onEnd)
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onEnd)

    cleanupDrag = () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onEnd)
      window.removeEventListener('pointercancel', onEnd)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onEnd)
      resizingId.value = null
      document.documentElement.removeAttribute('data-col-resizing')
    }
  }

  function resetColumn(id: string, event?: Event) {
    event?.preventDefault()
    event?.stopPropagation()
    const spec = byId.get(id)
    if (!spec) return
    widths[id] = spec.defaultWidth
    persist()
  }

  function resetAll() {
    for (const spec of specs) {
      widths[spec.id] = spec.defaultWidth
    }
    try {
      localStorage.removeItem(`${STORAGE_PREFIX}${storageKey}`)
    } catch {
      /* ignore */
    }
  }

  onBeforeUnmount(stopDrag)

  return {
    widths,
    resizingId,
    customized,
    startResize,
    resetColumn,
    resetAll,
  }
}
