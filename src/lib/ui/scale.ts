import { computed, ref } from 'vue'

/**
 * Desktop interface scale for 2K/4K displays.
 *
 * The UI is laid out in fixed CSS pixels, so on a 2560×1440 or 3840×2160 screen
 * running at 100 % OS scaling everything looks tiny and the window opens as a
 * postage stamp. Instead of rewriting every size, the webview zoom is raised
 * (like browser page zoom: layout, hit-testing and `getBoundingClientRect` stay
 * consistent). `auto` picks a factor from the monitor's logical size; users can
 * pin a value in 设置 › 外观 or with ⌘/Ctrl + = / - / 0.
 */
export type UiScalePreference = 'auto' | number

export const UI_SCALE_STEPS = [0.9, 1, 1.1, 1.25, 1.5, 1.75, 2] as const
const STORAGE_KEY = 'billow.ui-scale'
/** The desktop layout needs this many CSS px; zoom never pushes a window below it. */
const MIN_LAYOUT_WIDTH = 900
const MIN_LAYOUT_HEIGHT = 560
/** Default window size from tauri.conf.json. */
const DEFAULT_WINDOW = { width: 960, height: 680 }

export interface Size {
  width: number
  height: number
}

export interface ScaleDriver {
  apply(factor: number): Promise<void>
  /** Logical (OS-scaled) size of the monitor holding the window. */
  monitor(): Promise<Size | null>
  /** Logical inner size of the window, independent of the current zoom. */
  windowSize(): Promise<Size | null>
  resizeWindow(size: Size): Promise<void>
}

/** Pick a factor from the monitor's short side so ultrawides follow their height. */
export function autoScaleFor(monitor: Size | null): number {
  if (!monitor) return 1
  const short = Math.min(monitor.width, monitor.height)
  if (short >= 2000) return 1.5 // 4K / 5K at 100 %
  if (short >= 1600) return 1.25 // 3K–3.2K at 100 %
  if (short >= 1350) return 1.1 // 2K (1440p) at 100 %, or 4K at 150 %
  return 1
}

/** Shrink an enlargement until the window still fits the desktop layout; never below 1. */
export function fitScale(target: number, window: Size | null): number {
  if (target <= 1 || !window) return target
  const room = Math.min(window.width / MIN_LAYOUT_WIDTH, window.height / MIN_LAYOUT_HEIGHT)
  const fitted = Math.min(target, room)
  return Math.max(1, Math.floor(fitted * 20) / 20)
}

export function scaleLabel(factor: number): string {
  return `${Math.round(factor * 100)}%`
}

function readPreference(): UiScalePreference {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw || raw === 'auto') return 'auto'
    const value = Number(raw)
    return (UI_SCALE_STEPS as readonly number[]).includes(value) ? value : 'auto'
  } catch {
    return 'auto'
  }
}

function writePreference(value: UiScalePreference) {
  try {
    localStorage.setItem(STORAGE_KEY, String(value))
  } catch {
    // Private storage is optional; the choice still applies for this session.
  }
}

export function tauriScaleDriver(): ScaleDriver {
  let zoom = 1
  return {
    async apply(factor) {
      const { getCurrentWebview } = await import('@tauri-apps/api/webview')
      await getCurrentWebview().setZoom(factor)
      zoom = factor
    },
    async monitor() {
      const { currentMonitor } = await import('@tauri-apps/api/window')
      const monitor = await currentMonitor()
      if (!monitor) return null
      return { width: monitor.size.width / monitor.scaleFactor, height: monitor.size.height / monitor.scaleFactor }
    },
    async windowSize() {
      if (typeof window === 'undefined') return null
      // innerWidth is in zoomed CSS px; multiply back to the window's logical size.
      return { width: window.innerWidth * zoom, height: window.innerHeight * zoom }
    },
    async resizeWindow(size) {
      const { getCurrentWindow, LogicalSize } = await import('@tauri-apps/api/window')
      const win = getCurrentWindow()
      await win.setSize(new LogicalSize(Math.round(size.width), Math.round(size.height)))
      await win.center()
    },
  }
}

export function createUiScale(driver: ScaleDriver | null) {
  const preference = ref<UiScalePreference>(readPreference())
  const autoFactor = ref(1)
  /** Factor actually in effect after fitting the window; 1 until installed. */
  const applied = ref(1)
  const supported = ref(false)
  const target = computed(() => (preference.value === 'auto' ? autoFactor.value : preference.value))

  let installed = false
  let resizeTimer: ReturnType<typeof setTimeout> | null = null

  async function sync() {
    if (!driver || !installed) {
      applied.value = target.value
      return
    }
    const next = fitScale(target.value, await driver.windowSize())
    if (Math.abs(next - applied.value) < 0.001) return
    try {
      await driver.apply(next)
      applied.value = next
    } catch (error) {
      console.error(error)
    }
  }

  function onResize() {
    if (resizeTimer) clearTimeout(resizeTimer)
    // Re-fit only after the drag settles so a resize never stutters.
    resizeTimer = setTimeout(() => void sync(), 250)
  }

  async function install() {
    if (!driver || installed) return
    installed = true
    supported.value = true
    try {
      const monitor = await driver.monitor()
      autoFactor.value = autoScaleFor(monitor)
      // First launch on a big screen: the 960×680 default would be a tiny island.
      const size = await driver.windowSize()
      const factor = target.value
      if (monitor && size && factor > 1 && Math.abs(size.width - DEFAULT_WINDOW.width) < 2 && Math.abs(size.height - DEFAULT_WINDOW.height) < 2) {
        await driver.resizeWindow({
          width: Math.min(DEFAULT_WINDOW.width * factor, monitor.width * 0.85),
          height: Math.min(DEFAULT_WINDOW.height * factor, monitor.height * 0.85),
        })
      }
    } catch (error) {
      console.error(error)
    }
    window.addEventListener('resize', onResize)
    await sync()
  }

  function uninstall() {
    if (typeof window !== 'undefined') window.removeEventListener('resize', onResize)
    if (resizeTimer) clearTimeout(resizeTimer)
    resizeTimer = null
    installed = false
  }

  function set(next: UiScalePreference) {
    preference.value = next
    writePreference(next)
    void sync()
  }

  /** ⌘/Ctrl + = / -: walk the fixed steps from the factor currently in effect. */
  function step(direction: 1 | -1) {
    const steps = UI_SCALE_STEPS as readonly number[]
    const current = target.value
    const next = direction > 0
      ? steps.find((value) => value > current + 0.001)
      : [...steps].reverse().find((value) => value < current - 0.001)
    if (next == null) return null
    set(next)
    return next
  }

  return {
    preference,
    autoFactor,
    applied,
    target,
    supported,
    install,
    uninstall,
    set,
    step,
    reset: () => set('auto'),
  }
}

export type UiScale = ReturnType<typeof createUiScale>
