/**
 * Android edge-to-edge bridge. The native shell (MainActivity) measures the
 * status bar, navigation bar, display cutout and keyboard, and exposes them as
 * `window.BillowInsets.get()` plus a push callback `window.__billowInsets`.
 * Values land as CSS custom properties consumed by `--safe-*` in styles.css;
 * browsers and desktop shells never define the bridge and keep `env()`.
 */
export interface Insets {
  top: number
  right: number
  bottom: number
  left: number
  /** Keyboard height above the navigation bar, in CSS pixels; 0 when hidden. */
  ime: number
}

interface InsetsBridge {
  get(): string
  setLightBars?(light: boolean): void
}

declare global {
  interface Window {
    BillowInsets?: InsetsBridge
    __billowInsets?: (insets: Partial<Insets>) => void
  }
}

const SIDES = ['top', 'right', 'bottom', 'left'] as const

function px(value: unknown): number {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? Math.round(number) : 0
}

export function applyInsets(insets: Partial<Insets>, root: HTMLElement = document.documentElement): void {
  for (const side of SIDES) root.style.setProperty(`--native-${side}`, `${px(insets[side])}px`)
  const ime = px(insets.ime)
  root.style.setProperty('--native-ime', `${ime}px`)
  if (ime > 0) root.setAttribute('data-keyboard', '')
  else root.removeAttribute('data-keyboard')
}

function bridge(): InsetsBridge | null {
  return typeof window !== 'undefined' && window.BillowInsets ? window.BillowInsets : null
}

/** Read the current insets once and subscribe to native pushes. Returns a disposer. */
export function installInsets(): () => void {
  if (typeof window === 'undefined') return () => {}
  window.__billowInsets = (insets) => applyInsets(insets)
  const native = bridge()
  if (native) {
    try {
      applyInsets(JSON.parse(native.get()) as Partial<Insets>)
    } catch {
      /* bridge not ready; the next native push fills the values */
    }
  }
  return () => {
    if (window.__billowInsets) delete window.__billowInsets
  }
}

/** Keep the system bar icons readable against the app's own background. */
export function syncSystemBars(dark: boolean): void {
  try {
    bridge()?.setLightBars?.(!dark)
  } catch {
    /* older shells have no bar control */
  }
}
