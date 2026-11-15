import { nextTick, onBeforeUnmount, onMounted } from 'vue'

/**
 * Elements a dialog may move focus to. Kept as one selector so Modal, Menu and
 * the command palette agree on what counts as a keyboard target (R30).
 */
export const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

const EDITABLE_SELECTOR = 'input, textarea, select, [contenteditable="true"], [role="textbox"]'

function isHidden(element: HTMLElement): boolean {
  if (element.hidden || element.getAttribute('aria-hidden') === 'true') return true
  if (element.closest('[hidden], [aria-hidden="true"], [inert]')) return true
  const style = typeof window !== 'undefined' ? window.getComputedStyle?.(element) : null
  return Boolean(style && (style.display === 'none' || style.visibility === 'hidden'))
}

/** Focusable descendants in DOM order, excluding disabled, hidden and tabindex=-1 nodes. */
export function getFocusable(container: HTMLElement | null | undefined): HTMLElement[] {
  if (!container) return []
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (element) =>
      element.tabIndex !== -1 &&
      !element.hasAttribute('disabled') &&
      !isHidden(element),
  )
}

/** Walk up to the direct child of <body> so the whole page behind a dialog can be inert. */
export function topLevelElement(element: HTMLElement): HTMLElement {
  let node = element
  while (node.parentElement && node.parentElement !== document.body) node = node.parentElement
  return node
}

/** Move focus to the first sensible control: explicit target, autofocus, then first focusable. */
export function focusInitial(
  container: HTMLElement,
  preferred?: () => HTMLElement | null | undefined,
): HTMLElement | null {
  const target =
    preferred?.() ??
    container.querySelector<HTMLElement>('[autofocus], [data-autofocus]') ??
    getFocusable(container)[0] ??
    container
  if (!target) return null
  if (target === container && !container.hasAttribute('tabindex')) container.setAttribute('tabindex', '-1')
  target.focus({ preventScroll: true })
  return target
}

/** Keep Tab and Shift+Tab inside the container. */
export function trapTab(event: KeyboardEvent, container: HTMLElement): void {
  if (event.key !== 'Tab') return
  const focusable = getFocusable(container)
  if (!focusable.length) {
    event.preventDefault()
    return
  }
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (!first || !last) return
  const active = document.activeElement as HTMLElement | null
  const outside = !active || !container.contains(active)
  if (event.shiftKey) {
    if (outside || active === first) {
      event.preventDefault()
      last.focus()
    }
    return
  }
  if (outside || active === last) {
    event.preventDefault()
    first.focus()
  }
}

export interface FocusTrapOptions {
  /** Called when Escape reaches the topmost trap. */
  onClose?: () => void
  /** Optional first element to focus once the trap is active. */
  initialFocus?: () => HTMLElement | null | undefined
  /** Return focus to the element that was focused before activation. Defaults to true. */
  restoreFocus?: boolean
  /** Mark every other direct child of <body> inert. Defaults to true. */
  inert?: boolean
  /** Lock the `.main` scroller. Defaults to true. */
  lockScroll?: boolean
}

export interface FocusTrapHandle {
  activate: () => void
  deactivate: () => void
  readonly active: boolean
}

const traps: number[] = []
let nextTrapId = 0
let scrollLocks = 0
let scrollTarget: HTMLElement | null = null
let scrollPrevious = ''

/** Number of focus-trapped overlays currently open. */
export function overlayDepth(): number {
  return traps.length
}

/** True while a dialog, command palette or confirmation layer owns the screen. */
export function hasOpenOverlay(): boolean {
  return traps.length > 0
}

function lockBackgroundScroll(): void {
  scrollLocks += 1
  if (scrollLocks > 1) return
  scrollTarget = document.querySelector<HTMLElement>('.main')
  if (!scrollTarget) return
  scrollPrevious = scrollTarget.style.overflow
  scrollTarget.style.overflow = 'hidden'
}

function unlockBackgroundScroll(): void {
  if (scrollLocks === 0) return
  scrollLocks -= 1
  if (scrollLocks > 0 || !scrollTarget) return
  scrollTarget.style.overflow = scrollPrevious
  scrollTarget = null
  scrollPrevious = ''
}

const inertCounts = new Map<HTMLElement, number>()

function inertBackground(root: HTMLElement): HTMLElement[] {
  const inerted: HTMLElement[] = []
  for (const child of Array.from(document.body.children)) {
    if (!(child instanceof HTMLElement) || child === root) continue
    if (child.hasAttribute('inert') && !inertCounts.has(child)) continue
    const count = inertCounts.get(child) ?? 0
    if (count === 0) child.setAttribute('inert', '')
    inertCounts.set(child, count + 1)
    inerted.push(child)
  }
  return inerted
}

function releaseInert(inerted: readonly HTMLElement[]): void {
  for (const child of inerted) {
    const count = inertCounts.get(child) ?? 0
    if (count <= 1) {
      inertCounts.delete(child)
      child.removeAttribute('inert')
    } else {
      inertCounts.set(child, count - 1)
    }
  }
}

function isTopmost(id: number): boolean {
  return traps[traps.length - 1] === id
}

/**
 * Dialog focus management: focus moves in, Tab loops inside, Escape only closes
 * the topmost trap, background content is inert and `.main` cannot scroll.
 */
export function useFocusTrap(
  getContainer: () => HTMLElement | null | undefined,
  options: FocusTrapOptions = {},
): FocusTrapHandle {
  let id = 0
  let active = false
  let trigger: HTMLElement | null = null
  let inerted: HTMLElement[] = []
  let scrollLocked = false

  function onKeydown(event: KeyboardEvent): void {
    if (!active || !isTopmost(id)) return
    const container = getContainer()
    if (!container) return
    if (event.key === 'Escape') {
      if (event.isComposing || event.defaultPrevented) return
      event.preventDefault()
      event.stopPropagation()
      options.onClose?.()
      return
    }
    trapTab(event, container)
  }

  function onFocusIn(event: FocusEvent): void {
    if (!active || !isTopmost(id)) return
    const container = getContainer()
    const target = event.target
    if (container && target instanceof Node && !container.contains(target)) {
      focusInitial(container, options.initialFocus)
    }
  }

  function activate(): void {
    if (active) return
    const container = getContainer()
    const focused = document.activeElement
    trigger = focused instanceof HTMLElement && focused !== document.body ? focused : null
    id = ++nextTrapId
    traps.push(id)
    active = true
    if (container) {
      if (options.inert !== false) inerted = inertBackground(topLevelElement(container))
      if (options.lockScroll !== false) {
        lockBackgroundScroll()
        scrollLocked = true
      }
      void nextTick(() => focusInitial(container, options.initialFocus))
    }
    document.addEventListener('keydown', onKeydown)
    document.addEventListener('focusin', onFocusIn)
  }

  function deactivate(): void {
    if (!active) return
    active = false
    document.removeEventListener('keydown', onKeydown)
    document.removeEventListener('focusin', onFocusIn)
    const wasTopmost = isTopmost(id)
    const index = traps.lastIndexOf(id)
    if (index >= 0) traps.splice(index, 1)
    releaseInert(inerted)
    inerted = []
    if (scrollLocked) {
      unlockBackgroundScroll()
      scrollLocked = false
    }
    if (options.restoreFocus !== false && wasTopmost && trigger?.isConnected) {
      trigger.focus({ preventScroll: true })
    }
    trigger = null
  }

  onMounted(activate)
  onBeforeUnmount(deactivate)

  return {
    activate,
    deactivate,
    get active() {
      return active
    },
  }
}

/** True while a text field owns the keyboard, used by global shortcut guards. */
export function isEditableElement(target: EventTarget | null): boolean {
  const element = target instanceof HTMLElement ? target : null
  if (!element) return false
  if (element.isContentEditable) return true
  return Boolean(element.closest(EDITABLE_SELECTOR))
}
