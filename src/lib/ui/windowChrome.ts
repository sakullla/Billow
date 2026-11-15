/**
 * Desktop window chrome. Windows runs undecorated (tauri.windows.conf.json) and
 * draws its own caption buttons; macOS keeps native traffic lights over an
 * overlay title bar (tauri.macos.conf.json). Linux and browsers keep the
 * system frame, so they get no custom chrome.
 */
export type WindowChrome = 'windows' | 'macos' | null

export function detectChrome(
  win: (Window & { __TAURI_INTERNALS__?: unknown }) | undefined = typeof window === 'undefined' ? undefined : window,
): WindowChrome {
  if (!win) return null
  // Browser previews: `?chrome=windows|macos` shows the desktop chrome without Tauri.
  const forced = new URLSearchParams(win.location?.search ?? '').get('chrome')
  if (forced === 'windows' || forced === 'macos') return forced
  if (!('__TAURI_INTERNALS__' in win)) return null
  const agent = win.navigator?.userAgent ?? ''
  if (/Windows/i.test(agent)) return 'windows'
  if (/Macintosh|Mac OS X/i.test(agent) && !/iPhone|iPad/i.test(agent)) return 'macos'
  return null
}

type CurrentWindow = Awaited<ReturnType<typeof loadWindow>>

async function loadWindow() {
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  return getCurrentWindow()
}

let current: Promise<CurrentWindow | null> | null = null

function appWindow(): Promise<CurrentWindow | null> {
  current ??= loadWindow().catch(() => null)
  return current
}

export async function minimizeWindow() {
  await (await appWindow())?.minimize()
}

export async function toggleMaximizeWindow() {
  await (await appWindow())?.toggleMaximize()
}

/** Goes through CloseRequested, so "close to tray" keeps working. */
export async function closeWindow() {
  await (await appWindow())?.close()
}

/** Report maximized state now and after every resize; returns an unsubscribe. */
export async function watchMaximized(handler: (maximized: boolean) => void): Promise<() => void> {
  const win = await appWindow()
  if (!win) return () => {}
  const report = async () => handler(await win.isMaximized().catch(() => false))
  await report()
  return win.onResized(() => void report()).catch(() => () => {})
}
