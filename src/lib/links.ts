import { inTauri } from './backend'

export const REPO_URL = 'https://github.com/sakullla/Billow'
/** Shown without the scheme; the link itself always opens the full URL. */
export const REPO_LABEL = 'github.com/sakullla/Billow'

/** Opens a page in the system browser; the browser preview falls back to a new tab. */
export async function openExternal(url: string): Promise<void> {
  if (inTauri()) {
    const { openUrl } = await import('@tauri-apps/plugin-opener')
    await openUrl(url)
    return
  }
  window.open(url, '_blank', 'noopener,noreferrer')
}
