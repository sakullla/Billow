import { computed, ref, shallowRef } from 'vue'
import type { DownloadEvent } from '@tauri-apps/plugin-updater'

export interface AppUpdate {
  version: string
  body?: string
  kind: 'desktop' | 'android'
  download(onEvent: (event: DownloadEvent) => void): Promise<void>
  install(): Promise<void>
  close(): Promise<void>
}

export interface UpdateDriver {
  check(): Promise<AppUpdate | null>
  beforeInstall(): Promise<void>
  restart(): Promise<void>
}

export function nativeUpdateDriver(isAndroid: () => boolean): UpdateDriver {
  return {
    async check() {
      if (isAndroid()) {
        const { invoke } = await import('@tauri-apps/api/core')
        const info = await invoke<{ version: string; body: string; url: string } | null>('check_android_app_update')
        if (!info) return null
        return {
          ...info, kind: 'android',
          download: async () => {},
          async install() {
            const { openUrl } = await import('@tauri-apps/plugin-opener')
            await openUrl(info.url)
          },
          close: async () => {},
        }
      }
      const { check } = await import('@tauri-apps/plugin-updater')
      const update = await check({ timeout: 15_000 })
      if (!update) return null
      return {
        version: update.version, body: update.body, kind: 'desktop',
        download: (onEvent) => update.download(onEvent, { timeout: 300_000 }),
        install: () => update.install(),
        close: () => update.close(),
      }
    },
    async beforeInstall() {
      const { invoke } = await import('@tauri-apps/api/core')
      await invoke('prepare_app_update')
    },
    async restart() {
      const { relaunch } = await import('@tauri-apps/plugin-process')
      await relaunch()
    },
  }
}

/** One shared update offer; checks never install or interrupt a running connection. */
export function createAppUpdater(driver: UpdateDriver) {
  const status = ref<'idle' | 'checking' | 'current' | 'available' | 'downloading' | 'installing' | 'ready' | 'error'>('idle')
  const offer = shallowRef<AppUpdate | null>(null)
  const error = ref<string | null>(null)
  const downloaded = ref(0)
  const total = ref<number | null>(null)
  const busy = computed(() => ['checking', 'downloading', 'installing'].includes(status.value))
  let generation = 0
  let checking: Promise<void> | null = null
  let installing = false

  async function release(update: AppUpdate | null) {
    await update?.close().catch(() => {})
  }

  function check(silent = false) {
    if (checking) return checking
    if (installing || status.value === 'ready') return Promise.resolve()
    const session = generation
    status.value = 'checking'
    error.value = null
    checking = (async () => {
      try {
        const next = await driver.check()
        if (session !== generation) {
          await release(next)
          return
        }
        const previous = offer.value
        offer.value = next
        status.value = next ? 'available' : 'current'
        await release(previous)
      } catch (cause) {
        if (session !== generation) return
        error.value = silent ? null : String(cause)
        status.value = silent ? (offer.value ? 'available' : 'idle') : 'error'
      } finally {
        if (session === generation) checking = null
      }
    })()
    return checking
  }

  async function install() {
    const update = offer.value
    if (!update || busy.value || installing) return
    installing = true
    const session = generation
    error.value = null
    downloaded.value = 0
    total.value = null
    status.value = 'downloading'
    try {
      await update.download((event) => {
        if (session !== generation) return
        if (event.event === 'Started') total.value = event.data.contentLength ?? null
        if (event.event === 'Progress') downloaded.value += event.data.chunkLength
      })
      if (session !== generation) return
      status.value = 'installing'
      if (update.kind === 'desktop') await driver.beforeInstall()
      if (session !== generation) return
      await update.install()
      if (session !== generation) return
      if (update.kind === 'android') {
        status.value = 'available'
      } else {
        offer.value = null
        status.value = 'ready'
        await release(update)
      }
    } catch (cause) {
      if (session === generation) {
        error.value = String(cause)
        status.value = 'error'
      }
    } finally {
      installing = false
      if (session !== generation) await release(update)
    }
  }

  async function restart() {
    try {
      await driver.beforeInstall()
      await driver.restart()
    } catch (cause) {
      error.value = String(cause)
    }
  }

  function stop() {
    generation += 1
    checking = null
    const previous = offer.value
    offer.value = null
    // An active download still owns its resource; its finally block releases it.
    if (!installing) void release(previous)
    status.value = 'idle'
  }

  return { status, offer, error, downloaded, total, busy, check, install, restart, stop }
}
