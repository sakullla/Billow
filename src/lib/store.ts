import { computed, inject, reactive, ref, shallowRef, type InjectionKey } from 'vue'
import type { Backend } from './backend'
import {
  emptySnapshot,
  type AppInfo,
  type KernelChannel,
  type KernelSettings,
  type KernelStatus,
  type Mode,
  type Snapshot,
  type ThemePreference,
} from './types'

export type PageId = 'home' | 'proxies' | 'profiles' | 'connections' | 'rules' | 'resources' | 'logs' | 'settings'
export type SettingsTab = 'general' | 'kernel' | 'tun' | 'dns'

export const PAGES: { id: PageId; label: string; icon: string; mobile: boolean }[] = [
  { id: 'home', label: '首页', icon: 'home', mobile: true },
  { id: 'proxies', label: '代理', icon: 'globe', mobile: true },
  { id: 'profiles', label: '配置', icon: 'layers', mobile: true },
  { id: 'connections', label: '连接', icon: 'activity', mobile: true },
  { id: 'rules', label: '规则', icon: 'route', mobile: false },
  { id: 'resources', label: '资源', icon: 'database', mobile: false },
  { id: 'logs', label: '日志', icon: 'terminal', mobile: false },
  { id: 'settings', label: '设置', icon: 'settings', mobile: true },
]

export function resolvePage(value: string | null | undefined): PageId {
  if (value === 'nodes') return 'proxies'
  return PAGES.some((page) => page.id === value) ? (value as PageId) : 'home'
}

export interface Toast {
  id: number
  tone: 'info' | 'success' | 'error'
  text: string
}

const HISTORY = 60

export function applyTheme(preference: ThemePreference) {
  const root = document.documentElement
  if (preference === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', preference)
}

export function createStore(backend: Backend) {
  const snapshot = ref<Snapshot>(emptySnapshot())
  const kernel = ref<KernelStatus>({ channel: 'stable', failure: null, ready: false, version: null })
  const app = ref<AppInfo | null>(null)
  const theme = ref<ThemePreference>('system')
  const page = ref<PageId>('home')
  const focusGroup = ref<string | null>(null)
  const settingsTab = ref<SettingsTab>('general')
  const loaded = ref(false)
  const busy = reactive<Record<string, boolean>>({})
  const toasts = ref<Toast[]>([])
  const traffic = shallowRef<{ up: number[]; down: number[] }>({
    up: Array(HISTORY).fill(0),
    down: Array(HISTORY).fill(0),
  })
  const adding = ref(false)
  let toastId = 0
  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let polling = false
  let stopped = false
  let queue: Promise<unknown> = Promise.resolve()
  let unlisten: (() => void) | null = null

  const current = computed(() => snapshot.value.profiles.find((item) => item.current) ?? null)
  const hasProfiles = computed(() => snapshot.value.profiles.length > 0)
  const isAndroid = computed(() => snapshot.value.platform === 'android')
  const connecting = computed(() => Boolean(busy.connect))

  function toast(text: string, tone: Toast['tone'] = 'info') {
    const id = ++toastId
    toasts.value = [...toasts.value.slice(-3), { id, tone, text }]
    setTimeout(() => {
      toasts.value = toasts.value.filter((item) => item.id !== id)
    }, tone === 'error' ? 5200 : 2800)
  }

  function pushTraffic(next: Snapshot) {
    const up = next.connected ? next.upload ?? 0 : 0
    const down = next.connected ? next.download ?? 0 : 0
    traffic.value = {
      up: [...traffic.value.up.slice(1), up],
      down: [...traffic.value.down.slice(1), down],
    }
  }

  function apply(next: Snapshot) {
    snapshot.value = next
  }

  /** Runs mutating calls one at a time so snapshots arrive in order. */
  function run<T>(key: string | null, action: () => Promise<T>): Promise<T | undefined> {
    if (key) busy[key] = true
    const task = queue.then(async () => {
      try {
        const result = await action()
        if (result && typeof result === 'object' && 'profiles' in (result as object)) apply(result as unknown as Snapshot)
        return result
      } catch (error) {
        console.error(error)
        toast(error instanceof Error ? error.message : String(error), 'error')
        return undefined
      } finally {
        if (key) delete busy[key]
      }
    })
    queue = task.catch(() => undefined)
    return task
  }

  async function act(key: string | null, action: () => Promise<Snapshot>, success?: string) {
    const before = snapshot.value
    const result = await run(key, action)
    if (!result) return undefined
    if (result.failure && result.failure !== before.failure) toast(result.failure, 'error')
    else if (result.notice && result.notice !== before.notice) toast(result.notice, 'error')
    else if (result.input_error && result.input_error !== before.input_error) toast(result.input_error, 'error')
    else if (result.nodes_error && result.nodes_error !== before.nodes_error) toast(result.nodes_error, 'error')
    else if (success) toast(success, 'success')
    if (backend.live) void backend.syncTray()
    return result
  }

  async function poll() {
    if (stopped) return
    const visible = typeof document === 'undefined' || document.visibilityState !== 'hidden'
    if (visible && !polling && Object.keys(busy).length === 0) {
      polling = true
      try {
        const next = await backend.state()
        if (Object.keys(busy).length === 0) apply(next)
        pushTraffic(next)
      } catch (error) {
        console.error(error)
      } finally {
        polling = false
      }
    } else if (visible) {
      pushTraffic(snapshot.value)
    }
    const fast = snapshot.value.kernel_running || snapshot.value.connected
    pollTimer = setTimeout(poll, fast ? 1000 : 3000)
  }

  async function start() {
    stopped = false
    try {
      const shell = await backend.shell()
      theme.value = shell.theme
      page.value = resolvePage(shell.last_entry)
    } catch (error) {
      console.error(error)
    }
    applyTheme(theme.value)
    try {
      apply(await backend.state())
    } catch (error) {
      console.error(error)
    }
    loaded.value = true
    void backend.kernel().then((value) => (kernel.value = value)).catch(console.error)
    void backend.appInfo().then((value) => (app.value = value)).catch(console.error)
    try {
      unlisten = await backend.onChange((next) => apply(next))
    } catch (error) {
      console.error(error)
    }
    pollTimer = setTimeout(poll, 1000)
  }

  function stop() {
    stopped = true
    if (pollTimer) clearTimeout(pollTimer)
    unlisten?.()
  }

  function openSettings(tab: SettingsTab) {
    settingsTab.value = tab
    go('settings')
  }

  function go(next: PageId, group?: string) {
    page.value = next
    focusGroup.value = group ?? null
    void backend.setEntry(next).catch(console.error)
  }

  function setTheme(next: ThemePreference) {
    theme.value = next
    applyTheme(next)
    void backend.setTheme(next).catch(console.error)
  }

  return {
    backend,
    snapshot,
    kernel,
    app,
    theme,
    page,
    focusGroup,
    settingsTab,
    openSettings,
    loaded,
    busy,
    toasts,
    traffic,
    adding,
    current,
    hasProfiles,
    isAndroid,
    connecting,
    toast,
    start,
    stop,
    go,
    setTheme,
    refresh: () => run(null, () => backend.state()),

    toggleConnection() {
      if (connecting.value) return
      if (!hasProfiles.value) {
        adding.value = true
        return
      }
      if (snapshot.value.connected) return act('connect', () => backend.disconnect(), '已断开')
      return act('connect', () => backend.connect(), '已连接')
    },
    setMode: (mode: Mode) => act('mode', () => backend.setMode(mode)),
    setSystemProxy: (on: boolean) => act('proxy', () => backend.setSystemProxy(on)),
    setTun: (on: boolean) => act('tun', () => backend.setTun(on)),
    exclude: (pkg: string) => act(null, () => backend.exclude(pkg)),
    include: (pkg: string) => act(null, () => backend.include(pkg)),

    addSubscription: (url: string) => act('add', () => backend.addSubscription(url)),
    addLocal: (name: string, content: string) => act('add', () => backend.addLocal(name, content)),
    confirmInstall: () => act(null, () => backend.confirmInstall(), '已添加订阅'),
    cancelInstall: () => act(null, () => backend.cancelInstall()),
    enable: (id: string) => act(`enable:${id}`, () => backend.enable(id), '已切换配置'),
    update: (id: string) =>
      act(`update:${id}`, () => (snapshot.value.active_id === id ? backend.update(id) : backend.refresh(id)), '订阅已更新'),
    refreshAll: () => act('refreshAll', () => backend.refreshAll(), '全部订阅已更新'),
    remove: (id: string) => act(`remove:${id}`, () => backend.remove(id)),
    rename: (id: string, name: string) => act(null, () => backend.rename(id, name)),
    setSource: (id: string, url: string) => act(null, () => backend.setSource(id, url)),
    setInterval: (id: string, hours: number) => act(null, () => backend.setInterval(id, hours)),
    saveContent: (id: string, content: string) => act('content', () => backend.saveContent(id, content), '配置已保存'),
    saveOverride: (id: string, text: string) => act('override', () => backend.saveOverride(id, text)),

    selectNode: (group: string, node: string) => act(null, () => backend.selectNode(group, node)),
    testGroup: (group: string) => act(`test:${group}`, () => backend.testGroup(group)),
    testAll: () => act('testAll', () => backend.testAll()),
    testNode: (node: string) => act(`node:${node}`, () => backend.testNode(node)),

    closeConnection: (id: string | null) => act(null, () => backend.closeConnection(id)),
    clearLogs: () => act(null, () => backend.clearLogs()),
    flushCache: (which: 'fakeip' | 'dns') =>
      act(`flush:${which}`, () => backend.flushCache(which), which === 'fakeip' ? 'FakeIP 缓存已清除' : 'DNS 缓存已清除'),
    saveSettings: (settings: KernelSettings) => act('settings', () => backend.saveSettings(settings), '内核设置已保存'),

    async setChannel(channel: KernelChannel) {
      busy.kernel = true
      try {
        kernel.value = await backend.setChannel(channel)
        if (kernel.value.failure) toast(kernel.value.failure, 'error')
        else toast(`已切换到${channel === 'stable' ? '稳定版' : '预览版'}内核`, 'success')
      } catch (error) {
        toast(String(error), 'error')
      } finally {
        delete busy.kernel
      }
    },
    async refreshKernel() {
      busy.kernel = true
      try {
        kernel.value = await backend.refreshKernel()
        if (kernel.value.failure) toast(kernel.value.failure, 'error')
        else toast('内核已是最新', 'success')
      } catch (error) {
        toast(String(error), 'error')
      } finally {
        delete busy.kernel
      }
    },
    async setAutostart(enabled: boolean) {
      app.value = await backend.setAutostart(enabled)
    },
    async setBehavior(closeToTray: boolean, silentStart: boolean) {
      app.value = await backend.setAppBehavior(closeToTray, silentStart)
    },
  }
}

export type Store = ReturnType<typeof createStore>
export const STORE: InjectionKey<Store> = Symbol('billow-store')

export function useStore(): Store {
  const store = inject(STORE)
  if (!store) throw new Error('Billow store is missing')
  return store
}
