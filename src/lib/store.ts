import { computed, inject, reactive, ref, shallowRef, watch, type InjectionKey } from 'vue'
import type { Backend, NodeTestEvent } from './backend'
import { createAppUpdater, nativeUpdateDriver } from './appUpdate'
import {
  emptySnapshot,
  type AppInfo,
  type KernelChannel,
  type KernelSettings,
  type KernelStatus,
  type Mode,
  type NodeGroup,
  type Snapshot,
  type ThemePreference,
  type AppMode,
} from './types'

export type PageId = 'home' | 'proxies' | 'profiles' | 'connections' | 'rules' | 'resources' | 'logs' | 'settings' | 'apps'
export type SettingsTab = 'general' | 'proxy' | 'kernel' | 'tun' | 'dns'
/** Desktop sidebar grouping; settings is pinned below both groups (R25). */
export type PageGroup = 'core' | 'tools' | null

export const PAGES: { id: PageId; label: string; icon: string; mobile: boolean; group: PageGroup }[] = [
  { id: 'home', label: '首页', icon: 'home', mobile: true, group: 'core' },
  { id: 'proxies', label: '代理', icon: 'globe', mobile: true, group: 'core' },
  { id: 'profiles', label: '配置', icon: 'layers', mobile: true, group: 'core' },
  // Phones keep four tabs; connections joins the tools reached from Settings.
  { id: 'connections', label: '连接', icon: 'activity', mobile: false, group: 'core' },
  { id: 'rules', label: '规则', icon: 'route', mobile: false, group: 'tools' },
  { id: 'resources', label: '资源', icon: 'database', mobile: false, group: 'tools' },
  { id: 'logs', label: '日志', icon: 'terminal', mobile: false, group: 'tools' },
  { id: 'settings', label: '设置', icon: 'settings', mobile: true, group: null },
  // Android only, opened from Settings; never in a nav bar.
  { id: 'apps', label: '应用访问控制', icon: 'apps', mobile: false, group: null },
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

/** The home-level action behind the last failure banner, so "重试" repeats it (R24). */
export type HomeAction =
  | { kind: 'connect' }
  | { kind: 'disconnect' }
  | { kind: 'takeover'; target: 'system_proxy' | 'tun'; on: boolean }
  | { kind: 'mode'; mode: Mode }

/** One node result kept locally while a test runs, so rows update before the next snapshot. */
export interface NodeTestResult {
  delay: number | null
  failed: boolean
}

/** Per-card subscription update state; lives in the store so it survives page switches (R27). */
export interface ProfileUpdateState {
  state: 'updating' | 'success' | 'failure'
  reason: string | null
}

/** Completed/total/failed counts for the sequential update-all run (R27, R29). */
export interface ProfileRefreshProgress {
  done: number
  total: number
  failed: number
}

const HISTORY = 60

export function applyTheme(preference: ThemePreference) {
  const root = document.documentElement
  if (preference === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', preference)
}

export function createStore(backend: Backend) {
  // Backend snapshots are replaced as a whole; large lists need no deep proxies.
  const snapshot = shallowRef<Snapshot>(emptySnapshot())
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
  /** Samples collected in the current connected session; the chart waits for a few before drawing (R2). */
  const trafficSamples = ref(0)
  const adding = ref(false)
  /** Reason shown in the home failure banner; owned here so a retry can clear it (R24, R29). */
  const lastActionError = ref<string | null>(null)
  const lastFailedAction = ref<HomeAction | null>(null)
  /** Overlay results from the `node-test` stream; dropped once the final snapshot lands (R26). */
  const testResults = ref<Record<string, NodeTestResult>>({})
  /** Local completion time per node, so "测速 …" only appears after a real test (R26). */
  const testTimes = ref<Record<string, number>>({})
  /** `已测/总数` for the running or just-finished test-all; zeroed when the target changes. */
  const testProgress = ref<{ tested: number; total: number }>({ tested: 0, total: 0 })
  /** Card-level update feedback and the batch counters, kept here so a page switch keeps them. */
  const profileUpdates = reactive<Record<string, ProfileUpdateState>>({})
  const refreshProgress = ref<ProfileRefreshProgress>({ done: 0, total: 0, failed: 0 })
  let toastId = 0
  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let polling = false
  let stopped = false
  let generation = 0
  let starting: Promise<void> | null = null
  const toastTimers = new Map<number, ReturnType<typeof setTimeout>>()
  const toastMeta = new Map<number, { remaining: number; startedAt: number }>()
  let queue: Promise<unknown> = Promise.resolve()
  let unlisten: (() => void) | null = null
  let unlistenNodeTest: (() => void) | null = null
  let pendingEntry: PageId | null = null
  let savingEntry = false
  const lastRunError = ref<string | null>(null)

  const current = computed(() => snapshot.value.profiles.find((item) => item.current) ?? null)
  const hasProfiles = computed(() => snapshot.value.profiles.length > 0)
  const isAndroid = computed(() => snapshot.value.platform === 'android')
  const connecting = computed(() => Boolean(busy.connect))
  const connectStage = ref('')
  const appUpdate = createAppUpdater(nativeUpdateDriver(() => isAndroid.value))

  function dismissToast(id: number) {
    const timer = toastTimers.get(id)
    if (timer) clearTimeout(timer)
    toastTimers.delete(id)
    toastMeta.delete(id)
    toasts.value = toasts.value.filter((item) => item.id !== id)
  }

  function scheduleToast(id: number, duration: number) {
    const prev = toastTimers.get(id)
    if (prev) clearTimeout(prev)
    toastMeta.set(id, { remaining: duration, startedAt: Date.now() })
    toastTimers.set(
      id,
      setTimeout(() => {
        toastTimers.delete(id)
        toastMeta.delete(id)
        toasts.value = toasts.value.filter((item) => item.id !== id)
      }, duration),
    )
  }

  function pauseToast(id: number) {
    const timer = toastTimers.get(id)
    const meta = toastMeta.get(id)
    if (!timer || !meta) return
    clearTimeout(timer)
    toastTimers.delete(id)
    const elapsed = Math.max(0, Date.now() - meta.startedAt)
    toastMeta.set(id, { remaining: Math.max(900, meta.remaining - elapsed), startedAt: 0 })
  }

  function resumeToast(id: number) {
    if (toastTimers.has(id)) return
    const meta = toastMeta.get(id)
    if (!meta) return
    scheduleToast(id, meta.remaining)
  }

  function toast(text: string, tone: Toast['tone'] = 'info') {
    if (stopped) return
    const id = ++toastId
    for (const item of toasts.value.slice(0, -3)) {
      clearTimeout(toastTimers.get(item.id))
      toastTimers.delete(item.id)
      toastMeta.delete(item.id)
    }
    toasts.value = [...toasts.value.slice(-3), { id, tone, text }]
    scheduleToast(id, tone === 'error' ? 5200 : 2800)
  }

  function proxyEnvCommand(): { host: string; port: number; command: string } {
    const host = snapshot.value.settings.system_proxy.host.trim() || '127.0.0.1'
    const port = snapshot.value.mixed_port || snapshot.value.settings.mixed_port || 7890
    const isWin = typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent)
    const command = isWin
      ? `$env:HTTP_PROXY="http://${host}:${port}"; $env:HTTPS_PROXY="http://${host}:${port}"; $env:ALL_PROXY="socks5://${host}:${port}"`
      : `export https_proxy=http://${host}:${port} http_proxy=http://${host}:${port} all_proxy=socks5://${host}:${port}`
    return { host, port, command }
  }

  async function copyProxyEnv() {
    const { host, port, command } = proxyEnvCommand()
    return copyText(command, `已复制终端代理环境变量 (${host}:${port})`)
  }

  /**
   * Clipboard writes report their own failure; copying a connection summary or a
   * log line must never fail silently (R28, R29).
   */
  async function copyText(text: string, success: string) {
    try {
      await navigator.clipboard.writeText(text)
      toast(success, 'success')
      return true
    } catch (error) {
      console.error(error)
      toast('无法写入剪贴板', 'error')
      return false
    }
  }

  function pushTraffic(next: Snapshot) {
    if (!next.connected) {
      trafficSamples.value = 0
    } else if (trafficSamples.value === 0) {
      // A new session starts from a clean history instead of the previous curve (R2).
      traffic.value = { up: Array(HISTORY).fill(0), down: Array(HISTORY).fill(0) }
    }
    const up = next.connected ? next.upload ?? 0 : 0
    const down = next.connected ? next.download ?? 0 : 0
    traffic.value = {
      up: [...traffic.value.up.slice(1), up],
      down: [...traffic.value.down.slice(1), down],
    }
    if (next.connected) trafficSamples.value = Math.min(HISTORY, trafficSamples.value + 1)
  }

  function apply(next: Snapshot) {
    // Polling changes traffic every second, but usually leaves the node catalog intact.
    // Preserve its identity so proxy cards do not sort/render again on every tick.
    const previous = snapshot.value.node_catalog
    const sameGroup = (a: NodeGroup, b: NodeGroup) =>
      a.name === b.name && a.kind === b.kind && a.now === b.now && a.sort === b.sort &&
      a.group_type === b.group_type && a.icon === b.icon && a.nodes.length === b.nodes.length &&
      a.nodes.every((node, index) => {
        const other = b.nodes[index]!
        return node.name === other.name && node.node_type === other.node_type &&
          node.selected === other.selected && node.delay_ms === other.delay_ms && node.failed === other.failed &&
          node.tags.length === other.tags.length && node.tags.every((tag, i) => tag === other.tags[i])
      })
    const byName = new Map(previous.map((group) => [group.name, group]))
    let reused = false
    const catalog = next.node_catalog.map((group) => {
      const old = byName.get(group.name)
      if (!old || (old !== group && !sameGroup(old, group))) return group
      reused = true
      return old
    })
    if (catalog.length === previous.length && catalog.every((group, index) => group === previous[index])) {
      next = { ...next, node_catalog: previous }
    } else if (reused) {
      next = { ...next, node_catalog: catalog }
    }
    const logs = snapshot.value.logs
    if (logs.length === next.logs.length && logs.every((line, index) => {
      const other = next.logs[index]!
      return line.time_ms === other.time_ms && line.level === other.level && line.message === other.message
    })) {
      next = { ...next, logs }
    }
    const installed = snapshot.value.installed
    if (installed.length === next.installed.length && installed.every((app, index) => {
      const other = next.installed[index]!
      return app.package_name === other.package_name && app.name === other.name && app.system === other.system
    })) next = { ...next, installed }
    for (const key of ['excluded', 'included'] as const) {
      const previous = snapshot.value[key]
      if (previous.length === next[key].length && previous.every((pkg, i) => pkg === next[key][i])) {
        next = { ...next, [key]: previous }
      }
    }
    const prevSettings = snapshot.value.settings
    if (prevSettings !== next.settings) {
      let nextSettings = next.settings
      if (JSON.stringify(prevSettings.tun) === JSON.stringify(nextSettings.tun)) {
        nextSettings = { ...nextSettings, tun: prevSettings.tun }
      }
      if (JSON.stringify(prevSettings.dns) === JSON.stringify(nextSettings.dns)) {
        nextSettings = { ...nextSettings, dns: prevSettings.dns }
      }
      if (JSON.stringify(prevSettings.system_proxy) === JSON.stringify(nextSettings.system_proxy)) {
        nextSettings = { ...nextSettings, system_proxy: prevSettings.system_proxy }
      }
      if (JSON.stringify(prevSettings.geo_urls) === JSON.stringify(nextSettings.geo_urls)) {
        nextSettings = { ...nextSettings, geo_urls: prevSettings.geo_urls }
      }
      if (JSON.stringify(prevSettings) === JSON.stringify(nextSettings)) {
        nextSettings = prevSettings
      }
      if (nextSettings !== next.settings) {
        next = { ...next, settings: nextSettings }
      }
    }
    const prevConfigValues = snapshot.value.config_values
    if (prevConfigValues !== next.config_values && JSON.stringify(prevConfigValues) === JSON.stringify(next.config_values)) {
      next = { ...next, config_values: prevConfigValues }
    }
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
        lastRunError.value = error instanceof Error ? error.message : String(error)
        toast(lastRunError.value, 'error')
        return undefined
      } finally {
        if (key) delete busy[key]
      }
    })
    queue = task.catch(() => undefined)
    return task
  }

  /** Failure text this call newly introduced, compared with the snapshot it started from. */
  function newFailure(before: Snapshot, result: Snapshot): string | null {
    if (result.failure && result.failure !== before.failure) return result.failure
    if (result.notice && result.notice !== before.notice) return result.notice
    if (result.input_error && result.input_error !== before.input_error) return result.input_error
    if (result.nodes_error && result.nodes_error !== before.nodes_error) return result.nodes_error
    return null
  }

  /** `node-test` progress: every finished node is kept so rows paint 超时/延迟 before the next snapshot. */
  function recordNodeTest(event: NodeTestEvent) {
    if (event.node) {
      testResults.value[event.node] = { delay: event.delay, failed: event.failed }
      testTimes.value[event.node] = Date.now()
    }
    testProgress.value = { tested: event.tested, total: event.total }
  }

  /** One line after 全部测速: how many real nodes answered; nested group entries are skipped. */
  function testSummary(result: Snapshot): string | null {
    const groups = new Set(result.node_catalog.map((group) => group.name))
    const seen = new Map<string, boolean>()
    result.node_catalog.forEach((group) =>
      group.nodes.forEach((node) => {
        if (groups.has(node.name) || seen.has(node.name)) return
        if (node.failed) seen.set(node.name, false)
        else if (node.delay_ms != null) seen.set(node.name, true)
      }),
    )
    if (!seen.size) return null
    const ok = [...seen.values()].filter(Boolean).length
    const failed = seen.size - ok
    return failed ? `测速完成：${ok} 个可用，${failed} 个超时` : `测速完成：${ok} 个节点全部可用`
  }

  function clearTestProgress() {
    testResults.value = {}
    testTimes.value = {}
    testProgress.value = { tested: 0, total: 0 }
  }

  /** Single-node and per-group tests only stamp a time; values come from the fresh snapshot. */
  function stampTestTimes(names: string[]) {
    if (!names.length) return
    const at = Date.now()
    names.forEach((name) => {
      testTimes.value[name] = at
    })
  }

  /** A home-level attempt the failure banner can retry; `done` reads the outcome from the new snapshot. */
  interface HomeAttempt {
    action: HomeAction
    done: (next: Snapshot) => boolean
  }

  async function act(
    key: string | null,
    action: () => Promise<Snapshot>,
    success?: string,
    attempt?: HomeAttempt,
  ) {
    const before = snapshot.value
    lastRunError.value = null
    if (attempt) {
      // A new explicit attempt retires the previous banner before it runs (R24).
      lastActionError.value = null
      lastFailedAction.value = null
    }
    const result = await run(key, action)
    if (!result) {
      if (attempt) {
        lastActionError.value = lastRunError.value ?? '操作没有完成'
        lastFailedAction.value = attempt.action
      }
      return undefined
    }
    const changed = newFailure(before, result)
    const failed = attempt ? !attempt.done(result) : false
    if (changed) toast(changed, 'error')
    else if (!failed && success) toast(success, 'success')
    if (attempt) {
      if (failed) {
        lastActionError.value = result.failure ?? changed ?? '操作没有完成'
        lastFailedAction.value = attempt.action
      } else if (changed) {
        lastActionError.value = changed
      }
    }
    if (backend.live) void backend.syncTray()
    return result
  }

  /**
   * One subscription fetch with card feedback. A failed fetch is normal for a
   * dead subscription URL, so it is recorded on the card instead of aborting
   * the sequential update-all loop (R27).
   */
  async function trackUpdate(id: string, fetch: () => Promise<Snapshot>, quiet = false) {
    const before = snapshot.value
    profileUpdates[id] = { state: 'updating', reason: null }
    lastRunError.value = null
    const result = await run(`update:${id}`, fetch)
    let reason: string | null = null
    if (!result) reason = lastRunError.value ?? '订阅没有更新'
    else {
      const profile = result.profiles.find((item) => item.id === id)
      reason = profile?.failure ?? newFailure(before, result)
    }
    if (reason) {
      profileUpdates[id] = { state: 'failure', reason }
      if (!quiet) toast(reason, 'error')
      if (backend.live) void backend.syncTray()
      return false
    }
    profileUpdates[id] = { state: 'success', reason: null }
    if (!quiet) toast('订阅已更新', 'success')
    if (backend.live) void backend.syncTray()
    return true
  }

  /** Subscriptions in card order, used by update-all and the palette action. */
  function subscribeIds() {
    return snapshot.value.profiles.filter((item) => item.kind === 'subscription').map((item) => item.id)
  }

  /**
   * Sequential update-all driven here rather than by one blocking backend call:
   * each card paints 更新中/成功/失败, a failure leaves a retry, and the counters
   * live in the store so leaving the page does not lose progress (R27, R29).
   */
  async function updateAll() {
    if (busy.refreshAll) return
    const ids = subscribeIds()
    busy.refreshAll = true
    refreshProgress.value = { done: 0, total: ids.length, failed: 0 }
    try {
      for (const id of ids) {
        const ok = await trackUpdate(id, () => backend.refresh(id), true)
        refreshProgress.value = {
          done: refreshProgress.value.done + 1,
          total: ids.length,
          failed: refreshProgress.value.failed + (ok ? 0 : 1),
        }
      }
      const { done, total, failed } = refreshProgress.value
      if (total) {
        toast(
          failed ? `更新完成：${done}/${total}，${failed} 个订阅失败` : '全部订阅已更新',
          failed ? 'error' : 'success',
        )
      }
    } finally {
      delete busy.refreshAll
    }
  }

  // A failure that arrives through polling still reaches the banner, without a retry target.
  watch(
    () => snapshot.value.failure,
    (next, prev) => {
      if (next && next !== prev) lastActionError.value = next
    },
  )

  // A different config or a stopped kernel invalidates the per-node test results (R26).
  watch(
    () => [snapshot.value.active_id, snapshot.value.kernel_running] as const,
    ([id, running], [prevId, prevRunning]) => {
      if (id !== prevId || (prevRunning && !running)) clearTestProgress()
    },
  )

  const isCurrent = (session: number) => !stopped && session === generation
  const isVisible = () => typeof document === 'undefined' || document.visibilityState !== 'hidden'

  function cancelPoll() {
    if (pollTimer !== null) clearTimeout(pollTimer)
    pollTimer = null
  }

  function schedulePoll(session: number, delay: number) {
    if (!isCurrent(session) || !isVisible()) return
    cancelPoll()
    pollTimer = setTimeout(() => {
      pollTimer = null
      void poll(session)
    }, delay)
  }

  function onVisibilityChange() {
    cancelPoll()
    if (isVisible()) void poll(generation)
  }

  async function poll(session: number) {
    if (!isCurrent(session) || !isVisible()) return
    if (!polling && Object.keys(busy).length === 0) {
      polling = true
      try {
        const next = await backend.state()
        if (!isCurrent(session)) return
        if (Object.keys(busy).length === 0) apply(next)
        pushTraffic(next)
      } catch (error) {
        console.error(error)
      } finally {
        polling = false
      }
    } else {
      pushTraffic(snapshot.value)
    }
    const fast = snapshot.value.kernel_running || snapshot.value.connected
    schedulePoll(session, fast ? 1000 : 3000)
  }

  async function initialize(session: number) {
    try {
      const shell = await backend.shell()
      if (!isCurrent(session)) return
      theme.value = shell.theme
      page.value = resolvePage(shell.last_entry)
    } catch (error) {
      console.error(error)
    }
    if (!isCurrent(session)) return
    applyTheme(theme.value)
    try {
      const next = await backend.state()
      if (!isCurrent(session)) return
      apply(next)
    } catch (error) {
      console.error(error)
    }
    if (!isCurrent(session)) return
    loaded.value = true
    if (backend.live) void appUpdate.check(true)
    void backend.kernel().then((value) => {
      if (isCurrent(session)) kernel.value = value
    }).catch(console.error)
    void backend.appInfo().then((value) => {
      if (isCurrent(session)) app.value = value
    }).catch(console.error)
    try {
      const release = await backend.onChange((next) => {
        if (isCurrent(session)) apply(next)
      })
      if (!isCurrent(session)) {
        release()
        return
      }
      unlisten = release
    } catch (error) {
      console.error(error)
    }
    if (!isCurrent(session)) return
    try {
      const release = await backend.onNodeTest((event) => {
        if (isCurrent(session)) recordNodeTest(event)
      })
      if (!isCurrent(session)) {
        release()
        return
      }
      unlistenNodeTest = release
    } catch (error) {
      console.error(error)
    }
    if (!isCurrent(session)) return
    document.addEventListener('visibilitychange', onVisibilityChange)
    schedulePoll(session, 1000)
  }

  function start() {
    if (starting) return starting
    stopped = false
    starting = initialize(++generation)
    return starting
  }

  function stop() {
    appUpdate.stop()
    stopped = true
    generation += 1
    starting = null
    cancelPoll()
    document.removeEventListener('visibilitychange', onVisibilityChange)
    unlisten?.()
    unlisten = null
    unlistenNodeTest?.()
    unlistenNodeTest = null
    toastTimers.forEach((timer) => clearTimeout(timer))
    toastTimers.clear()
    toastMeta.clear()
    toasts.value = []
  }

  function openSettings(tab: SettingsTab) {
    settingsTab.value = tab
    go('settings')
  }

  async function saveEntry(next: PageId) {
    pendingEntry = next
    if (savingEntry) return
    savingEntry = true
    try {
      while (pendingEntry !== null) {
        const entry: PageId = pendingEntry
        pendingEntry = null
        await backend.setEntry(entry).catch(console.error)
      }
    } finally {
      savingEntry = false
    }
  }

  function go(next: PageId, group?: string) {
    const changed = page.value !== next
    page.value = next
    focusGroup.value = group ?? null
    // Native writes run off the UI thread. Serialize/coalesce them so rapid
    // navigation cannot save an older page after the latest one.
    if (changed) void saveEntry(next)
  }

  function setTheme(next: ThemePreference) {
    theme.value = next
    applyTheme(next)
    void backend.setTheme(next).catch(console.error)
  }

  /** Explicit connect used by the command palette; no implicit add-profile dialog. */
  function connect() {
    if (connecting.value || snapshot.value.connected) return Promise.resolve(undefined)
    if (!hasProfiles.value) {
      adding.value = true
      return Promise.resolve(undefined)
    }
    if (!snapshot.value.active_id && snapshot.value.profiles.length > 1) {
      go('profiles')
      toast('请先选择要使用的配置', 'info')
      return Promise.resolve(undefined)
    }
    return act('connect', async () => {
      try {
        if (!snapshot.value.active_id) {
          connectStage.value = '正在初始化内核和配置资源…'
          const id = snapshot.value.profiles[0]!.id
          const enabled = await backend.enable(id)
          if (enabled.active_id !== id || enabled.failure) return enabled
        }
        connectStage.value = isAndroid.value ? '正在建立 VPN，请留意系统授权提示…' : '正在建立代理连接…'
        return await backend.connect()
      } finally {
        connectStage.value = ''
      }
    }, '已连接', {
      action: { kind: 'connect' },
      done: (next) => next.connected,
    })
  }

  function disconnect() {
    if (connecting.value || !snapshot.value.connected) return Promise.resolve(undefined)
    return act('connect', () => backend.disconnect(), '已断开', {
      action: { kind: 'disconnect' },
      done: (next) => !next.connected,
    })
  }

  function setMode(mode: Mode) {
    return act('mode', () => backend.setMode(mode), undefined, {
      action: { kind: 'mode', mode },
      done: (next) => next.mode === mode,
    })
  }

  function setSystemProxy(on: boolean) {
    return act('proxy', () => backend.setSystemProxy(on), undefined, {
      action: { kind: 'takeover', target: 'system_proxy', on },
      done: (next) => next.system_proxy === on,
    })
  }

  function setTun(on: boolean) {
    return act('tun', () => backend.setTun(on), undefined, {
      action: { kind: 'takeover', target: 'tun', on },
      done: (next) => next.tun === on,
    })
  }

  /** Repeats the action behind the failure banner; success clears both the reason and the target. */
  function retryLastAction() {
    const action = lastFailedAction.value
    if (!action) return Promise.resolve(undefined)
    if (action.kind === 'mode') return setMode(action.mode)
    if (action.kind === 'disconnect') return disconnect()
    if (action.kind === 'takeover') return action.target === 'tun' ? setTun(action.on) : setSystemProxy(action.on)
    return connect()
  }

  return {
    backend,
    appUpdate,
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
    trafficSamples,
    adding,
    /** Home failure banner state (R24, R29). */
    lastActionError,
    lastFailedAction,
    /** Per-node test results and `已测/总数` for the proxy page (R26). */
    testResults,
    testTimes,
    testProgress,
    /** Per-card subscription update state and update-all counters (R27). */
    profileUpdates,
    refreshProgress,
    /** Last thrown backend message, so inline errors can show the real reason (R29). */
    lastRunError,
    current,
    hasProfiles,
    isAndroid,
    connecting,
    connectStage,
    toast,
    dismissToast,
    pauseToast,
    resumeToast,
    /** Shared clipboard helper so a failure surfaces as a toast instead of silence (R28). */
    copyText,
    copyProxyEnv,
    start,
    stop,
    go,
    setTheme,
    connect,
    disconnect,
    retryLastAction,
    /** Cycle system → light → dark so the palette command never needs a submenu. */
    cycleTheme() {
      const order: ThemePreference[] = ['system', 'light', 'dark']
      const next = order[(order.indexOf(theme.value) + 1) % order.length] ?? 'system'
      setTheme(next)
      return next
    },
    refresh: () => run(null, () => backend.state()),

    toggleConnection() {
      if (connecting.value) return Promise.resolve(undefined)
      if (snapshot.value.connected) return disconnect()
      return connect()
    },
    setMode,
    setSystemProxy,
    setTun,
    exclude: (pkg: string) => act(null, () => backend.exclude(pkg)),
    include: (pkg: string) => act(null, () => backend.include(pkg)),
    setAppRules: (mode: AppMode, packages: string[]) => act('apps', () => backend.setAppRules(mode, packages)),

    addSubscription: (url: string) => act('add', () => backend.addSubscription(url)),
    addLocal: (name: string, content: string) => act('add', () => backend.addLocal(name, content)),
    confirmInstall: () => act(null, () => backend.confirmInstall(), '已添加订阅'),
    cancelInstall: () => act(null, () => backend.cancelInstall()),
    enable: (id: string) => act(`enable:${id}`, () => backend.enable(id), '已切换配置'),
    update: (id: string) =>
      trackUpdate(id, () =>
        snapshot.value.active_id === id ? backend.update(id) : backend.refresh(id),
      ),
    updateAll,
    refreshAll: () => updateAll(),
    remove: (id: string) => act(`remove:${id}`, () => backend.remove(id)),
    rename: (id: string, name: string) => act(null, () => backend.rename(id, name)),
    setSource: (id: string, url: string) => act(null, () => backend.setSource(id, url)),
    setInterval: (id: string, hours: number) => act(null, () => backend.setInterval(id, hours)),
    setAgeKey: (id: string, key: string) => act(null, () => backend.setAgeKey(id, key)),
    saveContent: (id: string, content: string) => act('content', () => backend.saveContent(id, content), '配置已保存'),
    saveOverride: (id: string, text: string) => act('override', () => backend.saveOverride(id, text)),

    selectNode: (group: string, node: string) => act(null, () => backend.selectNode(group, node)),

    /** Per-group test stamps the local result time so headers can show "测速 …" (R26). */
    async testGroup(group: string) {
      const result = await act(`test:${group}`, () => backend.testGroup(group))
      // A snapshot that only reports "kernel not running" is not a test result.
      if (result && !result.nodes_error) {
        const names = snapshot.value.node_catalog.find((item) => item.name === group)?.nodes.map((item) => item.name) ?? []
        stampTestTimes(names)
      }
      return result
    },
    /**
     * Test-all progress arrives through `node-test`; the stream supplies both the
     * per-node result and its time. Once the final snapshot lands the overlay is
     * dropped so newer polled delays win instead of being shadowed forever (R26).
     */
    async testAll() {
      testProgress.value = { tested: 0, total: 0 }
      testResults.value = {}
      const result = await act('testAll', () => backend.testAll())
      if (result && !result.nodes_error) {
        testResults.value = {}
        const summary = testSummary(result)
        if (summary) toast(summary, 'success')
      } else clearTestProgress()
      return result
    },
    async testNode(node: string) {
      const result = await act(`node:${node}`, () => backend.testNode(node))
      if (result && !result.nodes_error) stampTestTimes([node])
      return result
    },

    closeConnection: (id: string | null) => act(null, () => backend.closeConnection(id)),
    clearLogs: () => act(null, () => backend.clearLogs()),
    flushCache: (which: 'fakeip' | 'dns') =>
      act(`flush:${which}`, () => backend.flushCache(which), which === 'fakeip' ? 'FakeIP 缓存已清除' : 'DNS 缓存已清除'),
    saveSettings: (settings: KernelSettings) => act('settings', () => backend.saveSettings(settings), '内核设置已保存'),
    async openUwpTool() {
      const ok = await run('uwp', async () => {
        await backend.openUwpTool()
        return true
      })
      if (ok) toast('已打开 UWP 回环豁免工具', 'success')
    },

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
