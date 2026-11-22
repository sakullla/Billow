import { computed, inject, reactive, ref, shallowRef, watch, type InjectionKey } from 'vue'
import type { Backend, NodeTestEvent } from './backend'
import { createAppUpdater, nativeUpdateDriver } from './appUpdate'
import { hostOf } from './format'
import { applyLocale, normalizeLanguage, normalizeLocale, t, tr } from './i18n'
import { runPool } from './pool'
import {
  emptySnapshot,
  type AppInfo,
  type ClosedConnectionRow,
  type ConnectionRow,
  type CustomNodesImportResult,
  type DialerTarget,
  type DnsQueryType,
  type ExitIpInfo,
  type KernelChannel,
  type KernelSettings,
  type KernelStatus,
  type LandingRule,
  type Mode,
  type NodeGroup,
  type SaveCustomNodeInput,
  type Snapshot,
  type ThemePreference,
  type LanguagePreference,
  type AppMode,
  type TrafficHistoryView,
  type TrafficRange,
} from './types'

export type PageId = 'home' | 'proxies' | 'profiles' | 'connections' | 'rules' | 'resources' | 'logs' | 'settings' | 'apps'
/**
 * Settings categories. `home` is the phone's category list; desktop shows the
 * general page for it, so it is always a valid landing tab.
 */
export type SettingsTab =
  | 'home'
  | 'general'
  | 'proxy'
  | 'tun'
  | 'network'
  | 'behavior'
  | 'dns'
  | 'kernel'
  | 'backup'
  | 'about'
export type ConfigViewTab = 'overview' | 'yaml'

const CONFIG_TAB_KEY = 'billow.configTab'
export function readConfigTab(): ConfigViewTab {
  try {
    return localStorage.getItem(CONFIG_TAB_KEY) === 'yaml' ? 'yaml' : 'overview'
  } catch {
    return 'overview'
  }
}
export function rememberConfigTab(tab: ConfigViewTab) {
  try {
    localStorage.setItem(CONFIG_TAB_KEY, tab)
  } catch {
    /* storage unavailable */
  }
}
/** Desktop sidebar grouping; settings is pinned below both groups (R25). */
export type PageGroup = 'core' | 'tools' | null

export const PAGES: { id: PageId; label: string; icon: string; mobile: boolean; group: PageGroup }[] = [
  { id: 'home', get label() { return tr('首页') }, icon: 'home', mobile: true, group: 'core' },
  { id: 'proxies', get label() { return tr('代理') }, icon: 'globe', mobile: true, group: 'core' },
  { id: 'profiles', get label() { return tr('配置') }, icon: 'layers', mobile: true, group: 'core' },
  // Phones keep four tabs; connections joins the tools reached from Settings.
  { id: 'connections', get label() { return tr('连接') }, icon: 'activity', mobile: false, group: 'core' },
  { id: 'rules', get label() { return tr('规则') }, icon: 'route', mobile: false, group: 'tools' },
  { id: 'resources', get label() { return tr('资源') }, icon: 'database', mobile: false, group: 'tools' },
  { id: 'logs', get label() { return tr('日志') }, icon: 'terminal', mobile: false, group: 'tools' },
  { id: 'settings', get label() { return tr('设置') }, icon: 'settings', mobile: true, group: null },
  // Android only, opened from Settings; never in a nav bar.
  { id: 'apps', get label() { return tr('应用访问控制') }, icon: 'apps', mobile: false, group: null },
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

/** Saved ConnectionsView state when drilling into a proxy group or rule-set (R4). */
export interface ConnectionReturnState {
  sessionId: number
  targetPage: 'proxies' | 'resources'
  tab: 'active' | 'closed'
  query: string
  routeFilter: 'all' | 'proxy' | 'direct'
  sortKey: 'time' | 'speed' | 'download' | 'upload' | 'host'
  sortDir: 'asc' | 'desc'
  listScrollTop: number
  paused: boolean
  pausedAt: number | null
  frozenRows: ConnectionRow[]
  frozenIds: string[]
  frozenTotal: number
  frozenUp: number | null
  frozenDown: number | null
  connectionKey: string | null
  detailFromClosed: boolean
  rulePolicy: string
}

const HISTORY = 60
const MAX_CLOSED_CONNECTIONS = 200

export function applyTheme(preference: ThemePreference) {
  const root = document.documentElement
  if (preference === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', preference)
}

function reuseEqual<T>(previous: T, incoming: T): T {
  return previous === incoming || JSON.stringify(previous) === JSON.stringify(incoming) ? previous : incoming
}

export function createStore(backend: Backend) {
  // Backend snapshots are replaced as a whole; large lists need no deep proxies.
  const snapshot = shallowRef<Snapshot>(emptySnapshot())
  const kernel = ref<KernelStatus>({ channel: 'stable', failure: null, ready: false, version: null })
  const app = ref<AppInfo | null>(null)
  const theme = ref<ThemePreference>('system')
  /** Stored language preference; the dictionary locale comes from the backend (R42). */
  const language = ref<LanguagePreference>('system')
  const page = ref<PageId>('home')
  const focusGroup = ref<string | null>(null)
  const focusProvider = ref<{ kind: 'proxy' | 'rule'; name: string } | null>(null)
  const connectionReturn = ref<ConnectionReturnState | null>(null)
  const connectionSessionId = ref(0)
  const settingsTab = ref<SettingsTab>('home')
  /** A row (`data-setting` id) the settings page should scroll to and highlight once shown. */
  const settingsFocus = ref<string | null>(null)
  /** Text another page asks the profiles page to append to a profile's 覆写 editor (unsaved). */
  const overrideRequest = ref<{ id: string; append: string } | null>(null)
  /** The DNS query dialog, opened from the DNS settings tab or the palette (R31). */
  const dnsQueryOpen = ref(false)
  /** Exit IP lookup result, stale mark, in-flight flag and last failure (R40). */
  const exitIp = shallowRef<ExitIpInfo | null>(null)
  const exitIpStale = ref(false)
  const exitIpBusy = ref(false)
  const exitIpError = ref<string | null>(null)
  /** Traffic stats dialog and its last read (R43). */
  const trafficStatsOpen = ref(false)
  const trafficStats = shallowRef<TrafficHistoryView | null>(null)
  const trafficStatsBusy = ref(false)
  const trafficStatsError = ref<string | null>(null)
  /** The range the dialog is showing, so enabling or clearing keeps it. */
  const trafficStatsRange = ref<{ range: TrafficRange; from: string | null; to: string | null }>({
    range: 'today',
    from: null,
    to: null,
  })
  let pendingTrafficStats: typeof trafficStatsRange.value | null = null
  let trafficStatsLoad: Promise<TrafficHistoryView | undefined> | null = null
  const loaded = ref(false)
  const busy = reactive<Record<string, boolean>>({})
  const toasts = ref<Toast[]>([])
  const traffic = shallowRef<{ up: number[]; down: number[] }>({
    up: Array(HISTORY).fill(0),
    down: Array(HISTORY).fill(0),
  })
  /** Samples collected in the current connected session; the chart waits for a few before drawing (R2). */
  const trafficSamples = ref(0)
  /** Recently closed connections observed during the current connected session, newest first. */
  const closedConnections = shallowRef<ClosedConnectionRow[]>([])
  let prevActiveConnections = new Map<string, ConnectionRow>()
  const connectionKey = (row: ConnectionRow) => row.id || `${row.host}|${row.source}|${row.start}`
  function clearClosedConnections() {
    closedConnections.value = []
  }
  const adding = ref(false)
  /** The effective-config viewer is app-wide so profiles, settings and the palette share one. */
  const configView = ref<ConfigViewTab | null>(null)
  /** Reason shown in the home failure banner; owned here so a retry can clear it (R24, R29). */
  const lastActionError = ref<string | null>(null)
  const lastFailedAction = ref<HomeAction | null>(null)
  /** Overlay results from the `node-test` stream; dropped once the final snapshot lands (R26). */
  const testResults = ref<Record<string, NodeTestResult>>({})
  /** Local completion time per node, so "测速 …" only appears after a real test (R26). */
  const testTimes = ref<Record<string, number>>({})
  /** `已测/总数` for the running or just-finished test-all; zeroed when the target changes. */
  const testProgress = ref<{ tested: number; total: number }>({ tested: 0, total: 0 })
  const activeTest = ref<{ kind: 'all' | 'group' | 'node'; group?: string } | null>(null)
  const testing = computed(() => activeTest.value !== null)
  const pendingTests = ref<Set<string>>(new Set())
  let testProfileId: string | null = null

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
  const hasProfiles = computed(
    () =>
      snapshot.value.profiles.length > 0 ||
      snapshot.value.custom_profile_active ||
      snapshot.value.custom_nodes.nodes.length > 0,
  )
  const customNodes = computed(() => snapshot.value.custom_nodes)
  const hasCustomNodes = computed(() => snapshot.value.custom_nodes.nodes.length > 0)
  const enabledCustomNodes = computed(() => snapshot.value.custom_nodes.nodes.filter((item) => item.enabled))
  const customNodesWarnings = computed(() => snapshot.value.custom_nodes_warnings)
  const customProfileActive = computed(() => snapshot.value.custom_profile_active)
  const landingPresets = computed(() => snapshot.value.landing_presets)
  const isAndroid = computed(() => snapshot.value.platform === 'android')
  /** Desktop OS from `AppInfo.platform` (Rust `std::env::consts::OS`); gates Linux / macOS-only options. */
  const isLinux = computed(() => !isAndroid.value && app.value?.platform === 'linux')
  const isMac = computed(() => !isAndroid.value && app.value?.platform === 'macos')
  const connecting = computed(() => Boolean(busy.connect))
  const connectStage = ref('')
  /** True while 重启内核 runs; the home status reads 重启中 instead of 断开中. */
  const restarting = ref(false)
  const appUpdate = createAppUpdater(nativeUpdateDriver(() => isAndroid.value))
  /** Automatic exit IP queries, off by default (R40); the home card reads it too. */
  const autoExitIp = computed(() => app.value?.auto_exit_ip ?? false)
  /** Which exit the proxy currently uses: profile, outbound mode and node choices (R40). */
  const exitIpSignature = computed(() => {
    if (!autoExitIp.value) return ''
    const groups = snapshot.value.node_catalog
    if (groups.length === 0) return ''
    return (
      `${snapshot.value.active_id ?? ''}|${snapshot.value.mode ?? ''}|` +
      groups.map((group) => `${group.name}=${group.now}|${group.fixed ?? ''}`).join(';')
    )
  })

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
    // Backend messages arrive in Chinese; the catalog translates a known reason
    // and leaves unknown text untouched (T8).
    const shown = tr(text)
    toasts.value = [...toasts.value.slice(-3), { id, tone, text: shown }]
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
    return copyText(command, tr('已复制终端代理环境变量 ({0}:{1})', { 0: host, 1: port }))
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
      toast(tr('无法写入剪贴板'), 'error')
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

  /**
   * Ask the backend for the exit IP through the local mixed port (R40). It must
   * only run from a click or from the automatic-query watchers below; a
   * disconnected snapshot or an off switch never sends a request. A failed
   * lookup keeps the previous result and only reports the reason.
   */
  async function queryExitIp(again = false) {
    // The card is the only manual entry point and it exists only while on (R40).
    if (stopped || !autoExitIp.value || exitIpBusy.value || !snapshot.value.connected) return undefined
    const session = generation
    const signature = exitIpSignature.value
    exitIpBusy.value = true
    exitIpError.value = null
    try {
      const result = await backend.exitIp()
      // Turning the option off while the request was in flight hides the card and
      // drops the answer instead of keeping a result nobody asked for (R40).
      if (!isCurrent(session) || !autoExitIp.value) return result
      exitIp.value = result
      // A switch while the request was in flight already makes this answer old.
      exitIpStale.value = signature !== exitIpSignature.value
      return result
    } catch (error) {
      if (isCurrent(session) && autoExitIp.value) {
        exitIpError.value = error instanceof Error ? error.message : String(error)
      }
      return undefined
    } finally {
      exitIpBusy.value = false
      // One follow-up at most: a switch that arrived during the request needs a
      // fresh answer, but a service that keeps changing must not loop.
      if (!again && isCurrent(session) && autoExitIp.value && snapshot.value.connected && exitIp.value && signature !== exitIpSignature.value) {
        void queryExitIp(true)
      }
    }
  }

  /** Turn the automatic lookup on or off; stored with the app settings (R40). */
  async function setAutoExitIp(enabled: boolean) {
    try {
      app.value = await backend.setExitIpAuto(enabled)
    } catch (error) {
      toast(error instanceof Error ? error.message : String(error), 'error')
    }
  }

  /**
   * Read the aggregated traffic history (R43). A failed read keeps the previous
   * rows on screen and only reports the reason.
   */
  function loadTrafficStats(
    range: TrafficRange = trafficStatsRange.value.range,
    from: string | null = trafficStatsRange.value.from,
    to: string | null = trafficStatsRange.value.to,
  ) {
    const request = { range, from, to }
    trafficStatsRange.value = request
    pendingTrafficStats = request
    trafficStatsBusy.value = true
    trafficStatsError.value = null

    if (trafficStatsLoad) return trafficStatsLoad
    trafficStatsLoad = readTrafficStats()
    return trafficStatsLoad
  }

  async function readTrafficStats() {
    // Only keep one native read in flight. Range changes replace the queued read.
    // Yield once so trafficStatsLoad is set even if no request ends up running.
    await Promise.resolve()
    let result: TrafficHistoryView | undefined
    while (pendingTrafficStats) {
      const request = pendingTrafficStats
      try {
        const view = await backend.trafficHistory(request.range, request.from, request.to)
        if (pendingTrafficStats !== request) continue
        trafficStats.value = view
        result = view
      } catch (error) {
        if (pendingTrafficStats !== request) continue
        trafficStatsError.value = error instanceof Error ? error.message : String(error)
      }
      pendingTrafficStats = null
    }
    trafficStatsLoad = null
    trafficStatsBusy.value = false
    return result
  }

  function releaseTrafficStats() {
    pendingTrafficStats = null
    trafficStats.value = null
    trafficStatsError.value = null
    trafficStatsBusy.value = false
  }

  function refreshOpenTrafficStats() {
    if (!stopped && trafficStatsOpen.value) {
      return loadTrafficStats()
    }
  }

  /** Open the dialog; it reads the rows itself on mount (R43). */
  function openTrafficStats() {
    trafficStatsOpen.value = true
  }

  /** The switch is stored with the other app settings; turning it off keeps rows (R43). */
  async function setTrafficRecording(enabled: boolean) {
    try {
      app.value = await backend.setTrafficRecording(enabled)
      await refreshOpenTrafficStats()
      toast(enabled ? t('traffic.recordStarted') : t('traffic.recordStopped'), 'success')
    } catch (error) {
      toast(error instanceof Error ? error.message : String(error), 'error')
    }
  }

  async function clearTrafficHistory() {
    try {
      await backend.clearTrafficHistory()
      await refreshOpenTrafficStats()
      toast(t('traffic.cleared'), 'success')
    } catch (error) {
      toast(error instanceof Error ? error.message : String(error), 'error')
    }
  }

  function shareCatalog(previous: NodeGroup[], incoming: NodeGroup[]) {
    // Polling changes traffic every second, but usually leaves the node catalog intact.
    // Preserve its identity so proxy cards do not sort/render again on every tick.
    if (previous === incoming) return previous
    const sameGroup = (a: NodeGroup, b: NodeGroup) =>
      a === b || a.name === b.name && a.kind === b.kind && a.now === b.now && a.sort === b.sort &&
      a.pinnable === b.pinnable && a.fixed === b.fixed && a.hidden === b.hidden &&
      a.group_type === b.group_type && a.icon === b.icon && a.nodes.length === b.nodes.length &&
      a.nodes.every((node, index) => {
        const other = b.nodes[index]!
        return node.name === other.name && node.node_type === other.node_type &&
          node.selected === other.selected && node.delay_ms === other.delay_ms && node.failed === other.failed &&
          (node.dialer_proxy ?? null) === (other.dialer_proxy ?? null) &&
          node.tags.length === other.tags.length && node.tags.every((tag, i) => tag === other.tags[i])
      })
    if (incoming.length === previous.length && incoming.every((group, i) => sameGroup(group, previous[i]!))) {
      return previous
    }
    if (!previous.length || !incoming.length) return incoming
    const byName = new Map(previous.map((group) => [group.name, group]))
    let reused = false
    const catalog = incoming.map((group) => {
      const old = byName.get(group.name)
      if (!old || !sameGroup(old, group)) return group
      reused = true
      return old
    })
    return reused ? catalog : incoming
  }

  function apply(incoming: Snapshot) {
    const next = { ...incoming, node_catalog: shareCatalog(snapshot.value.node_catalog, incoming.node_catalog) }
    const logs = snapshot.value.logs
    if (logs.length === next.logs.length && logs.every((line, index) => {
      const other = next.logs[index]!
      return line.time_ms === other.time_ms && line.level === other.level && line.message === other.message &&
        line.hint === other.hint && line.hint_kind === other.hint_kind
    })) {
      next.logs = logs
    }
    const installed = snapshot.value.installed
    if (installed.length === next.installed.length && installed.every((app, index) => {
      const other = next.installed[index]!
      return app.package_name === other.package_name && app.name === other.name && app.system === other.system
    })) next.installed = installed
    for (const key of ['excluded', 'included'] as const) {
      const previous = snapshot.value[key]
      if (previous.length === next[key].length && previous.every((pkg, i) => pkg === next[key][i])) {
        next[key] = previous
      }
    }
    const prevSettings = snapshot.value.settings
    if (prevSettings !== next.settings) {
      if (JSON.stringify(prevSettings) === JSON.stringify(next.settings)) {
        next.settings = prevSettings
      } else {
        const settings = next.settings
        next.settings = {
          ...settings,
          tun: reuseEqual(prevSettings.tun, settings.tun),
          dns: reuseEqual(prevSettings.dns, settings.dns),
          system_proxy: reuseEqual(prevSettings.system_proxy, settings.system_proxy),
          geo_urls: reuseEqual(prevSettings.geo_urls, settings.geo_urls),
        }
      }
    }
    next.config_values = reuseEqual(snapshot.value.config_values, next.config_values)
    const previousProfiles = snapshot.value.profiles
    if (previousProfiles.length !== next.profiles.length ||
      previousProfiles.some((profile, index) => profile.id !== next.profiles[index]?.id)) {
      const ids = new Set(next.profiles.map((profile) => profile.id))
      for (const id in profileUpdates) {
        if (!ids.has(id)) delete profileUpdates[id]
      }
      for (const id of pendingUpdates.keys()) {
        if (!ids.has(id)) {
          pendingUpdates.delete(id)
          delete busy[`update:${id}`]
        }
      }
    }
    if (Boolean(next.connected) !== Boolean(snapshot.value.connected)) {
      connectionSessionId.value += 1
    }
    if (!next.connected) {
      prevActiveConnections.clear()
      if (closedConnections.value.length > 0) closedConnections.value = []
    } else if (!next.connections_error) {
      const currentMap = new Map<string, ConnectionRow>()
      for (const row of next.connections) {
        currentMap.set(connectionKey(row), row)
      }
      if (snapshot.value.connected && prevActiveConnections.size > 0) {
        const closedAt = Date.now()
        const ended: ClosedConnectionRow[] = []
        for (const [key, oldRow] of prevActiveConnections) {
          if (!currentMap.has(key)) {
            ended.push({ ...oldRow, closed_at_ms: closedAt })
            if (ended.length === MAX_CLOSED_CONNECTIONS) break
          }
        }
        if (ended.length > 0) {
          closedConnections.value = ended.concat(closedConnections.value.slice(0, MAX_CLOSED_CONNECTIONS - ended.length))
        }
      }
      prevActiveConnections = currentMap
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
    if (!activeTest.value || testProfileId !== snapshot.value.active_id) return
    if (event.node) {
      pendingTests.value.delete(event.node)
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
    return failed ? tr('测速完成：{0} 个可用，{1} 个超时', { 0: ok, 1: failed }) : tr('测速完成：{0} 个节点全部可用', { 0: ok })
  }

  function clearTestProgress() {
    pendingTests.value = new Set()
    testResults.value = {}
    testTimes.value = {}
    testProgress.value = { tested: 0, total: 0 }
  }

  async function runNodeTest(
    scope: NonNullable<typeof activeTest.value>,
    key: string,
    names: string[],
    action: () => Promise<Snapshot>,
  ) {
    if (testing.value) return undefined
    activeTest.value = scope
    testProfileId = snapshot.value.active_id
    testResults.value = {}
    pendingTests.value = new Set(names)
    testProgress.value = { tested: 0, total: pendingTests.value.size }
    try {
      return await act(key, action)
    } finally {
      pendingTests.value = new Set()
      testResults.value = {}
      activeTest.value = null
    }
  }

  /** Completion stamps local test times after the final snapshot replaces streamed values. */
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
        lastActionError.value = lastRunError.value ?? tr('操作没有完成')
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
        lastActionError.value = result.failure ?? changed ?? tr('操作没有完成')
        lastFailedAction.value = attempt.action
      } else if (changed) {
        lastActionError.value = changed
      }
    }
    if (backend.live) void backend.syncTray()
    return result
  }

  const pendingUpdates = new Map<string, { settings: string; result: Promise<boolean> }>()

  function trackUpdate(id: string, quiet = false): Promise<boolean> {
    const profile = snapshot.value.profiles.find((item) => item.id === id)
    const settings = JSON.stringify([profile?.source, profile?.user_agent || snapshot.value.settings.subscription_user_agent, profile?.age_recipients])
    const pending = pendingUpdates.get(id)
    if (pending?.settings === settings) return pending.result

    const current = () => pendingUpdates.get(id)?.result === result
    const result: Promise<boolean> = Promise.resolve().then(() => fetchUpdate(id, quiet, current)).finally(() => {
      if (current()) {
        pendingUpdates.delete(id)
        delete busy[`update:${id}`]
      }
    })
    pendingUpdates.set(id, { settings, result })
    busy[`update:${id}`] = true
    return result
  }

  async function fetchUpdate(id: string, quiet: boolean, current: () => boolean) {
    profileUpdates[id] = { state: 'updating', reason: null }
    lastRunError.value = null
    let result: Snapshot | undefined
    let thrownError: string | null = null
    try {
      result = await backend.refresh(id)
      if (!current()) return false
      apply(result)
      if (!current()) return false
    } catch (error) {
      if (!current()) return false
      console.error(error)
      thrownError = error instanceof Error ? error.message : String(error)
      lastRunError.value = thrownError
    }
    let reason: string | null = null
    if (!result) {
      reason = thrownError ?? tr('订阅没有更新')
    } else {
      const profile = result.profiles.find((item) => item.id === id)
      reason = profile ? profile.failure : tr('没有这份配置')
    }
    if (reason) {
      profileUpdates[id] = { state: 'failure', reason }
      if (!quiet) toast(reason, 'error')
      if (!quiet && backend.live) void backend.syncTray()
      return false
    }
    profileUpdates[id] = { state: 'success', reason: null }
    if (!quiet) toast(tr('订阅已更新'), 'success')
    if (!quiet && backend.live) void backend.syncTray()
    return true
  }

  /** Subscriptions in card order, used by update-all and the palette action. */
  function subscribeIds() {
    return snapshot.value.profiles.filter((item) => item.kind === 'subscription').map((item) => item.id)
  }

  const SUBSCRIPTION_POOL_CONCURRENCY = 3
  const SUBSCRIPTION_MAX_PER_HOST = 2

  /**
   * Bounded concurrent subscription refresh (`concurrency = 3`, max 2 per upstream host):
   * each card paints 更新中/成功/失败 independently, failures stay isolated with per-card
   * and batch retry, and progress survives page switches (R27, R29).
   */
  async function updateAll(targetIds?: readonly string[]) {
    if (busy.refreshAll) return
    const ids = targetIds ? [...new Set(targetIds)] : subscribeIds()
    if (!ids.length) return
    busy.refreshAll = true
    refreshProgress.value = { done: 0, total: ids.length, failed: 0 }
    const urlById = new Map(snapshot.value.profiles.map((item) => [item.id, item.source]))
    try {
      const { done, failed } = await runPool(
        ids,
        {
          concurrency: SUBSCRIPTION_POOL_CONCURRENCY,
          maxPerGroup: SUBSCRIPTION_MAX_PER_HOST,
          groupKey: (id) => hostOf(urlById.get(id) ?? ''),
          shouldStop: () => stopped,
          onProgress: (completed, failedCount) => {
            refreshProgress.value = {
              done: completed,
              total: ids.length,
              failed: failedCount,
            }
          },
        },
        (id) => trackUpdate(id, true),
      )
      if (backend.live) void backend.syncTray()
      if (ids.length) {
        toast(
          failed ? tr('更新完成：{0}/{1}，{2} 个订阅失败', { 0: done, 1: ids.length, 2: failed }) : tr('全部订阅已更新'),
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

  // Reconnecting gets a fresh automatic lookup when the option is on (R40).
  watch(
    () => snapshot.value.connected,
    (connected, was) => {
      if (connected && !was && autoExitIp.value) void queryExitIp()
    },
  )

  // App settings can arrive after the first snapshot, e.g. a released window
  // reopening on a live connection or a launch auto-connect that finished first
  // (R44). The connected watcher above already missed that transition while
  // `auto_exit_ip` was still unknown, so evaluate once the option becomes known.
  // The card exists only while the option is on, so disabling it clears the old
  // answer and any error; enabling again queries the current connection (R40).
  watch(autoExitIp, (enabled) => {
    if (!enabled) {
      exitIp.value = null
      exitIpStale.value = false
      exitIpError.value = null
      return
    }
    if (snapshot.value.connected && exitIp.value === null) void queryExitIp()
  })

  // A node, outbound-mode or profile switch may change the exit (R40). Leaving
  // the connection (empty catalog) does not mark the last answer.
  watch(exitIpSignature, (next, prev) => {
    if (!prev || next === prev) return
    if (!snapshot.value.connected || snapshot.value.node_catalog.length === 0) return
    if (exitIp.value) exitIpStale.value = true
    if (autoExitIp.value) void queryExitIp()
  })

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
      language.value = normalizeLanguage(shell.language)
      applyLocale(normalizeLocale(shell.locale))
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
    activeTest.value = null
    pendingTests.value = new Set()
    appUpdate.stop()
    releaseTrafficStats()
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

  function openSettings(tab: SettingsTab, focus?: string) {
    settingsTab.value = tab
    settingsFocus.value = focus ?? null
    go('settings')
  }

  /** Open the viewer on a tab, or on the one the user last read. */
  function openConfig(tab?: ConfigViewTab) {
    configView.value = tab ?? readConfigTab()
  }

  /** Jump to Resources and open a specific rule-set or proxy-provider sheet. */
  function openProvider(kind: 'proxy' | 'rule', name: string) {
    const trimmed = name.trim()
    if (!trimmed) return
    focusProvider.value = { kind, name: trimmed }
    go('resources')
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
    if (
      connectionReturn.value &&
      next !== 'connections' &&
      next !== connectionReturn.value.targetPage
    ) {
      connectionReturn.value = null
    }
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

  /** Switching takes effect at once; the backend answers with the effective locale (R42). */
  async function setLanguage(next: LanguagePreference) {
    const preference = normalizeLanguage(next)
    language.value = preference
    if (preference !== 'system') applyLocale(preference)
    try {
      const shell = await backend.setLanguage(preference)
      language.value = normalizeLanguage(shell.language)
      applyLocale(normalizeLocale(shell.locale))
    } catch (error) {
      console.error(error)
    }
  }

  /** Re-read the app-level settings a restore may have replaced (R38). */
  async function refreshShell() {
    try {
      const shell = await backend.shell()
      theme.value = shell.theme
      language.value = normalizeLanguage(shell.language)
      applyLocale(normalizeLocale(shell.locale))
      applyTheme(theme.value)
    } catch (error) {
      console.error(error)
    }
    try {
      app.value = await backend.appInfo()
    } catch (error) {
      console.error(error)
    }
  }

  /** Write a backup file; the returned path is shown to the user. */
  function exportBackup() {
    return run('backup', () => backend.exportBackup())
  }

  /** Restore the whole state from a file. The confirmation happens in the UI. */
  async function restoreBackup(text: string) {
    const result = await run('backup', () => backend.restoreBackup(text))
    if (!result) return undefined
    await refreshShell()
    toast(t('backup.restored'), 'success')
    return result
  }

  /** Restore a cloud backup; the upload/restore choice is always the user's (R45). */
  async function restoreRemoteBackup(name: string) {
    const result = await run('backup', () => backend.restoreRemoteBackup(name))
    if (!result) return undefined
    await refreshShell()
    toast(t('backup.restored'), 'success')
    return result
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
      toast(tr('请先选择要使用的配置'), 'info')
      return Promise.resolve(undefined)
    }
    return act('connect', async () => {
      try {
        if (!snapshot.value.active_id) {
          connectStage.value = tr('正在初始化内核和配置资源…')
          if (snapshot.value.profiles.length === 0) {
            const activated = await backend.useCustomProfile()
            if (!activated.custom_profile_active || activated.failure) return activated
          } else {
            const id = snapshot.value.profiles[0]!.id
            const enabled = await backend.enable(id)
            if (enabled.active_id !== id || enabled.failure) return enabled
          }
        }
        connectStage.value = isAndroid.value ? tr('正在建立 VPN，请留意系统授权提示…') : tr('正在建立代理连接…')
        return await backend.connect()
      } finally {
        connectStage.value = ''
      }
    }, tr('已连接'), {
      action: { kind: 'connect' },
      done: (next) => next.connected,
    })
  }

  function disconnect() {
    if (connecting.value || !snapshot.value.connected) return Promise.resolve(undefined)
    return act('connect', () => backend.disconnect(), tr('已断开'), {
      action: { kind: 'disconnect' },
      done: (next) => !next.connected,
    })
  }

  /** Billow stops and respawns the kernel; it shares the connect slot so other takeover changes wait (R35). */
  async function restartKernel() {
    if (connecting.value || !snapshot.value.connected) return undefined
    restarting.value = true
    try {
      return await act('connect', async () => {
        connectStage.value = tr('正在重启内核…')
        try {
          return await backend.restartKernel()
        } finally {
          connectStage.value = ''
        }
      }, tr('内核已重启'))
    } finally {
      restarting.value = false
    }
  }

  /** 回收内存: success only toasts; the memory reading refreshes on its own stream. */
  async function gcKernel() {
    lastRunError.value = null
    const ok = await run('gc', async () => {
      await backend.gcKernel()
      return true
    })
    if (ok) toast(tr('已回收'), 'success')
    return ok
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
    language,
    page,
    focusGroup,
    focusProvider,
    openProvider,
    connectionReturn,
    connectionSessionId,
    settingsTab,
    settingsFocus,
    overrideRequest,
    dnsQueryOpen,
    openSettings,
    loaded,
    busy,
    toasts,
    traffic,
    trafficSamples,
    closedConnections,
    clearClosedConnections,
    adding,
    configView,
    openConfig,
    /** Home failure banner state (R24, R29). */
    lastActionError,
    lastFailedAction,
    /** Per-node test results and `已测/总数` for the proxy page (R26). */
    testResults,
    testTimes,
    testProgress,
    activeTest,
    testing,
    pendingTests,
    /** Per-card subscription update state and update-all counters (R27). */
    profileUpdates,
    refreshProgress,
    /** Last thrown backend message, so inline errors can show the real reason (R29). */
    lastRunError,
    current,
    hasProfiles,
    customNodes,
    hasCustomNodes,
    enabledCustomNodes,
    customNodesWarnings,
    customProfileActive,
    landingPresets,
    isAndroid,
    isLinux,
    isMac,
    connecting,
    connectStage,
    restarting,
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
    setLanguage,
    refreshShell,
    exportBackup,
    restoreBackup,
    restoreRemoteBackup,
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
    confirmInstall: () => act(null, () => backend.confirmInstall(), tr('已添加订阅')),
    cancelInstall: () => act(null, () => backend.cancelInstall()),
    async enable(id: string) {
      const before = snapshot.value
      lastRunError.value = null
      const result = await run(`enable:${id}`, () => backend.enable(id))
      if (!result) return undefined
      const target = result.profiles.find((item) => item.id === id)
      const switched = result.active_id === id && Boolean(target?.current) && !target?.failure && !target?.override_error
      const changed = newFailure(before, result)
      const targetError = !switched
        ? (target?.failure || target?.override_error || changed || result.failure || tr('配置未能启用'))
        : null
      if (changed || targetError) toast(changed ?? targetError!, 'error')
      else toast(tr('已切换配置'), 'success')
      if (backend.live) void backend.syncTray()
      return result
    },
    update: (id: string) => trackUpdate(id),
    updateAll,
    refreshAll: (ids?: readonly string[]) => updateAll(ids),
    remove: (id: string) => act(`remove:${id}`, () => backend.remove(id)),
    rename: (id: string, name: string) => act(null, () => backend.rename(id, name)),
    setSource: (id: string, url: string) => act(null, () => backend.setSource(id, url)),
    setUserAgent: (id: string, userAgent: string) => act(null, () => backend.setUserAgent(id, userAgent)),
    setInterval: (id: string, hours: number) => act(null, () => backend.setInterval(id, hours)),
    setAgeKey: (id: string, key: string) => act(null, () => backend.setAgeKey(id, key)),
    saveContent: (id: string, content: string) => act('content', () => backend.saveContent(id, content), tr('配置已保存')),
    saveOverride: (id: string, text: string) => act('override', () => backend.saveOverride(id, text)),
    /** Re-apply the active profile so a saved 覆写 takes effect without a manual re-enable. */
    applyOverride: (id: string) => act('override', () => backend.enable(id)),

    /** Preview custom-node input outside the action queue so typing never blocks mutations. */
    previewCustomNodesImport: (raw: string) => backend.previewCustomNodesImport(raw),
    async importCustomNodes(
      raw: string,
      dialer?: DialerTarget | null,
    ): Promise<CustomNodesImportResult | undefined> {
      lastRunError.value = null
      const result = await run('customNodes:import', async () => {
        const res = await backend.importCustomNodes(raw, dialer)
        apply(res.snapshot)
        return res
      })
      if (!result) return undefined
      if (result.errors.length > 0) {
        toast(
          tr('已导入 {0} 个自建节点，{1} 条未识别', {
            0: result.imported.length,
            1: result.errors.length,
          }),
          'info',
        )
      } else {
        toast(tr('已导入 {0} 个自建节点', { 0: result.imported.length }), 'success')
      }
      if (backend.live) void backend.syncTray()
      return result
    },
    saveCustomNode: (input: SaveCustomNodeInput) =>
      act('customNodes:save', () => backend.saveCustomNode(input), tr('已保存自建节点')),
    deleteCustomNode: (id: string) =>
      act(`customNodes:delete:${id}`, () => backend.deleteCustomNode(id), tr('已删除自建节点')),
    setCustomNodeEnabled: (id: string, enabled: boolean) =>
      act(`customNodes:toggle:${id}`, () => backend.setCustomNodeEnabled(id, enabled)),
    setCustomNodesOverlay: (enabled: boolean) =>
      act(
        'customNodes:overlay',
        () => backend.setCustomNodesOverlay(enabled),
        enabled ? tr('已开启叠加到当前订阅') : tr('已关闭叠加到当前订阅'),
      ),
    saveLandingRules: (rulesEnabled: boolean, rules: LandingRule[]) =>
      act('customNodes:rules', () => backend.saveLandingRules(rulesEnabled, rules), tr('已保存落地分流规则')),
    useCustomProfile: () =>
      act('customNodes:useProfile', () => backend.useCustomProfile(), tr('已切换到纯自建节点')),

    selectNode: (group: string, node: string) => act(`select:${group}`, () => backend.selectNode(group, node)),
    /** 恢复自动: a fixed url-test / fallback group picks by its own strategy again (R28). */
    unfixGroup: (group: string) => act(`select:${group}`, () => backend.unfixGroup(group), tr('已恢复自动选择')),

    /** Per-group test stamps the local result time so headers can show "测速 …" (R26). */
    async testGroup(group: string) {
      if (testing.value) return undefined
      const names = snapshot.value.node_catalog.find((item) => item.name === group)?.nodes.map((item) => item.name) ?? []
      const result = await runNodeTest({ kind: 'group', group }, `test:${group}`, names, () => backend.testGroup(group))
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
      if (testing.value) return undefined
      const names = [...new Set(snapshot.value.node_catalog.flatMap((group) => group.nodes.map((node) => node.name)))]
      const result = await runNodeTest({ kind: 'all' }, 'testAll', names, () => backend.testAll())
      if (result && !result.nodes_error) {
        testResults.value = {}
        const summary = testSummary(result)
        if (summary) toast(summary, 'success')
      } else clearTestProgress()
      return result
    },
    async testNode(node: string) {
      if (testing.value) return undefined
      const result = await runNodeTest({ kind: 'node' }, `node:${node}`, [node], () => backend.testNode(node))
      if (result && !result.nodes_error) stampTestTimes([node])
      return result
    },

    closeConnection: (id: string | null) => act(null, () => backend.closeConnection(id)),
    /** `null` closes every connection; a list closes exactly those rows (R30). */
    async closeConnections(ids: string[] | null) {
      lastRunError.value = null
      const result = await run('close-connections', () => backend.closeConnections(ids))
      if (!result) return undefined
      // The backend sets `notice` for this call alone, so a repeated failure count still toasts.
      if (result.notice) toast(result.notice, 'error')
      else toast(ids ? tr('已关闭 {0} 条连接', { 0: ids.length }) : tr('已关闭全部连接'), 'success')
      return result
    },
    /** Runs outside the action queue: a slow resolver must not hold up other controls. */
    dnsQuery: (name: string, qtype: DnsQueryType) => backend.dnsQuery(name, qtype),
    /** Exit IP lookup, its stale mark and last failure (R40). */
    exitIp,
    exitIpStale,
    exitIpBusy,
    exitIpError,
    autoExitIp,
    queryExitIp,
    setAutoExitIp,
    /** Traffic stats dialog, recording switch and clear-all (R43). */
    trafficStatsOpen,
    trafficStats,
    trafficStatsBusy,
    trafficStatsError,
    trafficStatsRange,
    loadTrafficStats,
    releaseTrafficStats,
    openTrafficStats,
    setTrafficRecording,
    clearTrafficHistory,
    clearLogs: () => act(null, () => backend.clearLogs()),
    flushCache: (which: 'fakeip' | 'dns') =>
      act(`flush:${which}`, () => backend.flushCache(which), which === 'fakeip' ? tr('FakeIP 缓存已清除') : tr('DNS 缓存已清除')),
    restartKernel,
    gcKernel,
    /**
     * `quiet` skips the success toast for rows that apply in place and show their
     * own state; `message` replaces it, e.g. for a reset.
     */
    saveSettings: (settings: KernelSettings, options?: { quiet?: boolean; message?: string }) =>
      act('settings', () => backend.saveSettings(settings), options?.message ?? (options?.quiet ? undefined : tr('内核设置已保存'))),
    async openUwpTool() {
      const ok = await run('uwp', async () => {
        await backend.openUwpTool()
        return true
      })
      if (ok) toast(tr('已打开 UWP 回环豁免工具'), 'success')
    },

    async setChannel(channel: KernelChannel) {
      busy.kernel = true
      try {
        kernel.value = await backend.setChannel(channel)
        if (kernel.value.failure) toast(kernel.value.failure, 'error')
        else toast(tr('已切换到{0}内核', { 0: channel === 'stable' ? tr('稳定版') : tr('预览版') }), 'success')
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
        else toast(tr('内核已是最新'), 'success')
      } catch (error) {
        toast(String(error), 'error')
      } finally {
        delete busy.kernel
      }
    },
    async setAutostart(enabled: boolean) {
      app.value = await backend.setAutostart(enabled)
    },
    async setBehavior(closeToTray: boolean, silentStart: boolean, releaseUiOnClose: boolean) {
      app.value = await backend.setAppBehavior(closeToTray, silentStart, releaseUiOnClose)
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
