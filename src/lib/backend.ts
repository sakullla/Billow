import {
  normalizeKernel,
  normalizeRuleRow,
  normalizeSnapshot,
  type AppInfo,
  type KernelChannel,
  type KernelSettings,
  type KernelStatus,
  type Mode,
  type ProvidersResult,
  type RulesResult,
  type ShellState,
  type Snapshot,
  type ThemePreference,
} from './types'
import { createDemoBackend } from './demo'

/** Rule rows plus the runtime-disabled keys; the keys are never persisted. */
export interface RulesSnapshot extends RulesResult {
  disabled: string[]
}

/** One finished node from the `node-test` progress event. */
export interface NodeTestEvent {
  node: string
  delay: number | null
  failed: boolean
  tested: number
  total: number
}

/** Everything the UI can ask of the Rust side. Each mutating call returns the fresh snapshot. */
export interface Backend {
  readonly live: boolean
  shell(): Promise<ShellState>
  setTheme(theme: ThemePreference): Promise<void>
  setEntry(entry: string): Promise<void>
  appInfo(): Promise<AppInfo>
  setAutostart(enabled: boolean): Promise<AppInfo>
  setAppBehavior(closeToTray: boolean, silentStart: boolean): Promise<AppInfo>

  kernel(): Promise<KernelStatus>
  setChannel(channel: KernelChannel): Promise<KernelStatus>
  refreshKernel(): Promise<KernelStatus>

  state(): Promise<Snapshot>
  addSubscription(url: string): Promise<Snapshot>
  addLocal(name: string, content: string): Promise<Snapshot>
  confirmInstall(): Promise<Snapshot>
  cancelInstall(): Promise<Snapshot>
  enable(id: string): Promise<Snapshot>
  update(id: string): Promise<Snapshot>
  refresh(id: string): Promise<Snapshot>
  refreshAll(): Promise<Snapshot>
  remove(id: string): Promise<Snapshot>
  rename(id: string, name: string): Promise<Snapshot>
  setSource(id: string, url: string): Promise<Snapshot>
  setInterval(id: string, hours: number): Promise<Snapshot>
  content(id: string): Promise<string>
  saveContent(id: string, content: string): Promise<Snapshot>
  /** The YAML the kernel runs for the active profile (or would run on the next connect). */
  effectiveConfig(): Promise<string>
  saveOverride(id: string, text: string): Promise<Snapshot>

  connect(): Promise<Snapshot>
  disconnect(): Promise<Snapshot>
  setSystemProxy(enabled: boolean): Promise<Snapshot>
  setTun(enabled: boolean): Promise<Snapshot>
  setMode(mode: Mode): Promise<Snapshot>
  exclude(pkg: string): Promise<Snapshot>
  include(pkg: string): Promise<Snapshot>

  selectNode(group: string, node: string): Promise<Snapshot>
  testGroup(group: string): Promise<Snapshot>
  testAll(): Promise<Snapshot>
  testNode(node: string): Promise<Snapshot>
  /** Subscribes to per-node progress while `testAll` runs. Returns an unsubscribe callback. */
  onNodeTest(handler: (event: NodeTestEvent) => void): Promise<() => void>

  closeConnection(id: string | null): Promise<Snapshot>
  rules(): Promise<RulesSnapshot>
  setRuleDisabled(key: string, disabled: boolean): Promise<RulesSnapshot>
  providers(): Promise<ProvidersResult>
  providerAction(kind: 'proxy' | 'rule', name: string, action: 'update' | 'healthcheck'): Promise<void>
  upgradeGeo(): Promise<void>
  flushCache(which: 'fakeip' | 'dns'): Promise<Snapshot>
  clearLogs(): Promise<Snapshot>
  exportLogs(content: string): Promise<string>
  clearNotice(): Promise<Snapshot>
  saveSettings(settings: KernelSettings): Promise<Snapshot>
  syncTray(): Promise<void>

  onChange(handler: (snapshot: Snapshot) => void): Promise<() => void>
  /** Desktop tray asks the window to open a page or the add-profile dialog. */
  onTrayNavigate?(handler: (target: string) => void): Promise<() => void>
}

export function normalizeNodeTest(raw: unknown): NodeTestEvent {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const delay =
    typeof value.delay === 'number' && Number.isFinite(value.delay) ? value.delay : null
  return {
    node: typeof value.node === 'string' ? value.node : '',
    delay,
    failed: Boolean(value.failed),
    tested: typeof value.tested === 'number' ? value.tested : 0,
    total: typeof value.total === 'number' ? value.total : 0,
  }
}

export function inTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

function createTauriBackend(): Backend {
  const call = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    const { invoke } = await import('@tauri-apps/api/core')
    return invoke<T>(command, args)
  }
  const snap = async (command: string, args?: Record<string, unknown>) =>
    normalizeSnapshot(await call<unknown>(command, args))
  const kern = async (command: string, args?: Record<string, unknown>) =>
    normalizeKernel(await call<unknown>(command, args))
  const rules = async (command: string, args?: Record<string, unknown>): Promise<RulesSnapshot> => {
    const raw = await call<RulesResult & { disabled?: unknown }>(command, args)
    return {
      rules: Array.isArray(raw.rules) ? raw.rules.map(normalizeRuleRow) : [],
      error: raw.error ?? null,
      disabled: Array.isArray(raw.disabled)
        ? raw.disabled.filter((key): key is string => typeof key === 'string')
        : [],
    }
  }

  return {
    live: true,
    async shell() {
      const raw = await call<{ theme: string; last_entry: string }>('shell_state')
      const theme = raw.theme === 'light' || raw.theme === 'dark' ? raw.theme : 'system'
      return { theme, last_entry: raw.last_entry }
    },
    async setTheme(theme) {
      await call('set_theme', { theme })
    },
    async setEntry(entry) {
      await call('set_last_entry', { entry })
    },
    appInfo: () => call<AppInfo>('app_info'),
    setAutostart: (enabled) => call<AppInfo>('set_autostart', { enabled }),
    setAppBehavior: (closeToTray, silentStart) =>
      call<AppInfo>('set_app_behavior', { closeToTray, silentStart }),

    kernel: () => kern('kernel_state'),
    setChannel: (channel) => kern('set_kernel_channel', { channel }),
    refreshKernel: () => kern('refresh_kernel'),

    state: () => snap('profile_state'),
    addSubscription: (url) => snap('add_subscription_profile', { url }),
    addLocal: (name, content) => snap('add_local_profile', { name, content }),
    confirmInstall: () => snap('confirm_install_link'),
    cancelInstall: () => snap('cancel_install_link'),
    enable: (id) => snap('enable_profile', { id }),
    update: (id) => snap('update_profile', { id }),
    refresh: (id) => snap('refresh_profile', { id }),
    refreshAll: () => snap('refresh_all_profiles'),
    remove: (id) => snap('delete_profile', { id }),
    rename: (id, name) => snap('rename_profile', { id, name }),
    setSource: (id, url) => snap('set_profile_source', { id, url }),
    setInterval: (id, hours) => snap('set_profile_interval', { id, hours }),
    content: async (id) => (await call<string | null>('profile_content', { id })) ?? '',
    saveContent: (id, content) => snap('save_profile_content', { id, content }),
    effectiveConfig: () => call<string>('effective_config'),
    saveOverride: (id, text) => snap('save_profile_override', { id, text }),

    connect: () => snap('connect_session'),
    disconnect: () => snap('disconnect_session'),
    setSystemProxy: (enabled) => snap('set_system_proxy', { enabled }),
    setTun: (enabled) => snap('set_tun_enabled', { enabled }),
    setMode: (mode) => snap('set_outbound_mode', { mode }),
    exclude: (packageName) => snap('exclude_package', { packageName }),
    include: (packageName) => snap('include_package', { packageName }),

    selectNode: (group, node) => snap('select_profile_node', { group, node }),
    testGroup: (group) => snap('test_profile_group', { group }),
    testAll: () => snap('test_all_nodes'),
    testNode: (node) => snap('test_node', { node }),
    async onNodeTest(handler) {
      const { listen } = await import('@tauri-apps/api/event')
      return listen<unknown>('node-test', (event) => handler(normalizeNodeTest(event.payload)))
    },

    closeConnection: (id) => snap('close_connection', { id }),
    rules: () => rules('kernel_rules'),
    setRuleDisabled: (key, disabled) =>
      rules('set_rule_disabled', { command: { key, disabled } }),
    providers: async () => {
      const raw = await call<ProvidersResult>('kernel_providers')
      return { providers: Array.isArray(raw.providers) ? raw.providers : [], error: raw.error ?? null }
    },
    providerAction: (kind, name, action) => call<void>('provider_action', { kind, name, action }),
    upgradeGeo: () => call<void>('upgrade_geo'),
    flushCache: (which) => snap('flush_cache', { which }),
    clearLogs: () => snap('clear_logs'),
    exportLogs: (content) => call<string>('export_logs', { content }),
    clearNotice: () => snap('clear_notice'),
    saveSettings: (settings) => snap('save_kernel_settings', { settings }),
    async syncTray() {
      await call('sync_tray').catch(() => undefined)
    },

    async onChange(handler) {
      const { listen } = await import('@tauri-apps/api/event')
      return listen<unknown>('profile-changed', (event) => handler(normalizeSnapshot(event.payload)))
    },

    async onTrayNavigate(handler) {
      const { listen } = await import('@tauri-apps/api/event')
      return listen<unknown>('tray-navigate', (event) => {
        if (typeof event.payload === 'string') handler(event.payload)
      })
    },
  }
}

/** Browser previews can pick the demo shape: `?demo=android` and/or `?demo=empty`. */
function demoOptionsFromUrl() {
  if (typeof window === 'undefined') return {}
  const flags = new URLSearchParams(window.location.search).getAll('demo').join(',').split(',')
  return {
    platform: flags.includes('android') ? ('android' as const) : ('desktop' as const),
    profiles: !flags.includes('empty'),
  }
}

export function createBackend(): Backend {
  return inTauri() ? createTauriBackend() : createDemoBackend(demoOptionsFromUrl())
}
