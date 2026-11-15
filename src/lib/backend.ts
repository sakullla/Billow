import {
  normalizeKernel,
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

  closeConnection(id: string | null): Promise<Snapshot>
  rules(): Promise<RulesResult>
  providers(): Promise<ProvidersResult>
  providerAction(kind: 'proxy' | 'rule', name: string, action: 'update' | 'healthcheck'): Promise<void>
  upgradeGeo(): Promise<void>
  flushCache(which: 'fakeip' | 'dns'): Promise<Snapshot>
  clearLogs(): Promise<Snapshot>
  clearNotice(): Promise<Snapshot>
  saveSettings(settings: KernelSettings): Promise<Snapshot>
  syncTray(): Promise<void>

  onChange(handler: (snapshot: Snapshot) => void): Promise<() => void>
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

    closeConnection: (id) => snap('close_connection', { id }),
    rules: async () => {
      const raw = await call<RulesResult>('kernel_rules')
      return { rules: Array.isArray(raw.rules) ? raw.rules : [], error: raw.error ?? null }
    },
    providers: async () => {
      const raw = await call<ProvidersResult>('kernel_providers')
      return { providers: Array.isArray(raw.providers) ? raw.providers : [], error: raw.error ?? null }
    },
    providerAction: (kind, name, action) => call<void>('provider_action', { kind, name, action }),
    upgradeGeo: () => call<void>('upgrade_geo'),
    flushCache: (which) => snap('flush_cache', { which }),
    clearLogs: () => snap('clear_logs'),
    clearNotice: () => snap('clear_notice'),
    saveSettings: (settings) => snap('save_kernel_settings', { settings }),
    async syncTray() {
      await call('sync_tray').catch(() => undefined)
    },

    async onChange(handler) {
      const { listen } = await import('@tauri-apps/api/event')
      return listen<unknown>('profile-changed', (event) => handler(normalizeSnapshot(event.payload)))
    },
  }
}

export function createBackend(): Backend {
  return inTauri() ? createTauriBackend() : createDemoBackend()
}
