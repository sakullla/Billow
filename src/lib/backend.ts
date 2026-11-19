import {
  normalizeConfigOverview,
  normalizeDnsQueryResult,
  normalizeKernel,
  normalizeRuleRow,
  normalizeSnapshot,
  HOTKEY_ACTIONS,
  type AppInfo,
  type ConfigOverview,
  type DnsQueryResult,
  type DnsQueryType,
  type HotkeyAction,
  type HotkeyBinding,
  type HotkeySettings,
  type OverridePreview,
  type KernelChannel,
  type KernelSettings,
  type KernelStatus,
  type LanguagePreference,
  type Mode,
  type ProvidersResult,
  type AppMode,
  type ProviderDetail,
  type GeoFile,
  type RemoteBackup,
  type RulesResult,
  type ShellState,
  type Snapshot,
  type ThemePreference,
  type UwpApp,
  type WebdavSettings,
  type WebdavTestResult,
} from './types'
import { normalizeLanguage, normalizeLocale } from './i18n'
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
  /** Store the language preference and return the effective locale (R42). */
  setLanguage(language: LanguagePreference): Promise<ShellState>
  setEntry(entry: string): Promise<void>
  appInfo(): Promise<AppInfo>
  setAutostart(enabled: boolean): Promise<AppInfo>
  setAppBehavior(closeToTray: boolean, silentStart: boolean): Promise<AppInfo>
  /** Desktop global shortcuts and whether this platform supports them (R39). */
  hotkeySettings(): Promise<HotkeySettings>
  /** Bind one action; an empty combo clears it. A rejection names the conflict. */
  setHotkey(action: HotkeyAction, combo: string): Promise<HotkeySettings>

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
  setUserAgent(id: string, userAgent: string): Promise<Snapshot>
  setInterval(id: string, hours: number): Promise<Snapshot>
  /** Replace the age identities of a subscription; an empty text clears them. */
  setAgeKey(id: string, key: string): Promise<Snapshot>
  content(id: string): Promise<string>
  saveContent(id: string, content: string): Promise<Snapshot>
  /** The YAML the kernel runs for the active profile (or would run on the next connect). */
  effectiveConfig(): Promise<string>
  /** Structured view of the same config: options per layer, list counts, masked credentials. */
  configOverview(): Promise<ConfigOverview>
  /** This machine's private LAN address, or null when it cannot be told reliably. */
  lanAddress(): Promise<string | null>
  saveOverride(id: string, text: string): Promise<Snapshot>
  /** Apply an unsaved 覆写 to the profile: merged YAML plus script `console` output. Rejects with the reason. */
  previewOverride(id: string, text: string): Promise<OverridePreview>

  connect(): Promise<Snapshot>
  disconnect(): Promise<Snapshot>
  setSystemProxy(enabled: boolean): Promise<Snapshot>
  setTun(enabled: boolean): Promise<Snapshot>
  setMode(mode: Mode): Promise<Snapshot>
  exclude(pkg: string): Promise<Snapshot>
  include(pkg: string): Promise<Snapshot>
  /** Replace one access-control mode's app list and make that mode current. */
  setAppRules(mode: AppMode, packages: string[]): Promise<Snapshot>

  selectNode(group: string, node: string): Promise<Snapshot>
  /** Release a fixed `url-test` / `fallback` group back to its own strategy (R28). */
  unfixGroup(group: string): Promise<Snapshot>
  testGroup(group: string): Promise<Snapshot>
  testAll(): Promise<Snapshot>
  testNode(node: string): Promise<Snapshot>
  /** Subscribes to per-node progress while `testAll` runs. Returns an unsubscribe callback. */
  onNodeTest(handler: (event: NodeTestEvent) => void): Promise<() => void>

  closeConnection(id: string | null): Promise<Snapshot>
  /** Close every active connection (`null`) or exactly these ids; failures land in `notice` (R30). */
  closeConnections(ids: string[] | null): Promise<Snapshot>
  /** Resolve `name` through the kernel's live DNS config (R31); failures come back in `error`. */
  dnsQuery(name: string, qtype: DnsQueryType): Promise<DnsQueryResult>
  rules(): Promise<RulesSnapshot>
  setRuleDisabled(key: string, disabled: boolean): Promise<RulesSnapshot>
  providers(): Promise<ProvidersResult>
  providerAction(kind: 'proxy' | 'rule', name: string, action: 'update' | 'healthcheck'): Promise<void>
  upgradeGeo(key?: string): Promise<GeoFile[]>
  /** Opens the Windows UWP loopback exemption tool. */
  openUwpTool(): Promise<void>
  /** Lists installed Windows UWP / AppContainer apps with loopback exemption state. */
  listUwpApps(): Promise<UwpApp[]>
  /** Saves the desired exempted Windows UWP PackageFamilyNames. */
  saveUwpExemptions(familyNames: string[]): Promise<UwpApp[]>
  /** Nodes of a proxy provider or rules of a rule provider. */
  /** A query filters a rule set's full content, beyond the rows a plain preview carries. */
  providerDetail(kind: 'proxy' | 'rule', name: string, query?: string): Promise<ProviderDetail>
  /** GEO database files the kernel loads, with size and modification time. */
  geoFiles(): Promise<GeoFile[]>
  flushCache(which: 'fakeip' | 'dns'): Promise<Snapshot>
  /** Stop and respawn the kernel with the running config; takeover and mode come back (R35). */
  restartKernel(): Promise<Snapshot>
  /** `PUT /debug/gc`; the kernel serves it only at log level debug (R35). */
  gcKernel(): Promise<void>
  clearLogs(): Promise<Snapshot>
  exportLogs(content: string): Promise<string>
  clearNotice(): Promise<Snapshot>
  saveSettings(settings: KernelSettings): Promise<Snapshot>
  syncTray(): Promise<void>

  /** Write a versioned backup file and return its full path (R38). */
  exportBackup(): Promise<string>
  /** Replace the whole state from backup text; rejects with the reason (R38). */
  restoreBackup(text: string): Promise<Snapshot>
  webdavSettings(): Promise<WebdavSettings>
  setWebdav(url: string, username: string, password: string): Promise<WebdavSettings>
  /** Test the WebDAV folder; only a success marks it usable. */
  testWebdav(): Promise<WebdavTestResult>
  /** Upload the current state by hand; returns the remote file name. */
  uploadBackup(): Promise<string>
  listRemoteBackups(): Promise<RemoteBackup[]>
  restoreRemoteBackup(name: string): Promise<Snapshot>

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

export function normalizeWebdav(raw: unknown): WebdavSettings {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  return {
    url: typeof value.url === 'string' ? value.url : '',
    username: typeof value.username === 'string' ? value.username : '',
    password: typeof value.password === 'string' ? value.password : '',
    available: Boolean(value.available),
  }
}

export function normalizeRemoteBackup(raw: unknown): RemoteBackup {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  return {
    name: typeof value.name === 'string' ? value.name : '',
    device: typeof value.device === 'string' ? value.device : '',
    modified: typeof value.modified === 'string' ? value.modified : null,
    size: typeof value.size === 'number' && Number.isFinite(value.size) ? value.size : null,
  }
}

function isHotkeyAction(value: unknown): value is HotkeyAction {
  return typeof value === 'string' && (HOTKEY_ACTIONS as readonly string[]).includes(value)
}

export function normalizeHotkeys(raw: unknown): HotkeySettings {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const rawBindings = Array.isArray(value.bindings) ? value.bindings : []
  const bindings: HotkeyBinding[] = []
  for (const entry of rawBindings) {
    const item = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : {}
    if (!isHotkeyAction(item.action) || typeof item.combo !== 'string' || !item.combo) continue
    bindings.push({
      action: item.action,
      combo: item.combo,
      active: Boolean(item.active),
      error: typeof item.error === 'string' ? item.error : null,
    })
  }
  return {
    available: Boolean(value.available),
    reason: typeof value.reason === 'string' ? value.reason : null,
    platform: typeof value.platform === 'string' ? value.platform : '',
    bindings,
  }
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
  const shellInfo = (raw: {
    theme?: unknown
    last_entry?: unknown
    language?: unknown
    locale?: unknown
  }): ShellState => ({
    theme: raw.theme === 'light' || raw.theme === 'dark' ? raw.theme : 'system',
    last_entry: typeof raw.last_entry === 'string' ? raw.last_entry : 'home',
    language: normalizeLanguage(raw.language),
    locale: normalizeLocale(raw.locale),
  })

  return {
    live: true,
    async shell() {
      return shellInfo(await call<Record<string, unknown>>('shell_state'))
    },
    async setTheme(theme) {
      await call('set_theme', { theme })
    },
    async setLanguage(language) {
      return shellInfo(await call<Record<string, unknown>>('set_language', { language }))
    },
    async setEntry(entry) {
      await call('set_last_entry', { entry })
    },
    appInfo: () => call<AppInfo>('app_info'),
    setAutostart: (enabled) => call<AppInfo>('set_autostart', { enabled }),
    setAppBehavior: (closeToTray, silentStart) =>
      call<AppInfo>('set_app_behavior', { closeToTray, silentStart }),
    hotkeySettings: async () => normalizeHotkeys(await call<unknown>('hotkey_settings')),
    setHotkey: async (action, combo) =>
      normalizeHotkeys(await call<unknown>('set_hotkey', { action, combo })),

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
    setUserAgent: (id, userAgent) => snap('set_profile_user_agent', { id, userAgent }),
    setInterval: (id, hours) => snap('set_profile_interval', { id, hours }),
    setAgeKey: (id, key) => snap('set_profile_age_key', { id, key }),
    content: async (id) => (await call<string | null>('profile_content', { id })) ?? '',
    saveContent: (id, content) => snap('save_profile_content', { id, content }),
    effectiveConfig: () => call<string>('effective_config'),
    configOverview: async () => normalizeConfigOverview(await call<unknown>('config_overview')),
    lanAddress: async () => (await call<string | null>('lan_address')) ?? null,
    saveOverride: (id, text) => snap('save_profile_override', { id, text }),
    previewOverride: (id, text) => call<OverridePreview>('preview_profile_override', { id, text }),

    connect: () => snap('connect_session'),
    disconnect: () => snap('disconnect_session'),
    setSystemProxy: (enabled) => snap('set_system_proxy', { enabled }),
    setTun: (enabled) => snap('set_tun_enabled', { enabled }),
    setMode: (mode) => snap('set_outbound_mode', { mode }),
    exclude: (packageName) => snap('exclude_package', { packageName }),
    include: (packageName) => snap('include_package', { packageName }),
    setAppRules: (mode, packages) => snap('set_app_rules', { mode, packages }),

    selectNode: (group, node) => snap('select_profile_node', { group, node }),
    unfixGroup: (group) => snap('unfix_profile_group', { group }),
    testGroup: (group) => snap('test_profile_group', { group }),
    testAll: () => snap('test_all_nodes'),
    testNode: (node) => snap('test_node', { node }),
    async onNodeTest(handler) {
      const { listen } = await import('@tauri-apps/api/event')
      return listen<unknown>('node-test', (event) => handler(normalizeNodeTest(event.payload)))
    },

    closeConnection: (id) => snap('close_connection', { id }),
    closeConnections: (ids) => snap('close_connections', { ids }),
    dnsQuery: async (name, qtype) => normalizeDnsQueryResult(await call<unknown>('dns_query', { name, qtype })),
    rules: () => rules('kernel_rules'),
    setRuleDisabled: (key, disabled) =>
      rules('set_rule_disabled', { command: { key, disabled } }),
    providers: async () => {
      const raw = await call<ProvidersResult>('kernel_providers')
      return { providers: Array.isArray(raw.providers) ? raw.providers : [], error: raw.error ?? null }
    },
    providerAction: (kind, name, action) => call<void>('provider_action', { kind, name, action }),
    upgradeGeo: (key) => call<GeoFile[]>('upgrade_geo', key ? { key } : {}),
    openUwpTool: () => call<void>('open_uwp_tool'),
    listUwpApps: () => call<UwpApp[]>('list_uwp_apps'),
    saveUwpExemptions: (familyNames) => call<UwpApp[]>('save_uwp_exemptions', { familyNames }),
    providerDetail: (kind, name, query) => call<ProviderDetail>('provider_detail', { kind, name, query: query ?? null }),
    geoFiles: () => call<GeoFile[]>('geo_files'),
    flushCache: (which) => snap('flush_cache', { which }),
    restartKernel: () => snap('restart_kernel'),
    gcKernel: () => call<void>('kernel_gc'),
    clearLogs: () => snap('clear_logs'),
    exportLogs: (content) => call<string>('export_logs', { content }),
    clearNotice: () => snap('clear_notice'),
    saveSettings: (settings) => snap('save_kernel_settings', { settings }),
    async syncTray() {
      await call('sync_tray').catch(() => undefined)
    },

    exportBackup: () => call<string>('export_backup'),
    restoreBackup: (text) => snap('restore_backup_text', { text }),
    webdavSettings: async () => normalizeWebdav(await call<unknown>('webdav_settings')),
    setWebdav: async (url, username, password) =>
      normalizeWebdav(await call<unknown>('set_webdav_settings', { url, username, password })),
    testWebdav: async () => {
      const raw = await call<{ available?: unknown; error?: unknown }>('test_webdav')
      return {
        available: Boolean(raw?.available),
        error: typeof raw?.error === 'string' ? raw.error : null,
      }
    },
    uploadBackup: () => call<string>('upload_backup'),
    listRemoteBackups: async () => {
      const raw = await call<unknown>('list_remote_backups')
      return Array.isArray(raw) ? raw.map(normalizeRemoteBackup) : []
    },
    restoreRemoteBackup: (name) => snap('restore_remote_backup', { name }),

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

/** Browser previews can pick the demo shape: `?demo=android|empty|many|long`, comma-separated. */
function demoOptionsFromUrl() {
  if (typeof window === 'undefined') return {}
  const flags = new URLSearchParams(window.location.search).getAll('demo').join(',').split(',')
  return {
    platform: flags.includes('android') ? ('android' as const) : ('desktop' as const),
    profiles: !flags.includes('empty'),
    manyProviders: flags.includes('many'),
    longNames: flags.includes('long'),
    big: flags.includes('big'),
  }
}

export function createBackend(): Backend {
  return inTauri() ? createTauriBackend() : createDemoBackend(demoOptionsFromUrl())
}
