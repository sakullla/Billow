import {
  NODES_EMPTY,
  NODES_KERNEL_DOWN,
  NODES_MISSING,
  NODES_NEED_PROFILE,
  NODES_NO_MATCH,
  NODES_NOT_MANUAL,
} from './copy'
import {
  emptyProfileSnapshot,
  normalizeLogFilter,
  normalizeMode,
  normalizeProfileSnapshot,
  type ConnectionRow,
  type LogLine,
  type NodeGroup,
  type NodeItem,
  type ProfileItem,
  type ProfileSnapshot,
} from './profile'

export interface ProfilePort {
  load(): Promise<ProfileSnapshot>
  addSubscription(url: string): Promise<ProfileSnapshot>
  addLocal(name: string, content: string): Promise<ProfileSnapshot>
  stageInstallLink(link: string): Promise<ProfileSnapshot>
  confirmInstall(): Promise<ProfileSnapshot>
  cancelInstall(): Promise<ProfileSnapshot>
  enable(id: string): Promise<ProfileSnapshot>
  update(id: string): Promise<ProfileSnapshot>
  saveOverride(id: string, text: string): Promise<ProfileSnapshot>
  connect(): Promise<ProfileSnapshot>
  disconnect(): Promise<ProfileSnapshot>
  setSystemProxy(enabled: boolean): Promise<ProfileSnapshot>
  setTun(enabled: boolean): Promise<ProfileSnapshot>
  excludePackage(packageName: string): Promise<ProfileSnapshot>
  includePackage(packageName: string): Promise<ProfileSnapshot>
  selectNode(group: string, node: string): Promise<ProfileSnapshot>
  testGroup(group: string): Promise<ProfileSnapshot>
  setNodeQuery(query: string): Promise<ProfileSnapshot>
  setNodeSort(group: string, sort: string): Promise<ProfileSnapshot>
  setConnectionQuery(query: string): Promise<ProfileSnapshot>
  setLogFilter(level: string): Promise<ProfileSnapshot>
  setMode(mode: string): Promise<ProfileSnapshot>
  subscribe?(handler: (snapshot: ProfileSnapshot) => void): () => void
}

const LOCAL_KEY = 'billow-profiles'

function readPort(raw: Partial<ProfileItem> | string): number | null {
  const text = typeof raw === 'string' ? raw : ''
  const matched = text.match(/mixed-port:\s*(\d+)/)
  return matched ? Number(matched[1]) : null
}

function clone(state: ProfileSnapshot): ProfileSnapshot {
  return normalizeProfileSnapshot(JSON.parse(JSON.stringify(state)) as ProfileSnapshot)
}

function copyGroups(groups: NodeGroup[]): NodeGroup[] {
  return groups.map((group) => ({ ...group, nodes: group.nodes.map((node) => ({ ...node })) }))
}

function delayKey(node: NodeItem, index: number): [number, number, number] {
  if (node.delay_ms != null && !node.failed) return [0, node.delay_ms, index]
  if (node.failed) return [2, 0, index]
  return [1, 0, index]
}

function sortNodes(group: NodeGroup): NodeItem[] {
  const items = group.nodes.map((node, index) => ({ node, index }))
  if (group.sort === 'name') {
    items.sort((left, right) => left.node.name.toLowerCase().localeCompare(right.node.name.toLowerCase()) || left.index - right.index)
  } else if (group.sort === 'delay') {
    items.sort((left, right) => {
      const a = delayKey(left.node, left.index)
      const b = delayKey(right.node, right.index)
      return a[0] - b[0] || a[1] - b[1] || a[2] - b[2]
    })
  }
  return items.map((item) => ({ ...item.node }))
}

function projectNodes(catalog: NodeGroup[], query: string, profileCount: number): { groups: NodeGroup[]; notice: string | null } {
  const sorted = catalog.map((group) => ({ ...group, nodes: sortNodes(group) }))
  const needle = query.trim().toLowerCase()
  if (!needle) {
    if (sorted.length === 0) return { groups: [], notice: profileCount > 0 ? NODES_EMPTY : NODES_NEED_PROFILE }
    return { groups: sorted, notice: null }
  }
  const groups = sorted
    .map((group) => ({
      ...group,
      nodes: group.nodes.filter((node) => node.name.toLowerCase().includes(needle)),
    }))
    .filter((group) => group.nodes.length > 0)
  if (groups.length === 0) return { groups: [], notice: NODES_NO_MATCH }
  return { groups, notice: null }
}

/// Browser fallback and component tests. Enable, override, and node decisions are made in Rust.
export function createMemoryProfilePort(initial?: Partial<ProfileSnapshot>): ProfilePort {
  const state = normalizeProfileSnapshot({ ...emptyProfileSnapshot(), ...initial })
  let catalog = copyGroups(state.node_catalog)
  let query = state.node_query
  let nodesError = state.nodes_error
  let kernelRunning = state.kernel_running
  let allConnections: ConnectionRow[] = state.connections.map((row) => ({ ...row }))
  let connectionQuery = state.connection_query
  let allLogs: LogLine[] = state.logs.map((line) => ({ ...line }))
  let logFilter = state.log_filter
  function visibleConnections(): ConnectionRow[] {
    if (!state.connected) return []
    const needle = connectionQuery.trim().toLowerCase()
    const rows = needle
      ? allConnections.filter((row) => row.host.toLowerCase().includes(needle))
      : allConnections
    return rows.map((row) => ({ ...row }))
  }
  function visibleLogs(): LogLine[] {
    const rows = logFilter === 'all' ? allLogs : allLogs.filter((line) => line.level === logFilter)
    return rows.map((line) => ({ ...line }))
  }
  function pushLog(level: LogLine['level'], message: string) {
    const text = message.trim()
    if (!text) return
    allLogs.push({ level, message: text })
  }
  function finish(): ProfileSnapshot {
    const view = projectNodes(catalog, query, state.profiles.length)
    state.node_catalog = copyGroups(catalog)
    state.node_groups = view.groups
    state.node_query = query
    state.nodes_notice = view.notice
    state.nodes_error = nodesError
    state.kernel_running = kernelRunning
    state.connections = visibleConnections()
    state.connection_query = connectionQuery
    state.logs = visibleLogs()
    state.log_filter = logFilter
    return clone(state)
  }
  function find(id: string): ProfileItem | undefined {
    return state.profiles.find((profile) => profile.id === id)
  }
  function activate(id: string): ProfileSnapshot {
    const profile = find(id)
    if (!profile) {
      state.failure = '没有这份配置'
      return finish()
    }
    const invalidOverride = profile.override_text.includes(':::') || profile.override_text.trim() === '['
    if (invalidOverride) {
      profile.override_error = '覆写无法应用'
      return finish()
    }
    if (profile.kind === 'subscription' && profile.source.includes('://') && !profile.override_text.includes('mixed-port:')) {
      const unreachable = profile.source.includes('fail') || profile.source.includes('down.')
      if (unreachable || profile.source.endsWith('/missing')) {
        profile.failure = '订阅没有取回'
        state.failure = '订阅没有取回'
        state.system_proxy = false
        state.tun = false
        state.vpn = false
        return finish()
      }
    }
    for (const item of state.profiles) item.current = item.id === id
    state.active_id = id
    profile.failure = null
    profile.override_error = null
    state.failure = null
    const port = readPort(profile.override_text) ?? readPort(profile.source)
    if (port != null) state.mixed_port = port
    return finish()
  }
  return {
    async load() {
      return finish()
    },
    async addSubscription(url) {
      const trimmed = url.trim()
      if (!trimmed.startsWith('https://') && !trimmed.startsWith('http://')) {
        state.input_error = '订阅链接不可用'
        return finish()
      }
      state.input_error = null
      state.profiles.push({
        id: `p${state.profiles.length + 1}`,
        name: trimmed,
        kind: 'subscription',
        source: trimmed,
        current: false,
        failure: null,
        override_text: '',
        override_error: null,
        used: null,
        total: null,
        expire: null,
        last_success_ms: null,
      })
      return finish()
    },
    async addLocal(name, content) {
      state.profiles.push({
        id: `p${state.profiles.length + 1}`,
        name,
        kind: 'local',
        source: name,
        current: false,
        failure: null,
        override_text: '',
        override_error: null,
        used: null,
        total: null,
        expire: null,
        last_success_ms: null,
      })
      const port = readPort(content)
      if (port != null) state.profiles[state.profiles.length - 1]!.source = content
      return finish()
    },
    async stageInstallLink() {
      return finish()
    },
    async confirmInstall() {
      const url = state.pending_url
      if (!url) return finish()
      state.pending_url = null
      state.profiles.push({
        id: `p${state.profiles.length + 1}`,
        name: url,
        kind: 'subscription',
        source: url,
        current: false,
        failure: null,
        override_text: '',
        override_error: null,
        used: null,
        total: null,
        expire: null,
        last_success_ms: null,
      })
      return finish()
    },
    async cancelInstall() {
      state.pending_url = null
      return finish()
    },
    async enable(id) {
      return activate(id)
    },
    async update(id) {
      return activate(id)
    },
    async saveOverride(id, text) {
      const profile = find(id)
      if (!profile) {
        state.input_error = '没有这份配置'
        return finish()
      }
      profile.override_text = text
      return finish()
    },
    async connect() {
      if (!state.active_id) {
        state.failure = '没有生效配置'
        state.connected = false
        state.upload = null
        state.download = null
        allConnections = []
        kernelRunning = false
        pushLog('error', '没有生效配置')
        return finish()
      }
      if (state.platform === 'android') {
        state.vpn = true
        state.system_proxy = false
        state.tun = false
        state.connected = true
      } else {
        state.system_proxy = true
        state.tun = state.tun_wanted
        state.vpn = false
        state.connected = true
      }
      state.failure = null
      state.upload = 128
      state.download = 256
      kernelRunning = true
      allConnections = []
      return finish()
    },
    async disconnect() {
      state.system_proxy = false
      state.tun = false
      state.vpn = false
      state.connected = false
      state.upload = null
      state.download = null
      state.failure = null
      kernelRunning = false
      allConnections = []
      return finish()
    },
    async setMode(mode) {
      const next = normalizeMode(mode)
      if (!next || !state.active_id) {
        state.failure = '模式没有切换'
        return finish()
      }
      state.mode = next
      state.failure = null
      return finish()
    },
    async setSystemProxy(enabled) {
      if (state.platform === 'android') return finish()
      state.system_proxy = enabled
      state.connected = enabled
      return finish()
    },
    async setTun(enabled) {
      if (state.platform === 'android') return finish()
      state.tun_wanted = enabled
      state.tun = enabled
      if (!enabled && state.system_proxy) state.connected = true
      return finish()
    },
    async excludePackage(packageName) {
      if (state.platform !== 'android') return finish()
      const name = packageName.trim()
      if (name && !state.excluded.includes(name)) state.excluded.push(name)
      return finish()
    },
    async includePackage(packageName) {
      state.excluded = state.excluded.filter((item) => item !== packageName)
      return finish()
    },
    async selectNode(group, node) {
      const found = catalog.find((item) => item.name === group)
      if (!found || found.kind !== 'manual') {
        nodesError = NODES_NOT_MANUAL
        return finish()
      }
      if (!found.nodes.some((item) => item.name === node)) {
        nodesError = NODES_MISSING
        return finish()
      }
      for (const item of found.nodes) item.selected = item.name === node
      found.now = node
      nodesError = null
      return finish()
    },
    async testGroup(group) {
      if (!catalog.some((item) => item.name === group)) {
        nodesError = NODES_MISSING
        return finish()
      }
      if (!kernelRunning) {
        nodesError = NODES_KERNEL_DOWN
        return finish()
      }
      nodesError = null
      return finish()
    },
    async setNodeQuery(next) {
      query = next
      return finish()
    },
    async setNodeSort(group, sort) {
      const found = catalog.find((item) => item.name === group)
      if (found) found.sort = sort === 'delay' || sort === 'name' ? sort : 'default'
      return finish()
    },
    async setConnectionQuery(next) {
      connectionQuery = next.slice(0, 200)
      return finish()
    },
    async setLogFilter(level) {
      logFilter = normalizeLogFilter(level)
      return finish()
    },
  }
}

export function createLocalProfilePort(storage: Storage): ProfilePort {
  const memory = createMemoryProfilePort(readStored(storage))
  return wrapStore(memory, storage)
}

function readStored(storage: Storage): Partial<ProfileSnapshot> {
  try {
    return JSON.parse(storage.getItem(LOCAL_KEY) || '') as Partial<ProfileSnapshot>
  } catch {
    return {}
  }
}

function wrapStore(inner: ProfilePort, storage: Storage): ProfilePort {
  async function keep(snapshot: ProfileSnapshot) {
    storage.setItem(LOCAL_KEY, JSON.stringify(snapshot))
    return snapshot
  }
  return {
    load: () => inner.load().then(keep),
    addSubscription: (url) => inner.addSubscription(url).then(keep),
    addLocal: (name, content) => inner.addLocal(name, content).then(keep),
    stageInstallLink: (link) => inner.stageInstallLink(link).then(keep),
    confirmInstall: () => inner.confirmInstall().then(keep),
    cancelInstall: () => inner.cancelInstall().then(keep),
    enable: (id) => inner.enable(id).then(keep),
    update: (id) => inner.update(id).then(keep),
    saveOverride: (id, text) => inner.saveOverride(id, text).then(keep),
    connect: () => inner.connect().then(keep),
    disconnect: () => inner.disconnect().then(keep),
    setSystemProxy: (enabled) => inner.setSystemProxy(enabled).then(keep),
    setTun: (enabled) => inner.setTun(enabled).then(keep),
    excludePackage: (packageName) => inner.excludePackage(packageName).then(keep),
    includePackage: (packageName) => inner.includePackage(packageName).then(keep),
    selectNode: (group, node) => inner.selectNode(group, node).then(keep),
    testGroup: (group) => inner.testGroup(group).then(keep),
    setNodeQuery: (query) => inner.setNodeQuery(query).then(keep),
    setNodeSort: (group, sort) => inner.setNodeSort(group, sort).then(keep),
    setConnectionQuery: (query) => inner.setConnectionQuery(query).then(keep),
    setLogFilter: (level) => inner.setLogFilter(level).then(keep),
    setMode: (mode) => inner.setMode(mode).then(keep),
  }
}

function inTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function createProfilePort(): ProfilePort {
  if (inTauri()) return createTauriProfilePort()
  return createLocalProfilePort(localStorage)
}

function applyRaw(raw: ProfileSnapshot): ProfileSnapshot {
  return normalizeProfileSnapshot(raw)
}

function createTauriProfilePort(): ProfilePort {
  return {
    async load() {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('profile_state'))
    },
    async addSubscription(url) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('add_subscription_profile', { url }))
    },
    async addLocal(name, content) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('add_local_profile', { name, content }))
    },
    async stageInstallLink(link) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('stage_install_link', { link }))
    },
    async confirmInstall() {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('confirm_install_link'))
    },
    async cancelInstall() {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('cancel_install_link'))
    },
    async enable(id) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('enable_profile', { id }))
    },
    async update(id) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('update_profile', { id }))
    },
    async saveOverride(id, text) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('save_profile_override', { id, text }))
    },
    async connect() {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('connect_session'))
    },
    async disconnect() {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('disconnect_session'))
    },
    async setSystemProxy(enabled) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_system_proxy', { enabled }))
    },
    async setTun(enabled) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_tun_enabled', { enabled }))
    },
    async excludePackage(packageName) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('exclude_package', { packageName }))
    },
    async includePackage(packageName) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('include_package', { packageName }))
    },
    async selectNode(group, node) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('select_profile_node', { group, node }))
    },
    async testGroup(group) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('test_profile_group', { group }))
    },
    async setNodeQuery(query) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_node_query', { query }))
    },
    async setNodeSort(group, sort) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_node_sort', { group, sort }))
    },
    async setConnectionQuery(query) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_connection_query', { query }))
    },
    async setLogFilter(level) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_log_filter', { level }))
    },
    async setMode(mode) {
      const { invoke } = await import('@tauri-apps/api/core')
      return applyRaw(await invoke<ProfileSnapshot>('set_outbound_mode', { mode }))
    },
    subscribe(handler) {
      let stop = () => {}
      void import('@tauri-apps/api/event').then(({ listen }) =>
        listen<ProfileSnapshot>('profile-changed', (event) => {
          handler(applyRaw(event.payload))
        }).then((unlisten) => {
          stop = unlisten
        }),
      )
      return () => stop()
    },
  }
}
