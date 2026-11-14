export interface ProfileItem {
  id: string
  name: string
  kind: string
  source: string
  current: boolean
  failure: string | null
  override_text: string
  override_error: string | null
  used: number | null
  total: number | null
  expire: number | null
}

export interface InstalledApp {
  name: string
  package_name: string
}

export interface NodeItem {
  name: string
  delay_ms: number | null
  failed: boolean
  selected: boolean
}

export interface NodeGroup {
  name: string
  kind: 'manual' | 'auto'
  now: string
  sort: 'default' | 'delay' | 'name'
  nodes: NodeItem[]
}

export interface ConnectionRow {
  host: string
  outbound: string
}

export interface LogLine {
  level: 'error' | 'warning' | 'info'
  message: string
}

export interface ProfileSnapshot {
  profiles: ProfileItem[]
  active_id: string | null
  mixed_port: number | null
  mode: string | null
  system_proxy: boolean
  tun: boolean
  vpn: boolean
  pending_url: string | null
  failure: string | null
  input_error: string | null
  connected: boolean
  platform: 'desktop' | 'android'
  tun_wanted: boolean
  excluded: string[]
  installed: InstalledApp[]
  node_groups: NodeGroup[]
  node_catalog: NodeGroup[]
  node_query: string
  nodes_notice: string | null
  nodes_error: string | null
  nodes_profile_id: string | null
  kernel_running: boolean
  connections: ConnectionRow[]
  connection_query: string
  logs: LogLine[]
  log_filter: 'all' | 'error' | 'warning' | 'info'
}

export const DIAGNOSTICS_SAMPLE_MS = 1000

export function emptyProfileSnapshot(): ProfileSnapshot {
  return {
    profiles: [],
    active_id: null,
    mixed_port: null,
    mode: null,
    system_proxy: false,
    tun: false,
    vpn: false,
    pending_url: null,
    failure: null,
    input_error: null,
    connected: false,
    platform: 'desktop',
    tun_wanted: false,
    excluded: [],
    installed: [],
    node_groups: [],
    node_catalog: [],
    node_query: '',
    nodes_notice: null,
    nodes_error: null,
    nodes_profile_id: null,
    kernel_running: false,
    connections: [],
    connection_query: '',
    logs: [],
    log_filter: 'all',
  }
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function whole(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null
  return value
}

function positive(value: unknown): number | null {
  const number = whole(value)
  return number != null && number > 0 ? number : null
}

function normalizeNode(raw: unknown): NodeItem | null {
  const node = raw && typeof raw === 'object' ? (raw as Partial<NodeItem>) : {}
  const name = typeof node.name === 'string' ? node.name.trim() : ''
  if (!name) return null
  const failed = Boolean(node.failed)
  return {
    name,
    delay_ms: failed ? null : whole(node.delay_ms),
    failed,
    selected: Boolean(node.selected),
  }
}

function normalizeGroup(raw: unknown): NodeGroup | null {
  const group = raw && typeof raw === 'object' ? (raw as Partial<NodeGroup>) : {}
  const name = typeof group.name === 'string' ? group.name.trim() : ''
  if (!name) return null
  const nodes = Array.isArray(group.nodes) ? group.nodes.flatMap((item) => {
    const node = normalizeNode(item)
    return node ? [node] : []
  }) : []
  return {
    name,
    kind: group.kind === 'auto' ? 'auto' : 'manual',
    now: typeof group.now === 'string' ? group.now : '',
    sort: group.sort === 'delay' || group.sort === 'name' ? group.sort : 'default',
    nodes,
  }
}

function normalizeConnection(raw: unknown): ConnectionRow | null {
  const row = raw && typeof raw === 'object' ? (raw as Partial<ConnectionRow>) : {}
  const host = typeof row.host === 'string' ? row.host.trim() : ''
  const outbound = typeof row.outbound === 'string' ? row.outbound.trim() : ''
  if (!host || !outbound) return null
  return { host, outbound }
}

function normalizeLog(raw: unknown): LogLine | null {
  const line = raw && typeof raw === 'object' ? (raw as Partial<LogLine>) : {}
  const level = line.level === 'error' || line.level === 'warning' || line.level === 'info' ? line.level : null
  const message = typeof line.message === 'string' ? line.message.trim() : ''
  if (!level || !message) return null
  return { level, message }
}

export function normalizeLogFilter(filter: unknown): ProfileSnapshot['log_filter'] {
  return filter === 'error' || filter === 'warning' || filter === 'info' ? filter : 'all'
}

function normalizeGroups(raw: unknown): NodeGroup[] {
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    const group = normalizeGroup(item)
    return group ? [group] : []
  })
}

export function normalizeProfileSnapshot(raw: unknown): ProfileSnapshot {
  const source = raw && typeof raw === 'object' ? (raw as Partial<ProfileSnapshot>) : {}
  const profiles = Array.isArray(source.profiles) ? source.profiles : []
  return {
    profiles: profiles.map((item) => {
      const profile = item && typeof item === 'object' ? (item as Partial<ProfileItem>) : {}
      return {
        id: typeof profile.id === 'string' ? profile.id : '',
        name: typeof profile.name === 'string' ? profile.name : '',
        kind: profile.kind === 'local' ? 'local' : 'subscription',
        source: typeof profile.source === 'string' ? profile.source : '',
        current: Boolean(profile.current),
        failure: text(profile.failure),
        override_text: typeof profile.override_text === 'string' ? profile.override_text : '',
        override_error: text(profile.override_error),
        used: whole(profile.used),
        total: positive(profile.total),
        expire: positive(profile.expire),
      }
    }),
    active_id: text(source.active_id),
    mixed_port: whole(source.mixed_port),
    mode: text(source.mode),
    system_proxy: Boolean(source.system_proxy),
    tun: Boolean(source.tun),
    vpn: Boolean(source.vpn),
    pending_url: text(source.pending_url),
    failure: text(source.failure),
    input_error: text(source.input_error),
    connected: Boolean(source.connected),
    platform: source.platform === 'android' ? 'android' : 'desktop',
    tun_wanted: Boolean(source.tun_wanted),
    excluded: Array.isArray(source.excluded)
      ? source.excluded.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      : [],
    node_groups: normalizeGroups(source.node_groups),
    node_catalog: normalizeGroups(source.node_catalog).length
      ? normalizeGroups(source.node_catalog)
      : normalizeGroups(source.node_groups),
    node_query: typeof source.node_query === 'string' ? source.node_query : '',
    nodes_notice: text(source.nodes_notice),
    nodes_error: text(source.nodes_error),
    nodes_profile_id: text(source.nodes_profile_id),
    kernel_running: Boolean(source.kernel_running),
    connections: Array.isArray(source.connections)
      ? source.connections.flatMap((item) => {
          const row = normalizeConnection(item)
          return row ? [row] : []
        })
      : [],
    connection_query: typeof source.connection_query === 'string' ? source.connection_query : '',
    logs: Array.isArray(source.logs)
      ? source.logs.flatMap((item) => {
          const line = normalizeLog(item)
          return line ? [line] : []
        })
      : [],
    log_filter: normalizeLogFilter(source.log_filter),
    installed: Array.isArray(source.installed)
      ? source.installed.flatMap((item) => {
          const app = item && typeof item === 'object' ? (item as Partial<InstalledApp>) : {}
          const name = typeof app.name === 'string' ? app.name : ''
          const packageName = typeof app.package_name === 'string' ? app.package_name.trim() : ''
          if (!name || !packageName) return []
          return [{ name, package_name: packageName }]
        })
      : [],
  }
}

export function formatExpire(expire: number): string {
  const date = new Date(expire * 1000)
  if (Number.isNaN(date.getTime())) return String(expire)
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

export function showsUsage(used: number | null, total: number | null): boolean {
  return used != null && total != null && total > 0
}

export function showsExpire(expire: number | null): boolean {
  return expire != null && expire > 0
}
