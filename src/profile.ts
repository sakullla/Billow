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
}

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
