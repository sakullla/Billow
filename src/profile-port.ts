import {
  emptyProfileSnapshot,
  normalizeProfileSnapshot,
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

/// Browser fallback and component tests. Enable and override decisions are made in Rust.
export function createMemoryProfilePort(initial?: Partial<ProfileSnapshot>): ProfilePort {
  const state = normalizeProfileSnapshot({ ...emptyProfileSnapshot(), ...initial })
  function finish(): ProfileSnapshot {
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
