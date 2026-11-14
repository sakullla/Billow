import type { KernelChannel } from './copy'
import { resolveKernelChannel, type KernelSnapshot } from './kernel'

export interface KernelPort {
  load(): Promise<KernelSnapshot>
  setChannel(channel: KernelChannel): Promise<KernelSnapshot>
}

const LOCAL_KEY = 'billow-kernel'

export function createMemoryKernelPort(initial?: Partial<KernelSnapshot>): KernelPort {
  const state: KernelSnapshot = {
    channel: resolveKernelChannel(initial?.channel),
    failure: initial?.failure ?? null,
    ready: initial?.ready ?? false,
  }
  return {
    async load() {
      return { channel: state.channel, failure: state.failure, ready: state.ready }
    },
    async setChannel(channel) {
      const resolved = resolveKernelChannel(channel)
      if (resolved !== channel) {
        state.failure = '没有这个内核渠道'
        return { channel: state.channel, failure: state.failure, ready: state.ready }
      }
      state.channel = resolved
      state.failure = null
      return { channel: state.channel, failure: state.failure, ready: state.ready }
    },
  }
}

export function createLocalKernelPort(storage: Storage): KernelPort {
  function read(): KernelSnapshot {
    try {
      const raw = JSON.parse(storage.getItem(LOCAL_KEY) || '') as Partial<KernelSnapshot>
      return {
        channel: resolveKernelChannel(typeof raw.channel === 'string' ? raw.channel : 'stable'),
        failure: typeof raw.failure === 'string' ? raw.failure : null,
        ready: false,
      }
    } catch {
      return { channel: 'stable', failure: null, ready: false }
    }
  }
  return {
    async load() {
      return read()
    },
    async setChannel(channel) {
      const current = read()
      const resolved = resolveKernelChannel(channel)
      if (resolved !== channel) {
        return { ...current, failure: '没有这个内核渠道' }
      }
      const next = { channel: resolved, failure: null, ready: false }
      storage.setItem(LOCAL_KEY, JSON.stringify(next))
      return next
    },
  }
}

function inTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function createKernelPort(): KernelPort {
  if (inTauri()) return createTauriKernelPort()
  return createLocalKernelPort(localStorage)
}

function createTauriKernelPort(): KernelPort {
  return {
    async load() {
      const { invoke } = await import('@tauri-apps/api/core')
      const raw = await invoke<KernelSnapshot>('kernel_state')
      return {
        channel: resolveKernelChannel(raw.channel),
        failure: typeof raw.failure === 'string' ? raw.failure : null,
        ready: Boolean(raw.ready),
      }
    },
    async setChannel(channel) {
      const { invoke } = await import('@tauri-apps/api/core')
      const raw = await invoke<KernelSnapshot>('set_kernel_channel', {
        channel: resolveKernelChannel(channel),
      })
      return {
        channel: resolveKernelChannel(raw.channel),
        failure: typeof raw.failure === 'string' ? raw.failure : null,
        ready: Boolean(raw.ready),
      }
    },
  }
}
