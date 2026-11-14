import { type KernelChannel } from './copy'

export interface KernelSnapshot {
  channel: string
  failure: string | null
  ready: boolean
}

export function resolveKernelChannel(value: string | null | undefined): KernelChannel {
  if (value === 'stable' || value === 'preview') return value
  return 'stable'
}
