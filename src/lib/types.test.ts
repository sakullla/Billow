import { describe, expect, it } from 'vitest'
import { normalizeKernel, normalizeSnapshot } from './types'
import { resolvePage } from './store'

describe('normalizeSnapshot', () => {
  it('fills every field from an empty or hostile payload', () => {
    for (const raw of [undefined, null, 42, 'x', [], {}]) {
      const snapshot = normalizeSnapshot(raw)
      expect(snapshot.profiles).toEqual([])
      expect(snapshot.platform).toBe('desktop')
      expect(snapshot.settings.mixed_port).toBeNull()
      expect(snapshot.connections).toEqual([])
    }
  })

  it('keeps backend fields and drops malformed rows', () => {
    const snapshot = normalizeSnapshot({
      profiles: [{ id: 'p1', name: 'A', kind: 'local', current: true, total: 0, expire: 0, proxy_count: 4 }],
      mode: 'GLOBAL',
      platform: 'android',
      node_catalog: [{ name: 'G', kind: 'auto', nodes: [{ name: 'n', delay_ms: 30, failed: true }, { name: '' }] }, { name: '' }],
      connections: [{ id: 'c', host: 'a.com', chains: ['x', 3], upload: -1 }],
      logs: [{ level: 'trace', message: 'm', time_ms: 5 }],
      settings: { mixed_port: 7891, allow_lan: true, log_level: '' },
    })
    expect(snapshot.profiles[0]).toMatchObject({ id: 'p1', kind: 'local', total: null, expire: null, proxy_count: 4 })
    expect(snapshot.mode).toBe('global')
    expect(snapshot.platform).toBe('android')
    expect(snapshot.node_catalog).toHaveLength(1)
    expect(snapshot.node_catalog[0].nodes).toEqual([
      { name: 'n', delay_ms: null, failed: true, selected: false, node_type: '' },
    ])
    expect(snapshot.connections[0].chains).toEqual(['x'])
    expect(snapshot.connections[0].upload).toBe(0)
    expect(snapshot.logs[0].level).toBe('info')
    expect(snapshot.settings).toMatchObject({ mixed_port: 7891, allow_lan: true, log_level: null })
  })

  it('reads kernel status', () => {
    expect(normalizeKernel({ channel: 'preview', ready: true, version: 'v1' })).toEqual({
      channel: 'preview',
      ready: true,
      version: 'v1',
      failure: null,
    })
    expect(normalizeKernel(null).channel).toBe('stable')
  })

  it('maps saved entries onto pages and falls back to home', () => {
    expect(resolvePage('nodes')).toBe('proxies')
    expect(resolvePage('logs')).toBe('logs')
    expect(resolvePage('diagnostics')).toBe('home')
    expect(resolvePage(null)).toBe('home')
  })
})
