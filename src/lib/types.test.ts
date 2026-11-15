import { describe, expect, it } from 'vitest'
import { normalizeKernel, normalizeRuleRow, normalizeSnapshot } from './types'
import { resolvePage } from './store'

describe('normalizeSnapshot', () => {
  it('fills every field from an empty or hostile payload', () => {
    for (const raw of [undefined, null, 42, 'x', [], {}]) {
      const snapshot = normalizeSnapshot(raw)
      expect(snapshot.profiles).toEqual([])
      expect(snapshot.platform).toBe('desktop')
      expect(snapshot.settings.mixed_port).toBeNull()
      expect(snapshot.connections).toEqual([])
      expect(snapshot.kernel_memory).toBeNull()
      expect(snapshot.kernel_uptime_secs).toBeNull()
      expect(snapshot.connection_total).toBe(0)
      expect(snapshot.connections_error).toBeNull()
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

  it('keeps only remote and inline group icons', () => {
    const group = (icon: unknown) =>
      normalizeSnapshot({ node_catalog: [{ name: 'G', kind: 'manual', icon }] }).node_catalog[0]

    expect(group(' https://icons.example.com/a.png ').icon).toBe('https://icons.example.com/a.png')
    expect(group('HTTP://icons.example.com/a.png').icon).toBe('HTTP://icons.example.com/a.png')
    expect(group('data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=').icon).toBe(
      'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
    )
    for (const icon of [
      'file:///tmp/a.png',
      'javascript:alert(1)',
      'ftp://icons.example.com/a.png',
      'https://icons.example.com/a b.png',
      'data:text/html;base64,AAAA',
      '',
      null,
      42,
    ]) {
      expect(group(icon).icon).toBeNull()
    }
    expect(normalizeSnapshot({ node_catalog: [{ name: 'G', kind: 'manual' }] }).node_catalog[0].icon).toBeNull()
  })

  it('keeps the reported runtime figures and leaves missing ones empty', () => {
    const live = normalizeSnapshot({
      kernel_memory: 134217728,
      kernel_uptime_secs: 90,
      connection_total: 620,
      connections: [{ id: 'c', host: 'a.com', chains: ['x'] }],
      connections_error: '连接没有读取',
    })
    expect(live.kernel_memory).toBe(134217728)
    expect(live.kernel_uptime_secs).toBe(90)
    expect(live.connection_total).toBe(620)
    expect(live.connection_total).toBeGreaterThan(live.connections.length)
    expect(live.connections_error).toBe('连接没有读取')

    const hostile = normalizeSnapshot({ kernel_memory: -1, kernel_uptime_secs: 'x', connection_total: -5 })
    expect(hostile.kernel_memory).toBeNull()
    expect(hostile.kernel_uptime_secs).toBeNull()
    expect(hostile.connection_total).toBe(0)
  })

  it('normalizes rule hit fields and drops unknown ones', () => {
    expect(
      normalizeRuleRow({
        kind: 'DomainSuffix',
        payload: 'example.com',
        proxy: 'DIRECT',
        hit_count: 7,
        last_hit: '2026-11-15T10:00:00Z',
        extra: { hitCount: 99 },
        disabled: true,
      }),
    ).toEqual({
      kind: 'DomainSuffix',
      payload: 'example.com',
      proxy: 'DIRECT',
      hit_count: 7,
      last_hit: '2026-11-15T10:00:00Z',
    })
    expect(normalizeRuleRow({ kind: 'Match', hit_count: '7', last_hit: '' })).toMatchObject({
      hit_count: null,
      last_hit: null,
    })
    expect(normalizeRuleRow({})).toEqual({ kind: '', payload: '', proxy: '', hit_count: null, last_hit: null })
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
