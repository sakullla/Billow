import { describe, expect, it } from 'vitest'
import { isValidDnsName, normalizeDnsQueryResult, normalizeIcon, normalizeKernel, normalizeRuleRow, normalizeSnapshot } from './types'
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
      { name: 'n', delay_ms: null, failed: true, selected: false, node_type: '', tags: [] },
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

  it('reads fixed and hidden groups and keeps a fixed node only on fixable auto groups', () => {
    const [auto, balance, manual, bare] = normalizeSnapshot({
      node_catalog: [
        { name: 'A', kind: 'auto', pinnable: true, fixed: '香港 01', hidden: true },
        { name: 'B', kind: 'auto', pinnable: false, fixed: '香港 01' },
        { name: 'C', kind: 'manual', pinnable: true, fixed: '香港 01', hidden: 'yes' },
        { name: 'D', kind: 'auto', pinnable: true, fixed: '' },
      ],
    }).node_catalog
    expect([auto.pinnable, auto.fixed, auto.hidden]).toEqual([true, '香港 01', true])
    expect([balance.pinnable, balance.fixed, balance.hidden]).toEqual([false, null, false])
    expect([manual.pinnable, manual.fixed, manual.hidden]).toEqual([false, null, false])
    expect([bare.pinnable, bare.fixed]).toEqual([true, null])
  })

  it('accepts only http(s) and image data through normalizeIcon', () => {
    expect(normalizeIcon('https://icons.example.com/a.png')).toBe('https://icons.example.com/a.png')
    expect(normalizeIcon('http://icons.example.com/a.png')).toBe('http://icons.example.com/a.png')
    expect(normalizeIcon('  data:image/png;base64,AAAA  ')).toBe('data:image/png;base64,AAAA')
    for (const rejected of [
      'ftp://icons.example.com/a.png',
      'file:///tmp/a.png',
      'javascript:alert(1)',
      'blob:https://icons.example.com/a',
      '//icons.example.com/a.png',
      'https://icons.example.com/a b.png',
      'data:text/html;base64,AAAA',
      '',
      null,
      undefined,
      42,
      { src: 'https://icons.example.com/a.png' },
    ]) {
      expect(normalizeIcon(rejected)).toBeNull()
    }
    const long = `https://icons.example.com/${'a'.repeat(4000)}.png`
    expect(normalizeIcon(long)).toHaveLength(2048)
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

  it('normalizes rule hit, identity and disabled fields and drops unknown ones', () => {
    expect(
      normalizeRuleRow({
        kind: 'DomainSuffix',
        payload: 'example.com',
        proxy: 'DIRECT',
        hit_count: 7,
        last_hit: '2026-11-15T10:00:00Z',
        key: 'domainsuffix|example.com|DIRECT|0',
        disabled: true,
        extra: { hitCount: 99 },
      }),
    ).toEqual({
      kind: 'DomainSuffix',
      payload: 'example.com',
      proxy: 'DIRECT',
      hit_count: 7,
      last_hit: '2026-11-15T10:00:00Z',
      key: 'domainsuffix|example.com|DIRECT|0',
      disabled: true,
    })
    expect(normalizeRuleRow({ kind: 'Match', hit_count: '7', last_hit: '', key: 7 })).toMatchObject({
      hit_count: null,
      last_hit: null,
      key: null,
      disabled: false,
    })
    expect(normalizeRuleRow({})).toEqual({
      kind: '',
      payload: '',
      proxy: '',
      hit_count: null,
      last_hit: null,
      key: null,
      disabled: false,
    })
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

  it('normalizes system proxy, DNS policy/hosts, and GEO URL overrides safely', () => {
    const snapshot = normalizeSnapshot({
      settings: {
        geodata_mode: false,
        geodata_loader: 'memconservative',
        geo_source: 'testingcf',
        geo_urls: {
          geoip: ' https://example.com/geoip.dat ',
          asn: 'https://example.com/asn.mmdb',
        },
        system_proxy: {
          host: ' 127.0.0.2 ',
          mode: 'pac',
          pac_script: 'function FindProxyForURL() { return "DIRECT"; }',
          bypass: ['localhost', '10.*'],
        },
        dns: {
          listen: '127.0.0.1:1053',
          enhanced_mode: 'fake-ip',
          fake_ip_filter_mode: 'whitelist',
          prefer_h3: true,
          cache_algorithm: 'arc',
          use_hosts: true,
          use_system_hosts: false,
          direct_nameserver_follow_policy: true,
          nameserver_policy: {
            'geosite:cn': ['223.5.5.5', '119.29.29.29'],
            ' +.corp.local ': '10.0.0.1',
          },
          hosts: {
            'router.local': ['192.168.1.1'],
          },
        },
      },
    })
    expect(snapshot.settings.geodata_mode).toBe(false)
    expect(snapshot.settings.geodata_loader).toBe('memconservative')
    expect(snapshot.settings.geo_source).toBe('testingcf')
    expect(snapshot.settings.geo_urls).toEqual({
      geoip: 'https://example.com/geoip.dat',
      mmdb: '',
      geosite: '',
      asn: 'https://example.com/asn.mmdb',
    })
    expect(snapshot.settings.system_proxy).toEqual({
      host: '127.0.0.2',
      mode: 'pac',
      pac_script: 'function FindProxyForURL() { return "DIRECT"; }',
      bypass: ['localhost', '10.*'],
    })
    expect(snapshot.settings.dns).toMatchObject({
      listen: '127.0.0.1:1053',
      fake_ip_filter_mode: 'whitelist',
      prefer_h3: true,
      cache_algorithm: 'arc',
      use_hosts: true,
      use_system_hosts: false,
      direct_nameserver_follow_policy: true,
      nameserver_policy: {
        'geosite:cn': ['223.5.5.5', '119.29.29.29'],
        '+.corp.local': ['10.0.0.1'],
      },
      hosts: {
        'router.local': ['192.168.1.1'],
      },
    })
  })
})

describe('DNS query helpers', () => {
  it('accepts hostnames and rejects what the backend would refuse', () => {
    for (const ok of ['example.com', 'Example.COM.', '_sip._tcp.example.com', 'localhost', 'xn--fiqs8s.cn']) {
      expect(isValidDnsName(ok), ok).toBe(true)
    }
    for (const bad of ['', '   ', 'not a domain', 'a..b', '-a.com', 'a-.com', '例子.com', `${'a'.repeat(64)}.com`, 'a/b', `${'a.'.repeat(127)}a`]) {
      expect(isValidDnsName(bad), bad).toBe(false)
    }
  })

  it('normalizes a query result and drops malformed answers', () => {
    expect(normalizeDnsQueryResult(null)).toEqual({ name: '', qtype: '', status: null, answers: [], elapsed_ms: 0, error: null })
    expect(
      normalizeDnsQueryResult({
        name: 'example.com',
        qtype: 'A',
        status: 0,
        answers: [{ type: 'A', value: '1.2.3.4', ttl: 60 }, { type: 'A', value: '' }, 'x', { type: 'A', value: '5.6.7.8', ttl: -1 }],
        elapsed_ms: 18,
        error: '',
      }),
    ).toEqual({
      name: 'example.com',
      qtype: 'A',
      status: 0,
      answers: [
        { type: 'A', value: '1.2.3.4', ttl: 60 },
        { type: 'A', value: '5.6.7.8', ttl: 0 },
      ],
      elapsed_ms: 18,
      error: null,
    })
  })
})
