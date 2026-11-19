import { describe, expect, it } from 'vitest'
import { buildOverview, filterOverview, formatValue } from './configOverview'
import type { ConfigOverview } from './types'

function overview(partial: Partial<ConfigOverview> = {}): ConfigOverview {
  return {
    effective: {},
    prepared: {},
    profile: {},
    counts: {},
    group_types: {},
    running: true,
    ...partial,
  }
}

const rowOf = (sections: ReturnType<typeof buildOverview>, path: string) =>
  sections.flatMap((section) => section.rows).find((row) => row.path === path)

describe('config overview', () => {
  it('names the last layer that changed each value', () => {
    const profile = { 'log-level': 'info', 'allow-lan': false, ipv6: true, dns: { enable: true, 'enhanced-mode': 'fake-ip' } }
    const prepared = { ...profile, 'log-level': 'debug' }
    const effective = { ...prepared, 'allow-lan': true }
    const sections = buildOverview(overview({ profile, prepared, effective }))

    expect(rowOf(sections, 'allow-lan')).toMatchObject({ value: '开启', source: 'billow', before: '关闭' })
    expect(rowOf(sections, 'log-level')).toMatchObject({ value: '调试', source: 'override', before: '信息' })
    expect(rowOf(sections, 'ipv6')).toMatchObject({ value: '开启', source: 'profile' })
    expect(rowOf(sections, 'dns.enhanced-mode')).toMatchObject({ value: 'Fake-IP', source: 'profile' })
    // Unset core options show the kernel default instead of disappearing.
    expect(rowOf(sections, 'unified-delay')).toMatchObject({ value: '关闭', source: 'default' })
  })

  it('hides niche options the config never sets, and shows them once it does', () => {
    expect(rowOf(buildOverview(overview()), 'routing-mark')).toBeUndefined()
    expect(rowOf(buildOverview(overview()), 'keep-alive-interval')).toBeUndefined()
    const set = buildOverview(overview({ effective: { 'routing-mark': 6666, 'keep-alive-interval': 30 } }))
    expect(rowOf(set, 'routing-mark')?.value).toBe('6666')
    expect(rowOf(set, 'keep-alive-interval')?.value).toBe('30 秒')
  })

  it('summarizes lists, users and groups without exposing secrets', () => {
    const sections = buildOverview(
      overview({
        effective: {
          authentication: ['alice:••••', 'bob:••••', 'carol:••••'],
          'dns': { nameserver: ['a', 'b', 'c', 'd', 'e'], 'nameserver-policy': { x: ['1'], y: ['2'] } },
        },
        counts: { proxies: 19, 'proxy-groups': 3, rules: 12 },
        group_types: { select: 2, fallback: 1 },
      }),
    )
    expect(rowOf(sections, 'authentication')?.value).toBe('alice、bob 等 3 个用户')
    expect(rowOf(sections, 'dns.nameserver')).toMatchObject({ value: 'a、b、c 等 5 项', title: 'a\nb\nc\nd\ne' })
    expect(rowOf(sections, 'dns.nameserver-policy')?.value).toBe('2 条')
    expect(rowOf(sections, 'proxies')).toMatchObject({ value: '19 个', to: { page: 'proxies' } })
    expect(rowOf(sections, 'proxy-groups')?.value).toBe('3 个 · 手选 2 · 故障转移 1')
    expect(rowOf(sections, 'rules')?.to).toEqual({ page: 'rules' })
  })

  it('keeps unknown keys in a folded section and leaves Billow-managed ones out', () => {
    const sections = buildOverview(
      overview({ effective: { 'external-controller': '127.0.0.1:9090', experimental: { 'quic-go-disable-gso': true }, 'tcp-keep-alive': 1 } }),
    )
    const rest = sections.find((section) => section.id === 'rest')!
    expect(rest.folded).toBe(true)
    expect(rest.rows.map((row) => row.path)).toEqual(['experimental', 'tcp-keep-alive'])
    expect(rowOf(sections, 'external-controller')).toBeUndefined()
  })

  it('drops TUN on Android, where the system owns routing', () => {
    const effective = { tun: { enable: false, stack: 'mixed' } }
    expect(buildOverview(overview({ effective })).some((section) => section.id === 'tun')).toBe(true)
    expect(buildOverview(overview({ effective }), { android: true }).some((section) => section.id === 'tun')).toBe(false)
  })

  it('filters by label, value or YAML key, and by source', () => {
    const effective = { 'allow-lan': true, 'log-level': 'info', dns: { enable: true, 'enhanced-mode': 'fake-ip' } }
    const sections = buildOverview(overview({ effective, prepared: { ...effective, 'allow-lan': false }, profile: { ...effective, 'allow-lan': false } }))
    const paths = (needle: string, source?: 'billow') =>
      filterOverview(sections, needle, source).flatMap((section) => section.rows.map((row) => row.path))
    expect(paths('enhanced-mode')).toEqual(['dns.enhanced-mode'])
    expect(paths('Fake-IP')).toEqual(['dns.enhanced-mode'])
    expect(paths('日志')).toEqual(['log-level'])
    expect(paths('', 'billow')).toEqual(['allow-lan'])
    expect(paths('nothing-like-this')).toEqual([])
  })

  it('follows mihomo v1.19.34: removed global fingerprint, low-memory GEO loader and Mips by default', () => {
    const sections = buildOverview(overview({ effective: { 'global-client-fingerprint': 'chrome', tun: { enable: false } } }))
    expect(rowOf(sections, 'global-client-fingerprint')).toMatchObject({ value: 'Chrome（内核已移除，不生效）' })
    expect(rowOf(sections, 'global-client-fingerprint')?.to).toBeUndefined()
    expect(rowOf(sections, 'geodata-loader')).toMatchObject({ value: '低内存', source: 'default' })
    expect(rowOf(sections, 'tun.stack')).toMatchObject({ value: '内核默认（Mips）', source: 'default' })
    const pinned = buildOverview(overview({ effective: { 'geodata-loader': 'standard', dns: { 'fake-ip-filter-mode': 'rule' } } }))
    expect(rowOf(pinned, 'geodata-loader')?.value).toBe('标准')
    expect(rowOf(pinned, 'dns.fake-ip-filter-mode')?.value).toBe('规则')
  })

  it('formats plain values the way settings label them', () => {
    expect(formatValue(true)).toBe('开启')
    expect(formatValue(undefined)).toBe('未设置')
    expect(formatValue([])).toBe('无')
    expect(formatValue({ a: 1, b: 2 })).toBe('2 项')
    expect(formatValue('strict')).toBe('自动')
  })

  it('labels the TUN route, sniff detail and extra port rows Billow sets (R32–R34)', () => {
    const profile = { 'mixed-port': 7890, sniffer: { enable: true, sniff: { TLS: { ports: [443] } } }, tun: { enable: false } }
    const effective = {
      ...profile,
      'socks-port': 7891,
      'redir-port': 0,
      sniffer: { enable: true, sniff: { TLS: { ports: [443, 8443] } }, 'skip-domain': ['a.example'] },
      tun: { enable: false, 'route-exclude-address': ['192.168.0.0/16'] },
    }
    const sections = buildOverview(overview({ profile, prepared: profile, effective }))
    expect(rowOf(sections, 'socks-port')).toMatchObject({ value: '7891', source: 'billow', to: { page: 'settings', tab: 'kernel' } })
    expect(rowOf(sections, 'redir-port')).toMatchObject({ value: '关闭', source: 'billow' })
    expect(rowOf(sections, 'sniffer.sniff.TLS.ports')).toMatchObject({ value: '443、8443', source: 'billow', before: '443' })
    expect(rowOf(sections, 'sniffer.skip-domain')).toMatchObject({ value: 'a.example', source: 'billow' })
    expect(rowOf(sections, 'tun.route-exclude-address')).toMatchObject({ value: '192.168.0.0/16', source: 'billow' })
    expect(rowOf(buildOverview(overview({ profile, prepared: profile, effective }), { android: true }), 'tun.route-exclude-address')).toBeUndefined()
  })
})
