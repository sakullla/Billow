import { describe, expect, it } from 'vitest'
import { locale } from './i18n'
import {
  autoTypeLabel,
  canPickNode,
  compareText,
  daysLeft,
  delayText,
  delayTone,
  formatBytes,
  formatDate,
  formatNumber,
  formatRelative,
  formatSpeed,
  formatSpeedCompact,
  groupStrategy,
  hostOf,
  isInfoNode,
  listedGroups,
  resolveChain,
  protocolLabel,
  splitNodePrefix,
  usagePercent,
} from './format'

describe('node and group labels', () => {
  it('badges only automatic strategies, never plain select groups', () => {
    expect(autoTypeLabel({ group_type: 'select', kind: 'manual' })).toBe('')
    expect(autoTypeLabel({ group_type: 'url-test', kind: 'auto' })).toBe('自动')
    expect(autoTypeLabel({ group_type: 'fallback', kind: 'auto' })).toBe('故障转移')
  })

  it('splits a provider tag off the front of a node name', () => {
    expect(splitNodePrefix('【KLM】 🇭🇰 Hong Kong 01')).toEqual({ prefix: '【KLM】 ', rest: '🇭🇰 Hong Kong 01' })
    expect(splitNodePrefix('[LOCAL] dmit-us')).toEqual({ prefix: '[LOCAL] ', rest: 'dmit-us' })
    expect(splitNodePrefix('香港 01')).toEqual({ prefix: '', rest: '香港 01' })
    // A name that is only a tag stays whole.
    expect(splitNodePrefix('【公告】')).toEqual({ prefix: '', rest: '【公告】' })
  })
})

describe('format', () => {
  it('formats byte sizes with sensible precision', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1,023 B')
    expect(formatBytes(1536)).toBe('1.50 KB')
    expect(formatBytes(15 * 1024 * 1024)).toBe('15.0 MB')
    expect(formatBytes(200 * 1024 ** 3)).toBe('200 GB')
    expect(formatBytes(null)).toBe('—')
    expect(formatSpeed(2048)).toBe('2.00 KB/s')
  })

  it('formats numbers, dates and collation in the selected language', () => {
    const before = locale.value
    try {
      const noon = new Date(2026, 5, 15, 12, 0, 0).getTime() / 1000
      locale.value = 'zh-CN'
      expect(formatNumber(1234)).toBe('1,234')
      expect(formatDate(noon)).toContain('2026')
      expect(compareText('a', 'b')).toBeLessThan(0)
      locale.value = 'en'
      expect(formatNumber(1234)).toBe('1,234')
      expect(formatDate(noon)).toContain('2026')
      expect(compareText('node10', 'node2')).toBeGreaterThan(0)
    } finally {
      locale.value = before
    }
  })

  it('keeps compact sidebar speeds within six characters', () => {
    expect(formatSpeedCompact(0)).toBe('0B')
    expect(formatSpeedCompact(1023)).toBe('1023B')
    expect(formatSpeedCompact(803 * 1024)).toBe('803K')
    expect(formatSpeedCompact(34.6 * 1024)).toBe('34.6K')
    expect(formatSpeedCompact(1.28 * 1024 ** 2)).toBe('1.28M')
    expect(formatSpeedCompact(1023.9 * 1024)).toBe('1024K')
    expect(formatSpeedCompact(null)).toBe('—')
    for (const value of [0, 999, 1023, 1024, 99_999, 1_048_575, 5e8, 9.99e11]) {
      expect(formatSpeedCompact(value).length).toBeLessThanOrEqual(6)
    }
  })

  it('classifies delays and always labels a failure in words', () => {
    expect(delayTone(80, false)).toBe('good')
    expect(delayTone(500, false)).toBe('fair')
    expect(delayTone(1500, false)).toBe('poor')
    expect(delayTone(null, true)).toBe('fail')
    expect(delayTone(null, false)).toBe('none')
    expect(delayText(null, true)).toBe('超时')
    expect(delayText(120, false)).toBe('120 ms')
    expect(delayText(null, false)).toBe('')
  })

  it('describes relative times and expiry', () => {
    const now = Date.UTC(2026, 10, 15)
    expect(formatRelative(null, now)).toBe('从未')
    expect(formatRelative(now - 10_000, now)).toBe('刚刚')
    expect(formatRelative(now - 5 * 60_000, now)).toBe('5 分钟前')
    expect(formatRelative(now - 3 * 3_600_000, now)).toBe('3 小时前')
    expect(formatRelative(now - 2 * 86_400_000, now)).toBe('2 天前')
    expect(daysLeft(now / 1000 + 10 * 86400, now)).toBe(10)
    expect(daysLeft(now / 1000 - 86400, now)).toBeLessThan(0)
  })

  it('computes usage only when a positive total exists', () => {
    expect(usagePercent(50, 200)).toBe(25)
    expect(usagePercent(500, 200)).toBe(100)
    expect(usagePercent(10, 0)).toBeNull()
    expect(usagePercent(null, 100)).toBeNull()
  })

  it('labels protocols and hosts', () => {
    expect(protocolLabel('vless')).toBe('VLESS')
    expect(protocolLabel('url-test')).toBe('自动')
    expect(protocolLabel('custom')).toBe('custom')
    expect(protocolLabel('')).toBe('')
    expect(hostOf('https://sub.example.com/a?b=1')).toBe('sub.example.com')
    expect(hostOf('not a url')).toBe('not a url')
  })

  it('recognises subscription quota/expiry pseudo-nodes without catching real servers', () => {
    for (const name of [
      '【KLM】Traffic Reset：17 Days Left',
      '【KLM】Expire Date：2027/05/04',
      '【KLM】4.49 GB | 500 GB',
      '剩余流量：120.5 GB',
      '套餐到期：2026-12-31',
      '距离下次重置剩余：12 天',
    ]) {
      expect(isInfoNode(name)).toBe(true)
    }
    for (const name of ['【KLM】🇭🇰 Hong Kong 01', '香港 01 流量倍率 0.5', '【LOCAL】🇭🇰 香港|hyperpods->nnc', 'US 10Gbps']) {
      expect(isInfoNode(name)).toBe(false)
    }
  })

  it('describes automatic strategies and follows nested group picks', () => {
    expect(groupStrategy('fallback')?.ordered).toBe(true)
    expect(groupStrategy('URLTest')?.label).toBe('自动')
    expect(groupStrategy('LoadBalance')?.label).toBe('负载均衡')
    expect(groupStrategy('smart')?.label).toBe('智能')
    expect(groupStrategy('select')).toBeNull()
    expect(protocolLabel('Shadowsocks')).toBe('SS')
    expect(protocolLabel('smart')).toBe('智能')

    const groups = [
      { name: '节点选择', now: '自动选择' },
      { name: '自动选择', now: '香港 01' },
      { name: 'A', now: 'B' },
      { name: 'B', now: 'A' },
    ]
    expect(resolveChain('节点选择', groups)).toEqual(['自动选择', '香港 01'])
    expect(resolveChain('A', groups)).toEqual(['B', 'A'])
    expect(resolveChain('missing', groups)).toEqual([])
  })

  it('lists only unhidden groups while chains still pass through hidden ones', () => {
    const groups = [
      { name: '漏网之鱼', now: '节点选择', hidden: false },
      { name: '节点选择', now: '香港 01', hidden: true },
      { name: '自动选择', now: '日本 01' },
    ]
    expect(listedGroups(groups).map((group) => group.name)).toEqual(['漏网之鱼', '自动选择'])
    expect(resolveChain('漏网之鱼', groups)).toEqual(['节点选择', '香港 01'])
  })

  it('lets select groups and fixable auto groups take a hand-picked node', () => {
    expect(canPickNode({ kind: 'manual' })).toBe(true)
    expect(canPickNode({ kind: 'auto', pinnable: true })).toBe(true)
    expect(canPickNode({ kind: 'auto', pinnable: false })).toBe(false)
    expect(canPickNode({ kind: 'auto' })).toBe(false)
  })
})
