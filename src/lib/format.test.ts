import { describe, expect, it } from 'vitest'
import {
  daysLeft,
  delayText,
  delayTone,
  formatBytes,
  formatRelative,
  formatSpeed,
  hostOf,
  protocolLabel,
  usagePercent,
} from './format'

describe('format', () => {
  it('formats byte sizes with sensible precision', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1536)).toBe('1.50 KB')
    expect(formatBytes(15 * 1024 * 1024)).toBe('15.0 MB')
    expect(formatBytes(200 * 1024 ** 3)).toBe('200 GB')
    expect(formatBytes(null)).toBe('—')
    expect(formatSpeed(2048)).toBe('2.00 KB/s')
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
})
