import { describe, expect, it } from 'vitest'
import { bypassOverride, bypassRule } from './bypass'

describe('bypass list to direct rules', () => {
  it('maps domains, wildcards and address ranges', () => {
    expect(bypassRule('g7e6ai.com')).toBe('DOMAIN-SUFFIX,g7e6ai.com,DIRECT')
    expect(bypassRule('*.corp.local')).toBe('DOMAIN-SUFFIX,corp.local,DIRECT')
    expect(bypassRule('+.e6yun.com')).toBe('DOMAIN-SUFFIX,e6yun.com,DIRECT')
    expect(bypassRule('time.*.com')).toBe('DOMAIN-WILDCARD,time.*.com,DIRECT')
    expect(bypassRule('localhost')).toBe('DOMAIN,localhost,DIRECT')
    expect(bypassRule('10.*')).toBe('IP-CIDR,10.0.0.0/8,DIRECT,no-resolve')
    expect(bypassRule('172.16.*')).toBe('IP-CIDR,172.16.0.0/16,DIRECT,no-resolve')
    expect(bypassRule('192.168.1.5')).toBe('IP-CIDR,192.168.1.5/32,DIRECT,no-resolve')
    expect(bypassRule('100.64.0.0/10')).toBe('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve')
    expect(bypassRule('fd00::/8')).toBe('IP-CIDR6,fd00::/8,DIRECT,no-resolve')
    expect(bypassRule('<local>')).toBeNull()
  })

  it('builds one +rules block without duplicates', () => {
    const text = bypassOverride(['<local>', 'a.com', '*.a.com', '10.*'])
    expect(text).toContain('+rules:\n  - DOMAIN-SUFFIX,a.com,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n')
    expect(bypassOverride(['<local>'])).toBe('')
  })
})
