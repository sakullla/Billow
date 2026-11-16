import { describe, expect, it } from 'vitest'
import { subscriptionUserAgent } from './subscription'

describe('subscription User-Agent', () => {
  it('uses subscription override, global override, actual version, then an unversioned fallback', () => {
    expect(subscriptionUserAgent('v1.19.34')).toBe('clash.meta/v1.19.34')
    expect(subscriptionUserAgent('alpha-build')).toBe('clash.meta/alpha-build')
    expect(subscriptionUserAgent(null)).toBe('clash.meta')
    expect(subscriptionUserAgent('  ')).toBe('clash.meta')
    expect(subscriptionUserAgent('v1.19.34', ' global ', ' custom ')).toBe('custom')
    expect(subscriptionUserAgent('v1.19.34', ' global ', ' ')).toBe('global')
  })
})
