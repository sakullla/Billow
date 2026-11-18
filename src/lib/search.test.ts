import { describe, expect, it } from 'vitest'
import { highlightTokens, matchesTokens, splitQueryTokens } from './search'

describe('search helpers', () => {
  it('splits multi-word queries into unique lowercase tokens', () => {
    expect(splitQueryTokens('  ')).toEqual([])
    expect(splitQueryTokens('香港  IPLC  香港')).toEqual(['香港', 'iplc'])
  })

  it('matches all tokens regardless of order or casing', () => {
    const tokens = splitQueryTokens('iplc 香港')
    expect(matchesTokens('🇭🇰 香港 HKT 家宽 丨 IPLC 专线', tokens)).toBe(true)
    expect(matchesTokens('🇭🇰 香港 HKT 家宽', tokens)).toBe(false)
  })

  it('highlights contiguous phrases as a single span and non-adjacent tokens separately', () => {
    expect(highlightTokens('日本 02 高速', '日本 02')).toEqual([
      { text: '日本 02', hit: true },
      { text: ' 高速', hit: false },
    ])

    expect(highlightTokens('香港 HKT 丨 IPLC 专线', '香港 iplc')).toEqual([
      { text: '香港', hit: true },
      { text: ' HKT 丨 ', hit: false },
      { text: 'IPLC', hit: true },
      { text: ' 专线', hit: false },
    ])
  })

  it('coalesces overlapping token ranges cleanly', () => {
    expect(highlightTokens('Reality', 'real reality')).toEqual([
      { text: 'Reality', hit: true },
    ])
  })
})
