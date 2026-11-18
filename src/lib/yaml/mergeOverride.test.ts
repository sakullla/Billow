import { describe, expect, it } from 'vitest'
import { mergeOverrideAppend } from './mergeOverride'

describe('mergeOverrideAppend', () => {
  it('writes the snippet directly when the override is empty', () => {
    const snippet = '# 由连接详情添加\n+rules:\n  - DOMAIN-SUFFIX,vault.kim,DIRECT\n'
    const res = mergeOverrideAppend('', snippet)
    expect(res.changed).toBe(true)
    expect(res.added).toBe(1)
    expect(res.text).toBe(snippet)
  })

  it('merges into an existing +rules block without creating duplicate YAML keys', () => {
    const existing = [
      '+rules:',
      '  - DOMAIN-SUFFIX,e6gpshk.com,DIRECT',
      '  - DOMAIN,g7e6ai.com,DIRECT',
      '',
      'dns:',
      '  enable: true',
    ].join('\n')
    const snippet = '# 由连接详情添加\n+rules:\n  - DOMAIN-SUFFIX,vault.kim,DIRECT\n'
    const res = mergeOverrideAppend(existing, snippet)
    expect(res.changed).toBe(true)
    expect(res.added).toBe(1)
    expect(res.text).toBe(
      [
        '+rules:',
        '  - DOMAIN-SUFFIX,e6gpshk.com,DIRECT',
        '  - DOMAIN,g7e6ai.com,DIRECT',
        '  - DOMAIN-SUFFIX,vault.kim,DIRECT',
        '',
        'dns:',
        '  enable: true',
      ].join('\n'),
    )
  })

  it('deduplicates rules that already exist in +rules or prepend-rules', () => {
    const existing = 'prepend-rules:\n  - DOMAIN-SUFFIX,vault.kim,DIRECT\n'
    const snippet = '+rules:\n  - DOMAIN-SUFFIX,vault.kim,DIRECT\n  - DOMAIN,api.vault.kim,DIRECT\n'
    const res = mergeOverrideAppend(existing, snippet)
    expect(res.changed).toBe(true)
    expect(res.added).toBe(1)
    expect(res.text).toContain('  - DOMAIN,api.vault.kim,DIRECT')
    expect(res.text.match(/vault\.kim/g)).toHaveLength(2)

    const noop = mergeOverrideAppend(res.text, '+rules:\n  - DOMAIN,api.vault.kim,DIRECT\n')
    expect(noop.changed).toBe(false)
    expect(noop.added).toBe(0)
  })
})
