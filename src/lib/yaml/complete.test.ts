import { describe, expect, it } from 'vitest'
import { collectNames, complete } from './complete'

/** `|` marks the cursor. */
function at(source: string, known = {}) {
  const pos = source.indexOf('|')
  return complete(source.replace('|', ''), pos, known)
}

const labels = (source: string, known = {}) => at(source, known)?.options.map((option) => option.label) ?? []

describe('mihomo yaml completion', () => {
  it('offers top-level keys and skips ones already present', () => {
    const options = labels('mixed-port: 7890\nmo|')
    expect(options).toContain('mode')
    expect(labels('mode: rule\n|')).not.toContain('mode')
    expect(at('mixed-port: 7890\nmo|')?.from).toBe('mixed-port: 7890\n'.length)
  })

  it('completes fixed values after a key', () => {
    expect(labels('mode: |')).toEqual(['rule', 'global', 'direct'])
    expect(labels('log-level: in|')[0]).toBe('info')
    expect(labels('allow-lan: |')).toEqual(['true', 'false'])
  })

  it('follows indentation into nested mappings', () => {
    expect(labels('dns:\n  enable: true\n  enh|')).toEqual(['enhanced-mode'])
    expect(labels('dns:\n  enhanced-mode: |')).toEqual(['fake-ip', 'redir-host', 'normal'])
    expect(labels('tun:\n  stack: |')).toEqual(['system', 'gvisor', 'mixed'])
    // Back at column 0 the path resets to the root.
    expect(labels('dns:\n  enable: true\nsni|')).toEqual(['sniffer'])
  })

  it('inserts block structure for mapping and list keys', () => {
    const dns = at('dn|')?.options.find((option) => option.label === 'dns')
    expect(dns?.apply).toBe('dns:\n  ')
    const filter = at('dns:\n  fake-ip-fil|')?.options.find((option) => option.label === 'fake-ip-filter')
    expect(filter?.apply).toBe('fake-ip-filter:\n    - ')
  })

  it('completes keys and values inside sequence items, including compact sequences', () => {
    expect(labels('proxy-groups:\n  - name: A\n    ty|')[0]).toBe('type')
    expect(labels('proxy-groups:\n- name: A\n  type: |')).toEqual(['select', 'url-test', 'fallback', 'load-balance', 'relay'])
    expect(labels('proxies:\n  - name: a\n    type: vl|')).toEqual(['vless'])
  })

  it('completes rule types, then targets from the config and built-ins', () => {
    const source = [
      'proxies:',
      '  - {name: 香港 01, type: ss, server: a, port: 1}',
      'proxy-groups:',
      '  - name: 节点选择',
      '    type: select',
      '    proxies:',
      '      - |',
    ].join('\n')
    expect(labels(source)).toEqual(['节点选择', 'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', '香港 01'])

    expect(labels('rules:\n  - DOMAIN-SU|')).toEqual(['DOMAIN-SUFFIX'])
    expect(at('rules:\n  - DOMAIN-SU|')?.options[0].apply).toBe('DOMAIN-SUFFIX,')
    expect(labels('rules:\n  - DOMAIN-SUFFIX,google.com,|', { groups: ['Proxy'] })).toContain('Proxy')
    expect(labels('rules:\n- MATCH,|', { groups: ['Proxy'] })[0]).toBe('Proxy')
    expect(labels('rules:\n  - IP-CIDR,10.0.0.0/8,DIRECT,|')).toEqual(['no-resolve'])
    expect(labels('rule-providers:\n  ads:\n    type: http\nrules:\n  - RULE-SET,|')).toEqual(['ads'])
  })

  it('reads names from block and flow proxies, groups and rule providers', () => {
    const names = collectNames(
      'proxies:\n- name: "a b"\n  type: ss\n- {name: c, type: ss}\nproxy-groups:\n  - name: G\nrule-providers:\n  x:\n    type: http\n',
    )
    expect(names).toEqual({ proxies: ['a b', 'c'], groups: ['G'], ruleProviders: ['x'] })
  })

  it('stays quiet in comments and unknown keys', () => {
    expect(at('# mo|')).toBeNull()
    expect(at('unknown:\n  fo|')).toBeNull()
  })

  it('quotes names that YAML would misread', () => {
    const option = at('rules:\n  - MATCH,|', { groups: ['🚀 Proxy: main'] })?.options[0]
    expect(option?.apply).toBe('"🚀 Proxy: main"')
  })
})
