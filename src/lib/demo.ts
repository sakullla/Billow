import type { Backend, NodeTestEvent } from './backend'
import { ruleKeys } from './backend'
import {
  emptyKernelSettings,
  emptySnapshot,
  type AppInfo,
  type ConnectionRow,
  type KernelStatus,
  type LogLine,
  type NodeGroup,
  type ProviderRow,
  type ProfileItem,
  type RuleRow,
  type Snapshot,
  type ThemePreference,
} from './types'

/**
 * In-memory backend used when the page runs outside Tauri (browser preview, tests).
 * It behaves like the real one closely enough to exercise every screen.
 */

const REGIONS = ['香港', '日本', '新加坡', '美国', '台湾', '韩国', '德国', '英国']
const TYPES = ['vless', 'trojan', 'ss', 'hysteria2', 'vmess', 'tuic']
const HOSTS = [
  'www.google.com',
  'api.github.com',
  'i.ytimg.com',
  'www.youtube.com',
  'gateway.icloud.com',
  'cdn.jsdelivr.net',
  'api.openai.com',
  'claude.ai',
  'www.bilibili.com',
  'registry.npmjs.org',
  'discord.com',
  'pbs.twimg.com',
]
const PROCESSES = ['chrome', 'Telegram', 'node', 'Code', 'curl', 'Safari', 'Discord']

function nodeNames(): string[] {
  const names: string[] = []
  REGIONS.forEach((region, index) => {
    const count = index < 3 ? 3 : 2
    for (let i = 1; i <= count; i += 1) names.push(`${region} ${String(i).padStart(2, '0')}`)
  })
  return names
}

interface DemoOptions {
  profiles?: boolean
  platform?: 'desktop' | 'android'
  /** Group icons by group name; include an unreachable URL to exercise the fallback. */
  groupIcons?: Record<string, string>
  /** Simulate a `/connections` read failure while connected. */
  connectionsFailure?: boolean
  /** When false, `/rules` reports no hit statistics. */
  rulesExtra?: boolean
}

const DEMO_GROUP_ICONS: Record<string, string> = {
  流媒体: 'https://icons.example.com/media.png',
  OpenAI: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
  国内网站: 'https://unreachable.invalid/cn.png',
}

export function createDemoBackend(options: DemoOptions = {}): Backend {
  const names = nodeNames()
  const groupIcons = options.groupIcons ?? DEMO_GROUP_ICONS
  const rulesExtra = options.rulesExtra !== false
  const types = new Map(names.map((name, index) => [name, TYPES[index % TYPES.length]]))
  const state: Snapshot = emptySnapshot()
  state.platform = options.platform ?? 'desktop'
  state.mode = 'rule'
  let theme: ThemePreference = 'system'
  let entry = 'home'
  let kernel: KernelStatus = { channel: 'stable', failure: null, ready: true, version: 'v1.19.17' }
  let app: AppInfo = {
    version: '0.2.0',
    platform: 'demo',
    autostart: false,
    close_to_tray: true,
    silent_start: false,
    data_dir: null,
  }
  const delays = new Map<string, number | null>()
  const selections = new Map<string, string>([['节点选择', '香港 01']])
  const autoNow = new Map<string, string>()
  let connections: ConnectionRow[] = []
  let totals = { up: 0, down: 0 }
  let startedAt: number | null = null
  let nextId = 1
  const listeners = new Set<(snapshot: Snapshot) => void>()
  const contents = new Map<string, string>()

  const groupsDef = (): { name: string; type: string; proxies: string[] }[] => [
    { name: '节点选择', type: 'select', proxies: ['自动选择', '故障转移', ...names, 'DIRECT'] },
    { name: '自动选择', type: 'url-test', proxies: names },
    { name: '故障转移', type: 'fallback', proxies: names.slice(0, 6) },
    { name: '流媒体', type: 'select', proxies: ['节点选择', ...names.filter((n) => !n.startsWith('德国'))] },
    { name: 'OpenAI', type: 'select', proxies: ['美国 01', '美国 02', '日本 01', '新加坡 01'] },
    { name: '国内网站', type: 'select', proxies: ['DIRECT', '节点选择'] },
    { name: '漏网之鱼', type: 'select', proxies: ['节点选择', 'DIRECT'] },
  ]

  function addProfile(partial: Partial<ProfileItem>): ProfileItem {
    const id = `p${nextId++}`
    const profile: ProfileItem = {
      id,
      name: '新配置',
      kind: 'subscription',
      source: '',
      current: false,
      failure: null,
      override_text: '',
      override_error: null,
      used: null,
      total: null,
      expire: null,
      last_success_ms: null,
      interval_hours: 0,
      updated_ms: null,
      proxy_count: names.length,
      ...partial,
    }
    state.profiles.push(profile)
    contents.set(id, `mixed-port: 7890\nmode: rule\nproxies:\n${names.map((n) => `  - { name: "${n}", type: ${types.get(n)}, server: example.com, port: 443 }`).join('\n')}\n`)
    return profile
  }

  if (options.profiles !== false) {
    const now = Date.now()
    addProfile({
      name: '星河云',
      source: 'https://sub.example.com/api/v1/client/subscribe?token=demo',
      used: 86.4 * 1024 ** 3,
      total: 200 * 1024 ** 3,
      expire: Math.floor(now / 1000) + 41 * 86400,
      last_success_ms: now - 2 * 3600_000,
      updated_ms: now - 2 * 3600_000,
      interval_hours: 12,
    })
    addProfile({
      name: '备用机场',
      source: 'https://backup.example.net/link/abcdef?clash=1',
      used: 12.1 * 1024 ** 3,
      total: 50 * 1024 ** 3,
      expire: Math.floor(now / 1000) + 5 * 86400,
      last_success_ms: now - 3 * 86400_000,
      updated_ms: now - 3 * 86400_000,
    })
    addProfile({ name: 'home-lab.yaml', kind: 'local', proxy_count: 4, updated_ms: now - 9 * 86400_000 })
    state.active_id = 'p1'
    state.mixed_port = 7890
  }

  if (state.platform === 'android') {
    state.installed = [
      { name: 'Chrome', package_name: 'com.android.chrome' },
      { name: 'Telegram', package_name: 'org.telegram.messenger' },
      { name: '微信', package_name: 'com.tencent.mm' },
      { name: '支付宝', package_name: 'com.eg.android.AlipayGphone' },
      { name: 'YouTube', package_name: 'com.google.android.youtube' },
      { name: '哔哩哔哩', package_name: 'tv.danmaku.bili' },
    ]
    state.excluded = ['com.tencent.mm']
  }

  const ruleSeeds: { kind: string; payload: string; proxy: string }[] = [
    { kind: 'DomainSuffix', payload: 'openai.com', proxy: 'OpenAI' },
    { kind: 'DomainSuffix', payload: 'claude.ai', proxy: 'OpenAI' },
    { kind: 'DomainKeyword', payload: 'youtube', proxy: '流媒体' },
    { kind: 'DomainSuffix', payload: 'netflix.com', proxy: '流媒体' },
    { kind: 'DomainSuffix', payload: 'github.com', proxy: '节点选择' },
    { kind: 'DomainSuffix', payload: 'google.com', proxy: '节点选择' },
    { kind: 'RuleSet', payload: 'telegram', proxy: '节点选择' },
    { kind: 'DomainSuffix', payload: 'bilibili.com', proxy: '国内网站' },
    { kind: 'RuleSet', payload: 'cn-domains', proxy: '国内网站' },
    { kind: 'GeoIP', payload: 'LAN', proxy: 'DIRECT' },
    { kind: 'GeoIP', payload: 'CN', proxy: '国内网站' },
    { kind: 'Match', payload: '', proxy: '漏网之鱼' },
  ]
  const ruleCounts = [18, 6, 130, 24, 91, 512, 77, 0, 1204, 880, 320, 46]
  const rules: RuleRow[] = ruleSeeds.map((rule, index) => ({
    ...rule,
    hit_count: rulesExtra ? ruleCounts[index] ?? 0 : null,
    last_hit: rulesExtra ? new Date(Date.now() - (index + 1) * 7 * 60_000).toISOString() : null,
  }))
  const ruleKeyList = ruleKeys(rules)
  const disabledRules = new Set<string>()
  const nodeTestListeners = new Set<(event: NodeTestEvent) => void>()

  const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000).toISOString()
  const providerRows: ProviderRow[] = [
    { name: '机场订阅', kind: 'proxy', vehicle: 'HTTP', behavior: '', format: '', count: 19, updated_at: hoursAgo(5), used: 86 * 1024 ** 3, total: 200 * 1024 ** 3, expire: null },
    { name: '自建节点', kind: 'proxy', vehicle: 'File', behavior: '', format: '', count: 3, updated_at: hoursAgo(80), used: null, total: null, expire: null },
    { name: 'cn-domains', kind: 'rule', vehicle: 'HTTP', behavior: 'Domain', format: 'MrsRule', count: 112480, updated_at: hoursAgo(20), used: null, total: null, expire: null },
    { name: 'telegram', kind: 'rule', vehicle: 'HTTP', behavior: 'IPCIDR', format: 'YamlRule', count: 18, updated_at: hoursAgo(20), used: null, total: null, expire: null },
    { name: 'private', kind: 'rule', vehicle: 'Inline', behavior: 'Classical', format: '', count: 6, updated_at: hoursAgo(20), used: null, total: null, expire: null },
  ]

  function log(level: LogLine['level'], message: string) {
    state.logs.push({ level, message, time_ms: Date.now() })
    if (state.logs.length > 1000) state.logs.splice(0, state.logs.length - 1000)
  }

  function catalog(): NodeGroup[] {
    if (!state.active_id) return []
    return groupsDef().map((group) => {
      const manual = group.type === 'select'
      const now = manual
        ? selections.get(group.name) ?? group.proxies[0]
        : autoNow.get(group.name) ?? (state.kernel_running ? group.proxies[0] : '')
      return {
        name: group.name,
        kind: manual ? 'manual' : 'auto',
        now,
        sort: 'default',
        group_type: group.type,
        icon: groupIcons[group.name] ?? null,
        nodes: group.proxies.map((name) => {
          const delay = delays.get(name)
          return {
            name,
            delay_ms: delay ?? null,
            failed: delay === null,
            selected: name === now,
            node_type: types.get(name) ?? groupsDef().find((g) => g.name === name)?.type ?? (name === 'DIRECT' ? 'direct' : ''),
          }
        }),
      }
    })
  }

  function makeConnection(): ConnectionRow {
    const host = HOSTS[Math.floor(Math.random() * HOSTS.length)]
    const chain = host.includes('bilibili') ? 'DIRECT' : selections.get('节点选择') ?? '香港 01'
    return {
      id: Math.random().toString(16).slice(2, 10) + '-' + Date.now().toString(16),
      host,
      outbound: chain,
      network: Math.random() > 0.85 ? 'udp' : 'tcp',
      conn_type: 'HTTP Connect',
      destination: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.0.${Math.floor(Math.random() * 255)}:443`,
      source: `127.0.0.1:${50000 + Math.floor(Math.random() * 9000)}`,
      process: PROCESSES[Math.floor(Math.random() * PROCESSES.length)],
      rule: host.includes('bilibili') ? 'DomainSuffix' : 'Match',
      rule_payload: host.includes('bilibili') ? 'bilibili.com' : '',
      chains: chain === 'DIRECT' ? ['DIRECT'] : [chain, '节点选择'],
      upload: Math.floor(Math.random() * 40_000),
      download: Math.floor(Math.random() * 4_000_000),
      start: new Date(Date.now() - Math.floor(Math.random() * 600_000)).toISOString(),
    }
  }

  function tick() {
    if (!state.connected) {
      state.upload = null
      state.download = null
      state.upload_total = null
      state.download_total = null
      connections = []
      return
    }
    const wave = Math.sin(Date.now() / 4000)
    const up = Math.max(0, Math.round(18_000 + wave * 12_000 + Math.random() * 15_000))
    const down = Math.max(0, Math.round(420_000 + wave * 380_000 + Math.random() * 600_000))
    state.upload = up
    state.download = down
    totals = { up: totals.up + up, down: totals.down + down }
    state.upload_total = totals.up
    state.download_total = totals.down
    connections = connections
      .filter(() => Math.random() > 0.06)
      .map((row) => ({ ...row, upload: row.upload + Math.floor(Math.random() * 3000), download: row.download + Math.floor(Math.random() * 90_000) }))
    while (connections.length < 14) connections.push(makeConnection())
    if (Math.random() > 0.6) {
      const row = connections[Math.floor(Math.random() * connections.length)]
      log('info', `[TCP] ${row.source} --> ${row.host}:443 match ${row.rule}(${row.rule_payload}) using ${row.chains.join('[')}${row.chains.length > 1 ? ']' : ''}`)
    }
    if (Math.random() > 0.97) log('warning', `[UDP] dial ${selections.get('节点选择')} error: i/o timeout`)
  }

  function snapshot(): Snapshot {
    tick()
    state.profiles.forEach((profile) => (profile.current = profile.id === state.active_id))
    const failure = Boolean(options.connectionsFailure) && state.connected
    state.connections = failure ? [] : [...connections]
    state.connection_total = state.connected && !failure ? connections.length : 0
    state.connections_error = failure ? '连接没有读取' : null
    state.kernel_memory = state.connected ? 128 * 1024 * 1024 : null
    state.kernel_uptime_secs =
      state.connected && startedAt !== null ? Math.max(0, Math.floor((Date.now() - startedAt) / 1000)) : null
    state.node_catalog = catalog()
    state.nodes_notice = state.active_id ? null : '需要先添加或更新配置'
    state.config_values = {
      mixed_port: 7890,
      allow_lan: false,
      ipv6: false,
      log_level: 'info',
      unified_delay: true,
      tcp_concurrent: true,
      find_process_mode: 'strict',
    }
    state.mixed_port = state.settings.mixed_port ?? (state.active_id ? 7890 : null)
    return structuredClone(state)
  }

  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
  const done = async (ms = 120) => {
    await wait(ms)
    const snap = snapshot()
    listeners.forEach((handler) => handler(snap))
    return snap
  }
  const profile = (id: string) => state.profiles.find((item) => item.id === id)

  function startKernel(): boolean {
    if (!state.active_id) {
      state.failure = '没有可用配置'
      log('error', state.failure)
      return false
    }
    state.kernel_running = true
    state.connected = true
    state.failure = null
    startedAt = Date.now()
    autoNow.set('自动选择', names[1])
    autoNow.set('故障转移', names[0])
    log('info', `Mihomo ${kernel.version} started, mixed proxy listening at 127.0.0.1:${state.mixed_port ?? 7890}`)
    return true
  }

  async function probe(list: string[]) {
    await wait(700)
    for (const name of list) {
      if (name === 'DIRECT') delays.set(name, 2 + Math.floor(Math.random() * 6))
      else if (Math.random() < 0.08) delays.set(name, null)
      else delays.set(name, 40 + Math.floor(Math.random() * 900 * Math.random()))
    }
  }

  function rulesSnapshot() {
    const disabled = [...disabledRules]
    if (!state.kernel_running) return { rules: [], error: '内核没有运行', disabled }
    return {
      rules: rules.filter((_, index) => !disabledRules.has(ruleKeyList[index])).map((row) => ({ ...row })),
      error: null,
      disabled,
    }
  }

  /** Emits one `node-test` event per node on a timer so progress is visible. */
  function simulateTestAll(): Promise<void> {
    const list = [...new Set(groupsDef().flatMap((group) => group.proxies))]
    const total = list.length
    return new Promise((resolve) => {
      let index = 0
      let tested = 0
      const step = () => {
        if (index >= list.length) {
          resolve()
          return
        }
        const name = list[index]
        const delay =
          name === 'DIRECT' ? 2 + (index % 6) : index % 9 === 8 ? null : 40 + ((index * 37) % 520)
        delays.set(name, delay)
        tested += 1
        const event: NodeTestEvent = { node: name, delay, failed: delay === null, tested, total }
        nodeTestListeners.forEach((handler) => handler(event))
        index += 1
        if (index < list.length) setTimeout(step, 70)
        else resolve()
      }
      step()
    })
  }

  return {
    live: false,
    async shell() {
      return { theme, last_entry: entry }
    },
    async setTheme(next) {
      theme = next
    },
    async setEntry(next) {
      entry = next
    },
    async appInfo() {
      return app
    },
    async setAutostart(enabled) {
      app = { ...app, autostart: enabled }
      return app
    },
    async setAppBehavior(closeToTray, silentStart) {
      app = { ...app, close_to_tray: closeToTray, silent_start: silentStart }
      return app
    },
    async kernel() {
      return kernel
    },
    async setChannel(channel) {
      await wait(800)
      kernel = { ...kernel, channel, version: channel === 'preview' ? 'alpha-3f2c1a9' : 'v1.19.17', failure: null }
      return kernel
    },
    async refreshKernel() {
      await wait(900)
      return kernel
    },

    state: async () => snapshot(),
    async addSubscription(url) {
      try {
        const parsed = new URL(url.trim())
        if (!/^https?:$/.test(parsed.protocol)) throw new Error('scheme')
        addProfile({ name: parsed.host, source: url.trim() })
        state.input_error = null
      } catch {
        state.input_error = '订阅链接不可用'
      }
      return done()
    },
    async addLocal(name, content) {
      if (!content.trim()) state.input_error = '配置无法应用'
      else {
        const created = addProfile({ name: name || '本地配置', kind: 'local', updated_ms: Date.now() })
        contents.set(created.id, content)
        state.input_error = null
      }
      return done()
    },
    async confirmInstall() {
      if (state.pending_url) addProfile({ name: new URL(state.pending_url).host, source: state.pending_url })
      state.pending_url = null
      return done()
    },
    async cancelInstall() {
      state.pending_url = null
      return done()
    },
    async enable(id) {
      const item = profile(id)
      if (item) {
        await wait(500)
        state.active_id = id
        item.last_success_ms = Date.now()
        item.failure = null
        delays.clear()
        if (state.kernel_running) log('info', `配置已切换为 ${item.name}`)
      }
      return done()
    },
    async update(id) {
      const item = profile(id)
      if (item) {
        await wait(900)
        item.updated_ms = Date.now()
        item.last_success_ms = Date.now()
      }
      return done()
    },
    async refresh(id) {
      return this.update(id)
    },
    async refreshAll() {
      await wait(1000)
      state.profiles.filter((p) => p.kind === 'subscription').forEach((p) => {
        p.updated_ms = Date.now()
        p.last_success_ms = Date.now()
      })
      return done()
    },
    async remove(id) {
      if (id === state.active_id && state.connected) state.notice = '请先断开连接再删除当前配置'
      else {
        state.profiles = state.profiles.filter((item) => item.id !== id)
        if (state.active_id === id) state.active_id = null
      }
      return done()
    },
    async rename(id, name) {
      const item = profile(id)
      if (item && name.trim()) item.name = name.trim()
      return done()
    },
    async setSource(id, url) {
      const item = profile(id)
      if (item) item.source = url.trim()
      return done()
    },
    async setInterval(id, hours) {
      const item = profile(id)
      if (item) item.interval_hours = hours
      return done()
    },
    async content(id) {
      return contents.get(id) ?? ''
    },
    async saveContent(id, content) {
      contents.set(id, content)
      return done()
    },
    async saveOverride(id, text) {
      const item = profile(id)
      if (item) {
        item.override_text = text
        item.override_error = /^\s*-/.test(text) ? '覆写无法应用' : null
      }
      return done()
    },

    async connect() {
      await wait(600)
      if (startKernel()) {
        if (state.platform === 'android') state.vpn = true
        else {
          state.system_proxy = true
          state.tun = state.tun_wanted
        }
      }
      return done(0)
    },
    async disconnect() {
      await wait(300)
      state.connected = false
      state.kernel_running = false
      state.system_proxy = false
      state.tun = false
      state.vpn = false
      startedAt = null
      autoNow.clear()
      log('info', '内核已停止')
      return done(0)
    },
    async setSystemProxy(enabled) {
      if (enabled && !state.kernel_running && !startKernel()) return done()
      state.system_proxy = enabled
      return done()
    },
    async setTun(enabled) {
      state.tun_wanted = enabled
      if (enabled && !state.kernel_running && !startKernel()) return done()
      state.tun = enabled
      return done(400)
    },
    async setMode(mode) {
      state.mode = mode
      log('info', `出站模式切换为 ${mode}`)
      return done()
    },
    async exclude(pkg) {
      if (!state.excluded.includes(pkg)) state.excluded.push(pkg)
      return done()
    },
    async include(pkg) {
      state.excluded = state.excluded.filter((item) => item !== pkg)
      return done()
    },

    async selectNode(group, node) {
      selections.set(group, node)
      return done(60)
    },
    async testGroup(group) {
      const def = groupsDef().find((item) => item.name === group)
      if (!state.kernel_running) state.nodes_error = '内核没有运行'
      else {
        state.nodes_error = null
        await probe(def?.proxies ?? [])
      }
      return done(0)
    },
    async testAll() {
      if (!state.kernel_running) {
        state.nodes_error = '内核没有运行'
        return done(0)
      }
      state.nodes_error = null
      await simulateTestAll()
      return done(0)
    },
    async testNode(node) {
      if (!state.kernel_running) state.nodes_error = '内核没有运行'
      else await probe([node])
      return done(0)
    },
    async onNodeTest(handler) {
      nodeTestListeners.add(handler)
      return () => nodeTestListeners.delete(handler)
    },

    async closeConnection(id) {
      connections = id ? connections.filter((row) => row.id !== id) : []
      return done(60)
    },
    async rules() {
      await wait(200)
      return rulesSnapshot()
    },
    async setRuleDisabled(key, disabled) {
      await wait(120)
      if (!state.kernel_running) throw new Error('内核没有运行')
      if (!ruleKeyList.includes(key)) throw new Error('没有这条规则')
      if (disabled) disabledRules.add(key)
      else disabledRules.delete(key)
      return rulesSnapshot()
    },
    async providers() {
      await wait(200)
      if (!state.kernel_running) return { providers: [], error: '内核没有运行' }
      return { providers: providerRows.map((row) => ({ ...row })), error: null }
    },
    async providerAction(kind, name, action) {
      await wait(900)
      const row = providerRows.find((item) => item.kind === kind && item.name === name)
      if (row && action === 'update') row.updated_at = new Date().toISOString()
      log('info', `${action === 'update' ? '更新' : '健康检查'} ${name} 完成`)
    },
    async upgradeGeo() {
      await wait(1500)
      log('info', 'GEO 数据库已更新')
    },
    async flushCache(which) {
      log('info', which === 'fakeip' ? 'FakeIP 缓存已清除' : 'DNS 缓存已清除')
      return done(100)
    },
    async clearLogs() {
      state.logs = []
      return done(0)
    },
    async exportLogs() {
      await wait(80)
      const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
      const directory =
        state.platform === 'android'
          ? '/storage/emulated/0/Android/data/app.billow/files/Documents'
          : 'C:\\Users\\demo\\Downloads'
      return `${directory}/billow-logs-${stamp}.log`
    },
    async clearNotice() {
      state.notice = null
      return done(0)
    },
    async saveSettings(settings) {
      state.settings = JSON.parse(JSON.stringify({ ...emptyKernelSettings(), ...settings }))
      return done(300)
    },
    async syncTray() {},

    async onChange(handler) {
      listeners.add(handler)
      return () => listeners.delete(handler)
    },
  }
}
