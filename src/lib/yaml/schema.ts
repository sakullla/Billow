/**
 * The subset of the Mihomo config schema the editor completes. Each node lists
 * its keys (`keys`), the schema of list items (`item`), or fixed scalar values
 * (`values`). Docs are short Chinese hints shown beside a suggestion.
 * Source: https://wiki.metacubex.one/config/ (general, dns, tun, sniffer,
 * proxies, proxy-groups, rules, rule-providers, proxy-providers).
 */
export interface SchemaNode {
  doc?: string
  /** Fixed scalar choices. */
  values?: readonly string[]
  /** Mapping keys. */
  keys?: Record<string, SchemaNode>
  /** Schema of each sequence item. */
  item?: SchemaNode
  /** Sequence items are proxy/group names from the current config. */
  names?: 'proxies' | 'groups' | 'targets'
  /** Sequence items are rules (`TYPE,payload,TARGET`). */
  rules?: boolean
}

const BOOL = ['true', 'false'] as const
const bool = (doc: string): SchemaNode => ({ doc, values: BOOL })
const text = (doc: string): SchemaNode => ({ doc })
const one = (doc: string, values: readonly string[]): SchemaNode => ({ doc, values })
const list = (doc: string, item: SchemaNode = {}): SchemaNode => ({ doc, item })

export const PROXY_TYPES = [
  'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'wireguard', 'snell',
  'socks5', 'http', 'ssh', 'anytls', 'mieru', 'direct', 'dns',
] as const

export const GROUP_TYPES = ['select', 'url-test', 'fallback', 'load-balance', 'relay'] as const

export const RULE_TYPES = [
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX', 'GEOSITE',
  'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN', 'GEOIP', 'SRC-GEOIP', 'SRC-IP-ASN', 'SRC-IP-CIDR',
  'SRC-IP-SUFFIX', 'DST-PORT', 'SRC-PORT', 'IN-PORT', 'IN-TYPE', 'IN-USER', 'IN-NAME',
  'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'PROCESS-NAME', 'PROCESS-NAME-REGEX', 'UID', 'NETWORK',
  'DSCP', 'RULE-SET', 'AND', 'OR', 'NOT', 'SUB-RULE', 'MATCH',
] as const

/** Built-in policies every rule may target. */
export const BUILTIN_TARGETS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'] as const

const PROXY: SchemaNode = {
  keys: {
    name: text('节点名称'),
    type: one('协议类型', PROXY_TYPES),
    server: text('服务器地址'),
    port: text('端口'),
    password: text('密码'),
    uuid: text('UUID'),
    cipher: text('加密方式'),
    udp: bool('允许 UDP'),
    tls: bool('启用 TLS'),
    sni: text('TLS SNI'),
    servername: text('TLS 服务器名'),
    'skip-cert-verify': bool('跳过证书校验'),
    'client-fingerprint': one('TLS 指纹', ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random']),
    alpn: list('ALPN'),
    network: one('传输层', ['tcp', 'ws', 'http', 'h2', 'grpc', 'xhttp']),
    flow: one('VLESS 流控', ['xtls-rprx-vision']),
    'reality-opts': { doc: 'REALITY', keys: { 'public-key': text('公钥'), 'short-id': text('Short ID') } },
    'ws-opts': { doc: 'WebSocket', keys: { path: text('路径'), headers: text('请求头') } },
    'grpc-opts': { doc: 'gRPC', keys: { 'grpc-service-name': text('服务名') } },
    'dialer-proxy': { doc: '前置代理', names: 'targets' },
    tfo: bool('TCP Fast Open'),
    mptcp: bool('Multipath TCP'),
    'ip-version': one('IP 版本', ['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer']),
    smux: { doc: '多路复用', keys: { enabled: bool('启用'), protocol: one('协议', ['smux', 'yamux', 'h2mux']) } },
  },
}

const GROUP: SchemaNode = {
  keys: {
    name: text('代理组名称'),
    type: one('代理组类型', GROUP_TYPES),
    proxies: { doc: '成员', item: { names: 'targets' } },
    use: list('引用的代理集'),
    url: text('测速地址'),
    interval: text('测速间隔（秒）'),
    tolerance: text('切换容差（毫秒）'),
    lazy: bool('无流量时不测速'),
    timeout: text('测速超时（毫秒）'),
    'max-failed-times': text('最大失败次数'),
    strategy: one('负载均衡策略', ['round-robin', 'consistent-hashing', 'sticky-sessions']),
    filter: text('筛选节点（正则）'),
    'exclude-filter': text('排除节点（正则）'),
    'exclude-type': text('排除协议类型'),
    'include-all': bool('包含全部节点与代理集'),
    'include-all-proxies': bool('包含全部节点'),
    'include-all-providers': bool('包含全部代理集'),
    'disable-udp': bool('禁用 UDP'),
    hidden: bool('在面板中隐藏'),
    icon: text('图标地址'),
  },
}

const PROVIDER: SchemaNode = {
  keys: {
    type: one('来源类型', ['http', 'file', 'inline']),
    url: text('下载地址'),
    path: text('本地路径'),
    interval: text('更新间隔（秒）'),
    proxy: { doc: '下载时使用的代理', names: 'targets' },
    behavior: one('规则集行为', ['domain', 'ipcidr', 'classical']),
    format: one('规则集格式', ['yaml', 'text', 'mrs']),
    'health-check': {
      doc: '健康检查',
      keys: { enable: bool('启用'), url: text('测速地址'), interval: text('间隔（秒）'), lazy: bool('无流量时不测速') },
    },
    override: text('覆写代理集节点属性'),
    filter: text('筛选节点（正则）'),
  },
}

const DNS: SchemaNode = {
  doc: 'DNS 设置',
  keys: {
    enable: bool('启用内置 DNS'),
    listen: text('监听地址，如 0.0.0.0:53'),
    ipv6: bool('解析 AAAA 记录'),
    'prefer-h3': bool('优先 DoH3'),
    'use-hosts': bool('使用配置中的 hosts'),
    'use-system-hosts': bool('使用系统 hosts'),
    'respect-rules': bool('DNS 连接遵循路由规则'),
    'enhanced-mode': one('增强模式', ['fake-ip', 'redir-host', 'normal']),
    'fake-ip-range': text('Fake-IP 网段'),
    'fake-ip-filter-mode': one('Fake-IP 过滤模式', ['blacklist', 'whitelist']),
    'fake-ip-filter': list('不使用 Fake-IP 的域名'),
    'default-nameserver': list('解析 DNS 服务器域名用的 IP DNS'),
    nameserver: list('默认 DNS 服务器'),
    fallback: list('备用 DNS 服务器'),
    'fallback-filter': {
      doc: '何时使用 fallback',
      keys: { geoip: bool('按 GeoIP 判断'), 'geoip-code': text('国家代码'), geosite: list('GeoSite'), ipcidr: list('IP 段'), domain: list('域名') },
    },
    'proxy-server-nameserver': list('解析代理节点域名的 DNS'),
    'direct-nameserver': list('直连流量使用的 DNS'),
    'nameserver-policy': text('按域名指定 DNS'),
    'cache-algorithm': one('缓存算法', ['lru', 'arc']),
  },
}

const TUN: SchemaNode = {
  doc: 'TUN 设置',
  keys: {
    enable: bool('启用 TUN'),
    stack: one('网络栈', ['system', 'gvisor', 'mixed']),
    device: text('网卡名称'),
    'auto-route': bool('自动设置路由'),
    'auto-redirect': bool('自动配置 iptables/nftables 重定向'),
    'auto-detect-interface': bool('自动选择出口网卡'),
    'strict-route': bool('严格路由'),
    'dns-hijack': list('劫持的 DNS 地址'),
    mtu: text('MTU'),
    'endpoint-independent-nat': bool('独立于端点的 NAT'),
    'route-address': list('仅路由这些网段'),
    'route-exclude-address': list('排除这些网段'),
    'include-package': list('仅代理这些安卓应用'),
    'exclude-package': list('排除这些安卓应用'),
  },
}

const SNIFFER: SchemaNode = {
  doc: '域名嗅探',
  keys: {
    enable: bool('启用嗅探'),
    'force-dns-mapping': bool('对 redir-host 强制嗅探'),
    'parse-pure-ip': bool('嗅探纯 IP 连接'),
    'override-destination': bool('用嗅探结果改写目标'),
    sniff: {
      doc: '嗅探协议',
      keys: {
        HTTP: { doc: 'HTTP', keys: { ports: list('端口'), 'override-destination': bool('改写目标') } },
        TLS: { doc: 'TLS', keys: { ports: list('端口') } },
        QUIC: { doc: 'QUIC', keys: { ports: list('端口') } },
      },
    },
    'force-domain': list('强制嗅探的域名'),
    'skip-domain': list('跳过嗅探的域名'),
  },
}

export const MIHOMO_SCHEMA: SchemaNode = {
  keys: {
    'mixed-port': text('HTTP/SOCKS 混合端口'),
    port: text('HTTP 端口'),
    'socks-port': text('SOCKS5 端口'),
    'redir-port': text('透明代理端口'),
    'tproxy-port': text('TProxy 端口'),
    'allow-lan': bool('允许局域网连接'),
    'bind-address': text('监听地址'),
    authentication: list('代理认证 user:pass'),
    'skip-auth-prefixes': list('免认证网段'),
    mode: one('出站模式', ['rule', 'global', 'direct']),
    'log-level': one('日志级别', ['silent', 'error', 'warning', 'info', 'debug']),
    ipv6: bool('允许 IPv6'),
    'unified-delay': bool('统一延迟'),
    'tcp-concurrent': bool('TCP 并发'),
    'find-process-mode': one('进程匹配', ['always', 'strict', 'off']),
    'global-client-fingerprint': one('全局 TLS 指纹', ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random']),
    'keep-alive-interval': text('TCP Keep-Alive 间隔（秒）'),
    'keep-alive-idle': text('TCP Keep-Alive 空闲（秒）'),
    'disable-keep-alive': bool('禁用 Keep-Alive'),
    'external-controller': text('RESTful API 地址'),
    'external-ui': text('面板目录'),
    secret: text('API 密钥'),
    'interface-name': text('出口网卡'),
    'routing-mark': text('路由标记'),
    'geodata-mode': bool('使用 dat 格式 GeoIP'),
    'geodata-loader': one('Geo 数据加载方式', ['standard', 'memconservative']),
    'geo-auto-update': bool('自动更新 Geo 数据'),
    'geo-update-interval': text('Geo 更新间隔（小时）'),
    'geox-url': {
      doc: 'Geo 数据下载地址',
      keys: { geoip: text('GeoIP'), geosite: text('GeoSite'), mmdb: text('MMDB'), asn: text('ASN') },
    },
    profile: {
      doc: '缓存',
      keys: { 'store-selected': bool('记住手动选择的节点'), 'store-fake-ip': bool('持久化 Fake-IP 映射') },
    },
    hosts: text('自定义 hosts'),
    dns: DNS,
    tun: TUN,
    sniffer: SNIFFER,
    proxies: { doc: '节点', item: PROXY },
    'proxy-groups': { doc: '代理组', item: GROUP },
    'proxy-providers': { doc: '代理集', keys: {}, item: PROVIDER },
    'rule-providers': { doc: '规则集', keys: {}, item: PROVIDER },
    rules: { doc: '分流规则', item: { rules: true } },
    'sub-rules': text('子规则'),
    experimental: text('实验功能'),
  },
}

/** Named mappings (`proxy-providers: { name: {...} }`) use `item` for every child key. */
export function child(node: SchemaNode | undefined, key: string): SchemaNode | undefined {
  if (!node) return undefined
  if (key === '[]') return node.item
  return node.keys?.[key] ?? (node.keys && node.item ? node.item : undefined)
}

export function resolve(path: readonly string[]): SchemaNode | undefined {
  let node: SchemaNode | undefined = MIHOMO_SCHEMA
  for (const key of path) node = child(node, key)
  return node
}
