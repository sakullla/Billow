<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Icon from '../../components/Icon.vue'
import Modal from '../../components/Modal.vue'
import Segmented from '../../components/Segmented.vue'
import Toggle from '../../components/Toggle.vue'
import EditorDialog from '../../components/settings/EditorDialog.vue'
import ListEditorDialog from '../../components/settings/ListEditorDialog.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { listSummary, useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import { defaultDns, type DnsSettings } from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const dns = computed(() => current.value.dns)
const busy = computed(() => Boolean(store.busy.settings))

function saveDns(patch: Partial<DnsSettings>) {
  return save({ dns: { ...dns.value, ...patch } })
}

const MODES = [
  { id: 'fake-ip' as DnsSettings['enhanced_mode'], label: 'Fake-IP' },
  { id: 'redir-host' as DnsSettings['enhanced_mode'], label: 'Redir-Host' },
  { id: 'normal' as DnsSettings['enhanced_mode'], label: 'Normal' },
]
const modeHint = computed(() =>
  dns.value.enhanced_mode === 'fake-ip'
    ? tr('Fake-IP：先返回虚拟地址，连接时再解析，速度最快')
    : dns.value.enhanced_mode === 'redir-host'
      ? tr('Redir-Host：返回真实 IP 并记录映射，兼容性更好')
      : tr('Normal：标准解析，不做增强映射'),
)
const FILTER_MODES = computed(() => [
  { id: 'blacklist' as DnsSettings['fake_ip_filter_mode'], label: tr('黑名单') },
  { id: 'whitelist' as DnsSettings['fake_ip_filter_mode'], label: tr('白名单') },
  { id: 'rule' as DnsSettings['fake_ip_filter_mode'], label: tr('规则') },
])
const FILTER_MODE_HINTS = computed<Record<DnsSettings['fake_ip_filter_mode'], string>>(() => ({
  blacklist: tr('黑名单：列表中的域名返回真实 IP，其余返回虚拟地址'),
  whitelist: tr('白名单：仅列表中的域名返回虚拟地址，其余返回真实 IP'),
  rule: tr('规则：列表按规则写法自上而下匹配，例如 GEOSITE,cn,real-ip，最后写 MATCH,fake-ip'),
}))
const CACHE_ALGOS = [
  { id: 'lru' as DnsSettings['cache_algorithm'], label: 'LRU' },
  { id: 'arc' as DnsSettings['cache_algorithm'], label: 'ARC' },
]

// ── Server lists, each edited as lines.
type ListKey = 'nameserver' | 'default_nameserver' | 'fallback' | 'proxy_server_nameserver' | 'direct_nameserver' | 'fake_ip_filter'
interface ListDef {
  key: ListKey
  setting: string
  title: () => string
  hint: () => string
  empty: () => string
}
const SERVER_LISTS: ListDef[] = [
  { key: 'nameserver', setting: 'dns-nameserver', title: () => tr('主 DNS 服务器'), hint: () => tr('默认用于解析所有域名，支持 DoH / DoT / DoQ'), empty: () => tr('未设置') },
  { key: 'default_nameserver', setting: 'dns-default-nameserver', title: () => tr('引导 DNS'), hint: () => tr('只用 IP 形式，用于解析 DoH 等服务器自身的域名'), empty: () => tr('未设置') },
  { key: 'proxy_server_nameserver', setting: 'dns-proxy-nameserver', title: () => tr('节点域名解析'), hint: () => tr('解析代理节点服务器地址'), empty: () => tr('用主 DNS') },
  { key: 'direct_nameserver', setting: 'dns-direct-nameserver', title: () => tr('直连域名解析'), hint: () => tr('直连出站使用；留空则用主 DNS'), empty: () => tr('用主 DNS') },
  { key: 'fallback', setting: 'dns-fallback', title: () => tr('备用 DNS'), hint: () => tr('可选，海外服务器；留空则不启用'), empty: () => tr('不启用') },
]
const FAKE_IP_FILTER: ListDef = {
  key: 'fake_ip_filter',
  setting: 'dns-fake-ip-filter',
  title: () => tr('Fake-IP 过滤'),
  hint: () => tr('黑名单下这些域名返回真实 IP；白名单下仅这些域名返回 Fake-IP；规则模式下每行一条规则'),
  empty: () => tr('未设置'),
}
const editingList = ref<ListDef | null>(null)
const openList = (list: ListDef) => (editingList.value = list)
const closeList = () => (editingList.value = null)
const activeList = computed(() => {
  const list = editingList.value
  if (!list) return null
  return {
    title: list.title(),
    hint: list.hint(),
    items: dns.value[list.key],
    placeholder: list.key === 'fake_ip_filter' ? ['*.lan', '+.local'].join('\n') : 'https://doh.pub/dns-query',
    setting: list.setting,
  }
})
async function saveList(items: string[]) {
  const target = editingList.value
  if (!target) return
  await saveDns({ [target.key]: items })
  editingList.value = null
}

// ── Single fields: Fake-IP range and listen address save on blur / Enter.
const fakeIpRange = ref(dns.value.fake_ip_range)
const listen = ref(dns.value.listen)
const focused = ref<'range' | 'listen' | null>(null)
watch(() => dns.value.fake_ip_range, (value) => {
  if (focused.value !== 'range') fakeIpRange.value = value
})
watch(() => dns.value.listen, (value) => {
  if (focused.value !== 'listen') listen.value = value
})
function commitRange() {
  focused.value = null
  const value = fakeIpRange.value.trim()
  if (value && value !== dns.value.fake_ip_range) void saveDns({ fake_ip_range: value })
  else fakeIpRange.value = dns.value.fake_ip_range
}
function commitListen() {
  focused.value = null
  const value = listen.value.trim()
  if (value !== dns.value.listen) void saveDns({ listen: value })
}

// ── Key/value editors shared by 解析策略 and Hosts.
const splitTargets = (text: string) => text.split(/[,;\n]+/).map((item) => item.trim()).filter(Boolean)
/** `#` starts a comment only at the line start or after a space; DNS URLs may carry `#proxy` / `#h3=true`. */
const stripComment = (line: string) => line.replace(/(^|\s)#.*$/, '').trim()
function mapToRows(map: Record<string, string[]>): { key: string; val: string }[] {
  return Object.entries(map).map(([key, vals]) => ({ key, val: vals.join(', ') }))
}
function formatMapText(rows: { key: string; val: string }[]): string {
  return rows.map((row) => `${row.key} = ${row.val}`).join('\n')
}
function invalidLines(text: string, parse: (line: string) => Record<string, string[]>): number[] {
  const out: number[] = []
  text.split(/\r?\n/).forEach((line, index) => {
    if (stripComment(line) && !Object.keys(parse(line)).length) out.push(index + 1)
  })
  return out
}
function parsePolicyBatchText(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine)
    if (!line) continue
    const eq = line.indexOf('=')
    let pattern = ''
    let rest = ''
    // Also read YAML pasted from a config: `'+.a.com': [1.1.1.1, 2.2.2.2]`.
    const yamlPair = /^(['"]?)(.+?)\1:\s+(.+)$/.exec(line)
    if (eq > 0) {
      pattern = line.slice(0, eq).trim()
      rest = line.slice(eq + 1).trim()
    } else if (yamlPair) {
      pattern = yamlPair[2]!
      rest = yamlPair[3]!
    } else {
      const ws = line.search(/\s+/)
      if (ws > 0) {
        pattern = line.slice(0, ws).trim()
        rest = line.slice(ws + 1).trim()
      }
    }
    pattern = pattern.replace(/^(['"])(.*)\1$/, '$2').trim()
    const servers = splitTargets(rest.replace(/^\[(.*)\]$/, '$1')).map((item) => item.replace(/^(['"])(.*)\1$/, '$2'))
    if (pattern && servers.length) out[pattern] = servers
  }
  return out
}
function parseHostsBatchText(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  const ipLiteral = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)$/
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine)
    if (!line) continue
    const eq = line.indexOf('=')
    if (eq > 0) {
      const domain = line.slice(0, eq).trim()
      const targets = splitTargets(line.slice(eq + 1))
      if (domain && targets.length) out[domain] = targets
      continue
    }
    const tokens = line.split(/\s+/).filter(Boolean)
    if (tokens.length >= 2 && ipLiteral.test(tokens[0]!)) {
      const ip = tokens[0]!
      for (const host of tokens.slice(1)) {
        const list = out[host] ?? []
        if (!list.includes(ip)) list.push(ip)
        out[host] = list
      }
    } else if (tokens.length >= 2) {
      const domain = tokens[0]!
      const targets = splitTargets(tokens.slice(1).join(','))
      if (domain && targets.length) out[domain] = targets
    }
  }
  return out
}

type KvKind = 'policy' | 'hosts'
const kvOpen = ref<KvKind | null>(null)
const kvRows = ref<{ key: string; val: string }[]>([])
const kvBatch = ref(false)
const kvBatchText = ref('')
const newKey = ref('')
const newVal = ref('')
const valInput = ref<HTMLInputElement | null>(null)
const kvParse = computed(() => (kvOpen.value === 'policy' ? parsePolicyBatchText : parseHostsBatchText))
const kvSaved = computed(() => (kvOpen.value === 'policy' ? dns.value.nameserver_policy : dns.value.hosts))

function openKv(kind: KvKind) {
  const map = kind === 'policy' ? dns.value.nameserver_policy : dns.value.hosts
  kvRows.value = mapToRows(map)
  kvBatchText.value = formatMapText(kvRows.value)
  kvBatch.value = false
  newKey.value = ''
  newVal.value = ''
  kvOpen.value = kind
}
function buildKvMap(): Record<string, string[]> {
  if (kvBatch.value) return kvParse.value(kvBatchText.value)
  const out: Record<string, string[]> = {}
  const pending = newKey.value.trim() && newVal.value.trim() ? [{ key: newKey.value, val: newVal.value }] : []
  for (const row of [...kvRows.value, ...pending]) {
    const key = row.key.trim()
    const vals = splitTargets(row.val)
    if (key && vals.length) out[key] = vals
  }
  return out
}
const kvDraft = computed(() => buildKvMap())
const kvDirty = computed(() => JSON.stringify(kvDraft.value) !== JSON.stringify(kvSaved.value))
const kvInvalid = computed(() => (kvBatch.value && kvOpen.value ? invalidLines(kvBatchText.value, kvParse.value) : []))
watch(kvBatchText, (text) => {
  if (kvBatch.value && kvOpen.value) kvRows.value = mapToRows(kvParse.value(text))
})
function addKvRow() {
  const key = newKey.value.trim()
  const vals = splitTargets(newVal.value)
  if (!key || !vals.length) return
  const existing = kvRows.value.find((row) => row.key.trim() === key)
  if (existing) existing.val = vals.join(', ')
  else kvRows.value.push({ key, val: vals.join(', ') })
  newKey.value = ''
  newVal.value = ''
}
function onKeyEnter() {
  if (!newKey.value.trim()) return
  if (!newVal.value.trim()) {
    valInput.value?.focus()
    return
  }
  addKvRow()
}
function toggleKvBatch() {
  if (kvBatch.value) {
    if (kvInvalid.value.length) {
      store.toast(tr('第 {0} 行格式不对，修正或删除后再切换', { 0: kvInvalid.value.join('、') }), 'error')
      return
    }
    kvRows.value = mapToRows(kvParse.value(kvBatchText.value))
    kvBatch.value = false
  } else {
    addKvRow()
    kvBatchText.value = formatMapText(kvRows.value)
    kvBatch.value = true
  }
}
function addCnPolicyPreset() {
  const presetKey = 'geosite:cn,private'
  const presetVal = 'https://doh.pub/dns-query, 223.5.5.5'
  if (kvBatch.value) {
    const map = parsePolicyBatchText(kvBatchText.value)
    map[presetKey] = splitTargets(presetVal)
    kvBatchText.value = formatMapText(mapToRows(map))
    return
  }
  const existing = kvRows.value.find((row) => row.key.trim() === presetKey)
  if (existing) existing.val = presetVal
  else kvRows.value.push({ key: presetKey, val: presetVal })
}
async function saveKv() {
  const kind = kvOpen.value
  if (!kind) return
  const map = buildKvMap()
  await saveDns(kind === 'policy' ? { nameserver_policy: map } : { hosts: map })
  kvOpen.value = null
}
const policyCount = computed(() => Object.keys(dns.value.nameserver_policy).length)
const hostsCount = computed(() => Object.keys(dns.value.hosts).length)

const confirmReset = ref(false)
async function resetDns() {
  confirmReset.value = false
  await save({ dns: defaultDns() }, tr('已恢复默认设置'))
}
</script>

<template>
  <div class="pane-root" data-testid="dns-settings">
    <SettingsSection>
      <SettingsRow :title="tr('DNS 覆写')" setting="dns-override" class="srow-master" :class="{ on: snap.settings.dns_override }">
        <template #description>
          {{ snap.settings.dns_override ? tr('正在用下面的设置替换每份配置里的 dns 段与 hosts') : tr('关闭时使用配置文件自带的 DNS 设置') }}
        </template>
        <Toggle
          :model-value="snap.settings.dns_override"
          :busy="busy"
          :label="tr('DNS 覆写')"
          data-testid="dns-override"
          @update:model-value="(on) => save({ dns_override: on })"
        />
      </SettingsRow>
    </SettingsSection>
    <p v-if="!snap.settings.dns_override" class="settings-note">
      <Icon name="info" :size="14" />
      <span>{{ tr('覆写关闭时，若开启 TUN 而配置文件没有启用 DNS，Billow 会自动使用下方设置，避免 TUN 下域名无法解析。') }}</span>
    </p>

    <SettingsSection :title="tr('解析方式')">
      <SettingsRow :title="tr('域名映射模式')" :description="modeHint" setting="dns-mode" :stacked="compact">
        <Segmented
          :model-value="dns.enhanced_mode"
          :options="MODES"
          size="sm"
          :label="tr('增强模式')"
          :disabled="busy"
          data-testid="dns-enhanced-mode"
          @update:model-value="(mode) => saveDns({ enhanced_mode: mode })"
        />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection :title="tr('上游服务器')">
      <SettingsRow
        v-for="list in SERVER_LISTS"
        :key="list.key"
        nav
        :title="list.title()"
        :description="list.hint()"
        :value="listSummary(dns[list.key], list.empty())"
        :setting="list.setting"
        :data-testid="`open-${list.setting}`"
        @open="openList(list)"
      />
    </SettingsSection>

    <SettingsSection :title="tr('分流解析')">
      <SettingsRow
        nav
        :title="tr('域名解析策略')"
        :description="tr('按域名或规则集指定上游 DNS，避免国内外分流污染')"
        :value="policyCount ? tr('{0} 条', { 0: policyCount }) : tr('未设置')"
        setting="dns-policy"
        data-testid="open-dns-policy"
        @open="openKv('policy')"
      />
      <SettingsRow :title="tr('遵循分流规则')" :description="tr('DNS 查询也按分流规则走代理或直连（respect-rules）')" setting="dns-respect-rules">
        <Toggle :model-value="dns.respect_rules" :label="tr('遵循分流规则')" :disabled="busy" @update:model-value="(on) => saveDns({ respect_rules: on })" />
      </SettingsRow>
      <SettingsRow :title="tr('直连遵循解析策略')" :description="tr('直连出站解析域名时优先匹配解析策略')" setting="dns-direct-follow">
        <Toggle
          :model-value="dns.direct_nameserver_follow_policy"
          :label="tr('直连遵循解析策略')"
          :disabled="busy"
          data-testid="dns-direct-follow-policy"
          @update:model-value="(on) => saveDns({ direct_nameserver_follow_policy: on })"
        />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection title="Hosts" data-testid="dns-hosts-card">
      <SettingsRow :title="tr('使用 hosts')" :description="tr('启用配置与自定义的静态域名映射（use-hosts）')" setting="dns-use-hosts">
        <Toggle :model-value="dns.use_hosts" :label="tr('使用 hosts')" :disabled="busy" @update:model-value="(on) => saveDns({ use_hosts: on })" />
      </SettingsRow>
      <SettingsRow :title="tr('读取系统 Hosts')" :description="tr('同时读取系统的 hosts 文件（use-system-hosts）')" setting="dns-system-hosts">
        <Toggle
          :model-value="dns.use_system_hosts"
          :label="tr('读取系统 Hosts')"
          :disabled="busy"
          data-testid="dns-system-hosts"
          @update:model-value="(on) => saveDns({ use_system_hosts: on })"
        />
      </SettingsRow>
      <SettingsRow
        nav
        :title="tr('自定义 Hosts')"
        :description="tr('把域名固定解析到指定的 IP 或域名')"
        :value="hostsCount ? tr('{0} 条', { 0: hostsCount }) : tr('未设置')"
        setting="dns-hosts"
        data-testid="open-dns-hosts"
        @open="openKv('hosts')"
      />
    </SettingsSection>

    <SettingsSection
      collapsible
      :title="tr('高级')"
      :summary="dns.enhanced_mode === 'fake-ip' ? tr('Fake-IP 地址池与过滤、监听地址、IPv6、HTTP/3 与缓存') : tr('监听地址、IPv6、HTTP/3 与缓存')"
    >
      <template v-if="dns.enhanced_mode === 'fake-ip'">
        <SettingsRow :title="tr('Fake-IP 地址段')" :description="tr('虚拟地址池，不要与本地网络冲突')" setting="dns-fake-ip-range">
          <input
            v-model="fakeIpRange"
            class="input sm mono srow-input"
            spellcheck="false"
            :aria-label="tr('Fake-IP 地址段')"
            data-testid="dns-fake-ip-range"
            @focus="focused = 'range'"
            @blur="commitRange"
            @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
          />
        </SettingsRow>
        <SettingsRow :title="tr('过滤列表模式')" :description="FILTER_MODE_HINTS[dns.fake_ip_filter_mode]" setting="dns-filter-mode" stacked>
          <Segmented
            :model-value="dns.fake_ip_filter_mode"
            :options="FILTER_MODES"
            size="sm"
            :label="tr('过滤列表模式')"
            :disabled="busy"
            data-testid="dns-filter-mode"
            @update:model-value="(mode) => saveDns({ fake_ip_filter_mode: mode })"
          />
        </SettingsRow>
        <SettingsRow
          nav
          :title="FAKE_IP_FILTER.title()"
          :description="tr('不返回虚拟地址的域名，如 *.lan')"
          :value="listSummary(dns.fake_ip_filter, FAKE_IP_FILTER.empty())"
          setting="dns-fake-ip-filter"
          data-testid="open-dns-fake-ip-filter"
          @open="openList(FAKE_IP_FILTER)"
        />
      </template>
      <SettingsRow :title="tr('DNS 监听地址')" :description="tr('留空则只在内核内部处理，例如 127.0.0.1:1053')" setting="dns-listen">
        <input
          v-model="listen"
          class="input sm mono srow-input"
          spellcheck="false"
          :placeholder="tr('留空不监听')"
          :aria-label="tr('DNS 监听地址')"
          data-testid="dns-listen"
          @focus="focused = 'listen'"
          @blur="commitListen"
          @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
        />
      </SettingsRow>
      <SettingsRow :title="tr('IPv6 解析')" :description="tr('允许返回 AAAA 记录')" setting="dns-ipv6">
        <Toggle :model-value="dns.ipv6" :label="tr('IPv6 解析')" :disabled="busy" @update:model-value="(on) => saveDns({ ipv6: on })" />
      </SettingsRow>
      <SettingsRow :title="tr('DoH 优先 HTTP/3')" :description="tr('加密 DNS 支持 QUIC 时优先使用 HTTP/3')" setting="dns-prefer-h3">
        <Toggle :model-value="dns.prefer_h3" :label="tr('DoH 优先 HTTP/3')" :disabled="busy" data-testid="dns-prefer-h3" @update:model-value="(on) => saveDns({ prefer_h3: on })" />
      </SettingsRow>
      <SettingsRow :title="tr('缓存算法')" :description="tr('ARC 命中率更高，LRU 内存开销更稳定')" setting="dns-cache-algorithm">
        <Segmented
          :model-value="dns.cache_algorithm"
          :options="CACHE_ALGOS"
          size="sm"
          :label="tr('缓存算法')"
          :disabled="busy"
          data-testid="dns-cache-algorithm"
          @update:model-value="(algo) => saveDns({ cache_algorithm: algo })"
        />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection :title="tr('工具')">
      <SettingsRow nav :title="tr('DNS 查询')" :description="tr('用内核当前的 DNS 配置解析域名，查看记录与耗时')" setting="dns-query" data-testid="open-dns-query" @open="store.dnsQueryOpen.value = true" />
      <SettingsRow :title="tr('清除 FakeIP 缓存')" :description="tr('虚拟地址映射错乱、换节点后网站仍打不开时使用')" setting="dns-flush-fakeip">
        <button type="button" class="btn ghost sm" :disabled="!snap.kernel_running || store.busy['flush:fakeip']" @click="store.flushCache('fakeip')">{{ tr('清除') }}</button>
      </SettingsRow>
      <SettingsRow :title="tr('清除 DNS 缓存')" :description="tr('让内核重新解析所有域名')" setting="dns-flush">
        <button type="button" class="btn ghost sm" :disabled="!snap.kernel_running || store.busy['flush:dns']" @click="store.flushCache('dns')">{{ tr('清除') }}</button>
      </SettingsRow>
    </SettingsSection>

    <div class="settings-pane-foot">
      <button type="button" class="btn ghost sm" data-testid="reset-dns" @click="confirmReset = true">
        <Icon name="refresh" :size="14" />{{ tr('恢复默认设置') }}
      </button>
    </div>

    <ListEditorDialog
      v-if="activeList"
      :title="activeList.title"
      :subtitle="activeList.hint"
      :items="activeList.items"
      :placeholder="activeList.placeholder"
      :saving="busy"
      :testid="activeList.setting"
      @save="saveList"
      @close="closeList"
    />

    <EditorDialog
      v-if="kvOpen"
      :title="kvOpen === 'policy' ? tr('域名解析策略') : tr('自定义 Hosts')"
      :subtitle="kvOpen === 'policy' ? tr('按域名、通配符或规则集指定专属上游 DNS（nameserver-policy）') : tr('静态域名解析，支持 IP 列表与泛域名')"
      wide
      :dirty="kvDirty"
      :saving="busy"
      :save-testid="kvOpen === 'policy' ? 'save-dns-policy' : 'save-dns-hosts'"
      @save="saveKv"
      @close="kvOpen = null"
    >
      <div class="kv-editor" :data-testid="kvOpen === 'policy' ? 'dns-policy-card' : 'dns-hosts-editor'">
        <div class="bypass-toolbar">
          <span class="muted small">{{ tr('{0} 条', { 0: Object.keys(kvDraft).length }) }}</span>
          <span class="grow" />
          <button v-if="kvOpen === 'policy'" type="button" class="btn ghost sm" data-testid="preset-cn-policy" @click="addCnPolicyPreset">
            <Icon name="plus" :size="14" />{{ tr('国内域名分流') }}
          </button>
          <button
            type="button"
            class="btn ghost sm"
            :data-testid="kvOpen === 'policy' ? 'toggle-policy-batch' : 'toggle-host-batch'"
            @click="toggleKvBatch"
          >{{ kvBatch ? tr('列表视图') : tr('批量编辑') }}</button>
        </div>
        <template v-if="!kvBatch">
          <div class="kv-add-row">
            <input
              v-model="newKey"
              class="input sm mono kv-key"
              :placeholder="kvOpen === 'policy' ? tr('规则，如 geosite:cn 或 +.corp.local') : tr('域名，如 router.local 或 *.dev.test')"
              :aria-label="kvOpen === 'policy' ? tr('解析策略匹配规则') : tr('Hosts 域名')"
              :data-testid="kvOpen === 'policy' ? 'policy-pattern-input' : 'host-domain-input'"
              @keydown.enter.prevent="onKeyEnter"
            />
            <input
              ref="valInput"
              v-model="newVal"
              class="input sm mono grow"
              :placeholder="kvOpen === 'policy' ? tr('DNS 服务器，多个用逗号分隔') : tr('IP 或目标域名，多个用逗号分隔')"
              :aria-label="kvOpen === 'policy' ? tr('解析策略 DNS 服务器') : tr('Hosts 目标地址')"
              :data-testid="kvOpen === 'policy' ? 'policy-servers-input' : 'host-target-input'"
              @keydown.enter.prevent="addKvRow"
            />
            <button
              type="button"
              class="btn sm"
              :disabled="!newKey.trim() || !newVal.trim()"
              :data-testid="kvOpen === 'policy' ? 'add-policy-btn' : 'add-host-btn'"
              @click="addKvRow"
            >
              <Icon name="plus" :size="14" />{{ tr('添加') }}
            </button>
          </div>
          <div v-if="kvRows.length" class="kv-list" :data-testid="kvOpen === 'policy' ? 'policy-list' : 'hosts-list'">
            <div v-for="(row, index) in kvRows" :key="index" class="kv-row">
              <input v-model="row.key" class="input sm mono kv-key" :aria-label="tr('第 {0} 条', { 0: index + 1 })" />
              <input v-model="row.val" class="input sm mono grow" :aria-label="tr('第 {0} 条的值', { 0: index + 1 })" />
              <button type="button" class="icon-btn sm" :title="tr('删除')" :aria-label="tr('删除')" @click="kvRows.splice(index, 1)">
                <Icon name="x" :size="14" />
              </button>
            </div>
          </div>
          <p v-else class="muted small empty-hint">
            <template v-if="kvOpen === 'policy'">{{ tr('尚未配置专属域名解析策略，支持') }} <code>+.domain.com</code>、<code>geosite:cn</code>、<code>rule-set:name</code> {{ tr('等格式。') }}</template>
            <template v-else>{{ tr('尚未添加自定义 Hosts 映射。') }}</template>
          </p>
        </template>
        <template v-else>
          <p v-if="kvOpen === 'policy'" class="muted small">
            {{ tr('每行一条，格式：') }}<code>{{ tr('规则 = DNS1, DNS2') }}</code>{{ tr('（例如') }} <code>geosite:cn,private = https://doh.pub/dns-query, 223.5.5.5</code>）
          </p>
          <p v-else class="muted small">{{ tr('支持') }} <code>{{ tr('域名 = IP1, IP2') }}</code> {{ tr('或标准系统 hosts 格式') }} <code>192.168.1.1 router.local</code></p>
          <textarea
            v-model="kvBatchText"
            class="input list-input mono editor-area"
            rows="10"
            spellcheck="false"
            :aria-label="kvOpen === 'policy' ? tr('域名解析策略批量编辑') : tr('Hosts 批量编辑')"
            :aria-invalid="kvInvalid.length ? 'true' : undefined"
            :data-testid="kvOpen === 'policy' ? 'policy-batch-textarea' : 'host-batch-textarea'"
          />
          <p v-if="kvInvalid.length" class="field-error small" role="alert" :data-testid="kvOpen === 'policy' ? 'policy-batch-invalid' : 'host-batch-invalid'">
            <Icon name="alert" :size="13" />
            {{ kvOpen === 'policy'
              ? tr('第 {0} 行缺少“=”或 DNS 服务器，保存时会被忽略', { 0: kvInvalid.join('、') })
              : tr('第 {0} 行缺少目标地址，保存时会被忽略', { 0: kvInvalid.join('、') }) }}
          </p>
        </template>
      </div>
    </EditorDialog>

    <Modal v-if="confirmReset" :title="tr('恢复 DNS 默认设置')" @close="confirmReset = false">
      <p class="small">{{ tr('服务器、解析策略、Hosts 与高级选项都会恢复为默认值。DNS 覆写的开关状态不变。') }}</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="confirmReset = false">{{ tr('取消') }}</button>
        <button type="button" class="btn primary" data-testid="confirm-reset-dns" @click="resetDns">{{ tr('恢复默认') }}</button>
      </template>
    </Modal>
  </div>
</template>
