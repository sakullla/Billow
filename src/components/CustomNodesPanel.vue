<script setup lang="ts">
import { computed, ref } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import type { CustomNode, DialerTarget, LandingRule } from '../lib/types'
import Icon from './Icon.vue'
import Menu, { type MenuItem } from './Menu.vue'
import Modal from './Modal.vue'
import Toggle from './Toggle.vue'

defineProps<{ compact?: boolean }>()

const emit = defineEmits<{
  openImport: [initialText?: string]
  openAdd: []
  openEdit: [node: CustomNode]
  openRules: []
}>()

const store = useStore()
const customNodes = computed(() => store.customNodes.value)
const nodes = computed(() => customNodes.value.nodes)
const enabledCount = computed(() => store.enabledCustomNodes.value.length)
const disabledCount = computed(() => nodes.value.length - enabledCount.value)
const chainedCount = computed(() => nodes.value.filter((n) => n.enabled && n.dialer.kind !== 'direct').length)
const totalChainedCount = computed(() => nodes.value.filter((n) => n.dialer.kind !== 'direct').length)
const totalDirectCount = computed(() => nodes.value.length - totalChainedCount.value)
const warnings = computed(() => store.customNodesWarnings.value)
const activeRuleCount = computed(() =>
  customNodes.value.rules_enabled ? customNodes.value.rules.filter((rule) => rule.enabled).length : 0,
)
const hasSubscription = computed(() => store.snapshot.value.profiles.length > 0 && !store.customProfileActive.value)
const overlayPaused = computed(() => hasSubscription.value && !customNodes.value.overlay_enabled)

const deleting = ref<CustomNode | null>(null)
const disabling = ref<CustomNode | null>(null)
const moreOpen = ref(false)
const query = ref('')
type RouteFilter = 'all' | 'chain' | 'direct' | 'disabled'
const routeFilter = ref<RouteFilter>('all')

const moreItems = computed<MenuItem[]>(() => {
  const items: MenuItem[] = []
  if (store.snapshot.value.profiles.length > 0 && !store.customProfileActive.value) {
    items.push({
      id: 'standalone',
      label: tr('切换纯自建配置'),
      icon: 'zap',
      disabled: enabledCount.value === 0 || Boolean(store.busy['customNodes:useProfile']),
    })
  }
  items.push({
    id: 'disable-feature',
    label: tr('关闭自建节点'),
    icon: 'eye-off',
    danger: true,
  })
  return items
})

function onMoreSelect(item: MenuItem) {
  moreOpen.value = false
  if (item.id === 'standalone') {
    void activateCustomProfile()
  } else if (item.id === 'disable-feature') {
    void store.setCustomNodesFeatureEnabled(false)
  }
}

function rulesForNode(nodeId: string): string[] {
  if (!customNodes.value.rules_enabled) return []
  return customNodes.value.rules
    .filter((rule) => rule.enabled && rule.target.kind === 'custom_node' && rule.target.id === nodeId)
    .map(describeRule)
}

const filteredNodes = computed(() => {
  const needle = query.value.trim().toLowerCase()
  return nodes.value.filter((node) => {
    if (routeFilter.value === 'chain' && node.dialer.kind === 'direct') return false
    if (routeFilter.value === 'direct' && node.dialer.kind !== 'direct') return false
    if (routeFilter.value === 'disabled' && node.enabled) return false
    if (!needle) return true
    const endpoint = extractEndpoint(node.raw_yaml)
    return (
      node.name.toLowerCase().includes(needle) ||
      node.protocol.toLowerCase().includes(needle) ||
      node.note.toLowerCase().includes(needle) ||
      (endpoint && endpoint.toLowerCase().includes(needle))
    )
  })
})

function extractEndpoint(rawYaml: string): string | null {
  let server = ''
  let port = ''
  for (const line of rawYaml.split(/\r?\n/)) {
    const trimmed = line.trim().replace(/^-\s+/, '')
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf(':')
    if (idx <= 0) continue
    const key = trimmed.slice(0, idx).trim()
    const val = trimmed.slice(idx + 1).trim().replace(/^['"]|['"]$/g, '')
    if (key === 'server' && !server) server = val
    else if (key === 'port' && !port) port = val
    if (server && port) break
  }
  if (!server) return null
  return port ? `${server}:${port}` : server
}

function describeRule(rule: LandingRule): string {
  if (rule.rule.kind === 'preset') {
    const presetId = rule.rule.id
    const preset = store.landingPresets.value.find((item) => item.id === presetId)
    return preset?.label ?? presetId
  }
  return rule.rule.pattern
}

function affectedByNode(nodeId: string): { chainedNodes: CustomNode[]; landingRules: string[] } {
  const chainedNodes = nodes.value.filter(
    (item) => item.id !== nodeId && item.dialer.kind === 'custom_node' && item.dialer.id === nodeId,
  )
  const landingRules = customNodes.value.rules
    .filter((rule) => rule.target.kind === 'custom_node' && rule.target.id === nodeId)
    .map(describeRule)
  return { chainedNodes, landingRules }
}

const deleteImpact = computed(() => (deleting.value ? affectedByNode(deleting.value.id) : { chainedNodes: [], landingRules: [] }))
const disableImpact = computed(() => (disabling.value ? affectedByNode(disabling.value.id) : { chainedNodes: [], landingRules: [] }))

function protocolTone(protocol: string): string {
  const p = protocol.toLowerCase()
  if (p === 'anytls' || p === 'vless') return 'proto-teal'
  if (p === 'hysteria2' || p === 'tuic') return 'proto-indigo'
  if (p === 'socks5' || p === 'http') return 'proto-amber'
  return 'proto-slate'
}

function dialerMeta(dialer: DialerTarget): {
  kind: 'direct' | 'chain' | 'warn'
  hopLabel: string
  fullLabel: string
  icon: string
} {
  if (dialer.kind === 'direct') {
    return {
      kind: 'direct',
      hopLabel: t('customNodes.dialer.direct'),
      fullLabel: t('customNodes.dialer.direct'),
      icon: 'zap',
    }
  }
  if (dialer.kind === 'profile_group') {
    const full = dialer.group
      ? t('customNodes.dialer.profileGroupNamed', { group: dialer.group })
      : t('customNodes.dialer.profileGroup')
    return {
      kind: 'chain',
      hopLabel: dialer.group || tr('当前订阅'),
      fullLabel: full,
      icon: 'globe',
    }
  }
  if (dialer.kind === 'fixed_proxy') {
    return {
      kind: 'chain',
      hopLabel: dialer.name,
      fullLabel: t('customNodes.dialer.fixedProxy', { name: dialer.name }),
      icon: 'locate',
    }
  }
  const target = nodes.value.find((item) => item.id === dialer.id)
  if (!target) {
    const label = tr('经自建节点「{0}」中转（已删除）', { 0: dialer.id })
    return { kind: 'warn', hopLabel: tr('前置已删除'), fullLabel: label, icon: 'alert' }
  }
  if (!target.enabled) {
    return {
      kind: 'warn',
      hopLabel: `${target.name}（${tr('已停用')}）`,
      fullLabel: t('customNodes.dialer.customNode', { name: target.name }),
      icon: 'alert',
    }
  }
  return {
    kind: 'chain',
    hopLabel: target.name,
    fullLabel: t('customNodes.dialer.customNode', { name: target.name }),
    icon: 'layers',
  }
}

async function quickToggleChain(node: CustomNode) {
  if (store.busy['customNodes:save']) return
  const nextDialer: DialerTarget =
    node.dialer.kind === 'direct'
      ? { kind: 'profile_group', group: null }
      : { kind: 'direct' }
  await store.saveCustomNode({
    id: node.id,
    name: node.name,
    enabled: node.enabled,
    note: node.note,
    dialer: nextDialer,
    raw_yaml: node.raw_yaml,
  })
}

async function toggleOverlay(enabled: boolean) {
  await store.setCustomNodesOverlay(enabled)
}

async function toggleNode(node: CustomNode, enabled: boolean) {
  if (!enabled) {
    const impact = affectedByNode(node.id)
    if (impact.chainedNodes.length > 0 || impact.landingRules.length > 0) {
      disabling.value = node
      return
    }
  }
  await store.setCustomNodeEnabled(node.id, enabled)
}

async function confirmDisable() {
  const target = disabling.value
  if (!target) return
  await store.setCustomNodeEnabled(target.id, false)
  disabling.value = null
}

async function activateCustomProfile() {
  await store.useCustomProfile()
}

async function confirmDelete() {
  const target = deleting.value
  if (!target) return
  await store.deleteCustomNode(target.id)
  deleting.value = null
}
</script>

<template>
  <section
    class="custom-nodes-workspace"
    :class="{ 'standalone-active': store.customProfileActive.value }"
    data-testid="custom-nodes-panel"
  >
    <div class="custom-workspace-bar">
      <div class="custom-workspace-status grow min0">
        <template v-if="store.customProfileActive.value">
          <span class="tag accent sm" data-testid="custom-profile-active-badge">
            {{ t('customNodes.standaloneActive') }}
          </span>
          <span class="muted small ellipsis">
            {{
              store.snapshot.value.profiles.length > 0
                ? tr('切回「订阅配置」点击任意订阅即可恢复')
                : t('customNodes.standaloneDetail')
            }}
          </span>
        </template>
        <template v-else-if="store.snapshot.value.profiles.length > 0">
          <div class="custom-overlay-inline" :title="t('customNodes.overlayHint')">
            <Toggle
              :model-value="customNodes.overlay_enabled"
              :busy="Boolean(store.busy['customNodes:overlay'])"
              :label="t('customNodes.overlay')"
              data-testid="custom-overlay-toggle"
              @update:model-value="toggleOverlay"
            />
            <span class="custom-overlay-label">{{ t('customNodes.overlay') }}</span>
          </div>
          <span v-if="overlayPaused" class="custom-stat-pill warn" data-testid="custom-overlay-paused-badge">
            {{ tr('已暂停叠加') }}
          </span>
          <span v-else class="custom-stat-pill">
            {{ tr('{0}/{1} 启用', { 0: enabledCount, 1: nodes.length }) }}
          </span>
          <span v-if="chainedCount > 0 && !overlayPaused" class="custom-stat-pill accent">
            <Icon name="globe" :size="11" /> {{ tr('{0} 链式', { 0: chainedCount }) }}
          </span>
        </template>
      </div>

      <div class="custom-hero-actions">
        <button
          type="button"
          class="btn sm custom-secondary-btn custom-rules-btn"
          :class="{ 'has-rules': activeRuleCount > 0 }"
          data-testid="open-landing-rules"
          :title="t('customNodes.landingRulesHint')"
          @click="emit('openRules')"
        >
          <Icon name="route" :size="14" />
          <span>{{ tr('落地规则') }}</span>
          <span v-if="activeRuleCount > 0" class="custom-badge-dot">{{ activeRuleCount }}</span>
        </button>
        <button
          type="button"
          class="btn sm custom-secondary-btn"
          data-testid="open-custom-add"
          @click="emit('openAdd')"
        >
          <Icon name="plus" :size="14" /> {{ tr('手动添加') }}
        </button>
        <button
          type="button"
          class="btn primary sm"
          data-testid="open-custom-import"
          @click="emit('openImport')"
        >
          <Icon name="link" :size="14" /> {{ tr('导入链接') }}
        </button>
        <div class="menu-anchor" @keydown.esc.stop.prevent="moreOpen = false">
          <button
            type="button"
            class="icon-btn sm custom-secondary-btn"
            :title="tr('更多操作')"
            :aria-label="tr('更多操作')"
            aria-haspopup="menu"
            :aria-expanded="moreOpen"
            data-testid="custom-nodes-more"
            @click="moreOpen = !moreOpen"
          >
            <Icon name="more" :size="15" />
          </button>
          <Menu
            :open="moreOpen"
            :items="moreItems"
            :label="t('customNodes.title')"
            @select="onMoreSelect"
            @close="moreOpen = false"
          />
        </div>
      </div>
    </div>

    <div v-if="warnings.length > 0" class="banner warn small custom-nodes-warnings" role="status" data-testid="custom-nodes-warnings">
      <Icon name="alert" :size="15" />
      <ul class="custom-error-list grow">
        <li v-for="(warning, idx) in warnings" :key="`${warning.code}-${idx}`">{{ warning.message }}</li>
      </ul>
    </div>

    <div v-if="nodes.length >= 3 || query || routeFilter !== 'all'" class="custom-filter-bar" data-testid="custom-filter-bar">
      <div class="search custom-node-search grow">
        <Icon name="search" :size="15" />
        <input
          v-model="query"
          type="search"
          :placeholder="tr('筛选自建节点名称、协议或地址')"
          data-testid="custom-node-search"
        />
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          :aria-label="tr('清空筛选')"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <div class="custom-filter-chips" role="group" :aria-label="tr('按状态筛选')">
        <button
          type="button"
          class="custom-filter-chip"
          :class="{ active: routeFilter === 'all' }"
          data-testid="custom-filter-all"
          @click="routeFilter = 'all'"
        >{{ tr('全部') }} <span class="mono">{{ nodes.length }}</span></button>
        <button
          v-if="totalChainedCount > 0"
          type="button"
          class="custom-filter-chip"
          :class="{ active: routeFilter === 'chain' }"
          data-testid="custom-filter-chain"
          @click="routeFilter = 'chain'"
        >{{ tr('链式') }} <span class="mono">{{ totalChainedCount }}</span></button>
        <button
          v-if="totalDirectCount > 0"
          type="button"
          class="custom-filter-chip"
          :class="{ active: routeFilter === 'direct' }"
          data-testid="custom-filter-direct"
          @click="routeFilter = 'direct'"
        >{{ tr('直连') }} <span class="mono">{{ totalDirectCount }}</span></button>
        <button
          v-if="disabledCount > 0"
          type="button"
          class="custom-filter-chip"
          :class="{ active: routeFilter === 'disabled' }"
          data-testid="custom-filter-disabled"
          @click="routeFilter = 'disabled'"
        >{{ tr('已停用') }} <span class="mono">{{ disabledCount }}</span></button>
      </div>
    </div>

    <!-- Clean Node Cards -->
    <ul
      v-if="filteredNodes.length > 0"
      class="custom-node-grid"
      :class="{ 'overlay-paused': overlayPaused }"
    >
      <li
        v-for="node in filteredNodes"
        :key="node.id"
        class="custom-node-card"
        :class="{
          disabled: !node.enabled,
          chained: node.enabled && dialerMeta(node.dialer).kind === 'chain',
          'has-warn': node.enabled && dialerMeta(node.dialer).kind === 'warn',
        }"
        :data-custom-node="node.id"
      >
        <div class="custom-node-card-top">
          <div class="custom-node-identity grow min0">
            <div class="custom-node-title-wrap min0">
              <span class="custom-proto-chip mono" :class="protocolTone(node.protocol)">
                {{ node.protocol.toUpperCase() }}
              </span>
              <strong class="custom-node-name ellipsis" :title="node.name">{{ node.name }}</strong>
              <span v-if="!node.enabled" class="custom-node-note-tag">{{ tr('已停用') }}</span>
              <span v-else-if="node.note" class="custom-node-note-tag ellipsis" :title="node.note">{{ node.note }}</span>
            </div>
            <span
              v-if="extractEndpoint(node.raw_yaml)"
              class="custom-node-endpoint mono muted ellipsis"
              :title="extractEndpoint(node.raw_yaml) ?? undefined"
            >
              {{ extractEndpoint(node.raw_yaml) }}
            </span>
          </div>
          <div class="custom-node-actions">
            <Toggle
              :model-value="node.enabled"
              :busy="Boolean(store.busy[`customNodes:toggle:${node.id}`])"
              :label="node.name"
              :data-testid="`toggle-custom-node-${node.id}`"
              @update:model-value="(value) => toggleNode(node, value)"
            />
            <button
              type="button"
              class="icon-btn sm custom-node-tool"
              :title="tr('编辑')"
              :aria-label="tr('编辑')"
              :data-testid="`edit-custom-node-${node.id}`"
              @click="emit('openEdit', node)"
            >
              <Icon name="edit" :size="15" />
            </button>
            <button
              type="button"
              class="icon-btn sm danger custom-node-tool"
              :title="tr('删除')"
              :aria-label="tr('删除')"
              :data-testid="`delete-custom-node-${node.id}`"
              @click="deleting = node"
            >
              <Icon name="trash" :size="15" />
            </button>
          </div>
        </div>

        <div class="custom-route-strip">
          <button
            type="button"
            class="custom-route-trigger grow min0"
            :title="tr('{0} · 点击调整中转方式', { 0: dialerMeta(node.dialer).fullLabel })"
            @click="emit('openEdit', node)"
          >
            <span class="custom-hop-pill" :class="dialerMeta(node.dialer).kind">
              <Icon :name="dialerMeta(node.dialer).icon" :size="12" />
              <span class="ellipsis">{{ dialerMeta(node.dialer).fullLabel }}</span>
            </span>
            <template v-if="node.dialer.kind !== 'direct'">
              <span class="custom-route-arrow" aria-hidden="true">→</span>
              <span class="custom-hop-exit ellipsis">{{ tr('此节点落地') }}</span>
            </template>
            <span
              v-if="rulesForNode(node.id).length > 0"
              class="custom-rule-hit-pill ellipsis"
              :title="rulesForNode(node.id).join('、')"
            >
              <Icon name="route" :size="11" />
              {{
                rulesForNode(node.id).length === 1
                  ? rulesForNode(node.id)[0]
                  : tr('{0} 条落地', { 0: rulesForNode(node.id).length })
              }}
            </span>
          </button>

          <button
            v-if="hasSubscription && node.enabled"
            type="button"
            class="custom-quick-chain-btn"
            :class="{ active: node.dialer.kind !== 'direct' }"
            :disabled="Boolean(store.busy['customNodes:save'])"
            :title="node.dialer.kind === 'direct' ? tr('一键切换为通过当前订阅链式落地') : tr('切换为直连出口')"
            :data-testid="`quick-chain-toggle-${node.id}`"
            @click="quickToggleChain(node)"
          >
            <Icon :name="node.dialer.kind === 'direct' ? 'globe' : 'zap'" :size="11" />
            <span>{{ node.dialer.kind === 'direct' ? tr('改链式') : tr('改直连') }}</span>
          </button>
        </div>
      </li>
    </ul>
    <p v-else-if="nodes.length > 0 && query" class="muted small custom-node-empty-filter">
      {{ tr('没有匹配的自建节点') }}
    </p>

    <Modal
      :open="Boolean(deleting)"
      :title="tr('删除自建节点')"
      @close="deleting = null"
    >
      <div v-if="deleting" class="stack-sm">
        <p>{{ t('customNodes.deleteConfirm', { name: deleting.name }) }}</p>
        <div
          v-if="deleteImpact.chainedNodes.length > 0 || deleteImpact.landingRules.length > 0"
          class="banner warn small"
          role="alert"
          data-testid="delete-custom-node-impact"
        >
          <Icon name="alert" :size="15" />
          <div class="grow stack-xs">
            <strong>{{ tr('删除后以下引用将失效，需重新指定目标：') }}</strong>
            <ul class="custom-error-list">
              <li v-if="deleteImpact.chainedNodes.length > 0">
                {{ tr('链式代理节点：') }}{{ deleteImpact.chainedNodes.map((n) => n.name).join('、') }}
              </li>
              <li v-if="deleteImpact.landingRules.length > 0">
                {{ tr('指定流量走落地规则：') }}{{ deleteImpact.landingRules.join('、') }}
              </li>
            </ul>
          </div>
        </div>
      </div>
      <template #footer>
        <button type="button" class="btn ghost" @click="deleting = null">{{ tr('取消') }}</button>
        <button
          type="button"
          class="btn danger"
          :disabled="deleting ? Boolean(store.busy[`customNodes:delete:${deleting.id}`]) : false"
          data-testid="confirm-delete-custom-node"
          @click="confirmDelete"
        >
          {{ tr('删除') }}
        </button>
      </template>
    </Modal>

    <Modal
      :open="Boolean(disabling)"
      :title="tr('停用自建节点')"
      @close="disabling = null"
    >
      <div v-if="disabling" class="stack-sm">
        <p>{{ tr('停用「{0}」会影响以下引用它的配置：', { 0: disabling.name }) }}</p>
        <div class="banner warn small" role="alert" data-testid="disable-custom-node-impact">
          <Icon name="alert" :size="15" />
          <div class="grow stack-xs">
            <ul class="custom-error-list">
              <li v-if="disableImpact.chainedNodes.length > 0">
                {{ tr('链式代理节点：') }}{{ disableImpact.chainedNodes.map((n) => n.name).join('、') }}
              </li>
              <li v-if="disableImpact.landingRules.length > 0">
                {{ tr('指定流量走落地规则：') }}{{ disableImpact.landingRules.join('、') }}
              </li>
            </ul>
          </div>
        </div>
      </div>
      <template #footer>
        <button type="button" class="btn ghost" @click="disabling = null">{{ tr('取消') }}</button>
        <button
          type="button"
          class="btn danger"
          :disabled="disabling ? Boolean(store.busy[`customNodes:toggle:${disabling.id}`]) : false"
          data-testid="confirm-disable-custom-node"
          @click="confirmDisable"
        >
          {{ tr('仍要停用') }}
        </button>
      </template>
    </Modal>
  </section>
</template>
