<script setup lang="ts">
import { computed, ref } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import type { CustomNode, DialerTarget, LandingRule } from '../lib/types'
import Icon from './Icon.vue'
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
const chainedCount = computed(() => nodes.value.filter((n) => n.enabled && n.dialer.kind !== 'direct').length)
const warnings = computed(() => store.customNodesWarnings.value)
const activeRuleCount = computed(() =>
  customNodes.value.rules_enabled ? customNodes.value.rules.filter((rule) => rule.enabled).length : 0,
)
const hasSubscription = computed(() => store.snapshot.value.profiles.length > 0 && !store.customProfileActive.value)

const deleting = ref<CustomNode | null>(null)
const disabling = ref<CustomNode | null>(null)

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
  <section class="card custom-nodes-panel" data-testid="custom-nodes-panel">
    <header class="custom-panel-hero">
      <div class="custom-panel-head-main grow min0">
        <div class="custom-entry-icon" aria-hidden="true">
          <Icon name="layers" :size="19" />
        </div>
        <div class="grow min0">
          <div class="custom-panel-title-row">
            <h2>{{ t('customNodes.title') }}</h2>
            <span class="custom-stat-pill">{{ t('customNodes.count', { count: nodes.length, enabled: enabledCount }) }}</span>
            <span v-if="chainedCount > 0" class="custom-stat-pill accent">
              <Icon name="globe" :size="11" /> {{ tr('{0} 链式', { 0: chainedCount }) }}
            </span>
            <span
              v-if="store.customProfileActive.value"
              class="tag accent sm"
              data-testid="custom-profile-active-badge"
            >
              {{ t('customNodes.standaloneActive') }}
            </span>
          </div>
          <p class="muted small">{{ t('customNodes.subtitle') }}</p>
        </div>
      </div>

      <div class="custom-hero-actions">
        <button
          type="button"
          class="btn ghost sm custom-rules-btn"
          data-testid="open-landing-rules"
          @click="emit('openRules')"
        >
          <Icon name="route" :size="14" />
          <span>{{ t('customNodes.landingRules') }}</span>
          <span v-if="activeRuleCount > 0" class="custom-badge-dot">{{ activeRuleCount }}</span>
        </button>
        <button
          type="button"
          class="btn ghost sm"
          data-testid="open-custom-add"
          @click="emit('openAdd')"
        >
          <Icon name="plus" :size="14" /> {{ t('customNodes.add') }}
        </button>
        <button
          type="button"
          class="btn primary sm"
          data-testid="open-custom-import"
          @click="emit('openImport')"
        >
          <Icon name="link" :size="14" /> {{ t('customNodes.import') }}
        </button>
      </div>
    </header>

    <!-- Simplified Mode Bar -->
    <div class="custom-mode-bar">
      <div v-if="store.snapshot.value.profiles.length > 0" class="custom-mode-item grow min0">
        <div class="custom-mode-copy grow min0">
          <span class="custom-mode-label">{{ t('customNodes.overlay') }}</span>
          <span class="muted small ellipsis">{{ t('customNodes.overlayHint') }}</span>
        </div>
        <Toggle
          :model-value="customNodes.overlay_enabled"
          :busy="Boolean(store.busy['customNodes:overlay'])"
          :label="t('customNodes.overlay')"
          data-testid="custom-overlay-toggle"
          @update:model-value="toggleOverlay"
        />
      </div>

      <div class="custom-mode-divider" v-if="store.snapshot.value.profiles.length > 0" aria-hidden="true" />

      <div class="custom-mode-item custom-mode-standalone">
        <div class="custom-mode-copy min0">
          <span class="custom-mode-label">
            {{ store.customProfileActive.value ? t('customNodes.standaloneActive') : t('customNodes.useStandalone') }}
          </span>
          <span class="muted small ellipsis">{{ t('customNodes.standaloneDetail') }}</span>
        </div>
        <span v-if="store.customProfileActive.value" class="tag ok sm">{{ tr('使用中') }}</span>
        <button
          v-else
          type="button"
          class="btn sm"
          :disabled="enabledCount === 0 || Boolean(store.busy['customNodes:useProfile'])"
          data-testid="use-custom-profile"
          @click="activateCustomProfile"
        >
          <Icon name="zap" :size="13" /> {{ tr('切换纯自建') }}
        </button>
      </div>
    </div>

    <div v-if="warnings.length > 0" class="banner warn small custom-nodes-warnings" role="status" data-testid="custom-nodes-warnings">
      <Icon name="alert" :size="15" />
      <ul class="custom-error-list grow">
        <li v-for="(warning, idx) in warnings" :key="`${warning.code}-${idx}`">{{ warning.message }}</li>
      </ul>
    </div>

    <!-- Visual Chain Flow Node Cards -->
    <ul v-if="nodes.length > 0" class="custom-node-grid">
      <li
        v-for="node in nodes"
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
          <div class="custom-node-title-wrap grow min0">
            <span class="custom-proto-chip mono" :class="protocolTone(node.protocol)">
              {{ node.protocol.toUpperCase() }}
            </span>
            <strong class="custom-node-name ellipsis" :title="node.name">{{ node.name }}</strong>
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
              class="icon-btn sm"
              :title="tr('编辑')"
              :aria-label="tr('编辑')"
              :data-testid="`edit-custom-node-${node.id}`"
              @click="emit('openEdit', node)"
            >
              <Icon name="edit" :size="15" />
            </button>
            <button
              type="button"
              class="icon-btn sm"
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
          <div class="custom-route-flow grow min0" :title="dialerMeta(node.dialer).fullLabel">
            <span class="custom-hop-pill" :class="dialerMeta(node.dialer).kind">
              <Icon :name="dialerMeta(node.dialer).icon" :size="12" />
              <span class="ellipsis">{{ dialerMeta(node.dialer).fullLabel }}</span>
            </span>
            <template v-if="node.dialer.kind !== 'direct'">
              <span class="custom-route-arrow" aria-hidden="true">→</span>
              <span class="custom-hop-exit ellipsis">{{ tr('此节点落地') }}</span>
            </template>
            <span v-if="node.note" class="custom-node-note ellipsis" :title="node.note">· {{ node.note }}</span>
          </div>

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
            {{ node.dialer.kind === 'direct' ? tr('改链式') : tr('改直连') }}
          </button>
        </div>
      </li>
    </ul>

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
