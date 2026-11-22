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
const warnings = computed(() => store.customNodesWarnings.value)
const activeRuleCount = computed(() =>
  customNodes.value.rules_enabled ? customNodes.value.rules.filter((rule) => rule.enabled).length : 0,
)

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

function dialerLabel(dialer: DialerTarget): string {
  if (dialer.kind === 'direct') return t('customNodes.dialer.direct')
  if (dialer.kind === 'profile_group') {
    return dialer.group
      ? t('customNodes.dialer.profileGroupNamed', { group: dialer.group })
      : t('customNodes.dialer.profileGroup')
  }
  if (dialer.kind === 'fixed_proxy') {
    return t('customNodes.dialer.fixedProxy', { name: dialer.name })
  }
  const target = nodes.value.find((item) => item.id === dialer.id)
  if (!target) {
    return tr('经自建节点「{0}」中转（已删除）', { 0: dialer.id })
  }
  return t('customNodes.dialer.customNode', { name: target.name })
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
    <header class="card-head wrap-head">
      <div class="grow min0">
        <div class="custom-panel-title-row">
          <h2>{{ t('customNodes.title') }}</h2>
          <span class="tag sm">{{ t('customNodes.count', { count: nodes.length, enabled: enabledCount }) }}</span>
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
      <div class="card-head-actions">
        <button
          type="button"
          class="btn ghost sm"
          data-testid="open-landing-rules"
          @click="emit('openRules')"
        >
          <Icon name="route" :size="14" />
          {{ t('customNodes.landingRules') }}
          <span v-if="activeRuleCount > 0" class="tag accent sm">{{ activeRuleCount }}</span>
        </button>
        <button
          type="button"
          class="btn ghost sm"
          data-testid="open-custom-import"
          @click="emit('openImport')"
        >
          <Icon name="link" :size="14" /> {{ t('customNodes.import') }}
        </button>
        <button
          type="button"
          class="btn ghost sm"
          data-testid="open-custom-add"
          @click="emit('openAdd')"
        >
          <Icon name="plus" :size="14" /> {{ t('customNodes.add') }}
        </button>
      </div>
    </header>

    <div class="custom-nodes-controls">
      <div v-if="store.snapshot.value.profiles.length > 0" class="custom-control-row">
        <div class="grow min0">
          <strong>{{ t('customNodes.overlay') }}</strong>
          <p class="muted small">{{ t('customNodes.overlayHint') }}</p>
        </div>
        <Toggle
          :model-value="customNodes.overlay_enabled"
          :busy="Boolean(store.busy['customNodes:overlay'])"
          :label="t('customNodes.overlay')"
          data-testid="custom-overlay-toggle"
          @update:model-value="toggleOverlay"
        />
      </div>

      <div class="custom-control-row">
        <div class="grow min0">
          <strong>{{ store.customProfileActive.value ? t('customNodes.standaloneActive') : t('customNodes.useStandalone') }}</strong>
          <p class="muted small">{{ t('customNodes.standaloneDetail') }}</p>
        </div>
        <span v-if="store.customProfileActive.value" class="tag ok sm">{{ tr('使用中') }}</span>
        <button
          v-else
          type="button"
          class="btn ghost sm"
          :disabled="enabledCount === 0 || Boolean(store.busy['customNodes:useProfile'])"
          data-testid="use-custom-profile"
          @click="activateCustomProfile"
        >
          <Icon name="zap" :size="14" /> {{ t('customNodes.useStandalone') }}
        </button>
      </div>
    </div>

    <div v-if="warnings.length > 0" class="banner warn small custom-nodes-warnings" role="status" data-testid="custom-nodes-warnings">
      <Icon name="alert" :size="15" />
      <ul class="custom-error-list grow">
        <li v-for="(warning, idx) in warnings" :key="`${warning.code}-${idx}`">{{ warning.message }}</li>
      </ul>
    </div>

    <ul v-if="nodes.length > 0" class="custom-node-list">
      <li
        v-for="node in nodes"
        :key="node.id"
        class="custom-node-row"
        :class="{ disabled: !node.enabled }"
        :data-custom-node="node.id"
      >
        <div class="grow min0">
          <div class="custom-node-name-row">
            <strong class="ellipsis" :title="node.name">{{ node.name }}</strong>
            <span class="tag sm">{{ node.protocol.toUpperCase() }}</span>
          </div>
          <p class="muted small custom-node-meta">
            <span>{{ dialerLabel(node.dialer) }}</span>
            <span v-if="node.note" class="ellipsis">· {{ node.note }}</span>
          </p>
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
