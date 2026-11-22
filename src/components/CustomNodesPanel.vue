<script setup lang="ts">
import { computed, ref } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import type { CustomNode, DialerTarget } from '../lib/types'
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
  return t('customNodes.dialer.customNode', { name: target?.name ?? dialer.id })
}

async function toggleOverlay(enabled: boolean) {
  await store.setCustomNodesOverlay(enabled)
}

async function toggleNode(node: CustomNode, enabled: boolean) {
  await store.setCustomNodeEnabled(node.id, enabled)
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
      <div v-if="store.hasProfiles.value" class="custom-control-row">
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
      <p v-if="deleting">{{ t('customNodes.deleteConfirm', { name: deleting.name }) }}</p>
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
  </section>
</template>
