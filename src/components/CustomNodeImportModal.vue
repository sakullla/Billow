<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import { LANDING_GROUP_NAME, type DialerTarget, type ParseNodesResult } from '../lib/types'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import SelectField, { type SelectOption } from './SelectField.vue'

const props = defineProps<{
  open: boolean
  initialText?: string
  compact?: boolean
}>()

const emit = defineEmits<{
  close: []
  imported: [count: number]
  switchToForm: []
}>()

const store = useStore()
const raw = ref('')
const dialerChoice = ref('direct')
const preview = ref<ParseNodesResult>({ parsed: [], errors: [] })
const previewing = ref(false)
const submitError = ref<string | null>(null)
let previewSeq = 0
let previewTimer: ReturnType<typeof setTimeout> | null = null

const hasSubscription = computed(() => store.snapshot.value.profiles.length > 0 && !store.customProfileActive.value)
const isChainedMode = computed(() => dialerChoice.value !== 'direct')

function selectRouteMode(mode: 'chain' | 'direct') {
  if (mode === 'direct') {
    dialerChoice.value = 'direct'
  } else if (dialerChoice.value === 'direct') {
    dialerChoice.value = 'profile_group:'
  }
}

const dialerOptions = computed<SelectOption[]>(() => {
  const options: SelectOption[] = hasSubscription.value
    ? [
        { value: 'profile_group:', label: t('customNodes.dialer.profileGroup'), icon: 'globe', hint: tr('推荐') },
        { value: 'direct', label: t('customNodes.dialer.direct'), icon: 'zap' },
      ]
    : [
        { value: 'direct', label: t('customNodes.dialer.direct'), icon: 'zap', hint: tr('推荐') },
        { value: 'profile_group:', label: t('customNodes.dialer.profileGroup'), icon: 'globe' },
      ]
  for (const group of store.snapshot.value.node_catalog) {
    if (group.kind === 'manual' && !group.hidden && group.name !== LANDING_GROUP_NAME) {
      options.push({
        value: `profile_group:${group.name}`,
        label: group.name,
        hint: group.now || undefined,
        groupIcon: group.icon,
        groupType: group.group_type || 'select',
      })
    }
  }
  for (const node of store.customNodes.value.nodes) {
    if (!node.enabled) continue
    options.push({
      value: `custom_node:${node.id}`,
      label: node.name,
      hint: tr('自建'),
      icon: 'layers',
    })
  }
  return options
})

function protocolTone(protocol: string): string {
  const p = protocol.toLowerCase()
  if (p === 'anytls' || p === 'vless') return 'proto-teal'
  if (p === 'hysteria2' || p === 'tuic') return 'proto-indigo'
  if (p === 'socks5' || p === 'http') return 'proto-amber'
  return 'proto-slate'
}

function resolveDialer(choice: string): DialerTarget {
  if (choice === 'direct') return { kind: 'direct' }
  if (choice.startsWith('profile_group:')) {
    const group = choice.slice('profile_group:'.length).trim()
    return { kind: 'profile_group', group: group || null }
  }
  if (choice.startsWith('custom_node:')) {
    return { kind: 'custom_node', id: choice.slice('custom_node:'.length) }
  }
  return { kind: 'direct' }
}

async function runPreview(text: string) {
  const seq = ++previewSeq
  const trimmed = text.trim()
  if (!trimmed) {
    preview.value = { parsed: [], errors: [] }
    previewing.value = false
    return
  }
  previewing.value = true
  try {
    const result = await store.previewCustomNodesImport(trimmed)
    if (seq !== previewSeq) return
    preview.value = result
  } catch (error) {
    if (seq !== previewSeq) return
    preview.value = {
      parsed: [],
      errors: [{ index: 1, source: trimmed.slice(0, 60), reason: error instanceof Error ? error.message : String(error) }],
    }
  } finally {
    if (seq === previewSeq) previewing.value = false
  }
}

function schedulePreview(text: string) {
  if (previewTimer) {
    clearTimeout(previewTimer)
    previewTimer = null
  }
  submitError.value = null
  if (!text.trim()) {
    previewSeq += 1
    preview.value = { parsed: [], errors: [] }
    previewing.value = false
    return
  }
  previewTimer = setTimeout(() => {
    previewTimer = null
    void runPreview(text)
  }, 120)
}

watch(
  () => props.open,
  (open) => {
    if (previewTimer) {
      clearTimeout(previewTimer)
      previewTimer = null
    }
    if (!open) return
    submitError.value = null
    dialerChoice.value = hasSubscription.value ? 'profile_group:' : 'direct'
    raw.value = props.initialText?.trim() ?? ''
    if (raw.value) void runPreview(raw.value)
    else preview.value = { parsed: [], errors: [] }
  },
  { immediate: true },
)

async function pasteClipboard() {
  try {
    const text = await navigator.clipboard.readText()
    if (text && text.trim()) {
      raw.value = text.trim()
      void runPreview(raw.value)
    } else {
      store.toast(tr('剪贴板为空'), 'info')
    }
  } catch {
    store.toast(tr('无法读取剪贴板，请手动粘贴'), 'error')
  }
}

async function submit() {
  const trimmed = raw.value.trim()
  if (!trimmed || store.busy['customNodes:import']) return
  submitError.value = null
  if (preview.value.parsed.length === 0) {
    await runPreview(trimmed)
  }
  if (preview.value.parsed.length === 0) {
    submitError.value = preview.value.errors[0]?.reason ?? tr('没有识别到可导入的节点')
    return
  }
  const result = await store.importCustomNodes(trimmed, resolveDialer(dialerChoice.value))
  if (!result) {
    submitError.value = store.lastRunError.value ?? tr('导入失败')
    return
  }
  emit('imported', result.imported.length)
  emit('close')
}
</script>

<template>
  <Modal
    :open="open"
    wide
    :title="t('customNodes.import.title')"
    :subtitle="t('customNodes.subtitle')"
    @close="emit('close')"
  >
    <div class="stack custom-import-body">
      <div class="field">
        <div class="field-label-row">
          <span>{{ t('customNodes.import') }}</span>
          <div class="custom-inline-actions">
            <button type="button" class="btn ghost sm" data-testid="custom-import-paste" @click="pasteClipboard">
              <Icon name="clipboard" :size="14" /> {{ tr('粘贴') }}
            </button>
            <button
              type="button"
              class="btn ghost sm"
              data-testid="custom-import-to-form"
              @click="emit('switchToForm')"
            >
              <Icon name="sliders" :size="14" /> {{ t('customNodes.quickForm') }}
            </button>
          </div>
        </div>
        <textarea
          v-model="raw"
          class="mono custom-import-textarea"
          rows="5"
          spellcheck="false"
          :placeholder="t('customNodes.import.placeholder')"
          data-testid="custom-node-import-input"
          @input="schedulePreview(raw)"
        />
      </div>

      <!-- Visual 2-Card Route Mode Picker -->
      <div class="custom-form-section">
        <p class="custom-section-title">{{ t('customNodes.dialer.label') }}</p>
        <div class="custom-route-cards" role="radiogroup" :aria-label="t('customNodes.dialer.label')">
          <button
            type="button"
            class="custom-route-card"
            :class="{ active: isChainedMode }"
            role="radio"
            :aria-checked="isChainedMode"
            data-testid="import-mode-chain"
            @click="selectRouteMode('chain')"
          >
            <div class="custom-route-card-head">
              <span class="custom-route-card-icon chain"><Icon name="globe" :size="15" /></span>
              <strong>{{ tr('链式落地') }}</strong>
              <span v-if="hasSubscription" class="tag accent sm">{{ tr('推荐') }}</span>
            </div>
            <p class="custom-route-card-flow">
              <span>{{ tr('订阅中转') }}</span>
              <span aria-hidden="true">→</span>
              <span>{{ tr('自建节点') }}</span>
            </p>
            <p class="muted small">{{ tr('隐藏真实 IP，适合 AI、住宅与纯净落地') }}</p>
          </button>

          <button
            type="button"
            class="custom-route-card"
            :class="{ active: !isChainedMode }"
            role="radio"
            :aria-checked="!isChainedMode"
            data-testid="import-mode-direct"
            @click="selectRouteMode('direct')"
          >
            <div class="custom-route-card-head">
              <span class="custom-route-card-icon direct"><Icon name="zap" :size="15" /></span>
              <strong>{{ tr('直连出口') }}</strong>
              <span v-if="!hasSubscription" class="tag accent sm">{{ tr('推荐') }}</span>
            </div>
            <p class="custom-route-card-flow">
              <span>{{ tr('本机') }}</span>
              <span aria-hidden="true">→</span>
              <span>{{ tr('自建节点') }}</span>
            </p>
            <p class="muted small">{{ tr('不经中转直连，适合高速自建或纯自建') }}</p>
          </button>
        </div>

        <div class="custom-dialer-select-wrap">
          <SelectField
            :model-value="dialerChoice"
            :options="dialerOptions"
            :sheet="compact"
            :label="t('customNodes.dialer.label')"
            class="field-select"
            data-testid="custom-import-dialer"
            @update:model-value="(value) => { dialerChoice = String(value) }"
          />
        </div>
      </div>

      <div v-if="previewing" class="muted small custom-preview-status">
        <span class="spinner xs" aria-hidden="true" />
        <span>{{ tr('正在识别节点…') }}</span>
      </div>

      <section v-if="preview.parsed.length > 0" class="custom-preview-box" data-testid="custom-import-preview">
        <header class="custom-preview-head">
          <span class="tag ok sm">{{ t('customNodes.import.previewReady', { count: preview.parsed.length }) }}</span>
          <span v-if="preview.errors.length > 0" class="tag warn sm">
            {{ t('customNodes.import.previewErrors', { count: preview.errors.length }) }}
          </span>
        </header>
        <ul class="custom-preview-list">
          <li v-for="(item, idx) in preview.parsed" :key="`${item.name}-${idx}`" class="custom-preview-item">
            <span class="custom-proto-chip mono" :class="protocolTone(item.protocol)">{{ item.protocol.toUpperCase() }}</span>
            <span class="custom-preview-name ellipsis grow">{{ item.name }}</span>
            <span class="muted small mono ellipsis">{{ item.server }}:{{ item.port }}</span>
          </li>
        </ul>
      </section>

      <section v-if="preview.errors.length > 0" class="banner warn small custom-preview-errors" data-testid="custom-import-errors">
        <Icon name="alert" :size="15" />
        <div class="grow stack-xs">
          <strong>{{ t('customNodes.import.previewErrors', { count: preview.errors.length }) }}</strong>
          <ul class="custom-error-list">
            <li v-for="err in preview.errors" :key="`${err.index}-${err.source}`">
              <span class="mono">#{{ err.index }}</span> {{ err.reason }}
            </li>
          </ul>
        </div>
      </section>

      <p v-if="submitError" class="field-error small" role="alert" data-testid="custom-import-submit-error">
        <Icon name="alert" :size="13" />
        <span>{{ submitError }}</span>
      </p>
    </div>

    <template #footer>
      <button type="button" class="btn ghost" @click="emit('close')">{{ tr('取消') }}</button>
      <button
        type="button"
        class="btn primary"
        :disabled="preview.parsed.length === 0 || Boolean(store.busy['customNodes:import'])"
        data-testid="custom-node-import-confirm"
        @click="submit"
      >
        <span v-if="store.busy['customNodes:import']" class="spinner xs" aria-hidden="true" />
        {{ t('customNodes.import.confirm') }}
      </button>
    </template>
  </Modal>
</template>
