<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import type { LandingRule, LandingRuleTarget } from '../lib/types'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import SelectField from './SelectField.vue'
import Toggle from './Toggle.vue'

const props = defineProps<{
  open: boolean
  compact?: boolean
}>()

const emit = defineEmits<{
  close: []
  saved: []
}>()

interface DomainRuleDraft {
  id: string
  enabled: boolean
  pattern: string
  target: string
}

const store = useStore()
const rulesEnabled = ref(true)
const presetDrafts = ref<Record<string, { id: string; enabled: boolean; target: string }>>({})
const domainRules = ref<DomainRuleDraft[]>([])
const newDomain = ref('')
const newDomainTarget = ref('custom_group')
const editingIndex = ref<number | null>(null)
const editPattern = ref('')
const editTarget = ref('custom_group')
const error = ref<string | null>(null)

const enabledSummaryCount = computed(() => {
  const presets = Object.values(presetDrafts.value).filter((item) => item.enabled).length
  const domains = domainRules.value.filter((item) => item.enabled).length
  return presets + domains
})

const baseTargetOptions = computed(() => {
  const options: { value: string; label: string }[] = [
    { value: 'custom_group', label: t('customNodes.rules.targetGroup') },
  ]
  for (const node of store.customNodes.value.nodes) {
    options.push({
      value: `custom_node:${node.id}`,
      label: node.enabled ? node.name : `${node.name}（${tr('已停用')}）`,
    })
  }
  return options
})

function presetIcon(id: string): string {
  if (id === 'ai') return 'zap'
  if (id === 'streaming') return 'play'
  return 'globe'
}

function encodeTarget(target: LandingRuleTarget): string {
  return target.kind === 'custom_node' ? `custom_node:${target.id}` : 'custom_group'
}

function decodeTarget(value: string): LandingRuleTarget {
  if (value.startsWith('custom_node:')) {
    return { kind: 'custom_node', id: value.slice('custom_node:'.length) }
  }
  return { kind: 'custom_group' }
}

function targetStatus(value: string): { label: string; issue: 'missing' | 'disabled' | null; notice: string | null } {
  if (value === 'custom_group') {
    return { label: t('customNodes.rules.targetGroup'), issue: null, notice: null }
  }
  if (value.startsWith('custom_node:')) {
    const id = value.slice('custom_node:'.length)
    const node = store.customNodes.value.nodes.find((item) => item.id === id)
    if (!node) {
      return {
        label: tr('目标节点已删除（{0}）', { 0: id }),
        issue: 'missing',
        notice: tr('目标节点已删除，请重新选择落地目标'),
      }
    }
    if (!node.enabled) {
      return {
        label: `${node.name}（${tr('已停用')}）`,
        issue: 'disabled',
        notice: tr('目标节点「{0}」已停用，此规则暂不生效', { 0: node.name }),
      }
    }
    return { label: node.name, issue: null, notice: null }
  }
  return { label: t('customNodes.rules.targetGroup'), issue: null, notice: null }
}

function targetOptionsFor(currentValue: string) {
  const options = [...baseTargetOptions.value]
  if (currentValue && !options.some((item) => item.value === currentValue)) {
    const status = targetStatus(currentValue)
    options.push({ value: currentValue, label: status.label })
  }
  return options
}

watch(
  () => props.open,
  (open) => {
    if (!open) return
    error.value = null
    newDomain.value = ''
    newDomainTarget.value = 'custom_group'
    editingIndex.value = null
    editPattern.value = ''
    editTarget.value = 'custom_group'
    const state = store.customNodes.value
    rulesEnabled.value = state.rules_enabled

    const nextPresets: Record<string, { id: string; enabled: boolean; target: string }> = {}
    for (const preset of store.landingPresets.value) {
      const existing = state.rules.find(
        (rule) => rule.rule.kind === 'preset' && rule.rule.id === preset.id,
      )
      nextPresets[preset.id] = {
        id: existing?.id ?? '',
        enabled: Boolean(existing?.enabled),
        target: existing ? encodeTarget(existing.target) : 'custom_group',
      }
    }
    presetDrafts.value = nextPresets

    domainRules.value = state.rules
      .filter((rule): rule is LandingRule & { rule: { kind: 'domain'; pattern: string } } => rule.rule.kind === 'domain')
      .map((rule) => ({
        id: rule.id,
        enabled: rule.enabled,
        pattern: rule.rule.pattern,
        target: encodeTarget(rule.target),
      }))
  },
  { immediate: true },
)

function addDomainRule() {
  const pattern = newDomain.value.trim()
  if (!pattern) return
  error.value = null
  if (domainRules.value.some((item) => item.pattern.toLowerCase() === pattern.toLowerCase())) {
    error.value = tr('该域名规则已存在')
    return
  }
  domainRules.value = [
    ...domainRules.value,
    {
      id: '',
      enabled: true,
      pattern,
      target: newDomainTarget.value,
    },
  ]
  newDomain.value = ''
}

function startEditDomainRule(index: number) {
  const item = domainRules.value[index]
  if (!item) return
  error.value = null
  editingIndex.value = index
  editPattern.value = item.pattern
  editTarget.value = item.target
}

function cancelEditDomainRule() {
  editingIndex.value = null
  editPattern.value = ''
  editTarget.value = 'custom_group'
  error.value = null
}

function saveEditDomainRule(index: number) {
  const pattern = editPattern.value.trim()
  if (!pattern) {
    error.value = tr('请填写域名规则')
    return
  }
  if (domainRules.value.some((item, i) => i !== index && item.pattern.toLowerCase() === pattern.toLowerCase())) {
    error.value = tr('该域名规则已存在')
    return
  }
  domainRules.value = domainRules.value.map((item, i) =>
    i === index ? { ...item, pattern, target: editTarget.value } : item,
  )
  cancelEditDomainRule()
}

function toggleDomainRule(index: number, enabled: boolean) {
  domainRules.value = domainRules.value.map((item, i) =>
    i === index ? { ...item, enabled } : item,
  )
}

function removeDomainRule(index: number) {
  if (editingIndex.value === index) cancelEditDomainRule()
  else if (editingIndex.value !== null && editingIndex.value > index) editingIndex.value -= 1
  domainRules.value = domainRules.value.filter((_, i) => i !== index)
  error.value = null
}

async function submit() {
  if (store.busy['customNodes:rules']) return
  error.value = null

  if (editingIndex.value !== null) {
    saveEditDomainRule(editingIndex.value)
    if (error.value) return
  }

  if (newDomain.value.trim()) {
    addDomainRule()
    if (error.value) return
  }

  const compiled: LandingRule[] = []
  for (const preset of store.landingPresets.value) {
    const draft = presetDrafts.value[preset.id]
    if (!draft?.enabled) continue
    compiled.push({
      id: draft.id,
      enabled: true,
      rule: { kind: 'preset', id: preset.id },
      target: decodeTarget(draft.target),
    })
  }
  for (const item of domainRules.value) {
    compiled.push({
      id: item.id,
      enabled: item.enabled,
      rule: { kind: 'domain', pattern: item.pattern },
      target: decodeTarget(item.target),
    })
  }

  const result = await store.saveLandingRules(rulesEnabled.value, compiled)
  if (!result) {
    error.value = store.lastRunError.value ?? tr('保存落地分流规则失败')
    return
  }
  emit('saved')
  emit('close')
}
</script>

<template>
  <Modal
    :open="open"
    wide
    :title="t('customNodes.rules.title')"
    :subtitle="t('customNodes.landingRulesHint')"
    @close="emit('close')"
  >
    <div class="stack">
      <div class="custom-switch-row custom-rules-master">
        <div class="grow min0">
          <div class="custom-panel-title-row">
            <strong>{{ t('customNodes.rules.masterToggle') }}</strong>
            <span v-if="enabledSummaryCount > 0" class="custom-stat-pill accent">
              {{ tr('已选 {0} 项', { 0: enabledSummaryCount }) }}
            </span>
          </div>
          <p class="muted small">{{ t('customNodes.landingRulesHint') }}</p>
        </div>
        <Toggle
          v-model="rulesEnabled"
          :label="t('customNodes.rules.masterToggle')"
          data-testid="landing-rules-master-toggle"
        />
      </div>

      <section class="stack-sm">
        <h3 class="custom-section-title">{{ t('customNodes.rules.presets') }}</h3>
        <div class="custom-preset-grid">
          <div
            v-for="preset in store.landingPresets.value"
            :key="preset.id"
            class="custom-preset-row"
            :class="{
              active: Boolean(presetDrafts[preset.id]?.enabled),
              'has-warning': Boolean(presetDrafts[preset.id]?.enabled && targetStatus(presetDrafts[preset.id]!.target).issue),
            }"
          >
            <div class="custom-preset-top">
              <span class="custom-preset-icon" aria-hidden="true">
                <Icon :name="presetIcon(preset.id)" :size="15" />
              </span>
              <div class="grow min0">
                <strong class="custom-preset-title">{{ preset.label }}</strong>
                <span class="muted small">{{ tr('{0} 个内置域名', { 0: preset.domains.length }) }}</span>
              </div>
              <Toggle
                :model-value="Boolean(presetDrafts[preset.id]?.enabled)"
                :label="preset.label"
                :data-testid="`landing-preset-${preset.id}`"
                @update:model-value="(value) => { if (presetDrafts[preset.id]) presetDrafts[preset.id]!.enabled = value }"
              />
            </div>

            <div v-if="presetDrafts[preset.id]?.enabled" class="custom-preset-target" :data-testid="`landing-preset-target-${preset.id}`">
              <SelectField
                :model-value="presetDrafts[preset.id]!.target"
                :options="targetOptionsFor(presetDrafts[preset.id]!.target)"
                :sheet="compact"
                :label="preset.label"
                class="field-select"
                @update:model-value="(value) => { presetDrafts[preset.id]!.target = String(value) }"
              />
            </div>
            <p
              v-if="presetDrafts[preset.id]?.enabled && targetStatus(presetDrafts[preset.id]!.target).notice"
              class="field-error small custom-target-warning"
              role="status"
              :data-testid="`landing-preset-warning-${preset.id}`"
            >
              <Icon name="alert" :size="13" />
              <span>{{ targetStatus(presetDrafts[preset.id]!.target).notice }}</span>
            </p>
          </div>
        </div>
      </section>

      <section class="stack-sm">
        <h3 class="custom-section-title">{{ t('customNodes.rules.customDomains') }}</h3>
        <form class="custom-domain-add-row" @submit.prevent="addDomainRule">
          <input
            v-model="newDomain"
            type="text"
            class="grow"
            spellcheck="false"
            :placeholder="t('customNodes.rules.domainPlaceholder')"
            data-testid="landing-domain-input"
            @input="error = null"
          />
          <div class="custom-domain-target-select" data-testid="landing-domain-target">
            <SelectField
              :model-value="newDomainTarget"
              :options="baseTargetOptions"
              :sheet="compact"
              :label="t('customNodes.rules.targetGroup')"
              @update:model-value="(value) => { newDomainTarget = String(value) }"
            />
          </div>
          <button
            type="submit"
            class="btn primary sm"
            :disabled="!newDomain.trim()"
            data-testid="landing-domain-add"
          >
            <Icon name="plus" :size="14" /> {{ t('customNodes.rules.addDomain') }}
          </button>
        </form>

        <ul v-if="domainRules.length > 0" class="custom-domain-list" data-testid="landing-domain-list">
          <li
            v-for="(item, index) in domainRules"
            :key="`${item.id || item.pattern}-${index}`"
            class="custom-domain-row"
            :class="{
              disabled: !item.enabled,
              'has-warning': Boolean(item.enabled && targetStatus(item.target).issue),
            }"
          >
            <template v-if="editingIndex === index">
              <div class="custom-domain-edit-row grow">
                <input
                  v-model="editPattern"
                  type="text"
                  class="grow mono"
                  spellcheck="false"
                  :placeholder="t('customNodes.rules.domainPlaceholder')"
                  :data-testid="`landing-rule-edit-input-${index}`"
                  @keydown.enter.prevent="saveEditDomainRule(index)"
                />
                <div class="custom-domain-target-select" :data-testid="`landing-rule-edit-target-${index}`">
                  <SelectField
                    :model-value="editTarget"
                    :options="targetOptionsFor(editTarget)"
                    :sheet="compact"
                    :label="t('customNodes.rules.targetGroup')"
                    @update:model-value="(value) => { editTarget = String(value) }"
                  />
                </div>
                <button
                  type="button"
                  class="btn primary sm"
                  :data-testid="`landing-rule-edit-save-${index}`"
                  @click="saveEditDomainRule(index)"
                >
                  {{ tr('完成') }}
                </button>
                <button
                  type="button"
                  class="btn ghost sm"
                  :data-testid="`landing-rule-edit-cancel-${index}`"
                  @click="cancelEditDomainRule"
                >
                  {{ tr('取消') }}
                </button>
              </div>
            </template>
            <template v-else>
              <div class="grow min0 stack-xs">
                <div class="custom-domain-main">
                  <span class="mono grow min0 ellipsis">{{ item.pattern }}</span>
                  <span
                    class="tag sm"
                    :class="{
                      danger: targetStatus(item.target).issue === 'missing',
                      warn: targetStatus(item.target).issue === 'disabled',
                    }"
                    :data-testid="`landing-rule-target-tag-${index}`"
                  >
                    {{ targetStatus(item.target).label }}
                  </span>
                </div>
                <p
                  v-if="item.enabled && targetStatus(item.target).notice"
                  class="field-error small custom-target-warning"
                  role="status"
                  :data-testid="`landing-rule-warning-${index}`"
                >
                  <Icon name="alert" :size="13" />
                  <span>{{ targetStatus(item.target).notice }}</span>
                </p>
              </div>
              <div class="custom-node-actions">
                <Toggle
                  :model-value="item.enabled"
                  :label="item.pattern"
                  :data-testid="`landing-rule-toggle-${index}`"
                  @update:model-value="(value) => toggleDomainRule(index, value)"
                />
                <button
                  type="button"
                  class="icon-btn sm"
                  :title="tr('编辑')"
                  :aria-label="tr('编辑')"
                  :data-testid="`landing-rule-edit-${index}`"
                  @click="startEditDomainRule(index)"
                >
                  <Icon name="edit" :size="14" />
                </button>
                <button
                  type="button"
                  class="icon-btn sm"
                  :title="tr('删除')"
                  :aria-label="tr('删除')"
                  :data-testid="`landing-rule-remove-${index}`"
                  @click="removeDomainRule(index)"
                >
                  <Icon name="trash" :size="14" />
                </button>
              </div>
            </template>
          </li>
        </ul>
      </section>

      <p v-if="error" class="field-error small" role="alert" data-testid="landing-rules-error">
        <Icon name="alert" :size="13" />
        <span>{{ error }}</span>
      </p>
    </div>

    <template #footer>
      <button type="button" class="btn ghost" @click="emit('close')">{{ tr('取消') }}</button>
      <button
        type="button"
        class="btn primary"
        :disabled="Boolean(store.busy['customNodes:rules'])"
        data-testid="landing-rules-save"
        @click="submit"
      >
        <span v-if="store.busy['customNodes:rules']" class="spinner xs" aria-hidden="true" />
        {{ t('customNodes.rules.save') }}
      </button>
    </template>
  </Modal>
</template>
