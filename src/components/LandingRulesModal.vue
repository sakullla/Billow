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

const store = useStore()
const rulesEnabled = ref(true)
const presetDrafts = ref<Record<string, { id: string; enabled: boolean; target: string }>>({})
const domainRules = ref<{ id: string; enabled: boolean; pattern: string; target: string }[]>([])
const newDomain = ref('')
const newDomainTarget = ref('custom_group')
const error = ref<string | null>(null)

const targetOptions = computed(() => {
  const options: { value: string; label: string }[] = [
    { value: 'custom_group', label: t('customNodes.rules.targetGroup') },
  ]
  for (const node of store.customNodes.value.nodes) {
    options.push({
      value: `custom_node:${node.id}`,
      label: node.enabled ? node.name : `${node.name} (${tr('已停用')})`,
    })
  }
  return options
})

function encodeTarget(target: LandingRuleTarget): string {
  return target.kind === 'custom_node' ? `custom_node:${target.id}` : 'custom_group'
}

function decodeTarget(value: string): LandingRuleTarget {
  if (value.startsWith('custom_node:')) {
    return { kind: 'custom_node', id: value.slice('custom_node:'.length) }
  }
  return { kind: 'custom_group' }
}

function targetLabel(value: string): string {
  return targetOptions.value.find((option) => option.value === value)?.label ?? t('customNodes.rules.targetGroup')
}

watch(
  () => props.open,
  (open) => {
    if (!open) return
    error.value = null
    newDomain.value = ''
    newDomainTarget.value = 'custom_group'
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

function removeDomainRule(index: number) {
  domainRules.value = domainRules.value.filter((_, i) => i !== index)
  error.value = null
}

async function submit() {
  if (store.busy['customNodes:rules']) return
  error.value = null

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
        <div>
          <strong>{{ t('customNodes.rules.masterToggle') }}</strong>
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
        <div
          v-for="preset in store.landingPresets.value"
          :key="preset.id"
          class="custom-preset-row"
        >
          <div class="grow min0">
            <div class="custom-preset-head">
              <strong>{{ preset.label }}</strong>
              <span class="muted small">{{ tr('{0} 个域名', { 0: preset.domains.length }) }}</span>
            </div>
            <div v-if="presetDrafts[preset.id]?.enabled" class="custom-preset-target">
              <SelectField
                :model-value="presetDrafts[preset.id]!.target"
                :options="targetOptions"
                :sheet="compact"
                :label="preset.label"
                class="field-select"
                :data-testid="`landing-preset-target-${preset.id}`"
                @update:model-value="(value) => { presetDrafts[preset.id]!.target = String(value) }"
              />
            </div>
          </div>
          <Toggle
            :model-value="Boolean(presetDrafts[preset.id]?.enabled)"
            :label="preset.label"
            :data-testid="`landing-preset-${preset.id}`"
            @update:model-value="(value) => { if (presetDrafts[preset.id]) presetDrafts[preset.id]!.enabled = value }"
          />
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
          <SelectField
            :model-value="newDomainTarget"
            :options="targetOptions"
            :sheet="compact"
            :label="t('customNodes.rules.targetGroup')"
            class="custom-domain-target-select"
            data-testid="landing-domain-target"
            @update:model-value="(value) => { newDomainTarget = String(value) }"
          />
          <button
            type="submit"
            class="btn ghost sm"
            :disabled="!newDomain.trim()"
            data-testid="landing-domain-add"
          >
            <Icon name="plus" :size="14" /> {{ t('customNodes.rules.addDomain') }}
          </button>
        </form>

        <ul v-if="domainRules.length > 0" class="custom-domain-list" data-testid="landing-domain-list">
          <li v-for="(item, index) in domainRules" :key="`${item.pattern}-${index}`" class="custom-domain-row">
            <span class="mono grow min0 ellipsis">{{ item.pattern }}</span>
            <span class="tag sm">{{ targetLabel(item.target) }}</span>
            <button
              type="button"
              class="icon-btn sm"
              :aria-label="tr('删除')"
              :data-testid="`landing-rule-remove-${index}`"
              @click="removeDomainRule(index)"
            >
              <Icon name="trash" :size="14" />
            </button>
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
