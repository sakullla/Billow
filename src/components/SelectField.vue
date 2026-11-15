<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'

export interface SelectOption {
  value: string | number
  label: string
  /** Secondary text, e.g. a count; shown right-aligned in the sheet. */
  hint?: string
}

defineOptions({ inheritAttrs: false })

const props = defineProps<{
  modelValue: string | number
  options: readonly SelectOption[]
  /** Accessible name and sheet title. */
  label: string
  /**
   * Phones get a bottom-sheet list instead of the platform picker: Android's
   * native select dialog ignores the app theme and font scale.
   */
  sheet?: boolean
  size?: 'sm'
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string | number] }>()

const open = ref(false)
const current = computed(() => props.options.find((option) => option.value === props.modelValue) ?? null)

function nativeLabel(option: SelectOption): string {
  return option.hint ? `${option.label} (${option.hint})` : option.label
}

function onNative(event: Event) {
  const raw = (event.target as HTMLSelectElement).value
  const option = props.options.find((item) => String(item.value) === raw)
  if (option) emit('update:modelValue', option.value)
}

function choose(option: SelectOption) {
  open.value = false
  if (option.value !== props.modelValue) emit('update:modelValue', option.value)
}
</script>

<template>
  <select
    v-if="!sheet"
    class="input"
    :class="size"
    :value="modelValue"
    :aria-label="label"
    v-bind="$attrs"
    @change="onNative"
  >
    <option v-for="option in options" :key="String(option.value)" :value="option.value">{{ nativeLabel(option) }}</option>
  </select>
  <template v-else>
    <button
      type="button"
      class="input select-trigger"
      :class="size"
      aria-haspopup="dialog"
      :aria-expanded="open"
      :aria-label="`${label}：${current?.label ?? '未选择'}`"
      v-bind="$attrs"
      @click="open = true"
    >
      <span class="select-trigger-text">{{ current?.label ?? '未选择' }}</span>
      <Icon name="chevron-down" :size="14" />
    </button>
    <Modal v-if="open" :title="label" @close="open = false">
      <div class="option-list" role="listbox" :aria-label="label">
        <button
          v-for="option in options"
          :key="String(option.value)"
          type="button"
          role="option"
          class="option-row"
          :class="{ active: option.value === modelValue }"
          :aria-selected="option.value === modelValue"
          @click="choose(option)"
        >
          <span class="option-label">{{ option.label }}</span>
          <span v-if="option.hint" class="option-hint">{{ option.hint }}</span>
          <Icon v-if="option.value === modelValue" name="check" :size="18" :stroke="2.4" class="option-check" />
        </button>
      </div>
    </Modal>
  </template>
</template>
