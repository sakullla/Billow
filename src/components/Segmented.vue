<script setup lang="ts" generic="T extends string">
import { ref } from 'vue'
import Icon from './Icon.vue'

const props = defineProps<{
  modelValue: T | null
  options: readonly { id: T; label: string; icon?: string }[]
  label?: string
  size?: 'sm' | 'md'
  block?: boolean
  disabled?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: T] }>()

const group = ref<HTMLElement | null>(null)

// Roving tabindex: the group is one tab stop, arrows move the selection (R30).
function tabIndex(index: number): number | undefined {
  if (props.disabled) return undefined
  const active = props.options.findIndex((option) => option.id === props.modelValue)
  return index === (active >= 0 ? active : 0) ? 0 : -1
}

function onKeydown(event: KeyboardEvent, index: number) {
  const count = props.options.length
  if (!count) return
  let next = -1
  if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % count
  else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + count) % count
  else if (event.key === 'Home') next = 0
  else if (event.key === 'End') next = count - 1
  if (next < 0) return
  event.preventDefault()
  const option = props.options[next]
  if (!option) return
  emit('update:modelValue', option.id)
  group.value?.querySelectorAll<HTMLButtonElement>('.segment')[next]?.focus()
}
</script>

<template>
  <div ref="group" class="segmented" :class="[size ?? 'md', { block }]" role="radiogroup" :aria-label="label">
    <button
      v-for="(option, index) in options"
      :key="option.id"
      type="button"
      role="radio"
      class="segment"
      :class="{ active: modelValue === option.id }"
      :aria-checked="modelValue === option.id"
      :tabindex="tabIndex(index)"
      :disabled="disabled"
      :data-value="option.id"
      @click="emit('update:modelValue', option.id)"
      @keydown="onKeydown($event, index)"
    >
      <Icon v-if="option.icon" :name="option.icon" :size="15" />
      <span>{{ option.label }}</span>
    </button>
  </div>
</template>
