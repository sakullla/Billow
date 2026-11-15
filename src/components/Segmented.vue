<script setup lang="ts" generic="T extends string">
import Icon from './Icon.vue'

defineProps<{
  modelValue: T | null
  options: readonly { id: T; label: string; icon?: string }[]
  label?: string
  size?: 'sm' | 'md'
  disabled?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: T] }>()
</script>

<template>
  <div class="segmented" :class="size ?? 'md'" role="radiogroup" :aria-label="label">
    <button
      v-for="option in options"
      :key="option.id"
      type="button"
      role="radio"
      class="segment"
      :class="{ active: modelValue === option.id }"
      :aria-checked="modelValue === option.id"
      :disabled="disabled"
      :data-value="option.id"
      @click="emit('update:modelValue', option.id)"
    >
      <Icon v-if="option.icon" :name="option.icon" :size="15" />
      <span>{{ option.label }}</span>
    </button>
  </div>
</template>
