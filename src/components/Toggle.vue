<script setup lang="ts">
defineProps<{ modelValue: boolean; disabled?: boolean; busy?: boolean; label?: string }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <button
    type="button"
    role="switch"
    class="toggle"
    :class="{ on: modelValue, busy }"
    :aria-checked="modelValue"
    :aria-label="label"
    :disabled="disabled || busy"
    @click="emit('update:modelValue', !modelValue)"
  >
    <span class="toggle-knob" />
  </button>
</template>
