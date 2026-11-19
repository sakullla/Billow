<script setup lang="ts">import { tr } from '../lib/i18n'

import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import type { KnownNames } from '../lib/yaml/complete'
import type { YamlEditorHandle } from '../lib/yaml/editor'
import type { OverrideLanguage } from '../lib/yaml/script'

const props = defineProps<{
  modelValue: string
  readonly?: boolean
  placeholder?: string
  label?: string
  /** Proxy/group names from outside the text (e.g. the profile an override applies to). */
  names?: KnownNames
  /** Editing a 覆写: complete `+key` / `key+` / `key!` modifiers. */
  override?: boolean
  language?: OverrideLanguage
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string]; save: [] }>()

const host = ref<HTMLElement | null>(null)
const handle = shallowRef<YamlEditorHandle | null>(null)
const failed = ref(false)
let disposed = false

onMounted(async () => {
  try {
    // The editor is a separate chunk; the rest of the app never pays for it.
    const { createYamlEditor } = await import('../lib/yaml/editor')
    if (disposed || !host.value) return
    handle.value = createYamlEditor(host.value, {
      doc: props.modelValue,
      readOnly: props.readonly,
      placeholder: props.placeholder,
      label: props.label,
      names: () => props.names ?? {},
      override: props.override,
      language: props.language,
      onChange: (value) => emit('update:modelValue', value),
      onSave: () => emit('save'),
    })
  } catch (error) {
    console.error(error)
    failed.value = true
  }
})

watch(
  () => props.modelValue,
  (value) => handle.value?.setValue(value),
)
watch(
  () => props.language,
  (value) => handle.value?.setLanguage(value ?? 'yaml'),
)
watch(
  () => props.readonly,
  (value) => handle.value?.setReadOnly(Boolean(value)),
)

onBeforeUnmount(() => {
  disposed = true
  handle.value?.destroy()
})

defineExpose({
  focus: () => handle.value?.focus(),
  handle,
})
</script>

<template>
  <div class="yaml-editor" :class="{ ready: handle, readonly }" data-testid="yaml-editor">
    <div ref="host" class="yaml-editor-host" />
    <!-- Fallback when the editor chunk cannot load: plain text, still editable. -->
    <textarea
      v-if="failed"
      class="editor-text mono"
      :value="modelValue"
      :readonly="readonly"
      :aria-label="label"
      spellcheck="false"
      @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
    />
    <div v-else-if="!handle" class="yaml-editor-loading muted small"><span class="spinner xs" /> {{ tr('正在载入编辑器…') }}</div>
  </div>
</template>
