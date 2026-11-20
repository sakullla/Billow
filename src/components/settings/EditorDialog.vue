<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { tr } from '../../lib/i18n'
import Modal from '../Modal.vue'

/**
 * The one place multi-field and list settings are edited: changes stay in the
 * dialog until 保存, 取消 drops them, and a dirty dialog does not close on a
 * stray backdrop click. Ctrl/⌘+S saves from any field.
 */
const props = defineProps<{
  title: string
  subtitle?: string
  dirty?: boolean
  saving?: boolean
  wide?: boolean
  saveLabel?: string
  saveTestid?: string
  cancelTestid?: string
}>()
const emit = defineEmits<{ save: []; close: [] }>()

function onKeydown(event: KeyboardEvent) {
  if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 's') {
    event.preventDefault()
    event.stopPropagation()
    if (!props.saving) emit('save')
  }
}
// The dialog is the top layer while open, so the shortcut works wherever focus is
// (fields, footer buttons or nothing focused at all).
onMounted(() => document.addEventListener('keydown', onKeydown, true))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown, true))
</script>

<template>
  <Modal :title="title" :subtitle="subtitle" :wide="wide" :close-on-backdrop="!dirty" @close="emit('close')">
    <div class="editor-dialog">
      <slot />
    </div>
    <template #footer>
      <div class="editor-dialog-start">
        <slot name="footer-start" />
      </div>
      <button type="button" class="btn ghost" :data-testid="cancelTestid ?? 'editor-cancel'" @click="emit('close')">{{ tr('取消') }}</button>
      <button
        type="button"
        class="btn primary"
        :disabled="saving"
        :aria-busy="saving || undefined"
        :data-testid="saveTestid"
        @click="emit('save')"
      >
        <span v-if="saving" class="spinner xs" aria-hidden="true" />
        {{ saveLabel ?? tr('保存') }}
      </button>
    </template>
  </Modal>
</template>
