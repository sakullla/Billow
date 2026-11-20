<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Icon from '../Icon.vue'
import EditorDialog from './EditorDialog.vue'
import { tr } from '../../lib/i18n'

/**
 * Edits one list setting (DNS servers, routes, domains…) as plain lines, the
 * format people copy from configs and docs. Bad entries are named before
 * anything is saved.
 */
const props = defineProps<{
  title: string
  subtitle?: string
  items: readonly string[] | null
  placeholder?: string
  /** Shown under the box, e.g. what an empty list means. */
  hint?: string
  validate?: (item: string) => boolean
  invalidMessage?: (item: string) => string
  /** Offers 恢复默认 with these entries. */
  defaults?: readonly string[]
  saving?: boolean
  testid?: string
}>()
const emit = defineEmits<{ save: [items: string[]]; close: [] }>()

const text = ref((props.items ?? []).join('\n'))
const error = ref<string | null>(null)
const area = ref<HTMLTextAreaElement | null>(null)

const parsed = computed(() => {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of text.value.split(/[\n,]+/)) {
    const item = raw.trim()
    if (item && !seen.has(item)) {
      seen.add(item)
      out.push(item)
    }
  }
  return out
})
const dirty = computed(() => parsed.value.join('\n') !== (props.items ?? []).join('\n'))
const rows = computed(() => Math.min(14, Math.max(5, text.value.split('\n').length + 1)))

onMounted(() => {
  requestAnimationFrame(() => area.value?.focus())
})

function save() {
  const bad = props.validate ? parsed.value.find((item) => !props.validate!(item)) : undefined
  if (bad) {
    error.value = props.invalidMessage ? props.invalidMessage(bad) : tr('无法识别「{0}」', { 0: bad })
    return
  }
  error.value = null
  emit('save', parsed.value)
}

function restoreDefaults() {
  text.value = (props.defaults ?? []).join('\n')
  error.value = null
}
</script>

<template>
  <EditorDialog
    :title="title"
    :subtitle="subtitle"
    :dirty="dirty"
    :saving="saving"
    :save-testid="testid ? `${testid}-save` : undefined"
    @save="save"
    @close="emit('close')"
  >
    <div class="list-editor">
      <div class="list-editor-head">
        <span class="muted small">{{ tr('每行一个') }}</span>
        <span class="muted small mono">{{ tr('{0} 项', { 0: parsed.length }) }}</span>
      </div>
      <textarea
        ref="area"
        v-model="text"
        class="input list-input mono"
        :rows="rows"
        spellcheck="false"
        autocapitalize="off"
        :placeholder="placeholder"
        :aria-label="title"
        :aria-invalid="error ? 'true' : undefined"
        :data-testid="testid ? `${testid}-input` : undefined"
        @input="error = null"
      />
      <p v-if="error" class="field-error small" role="alert" :data-testid="testid ? `${testid}-error` : undefined">
        <Icon name="alert" :size="13" /><span>{{ error }}</span>
      </p>
      <p v-else-if="hint" class="muted small">{{ hint }}</p>
    </div>
    <template v-if="defaults" #footer-start>
      <button type="button" class="btn ghost sm" @click="restoreDefaults">{{ tr('恢复默认') }}</button>
    </template>
  </EditorDialog>
</template>

<style scoped>
.list-editor {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.list-editor-head {
  display: flex;
  justify-content: space-between;
}
.list-editor textarea {
  width: 100%;
  resize: vertical;
}
</style>
