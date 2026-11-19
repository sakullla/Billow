<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Icon from './Icon.vue'
import { t } from '../lib/i18n'
import { useStore } from '../lib/store'
import { comboFromEvent, inWindowShortcut, shortcutKeyLabel } from '../lib/ui/shortcuts'
import { type HotkeyAction, type HotkeySettings } from '../lib/types'

/**
 * 全局快捷键 (R39). Nothing is bound until the user records a combination; a
 * rejected edit (another action, an in-window shortcut, a combination the
 * system refuses) keeps the old binding and says what it clashed with.
 */
defineProps<{ compact?: boolean }>()

const store = useStore()

const settings = ref<HotkeySettings | null>(null)
const error = ref<string | null>(null)
const recording = ref<HotkeyAction | null>(null)
const busy = ref(false)

const ACTIONS: { id: HotkeyAction; label: () => string }[] = [
  { id: 'connect', label: () => t('hotkey.connect') },
  { id: 'proxy', label: () => t('hotkey.proxy') },
  { id: 'tun', label: () => t('hotkey.tun') },
  { id: 'mode-rule', label: () => t('hotkey.modeRule') },
  { id: 'mode-global', label: () => t('hotkey.modeGlobal') },
  { id: 'mode-direct', label: () => t('hotkey.modeDirect') },
  { id: 'window', label: () => t('hotkey.window') },
]

const unavailable = computed(() => settings.value !== null && !settings.value.available)

function bindingFor(action: HotkeyAction) {
  return settings.value?.bindings.find((binding) => binding.action === action) ?? null
}

function comboText(action: HotkeyAction): string {
  const combo = bindingFor(action)?.combo ?? ''
  return combo ? shortcutKeyLabel(combo) : t('hotkey.empty')
}

async function load() {
  try {
    settings.value = await store.backend.hotkeySettings()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  }
}

onMounted(() => {
  void load()
})

function stopRecording() {
  recording.value = null
  window.removeEventListener('keydown', onKeydown, true)
}

function startRecording(action: HotkeyAction) {
  if (busy.value || unavailable.value) return
  error.value = null
  if (recording.value === action) {
    stopRecording()
    return
  }
  stopRecording()
  recording.value = action
  // Capture phase, so the window's own shortcuts (Ctrl+K, Ctrl+S, …) stay out
  // of the way while a combination is being recorded.
  window.addEventListener('keydown', onKeydown, true)
}

async function save(action: HotkeyAction, combo: string) {
  busy.value = true
  try {
    settings.value = await store.backend.setHotkey(action, combo)
    error.value = null
  } catch (reason) {
    // The backend refused the edit: the stored binding is unchanged.
    error.value = reason instanceof Error ? reason.message : String(reason)
  } finally {
    busy.value = false
  }
}

function onKeydown(event: KeyboardEvent) {
  const action = recording.value
  if (!action) return
  event.preventDefault()
  event.stopPropagation()
  if (event.repeat) return
  if (event.key === 'Escape') {
    stopRecording()
    return
  }
  const capture = comboFromEvent(event)
  if (capture.kind === 'modifier' || capture.kind === 'unsupported') return
  if (capture.kind === 'plain') {
    error.value = t('hotkey.plainKey')
    return
  }
  const clash = inWindowShortcut(capture.combo)
  if (clash) {
    error.value = t('hotkey.conflict.window', {
      combo: shortcutKeyLabel(capture.combo),
      action: clash.label,
    })
    stopRecording()
    return
  }
  stopRecording()
  void save(action, capture.combo)
}

function clear(action: HotkeyAction) {
  if (busy.value) return
  if (recording.value === action) stopRecording()
  void save(action, '')
}

onBeforeUnmount(() => {
  stopRecording()
})
</script>

<template>
  <section class="card" data-testid="hotkey-settings">
    <header v-if="!compact" class="card-head">
      <h2>{{ t('settings.hotkey.title') }}</h2>
      <span class="muted small">{{ t('settings.hotkey.detail') }}</span>
    </header>

    <p v-if="unavailable" class="muted small hotkey-note" data-testid="hotkey-unavailable">
      <Icon name="alert" :size="14" />
      <span>{{ t('hotkey.unavailable', { reason: settings?.reason ?? '' }) }}</span>
    </p>

    <div
      v-for="action in ACTIONS"
      :key="action.id"
      class="setting-row"
      :class="{ disabled: unavailable }"
      :data-testid="`hotkey-row-${action.id}`"
    >
      <div class="grow">
        <strong>{{ action.label() }}</strong>
        <p v-if="bindingFor(action.id) && !bindingFor(action.id)!.active && bindingFor(action.id)!.error" class="field-error small" :data-testid="`hotkey-inactive-${action.id}`">
          {{ t('hotkey.inactive', { reason: bindingFor(action.id)!.error ?? '' }) }}
        </p>
      </div>
      <div class="hotkey-actions">
        <kbd class="hotkey-combo" :data-testid="`hotkey-combo-${action.id}`">{{ comboText(action.id) }}</kbd>
        <button
          type="button"
          class="btn ghost sm"
          :class="{ recording: recording === action.id }"
          :disabled="unavailable || busy"
          :data-testid="`hotkey-record-${action.id}`"
          @click="startRecording(action.id)"
        >
          <Icon name="keyboard" :size="15" />{{ recording === action.id ? t('hotkey.recording') : t('hotkey.record') }}
        </button>
        <button
          v-if="bindingFor(action.id)"
          type="button"
          class="btn ghost sm"
          :disabled="busy"
          :data-testid="`hotkey-clear-${action.id}`"
          @click="clear(action.id)"
        >
          {{ t('hotkey.clear') }}
        </button>
      </div>
    </div>

    <p v-if="error" class="field-error small hotkey-note" role="alert" data-testid="hotkey-error">
      <Icon name="alert" :size="14" /><span>{{ error }}</span>
    </p>
    <p v-if="!unavailable" class="muted small hotkey-note" data-testid="hotkey-hint">{{ t('hotkey.hint') }}</p>
  </section>
</template>

<style scoped>
.hotkey-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  justify-content: flex-end;
}
.hotkey-combo {
  min-width: 84px;
  padding: 3px 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font: inherit;
  font-size: 12px;
  text-align: center;
  background: var(--surface-2, transparent);
}
.hotkey-note {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  padding: 0 20px 12px;
  margin: 0;
}
.hotkey-note span {
  flex: 1;
}
.setting-row.disabled {
  opacity: 0.6;
}
.recording {
  color: var(--accent-ink, inherit);
}
</style>
