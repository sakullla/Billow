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

function isBound(action: HotkeyAction): boolean {
  return Boolean(bindingFor(action)?.combo)
}

function inactiveReason(action: HotkeyAction): string | null {
  const binding = bindingFor(action)
  return binding && !binding.active && binding.error ? binding.error : null
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
  <section class="hotkey-section" data-testid="hotkey-settings">
    <header v-if="!compact" class="hotkey-head">
      <h3>{{ t('settings.hotkey.title') }}</h3>
      <p class="muted small">{{ t('settings.hotkey.detail') }}</p>
    </header>

    <p v-if="unavailable" class="hotkey-note warn small" data-testid="hotkey-unavailable">
      <Icon name="alert" :size="14" />
      <span>{{ t('hotkey.unavailable', { reason: settings?.reason ?? '' }) }}</span>
    </p>

    <ul class="hotkey-list" :class="{ disabled: unavailable }">
      <li v-for="action in ACTIONS" :key="action.id" class="hotkey-row" :data-testid="`hotkey-row-${action.id}`">
        <div class="grow min0">
          <span class="hotkey-label">{{ action.label() }}</span>
          <p v-if="inactiveReason(action.id)" class="field-error small" :data-testid="`hotkey-inactive-${action.id}`">
            {{ t('hotkey.inactive', { reason: inactiveReason(action.id) ?? '' }) }}
          </p>
        </div>
        <!-- One control per action: the key cap shows the binding and records a new one when clicked. -->
        <button
          type="button"
          class="hotkey-cap"
          :class="{ recording: recording === action.id, bound: isBound(action.id) }"
          :disabled="unavailable || busy"
          :aria-pressed="recording === action.id"
          :aria-label="`${action.label()}: ${recording === action.id ? t('hotkey.recording') : comboText(action.id)}`"
          :title="recording === action.id ? t('hotkey.recordingHint') : t('hotkey.record')"
          :data-testid="`hotkey-record-${action.id}`"
          @click="startRecording(action.id)"
        >
          <span v-if="recording === action.id" class="hotkey-cap-text">{{ t('hotkey.recording') }}</span>
          <kbd v-else class="hotkey-cap-text" :data-testid="`hotkey-combo-${action.id}`">{{ comboText(action.id) }}</kbd>
        </button>
        <button
          v-if="isBound(action.id)"
          type="button"
          class="icon-btn sm"
          :disabled="busy"
          :title="t('hotkey.clear')"
          :aria-label="`${t('hotkey.clear')}: ${action.label()}`"
          :data-testid="`hotkey-clear-${action.id}`"
          @click="clear(action.id)"
        >
          <Icon name="x" :size="14" />
        </button>
        <span v-else class="hotkey-clear-slot" aria-hidden="true" />
      </li>
    </ul>

    <p v-if="error" class="field-error small hotkey-note" role="alert" data-testid="hotkey-error">
      <Icon name="alert" :size="14" /><span>{{ error }}</span>
    </p>
    <p v-else-if="!unavailable" class="muted small hotkey-note" data-testid="hotkey-hint">{{ t('hotkey.hint') }}</p>
  </section>
</template>

<style scoped>
.hotkey-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.hotkey-head h3 {
  font-size: var(--text-md);
  font-weight: 680;
  color: var(--text);
}
.hotkey-head p {
  margin-top: 2px;
}
.hotkey-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.hotkey-list.disabled {
  opacity: 0.55;
}
.hotkey-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 40px;
  padding: 4px 0;
}
.hotkey-row + .hotkey-row {
  border-top: 1px solid var(--border);
}
.hotkey-label {
  font-size: var(--text-md);
  font-weight: 560;
  color: var(--text);
}
.hotkey-row .field-error {
  margin-top: 2px;
}
.hotkey-cap {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 128px;
  height: 30px;
  padding: 0 10px;
  border-radius: 8px;
  border: 1px dashed var(--border-input);
  background: transparent;
  color: var(--muted);
  font-size: var(--text-sm);
  cursor: pointer;
  transition: border-color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease), box-shadow var(--dur-fast) var(--ease);
}
.hotkey-cap.bound {
  border-style: solid;
  border-color: var(--border-input);
  background: var(--sunken);
  color: var(--text);
  font-weight: 600;
}
.hotkey-cap:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent-ink);
}
.hotkey-cap.recording {
  border-style: solid;
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--accent-ink);
  box-shadow: 0 0 0 3px var(--accent-soft);
  animation: hotkey-pulse 1.4s ease-in-out infinite;
}
.hotkey-cap:disabled {
  cursor: not-allowed;
}
.hotkey-cap-text {
  font: inherit;
  white-space: nowrap;
}
.hotkey-clear-slot {
  width: 28px;
  flex: none;
}
.hotkey-note {
  display: flex;
  gap: 6px;
  align-items: flex-start;
  margin: 2px 0 0;
}
.hotkey-note.warn {
  padding: 8px 10px;
  border-radius: var(--radius-control);
  background: var(--fair-soft);
  color: var(--fair-ink);
}
.hotkey-note span {
  flex: 1;
}
@keyframes hotkey-pulse {
  50% {
    box-shadow: 0 0 0 5px var(--accent-soft);
  }
}
@media (prefers-reduced-motion: reduce) {
  .hotkey-cap.recording {
    animation: none;
  }
}
</style>
