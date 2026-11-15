<script setup lang="ts">
import { ref, useId } from 'vue'
import { useFocusTrap } from '../lib/ui/focus'
import Icon from './Icon.vue'

const props = defineProps<{
  title: string
  wide?: boolean
  subtitle?: string
  /** Return false (or resolve false) to keep the dialog open, e.g. unsaved editor changes. */
  beforeClose?: () => boolean | Promise<boolean>
  /** Override the default first focus target. */
  initialFocus?: () => HTMLElement | null | undefined
  closeOnBackdrop?: boolean
}>()
const emit = defineEmits<{ close: [] }>()

const panel = ref<HTMLElement | null>(null)
const titleId = useId()
const subtitleId = useId()
const closing = ref(false)

async function requestClose() {
  if (closing.value) return
  closing.value = true
  try {
    if (props.beforeClose && !(await props.beforeClose())) return
    emit('close')
  } catch (error) {
    console.error(error)
  } finally {
    closing.value = false
  }
}

function onBackdrop() {
  if (props.closeOnBackdrop !== false) void requestClose()
}

/**
 * Touch screens: opening a sheet must not pop the keyboard or paint a focus ring
 * on the close button, so focus parks on the panel itself. Keyboards and mice
 * keep the first-control focus.
 */
function coarsePointer(): boolean {
  return typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches === true
}

useFocusTrap(() => panel.value, {
  onClose: () => void requestClose(),
  initialFocus: () => props.initialFocus?.() ?? (coarsePointer() ? panel.value : undefined),
})
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @mousedown.self="onBackdrop">
      <section
        ref="panel"
        class="modal"
        :class="{ wide }"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="titleId"
        :aria-describedby="subtitle ? subtitleId : undefined"
      >
        <header class="modal-head">
          <div>
            <h2 :id="titleId">{{ title }}</h2>
            <p v-if="subtitle" :id="subtitleId" class="muted small">{{ subtitle }}</p>
          </div>
          <button type="button" class="icon-btn" aria-label="关闭" @click="requestClose">
            <Icon name="x" />
          </button>
        </header>
        <div class="modal-body">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="modal-foot">
          <slot name="footer" />
        </footer>
      </section>
    </div>
  </Teleport>
</template>
