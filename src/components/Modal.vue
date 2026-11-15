<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import Icon from './Icon.vue'

const props = defineProps<{ title: string; wide?: boolean; subtitle?: string }>()
const emit = defineEmits<{ close: [] }>()

function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape') emit('close')
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
void props
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @mousedown.self="emit('close')">
      <section class="modal" :class="{ wide }" role="dialog" aria-modal="true" :aria-label="title">
        <header class="modal-head">
          <div>
            <h2>{{ title }}</h2>
            <p v-if="subtitle" class="muted small">{{ subtitle }}</p>
          </div>
          <button type="button" class="icon-btn" aria-label="关闭" @click="emit('close')">
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
