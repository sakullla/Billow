<script setup lang="ts">
/**
 * One group of settings rows: a quiet caption above a rounded card, in the
 * shape of the system settings apps. `collapsible` folds rarely used options
 * behind a single row; search opens the fold when it jumps inside.
 */
defineProps<{
  title?: string
  description?: string
  footnote?: string
  collapsible?: boolean
  /** Summary shown on the folded row, e.g. the options it hides. */
  summary?: string
  open?: boolean
}>()
</script>

<template>
  <section class="sgroup">
    <header v-if="(title && !collapsible) || $slots.action" class="sgroup-head">
      <div class="grow min0">
        <h3 v-if="title && !collapsible">{{ title }}</h3>
        <p v-if="description && !collapsible" class="sgroup-desc">{{ description }}</p>
      </div>
      <slot name="action" />
    </header>
    <details v-if="collapsible" class="sgroup-card sgroup-fold" :open="open || undefined">
      <summary class="srow srow-nav sgroup-fold-summary">
        <div class="srow-main">
          <span class="srow-title">{{ title }}</span>
          <span v-if="summary" class="srow-desc">{{ summary }}</span>
        </div>
        <svg class="sgroup-fold-chevron" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
          <path d="m9 6 6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </summary>
      <slot />
    </details>
    <div v-else class="sgroup-card">
      <slot />
    </div>
    <p v-if="footnote || $slots.footnote" class="sgroup-foot">
      <slot name="footnote">{{ footnote }}</slot>
    </p>
  </section>
</template>
