<script setup lang="ts">import { tr } from '../lib/i18n'

withDefaults(
  defineProps<{
    variant?: 'list' | 'card' | 'detail'
    rows?: number
    cards?: number
  }>(),
  { variant: 'list', rows: 5, cards: 3 },
)
</script>

<template>
  <div class="skeleton" :class="variant" role="status" aria-busy="true" aria-live="polite">
    <span class="sr-only">{{ tr('加载中') }}</span>

    <div v-if="variant === 'list'" class="sk-list" aria-hidden="true">
      <div v-for="row in rows" :key="row" class="sk-row">
        <span class="sk-bar sk-avatar" />
        <span class="sk-lines">
          <span class="sk-bar sk-w-60" />
          <span class="sk-bar sk-w-35" />
        </span>
        <span class="sk-bar sk-w-15" />
      </div>
    </div>

    <div v-else-if="variant === 'card'" class="sk-cards" aria-hidden="true">
      <div v-for="card in cards" :key="card" class="sk-card">
        <span class="sk-bar sk-w-45" />
        <span class="sk-bar sk-w-80" />
        <span class="sk-bar sk-w-60" />
        <span class="sk-bar sk-w-30" />
      </div>
    </div>

    <div v-else class="sk-detail" aria-hidden="true">
      <span class="sk-bar sk-w-40 sk-lg" />
      <span class="sk-bar sk-w-25" />
      <div v-for="row in rows" :key="row" class="sk-detail-row">
        <span class="sk-bar sk-w-20" />
        <span class="sk-bar sk-w-55" />
      </div>
    </div>
  </div>
</template>
