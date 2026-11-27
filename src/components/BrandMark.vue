<script setup lang="ts">
/**
 * Billow's logo inside the app: the traced wave mark on a tile the theme draws
 * (`--brand-tile`), so the logo follows the light and dark palettes instead of
 * carrying a fixed background baked into a bitmap.
 */
withDefaults(defineProps<{ size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' }>(), { size: 'md' })
const mark = `${import.meta.env.BASE_URL}brand-mark.svg`
</script>

<template>
  <span class="brand-mark" :class="size" aria-hidden="true"><img :src="mark" alt="" draggable="false" /></span>
</template>
