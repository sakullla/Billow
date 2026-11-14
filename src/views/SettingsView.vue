<script setup lang="ts">
import { ABOUT_TEXT, ABOUT_TITLE, SETTINGS_TITLE, THEME_TITLE, type ThemePreference } from '../copy'
import { THEME_OPTIONS } from '../theme'

defineProps<{ modelValue: ThemePreference }>()
const emit = defineEmits<{ 'update:modelValue': [value: ThemePreference] }>()
</script>

<template>
  <section class="screen" data-screen="settings">
    <h1 class="page-title">{{ SETTINGS_TITLE }}</h1>
    <article class="card">
      <h2>{{ THEME_TITLE }}</h2>
      <div class="choices" role="radiogroup" aria-label="主题">
        <label
          v-for="option in THEME_OPTIONS"
          :key="option.id"
          class="choice"
          :class="{ selected: modelValue === option.id }"
        >
          <input
            type="radio"
            name="theme"
            :value="option.id"
            :checked="modelValue === option.id"
            @change="emit('update:modelValue', option.id)"
          />
          <span>{{ option.label }}</span>
        </label>
      </div>
    </article>
    <article class="card" data-testid="about">
      <h2>{{ ABOUT_TITLE }}</h2>
      <p>{{ ABOUT_TEXT }}</p>
    </article>
  </section>
</template>
