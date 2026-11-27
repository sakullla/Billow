<script setup lang="ts">
import Icon from '../Icon.vue'

/**
 * A settings row: title and one-line explanation on the left, the control on
 * the right. `nav` rows are one big button that opens an editor and show the
 * current value instead of a control. `badge` marks an option that overrides
 * the profile, so the user can tell what Billow changed.
 */
withDefaults(
  defineProps<{
    title: string
    description?: string
    /** Search / deep-link anchor, rendered as `data-setting`. */
    setting?: string
    badge?: string
    nav?: boolean
    value?: string
    /** Put the control on its own line under the text (wide controls, phones). */
    stacked?: boolean
    disabled?: boolean
    nested?: boolean
    tone?: 'default' | 'danger'
  }>(),
  { tone: 'default' },
)
const emit = defineEmits<{ open: [] }>()
</script>

<template>
  <button
    v-if="nav"
    type="button"
    class="srow srow-nav"
    :class="{ nested, danger: tone === 'danger' }"
    :data-setting="setting"
    :disabled="disabled"
    @click="emit('open')"
  >
    <div class="srow-main">
      <span class="srow-title">{{ title }}<span v-if="badge" class="srow-badge">{{ badge }}</span></span>
      <span v-if="description || $slots.description" class="srow-desc"><slot name="description">{{ description }}</slot></span>
    </div>
    <span v-if="value" class="srow-value">{{ value }}</span>
    <Icon name="chevron-right" :size="16" class="srow-chevron" />
  </button>
  <div
    v-else
    class="srow"
    :class="{ stacked, nested, disabled, danger: tone === 'danger' }"
    :data-setting="setting"
  >
    <div class="srow-main">
      <span class="srow-title">{{ title }}<span v-if="badge" class="srow-badge">{{ badge }}</span></span>
      <span v-if="description || $slots.description" class="srow-desc"><slot name="description">{{ description }}</slot></span>
      <slot name="below" />
    </div>
    <div v-if="$slots.default" class="srow-control">
      <slot />
    </div>
  </div>
</template>
