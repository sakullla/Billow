<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed } from 'vue'
import Icon from './Icon.vue'

export type EmptyVariant = 'loading' | 'unavailable' | 'no-data' | 'no-match' | 'error'

const props = defineProps<{
  variant?: EmptyVariant
  title?: string
  description?: string
  icon?: string
  compact?: boolean
}>()

const DEFAULTS: Record<EmptyVariant, { icon: string; title: string; description: string; role?: 'status' | 'alert' }> = {
  loading: { icon: 'refresh', get title() { return tr('正在加载') }, get description() { return tr('读取本地状态与内核信息。') }, role: 'status' },
  unavailable: { icon: 'info', get title() { return tr('当前不可用') }, get description() { return tr('完成前置步骤后这里会显示内容。') } },
  'no-data': { icon: 'database', get title() { return tr('还没有数据') }, get description() { return tr('连接后或添加配置后会出现内容。') } },
  'no-match': { icon: 'search', get title() { return tr('没有匹配结果') }, get description() { return tr('换一个关键词，或清空当前筛选。') } },
  error: { icon: 'alert', get title() { return tr('读取失败') }, get description() { return tr('请重试；如果持续失败，请查看日志。') }, role: 'alert' },
}

const variant = computed(() => props.variant ?? 'no-data')
const preset = computed(() => DEFAULTS[variant.value])
const role = computed(() => preset.value.role)
const isLoading = computed(() => variant.value === 'loading')
/** Pages pass their own icon for empty/unavailable states; errors always keep the warning icon (R7). */
const iconName = computed(() => (variant.value === 'error' ? preset.value.icon : (props.icon ?? preset.value.icon)))
</script>

<template>
  <div
    class="empty-state"
    :class="[variant, { compact }]"
    :role="role"
    :aria-live="role === 'status' ? 'polite' : undefined"
    :aria-busy="isLoading ? 'true' : undefined"
  >
    <span v-if="isLoading" class="spinner" aria-hidden="true" />
    <Icon v-else :name="iconName" :size="28" :data-icon="iconName" />
    <h3>{{ title ?? preset.title }}</h3>
    <p class="muted small">
      <slot name="description">{{ description ?? preset.description }}</slot>
    </p>
    <div v-if="$slots.action" class="empty-actions">
      <slot name="action" />
    </div>
  </div>
</template>
