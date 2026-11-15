<script setup lang="ts">
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
  loading: { icon: 'refresh', title: '正在加载', description: '读取本地状态与内核信息。', role: 'status' },
  unavailable: { icon: 'info', title: '当前不可用', description: '完成前置步骤后这里会显示内容。' },
  'no-data': { icon: 'database', title: '还没有数据', description: '连接后或添加配置后会出现内容。' },
  'no-match': { icon: 'search', title: '没有匹配结果', description: '换一个关键词，或清空当前筛选。' },
  error: { icon: 'alert', title: '读取失败', description: '请重试；如果持续失败，请查看日志。', role: 'alert' },
}

const variant = computed(() => props.variant ?? 'no-data')
const preset = computed(() => DEFAULTS[variant.value])
const role = computed(() => preset.value.role)
const isLoading = computed(() => variant.value === 'loading')
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
    <Icon v-else :name="icon ?? preset.icon" :size="28" />
    <h3>{{ title ?? preset.title }}</h3>
    <p class="muted small">
      <slot name="description">{{ description ?? preset.description }}</slot>
    </p>
    <div v-if="$slots.action" class="empty-actions">
      <slot name="action" />
    </div>
  </div>
</template>
