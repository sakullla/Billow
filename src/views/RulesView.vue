<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import { useStore } from '../lib/store'
import type { RuleRow } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const rules = ref<RuleRow[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
const query = ref('')
const limit = ref(300)

async function load() {
  loading.value = true
  try {
    const result = await store.backend.rules()
    rules.value = result.rules
    error.value = result.error
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const indexed = rules.value.map((rule, index) => ({ rule, index }))
  if (!needle) return indexed
  return indexed.filter(({ rule }) =>
    [rule.kind, rule.payload, rule.proxy].some((text) => text.toLowerCase().includes(needle)),
  )
})

const kinds = computed(() => {
  const counts = new Map<string, number>()
  rules.value.forEach((rule) => counts.set(rule.kind, (counts.get(rule.kind) ?? 0) + 1))
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
})

watch(query, () => (limit.value = 300))
watch(() => snap.value.kernel_running, (running) => running && void load())
onMounted(load)
</script>

<template>
  <div class="page rules">
    <header class="page-head">
      <div>
        <h1>规则</h1>
        <p class="muted small">{{ rules.length ? `${rules.length} 条规则，自上而下匹配` : '运行中的内核按这些规则分流' }}</p>
      </div>
      <div class="head-actions">
        <button type="button" class="btn ghost sm" :disabled="loading" @click="load">
          <Icon name="refresh" :size="15" :class="{ spin: loading }" />刷新
        </button>
      </div>
    </header>

    <div v-if="rules.length" class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索规则内容或策略" data-page-search />
      </div>
    </div>
    <div v-if="kinds.length && !query" class="chips">
      <button v-for="[kind, count] in kinds" :key="kind" type="button" class="chip" @click="query = kind">
        {{ kind }} <span class="muted">{{ count }}</span>
      </button>
    </div>

    <div v-if="!rules.length && !loading" class="empty">
      <Icon name="route" :size="40" :stroke="1.4" />
      <h3>{{ error === '内核没有运行' || !snap.kernel_running ? '内核未运行' : error ?? '没有规则' }}</h3>
      <p class="muted">连接后可以查看当前配置生效的分流规则。</p>
    </div>
    <div v-else-if="rules.length && !filtered.length" class="empty small"><h3>没有匹配的规则</h3></div>

    <div v-if="filtered.length" class="card list-card">
      <div v-for="{ rule, index } in filtered.slice(0, limit)" :key="index" class="rule-row">
        <span class="rule-index mono muted">{{ index + 1 }}</span>
        <span class="tag">{{ rule.kind }}</span>
        <span class="rule-payload mono ellipsis" :title="rule.payload">{{ rule.payload || '—' }}</span>
        <span class="rule-proxy">{{ rule.proxy }}</span>
      </div>
      <button v-if="filtered.length > limit" type="button" class="btn ghost block" @click="limit += 500">
        显示更多（还有 {{ filtered.length - limit }} 条）
      </button>
    </div>
  </div>
</template>
