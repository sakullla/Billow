<script setup lang="ts">
import { computed, ref } from 'vue'
import { DNS_QUERY_TYPES, isValidDnsName, type DnsQueryResult, type DnsQueryType } from '../lib/types'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import SelectField from './SelectField.vue'

/**
 * Resolves one name through the kernel's live DNS config (R31). The dialog
 * opens while the kernel is down so the reason is visible; only the query
 * button is disabled then.
 */
const props = defineProps<{
  running: boolean
  query: (name: string, qtype: DnsQueryType) => Promise<DnsQueryResult>
  /** Phones pick the record type from a bottom sheet. */
  compact?: boolean
}>()
const emit = defineEmits<{ close: [] }>()

const name = ref('')
const qtype = ref<DnsQueryType>('A')
const pending = ref(false)
const inputError = ref<string | null>(null)
const result = ref<DnsQueryResult | null>(null)
const failure = ref<string | null>(null)
const input = ref<HTMLInputElement | null>(null)
let generation = 0

const typeOptions = DNS_QUERY_TYPES.map((type) => ({ value: type, label: type }))
const blockedReason = computed(() => (props.running ? null : '内核没有运行，连接后才能查询'))
const canQuery = computed(() => props.running && !pending.value)

function onInput() {
  inputError.value = null
}

async function submit() {
  if (!canQuery.value) return
  const text = name.value.trim()
  if (!text) {
    inputError.value = '请输入域名'
    return
  }
  if (!isValidDnsName(text)) {
    inputError.value = '域名格式无效，例如 example.com'
    return
  }
  inputError.value = null
  failure.value = null
  pending.value = true
  const ticket = ++generation
  try {
    const answer = await props.query(text, qtype.value)
    if (ticket !== generation) return
    result.value = answer
  } catch (error) {
    if (ticket !== generation) return
    result.value = null
    failure.value = error instanceof Error ? error.message : String(error)
  } finally {
    if (ticket === generation) pending.value = false
  }
}

function setType(value: string | number) {
  qtype.value = String(value) as DnsQueryType
}
</script>

<template>
  <Modal title="DNS 查询" subtitle="使用内核当前生效的 DNS 配置解析" :initial-focus="() => input" @close="emit('close')">
    <form class="dns-query" data-testid="dns-query-form" @submit.prevent="submit">
      <div class="dns-query-row">
        <input
          ref="input"
          v-model="name"
          class="input mono grow"
          type="text"
          placeholder="example.com"
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          enterkeyhint="search"
          aria-label="域名"
          :aria-invalid="inputError ? 'true' : undefined"
          data-testid="dns-query-name"
          @input="onInput"
        />
        <SelectField
          :model-value="qtype"
          :options="typeOptions"
          :sheet="compact"
          size="sm"
          label="记录类型"
          data-testid="dns-query-type"
          @update:model-value="setType"
        />
        <button type="submit" class="btn primary sm" :disabled="!canQuery" data-testid="dns-query-submit">
          <Icon name="search" :size="14" />{{ pending ? '查询中' : '查询' }}
        </button>
      </div>
      <p v-if="blockedReason" class="muted small" role="status" data-testid="dns-query-blocked">
        <Icon name="info" :size="13" /> {{ blockedReason }}
      </p>
      <p v-if="inputError" class="field-error small" role="alert" data-testid="dns-query-input-error">
        <Icon name="alert" :size="13" /> {{ inputError }}
      </p>
    </form>

    <div v-if="failure" class="field-error small" role="alert" data-testid="dns-query-error">
      <Icon name="alert" :size="13" /> {{ failure }}
    </div>
    <section v-else-if="result" class="dns-query-result" aria-live="polite" data-testid="dns-query-result">
      <p class="muted small mono" data-testid="dns-query-meta">
        {{ result.name || name.trim() }} · {{ result.qtype || qtype }} · 耗时 {{ result.elapsed_ms }} ms<template v-if="result.status !== null && result.status !== 0"> · 状态码 {{ result.status }}</template>
      </p>
      <p v-if="result.error" class="field-error small" role="alert" data-testid="dns-query-error">
        <Icon name="alert" :size="13" /> {{ result.error }}
      </p>
      <table v-if="result.answers.length" class="dns-query-table small">
        <thead>
          <tr>
            <th>类型</th>
            <th>值</th>
            <th class="num">TTL</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(answer, index) in result.answers" :key="index" data-testid="dns-query-answer">
            <td class="mono">{{ answer.type }}</td>
            <td class="mono value">{{ answer.value }}</td>
            <td class="mono num">{{ answer.ttl }} 秒</td>
          </tr>
        </tbody>
      </table>
    </section>
  </Modal>
</template>

<style scoped>
.dns-query {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.dns-query-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.dns-query-row .input {
  min-width: 0;
}

.dns-query-result {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.dns-query-table {
  width: 100%;
  border-collapse: collapse;
}

.dns-query-table th,
.dns-query-table td {
  padding: 6px 8px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

.dns-query-table th {
  font-weight: 500;
  color: var(--muted);
}

.dns-query-table .num {
  text-align: right;
  white-space: nowrap;
}

.dns-query-table .value {
  word-break: break-all;
}
</style>
