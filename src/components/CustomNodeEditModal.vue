<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { t, tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import {
  LANDING_GROUP_NAME,
  type CustomNode,
  type DialerTarget,
  type SaveCustomNodeInput,
  type SimpleProxyForm,
} from '../lib/types'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import Segmented from './Segmented.vue'
import SelectField from './SelectField.vue'
import Toggle from './Toggle.vue'

const props = defineProps<{
  open: boolean
  node: CustomNode | null
  compact?: boolean
}>()

const emit = defineEmits<{
  close: []
  saved: []
}>()

const store = useStore()
const mode = ref<'simple' | 'yaml'>('simple')
const enabled = ref(true)
const note = ref('')
const dialerChoice = ref('direct')
const fixedProxyName = ref('')
const error = ref<string | null>(null)

const simple = ref<SimpleProxyForm>({
  name: '',
  protocol: 'socks5',
  server: '',
  port: 1080,
  username: '',
  password: '',
  tls: false,
  skip_cert_verify: false,
  udp: true,
})

const yamlName = ref('')
const yamlText = ref('')

const modeOptions = computed((): readonly { id: 'simple' | 'yaml'; label: string }[] => [
  { id: 'simple', label: t('customNodes.quickForm') },
  { id: 'yaml', label: t('customNodes.yamlEdit') },
])

const protocolOptions = [
  { value: 'socks5', label: 'SOCKS5' },
  { value: 'http', label: 'HTTP / HTTPS' },
]

const dialerOptions = computed(() => {
  const options: { value: string; label: string }[] = [
    { value: 'direct', label: t('customNodes.dialer.direct') },
    { value: 'profile_group:', label: t('customNodes.dialer.profileGroup') },
  ]
  for (const group of store.snapshot.value.node_catalog) {
    if (group.kind === 'manual' && !group.hidden && group.name !== LANDING_GROUP_NAME) {
      options.push({
        value: `profile_group:${group.name}`,
        label: t('customNodes.dialer.profileGroupNamed', { group: group.name }),
      })
    }
  }
  const selfId = props.node?.id ?? null
  for (const candidate of store.customNodes.value.nodes) {
    if (candidate.id === selfId) continue
    options.push({
      value: `custom_node:${candidate.id}`,
      label: t('customNodes.dialer.customNode', { name: candidate.name }),
    })
  }
  options.push({ value: 'fixed_proxy', label: tr('指定订阅节点名…') })
  return options
})

function unquoteYamlScalar(raw: string): string {
  const trimmed = raw.trim()
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

function extractSimpleFromYaml(node: CustomNode): SimpleProxyForm | null {
  const proto = node.protocol.toLowerCase()
  if (proto !== 'socks5' && proto !== 'http') return null
  const fields: Record<string, string> = {}
  for (const line of node.raw_yaml.split(/\r?\n/)) {
    const trimmed = line.trim().replace(/^-\s+/, '')
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf(':')
    if (idx <= 0) continue
    const key = trimmed.slice(0, idx).trim()
    const value = unquoteYamlScalar(trimmed.slice(idx + 1))
    fields[key] = value
  }
  const server = fields.server ?? ''
  const port = Number(fields.port)
  if (!server || !Number.isInteger(port) || port < 1 || port > 65535) return null
  return {
    name: node.name || fields.name || '',
    protocol: proto,
    server,
    port,
    username: fields.username ?? '',
    password: fields.password ?? '',
    tls: fields.tls === 'true',
    skip_cert_verify: fields['skip-cert-verify'] === 'true',
    udp: fields.udp !== 'false',
  }
}

function encodeDialer(dialer: DialerTarget): { choice: string; fixedName: string } {
  if (dialer.kind === 'direct') return { choice: 'direct', fixedName: '' }
  if (dialer.kind === 'profile_group') {
    return { choice: `profile_group:${dialer.group ?? ''}`, fixedName: '' }
  }
  if (dialer.kind === 'custom_node') {
    return { choice: `custom_node:${dialer.id}`, fixedName: '' }
  }
  return { choice: 'fixed_proxy', fixedName: dialer.name }
}

function decodeDialer(): DialerTarget {
  const choice = dialerChoice.value
  if (choice === 'direct') return { kind: 'direct' }
  if (choice.startsWith('profile_group:')) {
    const group = choice.slice('profile_group:'.length).trim()
    return { kind: 'profile_group', group: group || null }
  }
  if (choice.startsWith('custom_node:')) {
    return { kind: 'custom_node', id: choice.slice('custom_node:'.length) }
  }
  if (choice === 'fixed_proxy') {
    return { kind: 'fixed_proxy', name: fixedProxyName.value.trim() }
  }
  return { kind: 'direct' }
}

watch(
  () => [props.open, props.node] as const,
  ([open, node]) => {
    if (!open) return
    error.value = null
    if (!node) {
      mode.value = 'simple'
      enabled.value = true
      note.value = ''
      dialerChoice.value = store.hasProfiles.value ? 'profile_group:' : 'direct'
      fixedProxyName.value = ''
      simple.value = {
        name: '',
        protocol: 'socks5',
        server: '',
        port: 1080,
        username: '',
        password: '',
        tls: false,
        skip_cert_verify: false,
        udp: true,
      }
      yamlName.value = ''
      yamlText.value = ''
      return
    }
    enabled.value = node.enabled
    note.value = node.note
    const encoded = encodeDialer(node.dialer)
    dialerChoice.value = encoded.choice
    fixedProxyName.value = encoded.fixedName
    yamlName.value = node.name
    yamlText.value = node.raw_yaml
    const extracted = extractSimpleFromYaml(node)
    if (extracted) {
      simple.value = extracted
      mode.value = 'simple'
    } else {
      simple.value = {
        name: node.name,
        protocol: 'socks5',
        server: '',
        port: 1080,
        username: '',
        password: '',
        tls: false,
        skip_cert_verify: false,
        udp: true,
      }
      mode.value = 'yaml'
    }
  },
  { immediate: true },
)

async function submit() {
  if (store.busy['customNodes:save']) return
  error.value = null
  const dialer = decodeDialer()
  if (dialer.kind === 'fixed_proxy' && !dialer.name) {
    error.value = tr('请填写中转节点或代理组名称')
    return
  }

  let input: SaveCustomNodeInput
  if (mode.value === 'simple') {
    const server = simple.value.server.trim()
    const port = Number(simple.value.port)
    if (!server) {
      error.value = tr('请填写服务器地址')
      return
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      error.value = tr('端口需在 1 到 65535 之间')
      return
    }
    const name = simple.value.name.trim() || `${server}:${port}`
    input = {
      id: props.node?.id ?? null,
      name,
      enabled: enabled.value,
      note: note.value.trim(),
      dialer,
      simple: {
        ...simple.value,
        name,
        server,
        port,
        username: simple.value.username.trim(),
        password: simple.value.password,
      },
      raw_yaml: null,
    }
  } else {
    const rawYaml = yamlText.value.trim()
    if (!rawYaml) {
      error.value = tr('请填写单节点 YAML 片段')
      return
    }
    input = {
      id: props.node?.id ?? null,
      name: yamlName.value.trim() || null,
      enabled: enabled.value,
      note: note.value.trim(),
      dialer,
      simple: null,
      raw_yaml: rawYaml,
    }
  }

  const result = await store.saveCustomNode(input)
  if (!result) {
    error.value = store.lastRunError.value ?? tr('保存自建节点失败')
    return
  }
  emit('saved')
  emit('close')
}
</script>

<template>
  <Modal
    :open="open"
    :title="node ? t('customNodes.edit.titleEdit') : t('customNodes.edit.titleAdd')"
    @close="emit('close')"
  >
    <form class="stack" novalidate @submit.prevent="submit">
      <Segmented
        :model-value="mode"
        :options="modeOptions"
        size="sm"
        :label="tr('编辑方式')"
        data-testid="custom-node-edit-mode"
        @update:model-value="(value) => { mode = value === 'yaml' ? 'yaml' : 'simple'; error = null }"
      />

      <template v-if="mode === 'simple'">
        <div class="stack" data-testid="custom-node-simple-form">
          <label class="field">
            <span>{{ t('customNodes.edit.name') }}</span>
            <input
              v-model="simple.name"
              type="text"
              :placeholder="tr('例如：美国住宅落地')"
              data-testid="custom-node-name"
            />
          </label>

          <div class="custom-form-grid">
            <div class="field">
              <span>{{ t('customNodes.edit.protocol') }}</span>
              <SelectField
                :model-value="simple.protocol"
                :options="protocolOptions"
                :sheet="compact"
                :label="t('customNodes.edit.protocol')"
                class="field-select"
                data-testid="custom-node-protocol"
                @update:model-value="(value) => { simple.protocol = String(value) }"
              />
            </div>

            <label class="field">
              <span>{{ t('customNodes.edit.port') }}</span>
              <input
                v-model.number="simple.port"
                type="number"
                min="1"
                max="65535"
                data-testid="custom-node-port"
              />
            </label>
          </div>

          <label class="field">
            <span>{{ t('customNodes.edit.server') }}</span>
            <input
              v-model="simple.server"
              type="text"
              spellcheck="false"
              placeholder="1.2.3.4"
              data-testid="custom-node-server"
            />
          </label>

          <div class="custom-form-grid">
            <label class="field">
              <span>{{ t('customNodes.edit.username') }}</span>
              <input
                v-model="simple.username"
                type="text"
                spellcheck="false"
                autocomplete="off"
                data-testid="custom-node-username"
              />
            </label>
            <label class="field">
              <span>{{ t('customNodes.edit.password') }}</span>
              <input
                v-model="simple.password"
                type="password"
                autocomplete="off"
                data-testid="custom-node-password"
              />
            </label>
          </div>

          <div class="custom-switch-row">
            <span>{{ t('customNodes.edit.tls') }}</span>
            <Toggle v-model="simple.tls" :label="t('customNodes.edit.tls')" data-testid="custom-node-tls" />
          </div>
          <div v-if="simple.tls" class="custom-switch-row">
            <span>{{ t('customNodes.edit.skipCert') }}</span>
            <Toggle
              v-model="simple.skip_cert_verify"
              :label="t('customNodes.edit.skipCert')"
              data-testid="custom-node-skip-cert"
            />
          </div>
          <div v-if="simple.protocol === 'socks5'" class="custom-switch-row">
            <span>{{ t('customNodes.edit.udp') }}</span>
            <Toggle v-model="simple.udp" :label="t('customNodes.edit.udp')" data-testid="custom-node-udp" />
          </div>
        </div>
      </template>

      <template v-else>
        <div class="stack" data-testid="custom-node-yaml-form">
          <label class="field">
            <span>{{ t('customNodes.edit.name') }}</span>
            <input
              v-model="yamlName"
              type="text"
              :placeholder="tr('留空使用 YAML 中的 name')"
              data-testid="custom-node-yaml-name"
            />
          </label>
          <label class="field">
            <span>{{ t('customNodes.yamlEdit') }}</span>
            <textarea
              v-model="yamlText"
              class="mono custom-yaml-textarea"
              rows="7"
              spellcheck="false"
              :placeholder="tr('name: 我的节点\ntype: anytls\nserver: example.com\nport: 443\npassword: secret')"
              data-testid="custom-node-yaml-input"
            />
          </label>
        </div>
      </template>

      <div class="field" data-testid="custom-node-dialer">
        <span>{{ t('customNodes.dialer.label') }}</span>
        <SelectField
          :model-value="dialerChoice"
          :options="dialerOptions"
          :sheet="compact"
          :label="t('customNodes.dialer.label')"
          class="field-select"
          @update:model-value="(value) => { dialerChoice = String(value); error = null }"
        />
      </div>

      <label v-if="dialerChoice === 'fixed_proxy'" class="field">
        <span>{{ tr('固定中转节点或组名') }}</span>
        <input
          v-model="fixedProxyName"
          type="text"
          spellcheck="false"
          :placeholder="tr('例如：香港 01')"
          data-testid="custom-node-fixed-proxy"
        />
      </label>

      <label class="field">
        <span>{{ t('customNodes.edit.note') }}</span>
        <input
          v-model="note"
          type="text"
          :placeholder="tr('可选备注，便于区分用途')"
          data-testid="custom-node-note"
        />
      </label>

      <div class="custom-switch-row">
        <span>{{ tr('启用此节点') }}</span>
        <Toggle v-model="enabled" :label="tr('启用此节点')" data-testid="custom-node-enabled" />
      </div>

      <p v-if="error" class="field-error small" role="alert" data-testid="custom-node-edit-error">
        <Icon name="alert" :size="13" />
        <span>{{ error }}</span>
      </p>
    </form>

    <template #footer>
      <button type="button" class="btn ghost" @click="emit('close')">{{ tr('取消') }}</button>
      <button
        type="button"
        class="btn primary"
        :disabled="Boolean(store.busy['customNodes:save'])"
        data-testid="custom-node-save"
        @click="submit"
      >
        <span v-if="store.busy['customNodes:save']" class="spinner xs" aria-hidden="true" />
        {{ t('customNodes.edit.save') }}
      </button>
    </template>
  </Modal>
</template>
