<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '../../components/Icon.vue'
import Segmented from '../../components/Segmented.vue'
import SelectField from '../../components/SelectField.vue'
import Toggle from '../../components/Toggle.vue'
import EditorDialog from '../../components/settings/EditorDialog.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import { subscriptionUserAgent } from '../../lib/subscription'
import { emptySniffPorts, isPortEntry, splitList } from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const settings = computed(() => snap.value.settings)
const config = computed(() => snap.value.config_values)
const busy = computed(() => Boolean(store.busy.settings))
const overridden = tr('已覆盖')

function effective(key: 'unified_delay'): boolean {
  return current.value[key] ?? config.value[key] ?? false
}

// ── Delay test: URL and timeout save on blur / Enter.
const testUrl = ref(settings.value.test_url)
const timeout = ref(settings.value.test_timeout_ms ? String(settings.value.test_timeout_ms) : '')
const probeFocused = ref<'url' | 'timeout' | null>(null)
watch(() => settings.value.test_url, (value) => {
  if (probeFocused.value !== 'url') testUrl.value = value
})
watch(() => settings.value.test_timeout_ms, (value) => {
  if (probeFocused.value !== 'timeout') timeout.value = value ? String(value) : ''
})
const timeoutError = ref<string | null>(null)
function commitProbe(silent = false) {
  probeFocused.value = null
  const url = testUrl.value.trim()
  const raw = timeout.value.trim()
  const ms = raw ? Number(raw) : 0
  if (raw && (!Number.isInteger(ms) || ms < 0)) {
    if (!silent) timeoutError.value = tr('测速超时需要是非负整数（毫秒）')
    return
  }
  timeoutError.value = null
  if (url === current.value.test_url && ms === current.value.test_timeout_ms) return
  void save({ test_url: url, test_timeout_ms: ms })
}
onBeforeUnmount(() => commitProbe(true))

// ── Process matching (desktop).
const PROCESS_MODES = computed(() => [
  { value: '', label: tr('跟随配置') },
  { value: 'always', label: tr('始终') },
  { value: 'strict', label: tr('自动') },
  { value: 'off', label: tr('关闭') },
])

// ── Sniffer (R33): the switch here, the details in their own editor.
const snifferOn = computed(() => current.value.sniffer ?? config.value.sniffer ?? false)
type OverrideChoice = '' | 'on' | 'off'
const OVERRIDE_CHOICES = computed<{ id: OverrideChoice; label: string }[]>(() => [
  { id: '', label: tr('跟随配置') },
  { id: 'on', label: tr('覆盖') },
  { id: 'off', label: tr('不覆盖') },
])
const SNIFF_PORTS = [
  { key: 'http', title: () => tr('HTTP 端口'), config: 'sniff_http_ports' },
  { key: 'tls', title: () => tr('TLS 端口'), config: 'sniff_tls_ports' },
  { key: 'quic', title: () => tr('QUIC 端口'), config: 'sniff_quic_ports' },
] as const
const sniffSaved = computed(() => {
  const s = settings.value
  return { ports: { ...s.sniff_ports }, force: s.sniff_force_domain, skip: s.sniff_skip_domain, override: s.sniff_override_destination }
})
const sniffOverridden = computed(
  () => JSON.stringify(sniffSaved.value) !== JSON.stringify({ ports: emptySniffPorts(), force: null, skip: null, override: null }),
)
const sniffOpen = ref(false)
const sniffText = ref({ http: '', tls: '', quic: '', force: '', skip: '' })
const sniffOverride = ref<OverrideChoice>('')
const sniffError = ref<string | null>(null)
function openSniff() {
  const value = sniffSaved.value
  sniffText.value = {
    http: (value.ports.http ?? []).join(', '),
    tls: (value.ports.tls ?? []).join(', '),
    quic: (value.ports.quic ?? []).join(', '),
    force: (value.force ?? []).join('\n'),
    skip: (value.skip ?? []).join('\n'),
  }
  sniffOverride.value = value.override == null ? '' : value.override ? 'on' : 'off'
  sniffError.value = null
  sniffOpen.value = true
}
const listOrNull = (items: string[]) => (items.length ? items : null)
const domainLines = (text: string) => listOrNull(text.split(/[\n,，]/).map((item) => item.trim()).filter(Boolean))
const sniffDraft = computed(() => ({
  ports: {
    http: listOrNull(splitList(sniffText.value.http)),
    tls: listOrNull(splitList(sniffText.value.tls)),
    quic: listOrNull(splitList(sniffText.value.quic)),
  },
  force: domainLines(sniffText.value.force),
  skip: domainLines(sniffText.value.skip),
  override: sniffOverride.value === '' ? null : sniffOverride.value === 'on',
}))
const sniffDirty = computed(() => JSON.stringify(sniffDraft.value) !== JSON.stringify(sniffSaved.value))
const configList = (items: string[] | null) => (items?.length ? tr('配置中为 {0}', { 0: items.join('、') }) : tr('配置未设置'))
async function saveSniff() {
  const draft = sniffDraft.value
  for (const field of SNIFF_PORTS) {
    const bad = draft.ports[field.key]?.find((item) => !isPortEntry(item))
    if (bad) {
      sniffError.value = tr('{0}中的「{1}」无效，请填 1–65535 的端口或“起-止”范围，例如 443 或 8000-9000', { 0: field.title(), 1: bad })
      return
    }
  }
  sniffError.value = null
  await save({
    sniff_ports: draft.ports,
    sniff_force_domain: draft.force,
    sniff_skip_domain: draft.skip,
    sniff_override_destination: draft.override,
  })
  sniffOpen.value = false
}

// ── Subscription User-Agent: saved on blur / Enter.
const subscriptionUa = ref(settings.value.subscription_user_agent)
const uaFocused = ref(false)
const uaError = ref<string | null>(null)
const defaultUa = computed(() => subscriptionUserAgent(store.kernel.value.version))
watch(() => settings.value.subscription_user_agent, (value) => {
  if (!uaFocused.value) subscriptionUa.value = value
})
function commitUa() {
  uaFocused.value = false
  const value = subscriptionUa.value
  if (value.length > 256 || /[^\x20-\x7e]/.test(value)) {
    uaError.value = tr('User-Agent 只能包含可打印的 ASCII 字符，不能含换行')
    return
  }
  uaError.value = null
  if (value.trim() !== current.value.subscription_user_agent) void save({ subscription_user_agent: value.trim() })
}
</script>

<template>
  <SettingsSection :title="tr('切换节点')">
    <SettingsRow
      :title="tr('切换节点后重连')"
      :description="tr('让旧连接立即改走新节点，下载或通话可能中断')"
      setting="node-switch"
      data-testid="node-switch-settings"
    >
      <Toggle
        :model-value="current.close_connections_on_switch"
        :label="tr('切换节点后重连')"
        data-testid="close-on-node-switch"
        @update:model-value="(on) => save({ close_connections_on_switch: on })"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection :title="tr('延迟测试')">
    <SettingsRow :title="tr('测速地址')" :description="tr('测试节点延迟时请求的网址')" setting="test-url" :stacked="compact">
      <input
        v-model="testUrl"
        class="input sm mono srow-input wide"
        type="url"
        spellcheck="false"
        placeholder="http://www.gstatic.com/generate_204"
        :aria-label="tr('测速地址')"
        data-testid="test-url"
        @focus="probeFocused = 'url'"
        @blur="commitProbe()"
        @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
      />
    </SettingsRow>
    <SettingsRow :title="tr('测速超时')" :description="tr('超过这个时间（毫秒）算作超时')" setting="test-timeout">
      <template #below>
        <span v-if="timeoutError" class="field-error small" role="alert"><Icon name="alert" :size="13" />{{ timeoutError }}</span>
      </template>
      <input
        v-model="timeout"
        class="input sm mono srow-input short"
        inputmode="numeric"
        placeholder="5000"
        :aria-label="tr('测速超时')"
        data-testid="test-timeout"
        @focus="probeFocused = 'timeout'"
        @blur="commitProbe()"
        @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
      />
    </SettingsRow>
    <SettingsRow
      :title="tr('统一延迟')"
      :description="tr('测速时去除握手耗时，结果更接近真实体验')"
      :badge="settings.unified_delay != null ? overridden : undefined"
      setting="unified-delay"
    >
      <Toggle :model-value="effective('unified_delay')" :busy="busy" :label="tr('统一延迟')" @update:model-value="(on) => save({ unified_delay: on })" />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection :title="tr('流量识别')">
    <SettingsRow
      :title="tr('域名嗅探')"
      :description="tr('从 HTTP / TLS / QUIC 流量中识别域名，让按域名分流在 IP 直连时也生效')"
      :badge="settings.sniffer != null ? overridden : undefined"
      setting="sniffer"
    >
      <Toggle :model-value="snifferOn" :busy="busy" :label="tr('域名嗅探')" @update:model-value="(on) => save({ sniffer: on })" />
    </SettingsRow>
    <!-- Details layer on whichever sniffer block is on; while it is off they stay saved but hidden (R33). -->
    <SettingsRow
      v-if="snifferOn"
      nav
      nested
      :title="tr('嗅探选项')"
      :description="tr('嗅探端口、强制与跳过的域名')"
      :value="sniffOverridden ? tr('已自定义') : tr('跟随配置')"
      setting="sniffer-options"
      data-testid="sniff-advanced"
      @open="openSniff"
    />
    <SettingsRow
      v-if="!store.isAndroid.value"
      :title="tr('进程匹配')"
      :description="tr('识别连接来自哪个应用，用于连接页与进程规则')"
      :badge="settings.find_process_mode ? overridden : undefined"
      setting="process-mode"
    >
      <SelectField
        :model-value="settings.find_process_mode ?? ''"
        :options="PROCESS_MODES"
        :sheet="compact"
        size="sm"
        :label="tr('进程匹配')"
        data-testid="process-mode-select"
        @update:model-value="(value) => save({ find_process_mode: String(value) || null })"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection :title="tr('订阅')">
    <SettingsRow
      :title="tr('订阅 User-Agent')"
      :description="tr('更新订阅时使用；留空用默认值，单个订阅可在「编辑信息」中覆盖')"
      :badge="settings.subscription_user_agent ? tr('已自定义') : undefined"
      setting="subscription-ua"
      stacked
      data-testid="subscription-settings"
    >
      <template #below>
        <span v-if="uaError" class="field-error small" role="alert"><Icon name="alert" :size="13" />{{ uaError }}</span>
      </template>
      <input
        v-model="subscriptionUa"
        class="input sm mono srow-input full"
        type="text"
        maxlength="256"
        :placeholder="defaultUa"
        spellcheck="false"
        autocomplete="off"
        autocapitalize="off"
        enterkeyhint="done"
        :aria-label="tr('默认 User-Agent')"
        data-testid="global-subscription-user-agent"
        @focus="uaFocused = true"
        @blur="commitUa"
        @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
      />
    </SettingsRow>
  </SettingsSection>

  <EditorDialog
    v-if="sniffOpen"
    :title="tr('嗅探选项')"
    :subtitle="tr('留空的项跟随配置文件')"
    :dirty="sniffDirty"
    :saving="busy"
    save-testid="save-sniff"
    cancel-testid="undo-sniff"
    @save="saveSniff"
    @close="sniffOpen = false"
  >
    <div class="form-stack">
      <div class="form-grid three">
        <label v-for="field in SNIFF_PORTS" :key="field.key" class="field">
          <span>{{ field.title() }}</span>
          <input
            v-model="sniffText[field.key]"
            class="input mono"
            spellcheck="false"
            :placeholder="config[field.config]?.join(', ') || tr('跟随配置')"
            :aria-label="tr('{0} 嗅探端口', { 0: field.key.toUpperCase() })"
            :data-testid="`sniff-ports-${field.key}`"
          />
        </label>
      </div>
      <p class="muted small">{{ tr('端口或“起-止”范围，逗号分隔') }}</p>
      <label class="field">
        <span>{{ tr('强制嗅探域名') }}</span>
        <textarea v-model="sniffText.force" class="input list-input mono" rows="3" spellcheck="false" :aria-label="tr('强制嗅探域名')" data-testid="sniff-force-domain" />
        <span class="muted small field-note">{{ tr('这些域名总是嗅探，每行一个') }} · {{ configList(config.sniff_force_domain) }}</span>
      </label>
      <label class="field">
        <span>{{ tr('跳过嗅探域名') }}</span>
        <textarea v-model="sniffText.skip" class="input list-input mono" rows="3" spellcheck="false" :aria-label="tr('跳过嗅探域名')" data-testid="sniff-skip-domain" />
        <span class="muted small field-note">{{ tr('嗅探到这些域名时不改写，每行一个') }} · {{ configList(config.sniff_skip_domain) }}</span>
      </label>
      <div class="field">
        <span>{{ tr('用嗅探结果覆盖目标') }}</span>
        <Segmented v-model="sniffOverride" :options="OVERRIDE_CHOICES" size="sm" :label="tr('用嗅探结果覆盖目标')" data-testid="sniff-override" />
        <span class="muted small field-note">
          {{ tr('用嗅探到的域名替换连接的目标地址') }}{{ config.sniff_override_destination == null ? '' : tr(' · 配置中为{0}', { 0: config.sniff_override_destination ? tr('覆盖') : tr('不覆盖') }) }}
        </span>
      </div>
      <p v-if="sniffError" class="field-error small" role="alert" data-testid="sniff-error">
        <Icon name="alert" :size="13" /><span>{{ sniffError }}</span>
      </p>
    </div>
  </EditorDialog>
</template>
