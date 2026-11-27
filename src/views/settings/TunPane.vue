<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Icon from '../../components/Icon.vue'
import Modal from '../../components/Modal.vue'
import Segmented from '../../components/Segmented.vue'
import Toggle from '../../components/Toggle.vue'
import ListEditorDialog from '../../components/settings/ListEditorDialog.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { listSummary, useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import { defaultTun, isCidrEntry, type TunSettings } from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const tun = computed(() => current.value.tun)
const busy = computed(() => Boolean(store.busy.settings))

function saveTun(patch: Partial<TunSettings>) {
  return save({ tun: { ...tun.value, ...patch } })
}

const STACKS = computed(() => [
  { id: '' as TunSettings['stack'], label: tr('默认') },
  { id: 'mixed' as TunSettings['stack'], label: 'Mixed' },
  { id: 'gvisor' as TunSettings['stack'], label: 'gVisor' },
  { id: 'system' as TunSettings['stack'], label: 'System' },
])
const STACK_HINTS = computed<Record<TunSettings['stack'], string>>(() => ({
  '': tr('跟随配置；配置未指定时用内核推荐的 Mips 自研协议栈（旧内核为 gVisor）'),
  mips: tr('Mips：mihomo 自研协议栈，新版内核的默认值'),
  mixed: tr('Mixed：TCP 走系统栈、UDP 走 gVisor；开着防火墙时需放行内核'),
  gvisor: tr('gVisor：用户态协议栈，隔离性好，不受系统防火墙影响'),
  system: tr('System：系统协议栈，占用最低；开着防火墙时需放行内核'),
}))

const statusText = computed(() =>
  snap.value.tun
    ? tr('运行中，所有应用的流量都经过 Billow')
    : snap.value.tun_wanted
      ? tr('已记住开启，下次连接生效')
      : tr('接管不读系统代理的应用和命令行工具；首次开启需要系统授权'),
)

// ── Single fields: MTU and device name save on blur / Enter.
const mtu = ref(tun.value.mtu ? String(tun.value.mtu) : '')
const device = ref(tun.value.device)
const focused = ref<'mtu' | 'device' | null>(null)
watch(() => tun.value.mtu, (value) => {
  if (focused.value !== 'mtu') mtu.value = value ? String(value) : ''
})
watch(() => tun.value.device, (value) => {
  if (focused.value !== 'device') device.value = value
})
const mtuError = ref<string | null>(null)
function commitMtu() {
  focused.value = null
  const raw = mtu.value.trim()
  const value = raw ? Number(raw) : 0
  if (raw && (!Number.isInteger(value) || value < 576 || value > 65535)) {
    mtuError.value = tr('MTU 需要是 576–65535 的整数；留空使用默认值')
    return
  }
  mtuError.value = null
  if (value !== tun.value.mtu) void saveTun({ mtu: value })
}
function commitDevice() {
  focused.value = null
  const value = device.value.trim()
  if (value !== tun.value.device) void saveTun({ device: value })
}

// ── List editors: DNS hijack and the two route lists (R32).
type ListKey = 'dns_hijack' | 'route_exclude_address' | 'route_address'
const editing = ref<ListKey | null>(null)
const ROUTES = computed(() => [
  {
    key: 'route_exclude_address' as const,
    setting: 'tun-route-exclude',
    title: tr('不走 TUN 的地址'),
    hint: tr('这些 IP 或网段绕过 TUN，例如局域网 192.168.0.0/16'),
    config: snap.value.config_values.tun_route_exclude_address,
  },
  {
    key: 'route_address' as const,
    setting: 'tun-route-include',
    title: tr('只让这些地址走 TUN'),
    hint: tr('只把这些 IP 或网段路由进 TUN，其余不接管'),
    config: snap.value.config_values.tun_route_address,
  },
])
const editor = computed(() => {
  const key = editing.value
  if (!key) return null
  if (key === 'dns_hijack') {
    return {
      title: tr('DNS 劫持'),
      subtitle: tr('把发往这些地址的 DNS 查询交给内核'),
      items: tun.value.dns_hijack,
      placeholder: 'any:53\ntcp://any:53',
      hint: undefined as string | undefined,
      validate: undefined as ((item: string) => boolean) | undefined,
      testid: 'tun-dns-hijack',
    }
  }
  const route = ROUTES.value.find((item) => item.key === key)!
  return {
    title: route.title,
    subtitle: route.hint,
    items: tun.value[key],
    placeholder: '192.168.0.0/16',
    hint: route.config?.length
      ? tr('留空则跟随配置：{0}', { 0: route.config.join('、') })
      : tr('留空则跟随配置（配置未设置）'),
    validate: isCidrEntry,
    testid: `tun-${key.replace(/_/g, '-')}`,
  }
})
async function saveList(items: string[]) {
  const key = editing.value
  if (!key) return
  if (key === 'dns_hijack') await saveTun({ dns_hijack: items })
  else await saveTun({ [key]: items.length ? items : null })
  editing.value = null
}
function routeValue(key: 'route_exclude_address' | 'route_address', config: string[] | null): string {
  const own = tun.value[key]
  if (own != null) return listSummary(own, tr('空'))
  return config?.length ? tr('跟随配置') : tr('未设置')
}

const confirmReset = ref(false)
async function resetTun() {
  confirmReset.value = false
  await save({ tun: defaultTun() }, tr('已恢复默认设置'))
}
</script>

<template>
  <div class="pane-root" data-testid="tun-settings">
    <SettingsSection>
      <SettingsRow :title="tr('启用 TUN')" setting="tun" class="srow-master" :class="{ on: snap.tun }">
        <template #description>{{ statusText }}</template>
        <Toggle :model-value="snap.tun" :busy="store.busy.tun" :label="tr('启用 TUN')" @update:model-value="store.setTun" />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection :title="tr('网卡与路由')">
      <SettingsRow :title="tr('协议栈')" :description="STACK_HINTS[tun.stack]" setting="tun-stack" stacked>
        <Segmented
          :model-value="tun.stack"
          :options="STACKS"
          size="sm"
          :label="tr('协议栈')"
          :disabled="busy"
          data-testid="tun-stack"
          @update:model-value="(stack) => saveTun({ stack })"
        />
      </SettingsRow>
      <SettingsRow :title="tr('自动设置路由')" :description="tr('把全局流量路由到 TUN 网卡；关闭后需要自行配置路由')" setting="tun-auto-route">
        <Toggle :model-value="tun.auto_route" :label="tr('自动设置路由')" :disabled="busy" @update:model-value="(on) => saveTun({ auto_route: on })" />
      </SettingsRow>
      <SettingsRow :title="tr('严格路由')" :description="tr('防止流量绕过 TUN 和 DNS 泄漏，但可能影响局域网访问')" setting="tun-strict-route">
        <Toggle :model-value="tun.strict_route" :label="tr('严格路由')" :disabled="busy" @update:model-value="(on) => saveTun({ strict_route: on })" />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection v-if="!store.isAndroid.value" :title="tr('路由范围')" :description="tr('留空跟随配置文件')">
      <SettingsRow
        v-for="route in ROUTES"
        :key="route.key"
        nav
        :title="route.title"
        :description="route.hint"
        :badge="tun[route.key] != null ? tr('已覆盖') : undefined"
        :value="routeValue(route.key, route.config)"
        :setting="route.setting"
        :data-testid="`open-${route.setting}`"
        @open="editing = route.key"
      />
    </SettingsSection>

    <SettingsSection collapsible :title="tr('高级')" :summary="tr('出口网卡、DNS 劫持、MTU 与网卡名称')">
      <SettingsRow :title="tr('自动选择出口网卡')" :description="tr('避免代理流量绕回 TUN 造成回环')" setting="tun-auto-detect">
        <Toggle
          :model-value="tun.auto_detect_interface"
          :label="tr('自动选择出口网卡')"
          :disabled="busy"
          @update:model-value="(on) => saveTun({ auto_detect_interface: on })"
        />
      </SettingsRow>
      <SettingsRow
        nav
        :title="tr('DNS 劫持')"
        :description="tr('把发往这些地址的 DNS 查询交给内核')"
        :value="listSummary(tun.dns_hijack, tr('未设置'))"
        setting="tun-dns-hijack"
        data-testid="open-tun-dns-hijack"
        @open="editing = 'dns_hijack'"
      />
      <SettingsRow title="MTU" :description="tr('一般保持默认；遇到大包问题可调小，例如 1400')" setting="tun-mtu">
        <template #below>
          <span v-if="mtuError" class="field-error small" role="alert" data-testid="tun-error"><Icon name="alert" :size="13" />{{ mtuError }}</span>
        </template>
        <input
          v-model="mtu"
          class="input sm mono srow-input short"
          inputmode="numeric"
          placeholder="1500"
          aria-label="MTU"
          data-testid="tun-mtu"
          @focus="focused = 'mtu'"
          @blur="commitMtu"
          @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
        />
      </SettingsRow>
      <SettingsRow :title="tr('网卡名称')" :description="tr('留空由内核决定（macOS 需为 utun 开头）')" setting="tun-device">
        <input
          v-model="device"
          class="input sm mono srow-input"
          :placeholder="tr('自动')"
          spellcheck="false"
          :aria-label="tr('网卡名称')"
          data-testid="tun-device"
          @focus="focused = 'device'"
          @blur="commitDevice"
          @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
        />
      </SettingsRow>
    </SettingsSection>

    <div class="settings-pane-foot">
      <button type="button" class="btn ghost sm" data-testid="reset-tun" @click="confirmReset = true">
        <Icon name="refresh" :size="14" />{{ tr('恢复默认设置') }}
      </button>
    </div>

    <ListEditorDialog
      v-if="editor"
      :title="editor.title"
      :subtitle="editor.subtitle"
      :items="editor.items"
      :placeholder="editor.placeholder"
      :hint="editor.hint"
      :validate="editor.validate"
      :invalid-message="(item) => tr('{0}中的「{1}」不是有效的 IP 或网段，例如 192.168.0.0/16', { 0: editor!.title, 1: item })"
      :saving="busy"
      :testid="editor.testid"
      @save="saveList"
      @close="editing = null"
    />

    <Modal v-if="confirmReset" :title="tr('恢复 TUN 默认设置')" @close="confirmReset = false">
      <p class="small">{{ tr('协议栈、路由、DNS 劫持、MTU 与路由范围都会恢复为默认值。TUN 的开关状态不变。') }}</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="confirmReset = false">{{ tr('取消') }}</button>
        <button type="button" class="btn primary" data-testid="confirm-reset-tun" @click="resetTun">{{ tr('恢复默认') }}</button>
      </template>
    </Modal>
  </div>
</template>
