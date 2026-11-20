<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from '../../components/Icon.vue'
import Modal from '../../components/Modal.vue'
import Segmented from '../../components/Segmented.vue'
import SelectField from '../../components/SelectField.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import { emptySniffPorts, type KernelChannel } from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const kernel = computed(() => store.kernel.value)

const CHANNELS = computed<{ id: KernelChannel; label: string }[]>(() => [
  { id: 'stable', label: tr('稳定版') },
  { id: 'preview', label: tr('预览版') },
])
const LOG_LEVELS = computed(() => [
  { value: '', label: tr('跟随配置') },
  { value: 'debug', label: tr('调试') },
  { value: 'info', label: tr('信息') },
  { value: 'warning', label: tr('警告') },
  { value: 'error', label: tr('错误') },
  { value: 'silent', label: tr('静默') },
])

const updateBusy = computed(() => (store.isAndroid.value ? store.appUpdate.busy.value : Boolean(store.busy.kernel)))
const updateSubtitle = computed(() => {
  if (kernel.value.failure) return tr(kernel.value.failure)
  if (!store.isAndroid.value) return tr('已安装的内核直接使用；可手动检查新版本')
  const status = store.appUpdate.status.value
  if (status === 'checking') return tr('正在检查 Billow 与内核更新…')
  if (store.appUpdate.offer.value) return tr('发现新版本 v{0}，内核随应用一并更新', { 0: store.appUpdate.offer.value.version })
  if (status === 'current') return tr('当前 Billow 与内核均已是最新版本')
  if (status === 'error' && store.appUpdate.error.value) return tr('检查失败：{0}', { 0: store.appUpdate.error.value })
  return tr('内核随 Billow 更新，安装后即可使用')
})
async function onCheckUpdate() {
  if (!store.isAndroid.value) {
    await store.refreshKernel()
    return
  }
  if (store.appUpdate.offer.value) {
    await store.appUpdate.install()
    return
  }
  await store.appUpdate.check(false)
  const { offer, error, status } = store.appUpdate
  if (offer.value) store.toast(tr('发现新版本 v{0}，可点击下载更新', { 0: offer.value.version }), 'success')
  else if (error.value) store.toast(tr('检查更新失败：{0}', { 0: error.value }), 'error')
  else if (status.value === 'current') store.toast(tr('当前 Billow 与内核已是最新版本'), 'success')
}

/** mihomo mounts `/debug` only at log level debug, so 回收内存 shows only then (R35). */
const debugLogging = computed(() => (snap.value.settings.log_level ?? snap.value.config_values.log_level ?? 'info') === 'debug')

/** 重启内核 drops live connections, so it runs only after the user confirms (R35). */
const confirmRestart = ref(false)
function restartConfirmed() {
  confirmRestart.value = false
  void store.restartKernel()
}

// ── Everything Billow overrides on top of the profile, and the way back.
const FLAG_KEYS = ['allow_lan', 'ipv6', 'unified_delay', 'tcp_concurrent'] as const
const NET_KEYS = ['socks_port', 'http_port', 'redir_port', 'tproxy_port', 'interface_name', 'routing_mark'] as const
const overrideCount = computed(() => {
  const s = snap.value.settings
  const sniff =
    JSON.stringify({ ports: s.sniff_ports, force: s.sniff_force_domain, skip: s.sniff_skip_domain, override: s.sniff_override_destination }) !==
    JSON.stringify({ ports: emptySniffPorts(), force: null, skip: null, override: null })
  return [
    s.mixed_port,
    s.log_level,
    s.find_process_mode,
    s.test_url,
    s.test_timeout_ms,
    s.sniffer != null,
    s.keep_alive_interval != null,
    s.lan_auth.length,
    s.lan_allowed_ips.length,
    sniff,
    s.tun.route_address != null,
    s.tun.route_exclude_address != null,
    ...FLAG_KEYS.map((key) => s[key] != null),
    ...NET_KEYS.map((key) => s[key] != null),
  ].filter(Boolean).length
})
const confirmReset = ref(false)
function resetOverrides() {
  confirmReset.value = false
  void save({
    sniffer: null,
    keep_alive_interval: null,
    lan_auth: [],
    lan_allowed_ips: [],
    mixed_port: null,
    allow_lan: null,
    ipv6: null,
    log_level: null,
    unified_delay: null,
    tcp_concurrent: null,
    find_process_mode: null,
    test_url: '',
    test_timeout_ms: 0,
    sniff_ports: emptySniffPorts(),
    sniff_force_domain: null,
    sniff_skip_domain: null,
    sniff_override_destination: null,
    socks_port: null,
    http_port: null,
    redir_port: null,
    tproxy_port: null,
    interface_name: null,
    routing_mark: null,
    // TUN routes are the one TUN item 全部跟随配置 also clears (R32).
    tun: { ...current.value.tun, route_address: null, route_exclude_address: null },
  }, tr('已全部恢复为跟随配置'))
}
</script>

<template>
  <SettingsSection :title="tr('Mihomo 内核')">
    <div class="srow kernel-hero" data-setting="kernel-version">
      <span class="kernel-mark" aria-hidden="true"><Icon name="cpu" :size="20" /></span>
      <div class="srow-main">
        <span class="srow-title">Mihomo <span class="mono">{{ kernel.version ?? '' }}</span></span>
        <span class="srow-desc" data-testid="kernel-update-subtitle">{{ updateSubtitle }}</span>
      </div>
      <span class="tag" :class="kernel.ready ? 'ok' : 'warn'">{{ kernel.ready ? tr('已安装') : tr('未安装') }}</span>
      <button
        type="button"
        class="btn sm"
        :class="store.isAndroid.value && store.appUpdate.offer.value ? 'primary' : ''"
        :disabled="updateBusy"
        :aria-busy="updateBusy || undefined"
        data-setting="kernel-update"
        data-testid="kernel-check-update"
        @click="onCheckUpdate"
      >
        <Icon :name="store.isAndroid.value && store.appUpdate.offer.value ? 'download' : 'refresh'" :size="15" :class="{ spin: updateBusy }" />
        {{ updateBusy ? tr('检查中') : store.isAndroid.value && store.appUpdate.offer.value ? tr('下载') : tr('检查更新') }}
      </button>
    </div>
    <SettingsRow :title="tr('更新渠道')" :description="tr('预览版更新更快，可能不稳定；切换后下次连接生效')" setting="kernel-channel">
      <Segmented
        :model-value="kernel.channel"
        :options="CHANNELS"
        size="sm"
        :label="tr('内核渠道')"
        :disabled="store.busy.kernel"
        @update:model-value="store.setChannel"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection :title="tr('运行与诊断')">
    <SettingsRow :title="tr('日志级别')" :badge="snap.settings.log_level ? tr('已覆盖') : undefined" setting="log-level">
      <template #description>{{ tr('配置中为') }} {{ snap.config_values.log_level ?? 'info' }}</template>
      <SelectField
        :model-value="snap.settings.log_level ?? ''"
        :options="LOG_LEVELS"
        :sheet="compact"
        size="sm"
        :label="tr('日志级别')"
        data-testid="log-level-select"
        @update:model-value="(value) => save({ log_level: String(value) || null })"
      />
    </SettingsRow>
    <SettingsRow
      nav
      :title="tr('生效配置')"
      :description="snap.active_id ? tr('订阅、覆写与 Billow 设置合并后的全部选项，并标出每项来源') : tr('启用一份配置后可查看')"
      :disabled="!snap.active_id"
      setting="effective-config"
      data-testid="settings-open-config"
      @open="store.openConfig()"
    />
    <SettingsRow
      :title="tr('重启内核')"
      :description="snap.connected ? tr('以当前配置重新启动内核，代理、TUN 与出站模式保持不变') : tr('连接后可用')"
      setting="kernel-restart"
    >
      <button
        type="button"
        class="btn ghost sm"
        :disabled="!snap.connected || store.connecting.value"
        data-testid="restart-kernel"
        @click="confirmRestart = true"
      >
        <Icon name="refresh" :size="15" :class="{ spin: store.restarting.value }" />{{ tr('重启') }}
      </button>
    </SettingsRow>
    <SettingsRow
      v-if="debugLogging"
      :title="tr('回收内存')"
      :description="tr('让内核立即释放空闲内存，仅在日志级别为 debug 时可用')"
      setting="kernel-gc"
      data-testid="kernel-gc-row"
    >
      <button
        type="button"
        class="btn ghost sm"
        :disabled="!snap.kernel_running || store.busy.gc"
        data-testid="kernel-gc"
        @click="store.gcKernel()"
      >{{ tr('回收') }}</button>
    </SettingsRow>
  </SettingsSection>

  <SettingsSection
    :title="tr('覆盖配置')"
    :footnote="tr('Billow 的设置会覆盖每份配置里的同名项；标有“已覆盖”的选项可以在这里一次恢复为跟随配置。')"
  >
    <SettingsRow
      :title="tr('全部跟随配置')"
      :description="overrideCount ? tr('当前覆盖了 {0} 项内核选项', { 0: overrideCount }) : tr('所有内核选项都在跟随配置文件')"
      setting="kernel-reset"
    >
      <button type="button" class="btn ghost sm" :disabled="!overrideCount" data-testid="reset-overrides" @click="confirmReset = true">
        {{ tr('全部恢复') }}
      </button>
    </SettingsRow>
  </SettingsSection>

  <Modal v-if="confirmRestart" :title="tr('重启内核')" @close="confirmRestart = false">
    <p class="small" data-testid="restart-kernel-note">{{ tr('内核会以当前生效配置重新启动，已建立的连接会中断；代理、TUN 与出站模式保持不变。') }}</p>
    <template #footer>
      <button type="button" class="btn ghost" data-testid="cancel-restart-kernel" @click="confirmRestart = false">{{ tr('取消') }}</button>
      <button type="button" class="btn danger" data-testid="confirm-restart-kernel" @click="restartConfirmed">{{ tr('重启') }}</button>
    </template>
  </Modal>
  <Modal v-if="confirmReset" :title="tr('全部跟随配置')" @close="confirmReset = false">
    <p class="small">{{ tr('端口、局域网、嗅探、测速、日志等 {0} 项覆盖会被清除，改为使用每份配置自己的值。运行中的内核会自动重启。', { 0: overrideCount }) }}</p>
    <template #footer>
      <button type="button" class="btn ghost" @click="confirmReset = false">{{ tr('取消') }}</button>
      <button type="button" class="btn primary" data-testid="confirm-reset-overrides" @click="resetOverrides">{{ tr('全部恢复') }}</button>
    </template>
  </Modal>
</template>
