<script setup lang="ts">
import { computed, inject } from 'vue'
import Segmented from '../../components/Segmented.vue'
import Toggle from '../../components/Toggle.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { t, tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import type { LanguagePreference, ThemePreference } from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const app = computed(() => store.app.value)
const openShortcuts = inject<(() => void) | null>('openShortcuts', null)

const THEMES = computed<{ id: ThemePreference; label: string; icon: string }[]>(() => [
  { id: 'system', label: tr('自动'), icon: 'laptop' },
  { id: 'light', label: tr('浅色'), icon: 'sun' },
  { id: 'dark', label: tr('深色'), icon: 'moon' },
])
const LANGUAGES = computed<{ id: LanguagePreference; label: string }[]>(() => [
  { id: 'system', label: t('language.system') },
  { id: 'zh-CN', label: tr('简体中文') },
  { id: 'en', label: 'English' },
])

/** Desktop-only window behaviour exists once the shell reports autostart support. */
const desktopWindow = computed(() => Boolean(app.value && app.value.autostart != null && !store.isAndroid.value))
</script>

<template>
  <SettingsSection :title="tr('外观')">
    <SettingsRow :title="tr('主题')" setting="theme" :stacked="compact">
      <Segmented :model-value="store.theme.value" :options="THEMES" size="sm" :label="tr('主题')" @update:model-value="store.setTheme" />
    </SettingsRow>
    <SettingsRow
      :title="t('settings.language.title')"
      :description="t('settings.language.detail')"
      setting="language"
      :stacked="compact"
      data-testid="language-setting"
    >
      <Segmented
        class="language-control"
        :model-value="store.language.value"
        :options="LANGUAGES"
        size="sm"
        :label="t('settings.language.title')"
        data-testid="language-select"
        @update:model-value="store.setLanguage"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection :title="tr('启动')" data-testid="startup-settings">
    <SettingsRow
      :title="tr('打开时自动启动内核')"
      :description="tr('打开 Billow 后自动连接；连续失败时会停下并恢复系统代理')"
      setting="auto-connect"
    >
      <Toggle
        :model-value="current.auto_connect"
        :label="tr('打开时自动启动内核')"
        data-testid="auto-connect-toggle"
        @update:model-value="(on) => save({ auto_connect: on })"
      />
    </SettingsRow>
    <template v-if="desktopWindow && app">
      <SettingsRow :title="tr('开机自启')" :description="tr('登录系统后自动运行 Billow')" setting="autostart">
        <Toggle :model-value="Boolean(app.autostart)" :label="tr('开机自启')" @update:model-value="store.setAutostart" />
      </SettingsRow>
      <SettingsRow
        v-if="app.autostart"
        nested
        :title="tr('静默启动')"
        :description="tr('开机自启时不弹出主窗口，只在托盘显示')"
        setting="silent-start"
      >
        <Toggle
          :model-value="app.silent_start"
          :label="tr('静默启动')"
          @update:model-value="(on) => store.setBehavior(app!.close_to_tray, on, app!.release_ui_on_close)"
        />
      </SettingsRow>
    </template>
  </SettingsSection>

  <SettingsSection v-if="desktopWindow && app" :title="tr('窗口')">
    <SettingsRow :title="tr('关闭时最小化到托盘')" :description="tr('关闭窗口后继续在后台运行；从托盘菜单退出')" setting="close-to-tray">
      <Toggle
        :model-value="app.close_to_tray"
        :label="tr('关闭时最小化到托盘')"
        @update:model-value="(on) => store.setBehavior(on, app!.silent_start, app!.release_ui_on_close)"
      />
    </SettingsRow>
    <!-- Lightweight mode only exists while the window stays in the tray (R44). -->
    <SettingsRow
      v-if="app.close_to_tray"
      nested
      :title="t('settings.behavior.releaseUi')"
      :description="t('settings.behavior.releaseUiDetail')"
      setting="release-ui"
      data-testid="release-ui-setting"
    >
      <Toggle
        :model-value="app.release_ui_on_close"
        :label="t('settings.behavior.releaseUi')"
        data-testid="release-ui-toggle"
        @update:model-value="(on) => store.setBehavior(app!.close_to_tray, app!.silent_start, on)"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection v-if="app" :title="tr('首页与统计')" data-testid="settings-network">
    <SettingsRow :title="t('settings.exitIp.auto')" :description="t('settings.exitIp.detail')" setting="exit-ip" data-testid="auto-exit-ip-setting">
      <Toggle
        :model-value="app.auto_exit_ip"
        :label="t('settings.exitIp.auto')"
        data-testid="auto-exit-ip-toggle"
        @update:model-value="store.setAutoExitIp"
      />
    </SettingsRow>
    <SettingsRow
      :title="t('settings.traffic.title')"
      setting="traffic-history"
      data-testid="traffic-history-setting"
    >
      <template #description>
        {{ t('settings.traffic.detail', { days: store.trafficStats.value?.retention_days ?? 90 }) }} ·
        <button type="button" class="link-btn" data-testid="open-traffic-stats" @click="store.openTrafficStats">{{ t('settings.traffic.open') }}</button>
      </template>
      <Toggle
        :model-value="app.traffic_history"
        :label="t('settings.traffic.record')"
        data-testid="traffic-history-toggle"
        @update:model-value="store.setTrafficRecording"
      />
    </SettingsRow>
  </SettingsSection>

  <SettingsSection v-if="openShortcuts && !compact" :title="tr('键盘')">
    <SettingsRow
      nav
      :title="tr('键盘快捷键')"
      :description="store.isAndroid.value ? tr('命令面板、搜索聚焦与快速清除') : tr('应用内快捷键与全局快捷键')"
      setting="shortcuts"
      data-testid="settings-shortcuts"
      @open="openShortcuts()"
    />
  </SettingsSection>
</template>
