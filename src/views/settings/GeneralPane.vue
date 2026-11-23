<script setup lang="ts">
import { computed, inject } from 'vue'
import Icon from '../../components/Icon.vue'
import Segmented from '../../components/Segmented.vue'
import Toggle from '../../components/Toggle.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { t, tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import type { LanguagePreference, PalettePreference, ThemePreference } from '../../lib/types'

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
const PALETTE_OPTIONS = computed<
  {
    id: PalettePreference
    label: string
    accent: string
    darkAccent: string
    chrome: string
    surface: string
    darkChrome: string
    darkSurface: string
  }[]
>(() => [
  { id: 'teal', label: tr('碧潮'), accent: '#0d9488', darkAccent: '#14b8a6', chrome: '#e4eded', surface: '#ffffff', darkChrome: '#091012', darkSurface: '#141e22' },
  { id: 'sapphire', label: tr('晴空蓝'), accent: '#2563eb', darkAccent: '#3b82f6', chrome: '#e6ebf5', surface: '#ffffff', darkChrome: '#090d14', darkSurface: '#151c27' },
  { id: 'indigo', label: tr('星夜靛'), accent: '#4f46e5', darkAccent: '#818cf8', chrome: '#eaeaf6', surface: '#ffffff', darkChrome: '#0a0a14', darkSurface: '#181828' },
  { id: 'terracotta', label: tr('暖砂陶'), accent: '#c25e2c', darkAccent: '#e8834f', chrome: '#efe8dd', surface: '#fffdfa', darkChrome: '#100d0a', darkSurface: '#1e1915' },
  { id: 'berry', label: tr('绯莓'), accent: '#be185d', darkAccent: '#f472b6', chrome: '#f0e6ec', surface: '#ffffff', darkChrome: '#100a0f', darkSurface: '#1e151c' },
  { id: 'graphite', label: tr('墨韵'), accent: '#18181b', darkAccent: '#e4e4e7', chrome: '#e9e9ec', surface: '#ffffff', darkChrome: '#09090b', darkSurface: '#18181c' },
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
      :title="tr('配色方案')"
      :description="tr('与明暗模式自由组合，实时切换表面色温与主色')"
      setting="palette"
      stacked
      data-testid="palette-setting"
    >
      <div class="palette-picker" role="radiogroup" :aria-label="tr('配色方案')" data-testid="palette-picker">
        <button
          v-for="item in PALETTE_OPTIONS"
          :key="item.id"
          type="button"
          role="radio"
          class="palette-chip"
          :class="{ active: store.palette.value === item.id }"
          :aria-checked="store.palette.value === item.id"
          :data-value="item.id"
          :style="{
            '--pv-accent': item.accent,
            '--pv-dark-accent': item.darkAccent,
            '--pv-chrome': item.chrome,
            '--pv-surface': item.surface,
            '--pv-dark-chrome': item.darkChrome,
            '--pv-dark-surface': item.darkSurface,
          }"
          @click="store.setPalette(item.id)"
        >
          <span class="palette-preview" aria-hidden="true">
            <span class="palette-pv-side">
              <span class="palette-pv-dot" />
              <span class="palette-pv-bar" />
              <span class="palette-pv-bar short" />
            </span>
            <span class="palette-pv-main">
              <span class="palette-pv-pill" />
              <span class="palette-pv-lines"><i /><i /></span>
            </span>
            <span v-if="store.palette.value === item.id" class="palette-check">
              <Icon name="check" :size="10" :stroke="2.8" />
            </span>
          </span>
          <span class="palette-label">{{ item.label }}</span>
        </button>
      </div>
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

  <SettingsSection :title="tr('功能')" data-testid="settings-features">
    <SettingsRow
      :title="t('customNodes.title')"
      :description="tr('在配置页管理独立自建节点、链式代理与落地分流规则；关闭后隐藏入口并停止注入')"
      setting="custom-nodes"
      data-testid="custom-nodes-feature-setting"
    >
      <Toggle
        :model-value="store.customNodesFeatureEnabled.value"
        :busy="Boolean(store.busy['customNodes:overlay'])"
        :label="t('customNodes.title')"
        data-testid="custom-nodes-feature-toggle"
        @update:model-value="(on) => store.setCustomNodesFeatureEnabled(on)"
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
