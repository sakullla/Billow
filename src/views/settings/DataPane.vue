<script setup lang="ts">
import { computed } from 'vue'
import BackupSection from '../../components/BackupSection.vue'
import Toggle from '../../components/Toggle.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { t, tr } from '../../lib/i18n'
import { useStore } from '../../lib/store'

defineProps<{ compact?: boolean }>()
const store = useStore()
const app = computed(() => store.app.value)
</script>

<template>
  <!-- Both reach outside the app (a third-party lookup, a background recorder), so both default off (R40, R43). -->
  <SettingsSection v-if="app" :title="tr('隐私与统计')" data-testid="settings-network">
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
  <BackupSection :compact="compact" />
</template>
