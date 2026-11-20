<script setup lang="ts">
import { computed } from 'vue'
import AppUpdateCard from '../../components/AppUpdateCard.vue'
import BrandMark from '../../components/BrandMark.vue'
import Icon from '../../components/Icon.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { REPO_LABEL, REPO_URL, openExternal } from '../../lib/links'
import { useStore } from '../../lib/store'

defineProps<{ compact?: boolean }>()
const store = useStore()
const app = computed(() => store.app.value)
const kernel = computed(() => store.kernel.value)

function openRepo() {
  openExternal(REPO_URL).catch(() => store.toast(tr('无法打开浏览器，请访问 ') + REPO_URL, 'error'))
}
</script>

<template>
  <section class="about-hero" data-setting="about" data-testid="settings-about">
    <BrandMark size="xl" />
    <div class="about-hero-text">
      <h3>Billow</h3>
      <p class="muted">{{ tr('基于 Mihomo 内核的跨平台代理客户端 · GPL-3.0') }}</p>
      <p class="about-hero-versions mono">
        <span>v{{ app?.version ?? '—' }}</span>
        <span v-if="kernel.version">Mihomo {{ kernel.version }}</span>
      </p>
    </div>
    <button type="button" class="btn ghost sm" :title="REPO_URL" data-testid="open-repo" @click="openRepo">
      <Icon name="github" :size="15" />{{ REPO_LABEL }}<Icon name="external" :size="12" />
    </button>
  </section>

  <SettingsSection :title="tr('应用更新')">
    <div data-setting="app-update" class="about-update">
      <AppUpdateCard variant="row" />
    </div>
  </SettingsSection>
</template>
