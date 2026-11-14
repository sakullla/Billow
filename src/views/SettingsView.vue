<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  ABOUT_TEXT,
  ABOUT_TITLE,
  ACTION_ADD_PROFILE,
  ACTION_CLOSE,
  ACTION_SAVE,
  CURRENT_MARK,
  EFFECTIVE_LABEL,
  KERNEL_OPTIONS,
  KERNEL_TITLE,
  OVERRIDE_TITLE,
  PROFILE_ADVANCED,
  PROFILE_ENABLE,
  PROFILE_LOCAL,
  PROFILE_SUBSCRIPTION,
  PROFILE_SUCCESS,
  PROFILE_UPDATE,
  PROFILES_EMPTY,
  SETTINGS_TITLE,
  TAKEOVER_PROXY,
  TAKEOVER_TUN,
  TAKEOVER_VPN,
  THEME_TITLE,
  USAGE_EXPIRE,
  USAGE_TOTAL,
  USAGE_USED,
  type KernelChannel,
  type ThemePreference,
} from '../copy'
import { formatExpire, formatSuccess, showsExpire, showsUsage, type ProfileSnapshot } from '../profile'
import { THEME_OPTIONS } from '../theme'

const props = defineProps<{
  modelValue: ThemePreference
  channel: KernelChannel
  failure: string | null
  profiles: ProfileSnapshot
}>()
const emit = defineEmits<{
  'update:modelValue': [value: ThemePreference]
  'update:channel': [value: KernelChannel]
  enable: [id: string]
  update: [id: string]
  'save-override': [id: string, text: string]
  add: []
}>()

const advancedId = ref<string | null>(null)
const draft = ref('')
const orderedProfiles = computed(() =>
  [...props.profiles.profiles].sort((left, right) => Number(right.current) - Number(left.current)),
)
const advancedProfile = computed(
  () => props.profiles.profiles.find((profile) => profile.id === advancedId.value) ?? null,
)

function openAdvanced(id: string, text: string) {
  advancedId.value = id
  draft.value = text
}

function closeAdvanced() {
  advancedId.value = null
  draft.value = ''
}

function saveAdvanced() {
  if (!advancedId.value) return
  emit('save-override', advancedId.value, draft.value)
}

function onDraft(event: Event) {
  const target = event.target
  if (target instanceof HTMLTextAreaElement) draft.value = target.value
}
</script>

<template>
  <section class="screen" data-screen="settings">
    <h1 class="page-title">{{ SETTINGS_TITLE }}</h1>
    <article class="card" data-testid="profiles">
      <button type="button" class="btn" data-testid="open-add-profile" @click="emit('add')">
        {{ ACTION_ADD_PROFILE }}
      </button>
      <p
        data-testid="takeover"
        :data-system-proxy="profiles.system_proxy ? 'on' : 'off'"
        :data-tun="profiles.tun ? 'on' : 'off'"
        :data-vpn="profiles.vpn ? 'on' : 'off'"
      >
        {{ TAKEOVER_PROXY }}{{ profiles.system_proxy ? '开启' : '关闭' }}
        {{ TAKEOVER_TUN }}{{ profiles.tun ? '开启' : '关闭' }}
        {{ TAKEOVER_VPN }}{{ profiles.vpn ? '开启' : '关闭' }}
      </p>
      <p v-if="orderedProfiles.length === 0">{{ PROFILES_EMPTY }}</p>
      <ul v-else class="profile-list">
        <li
          v-for="profile in orderedProfiles"
          :key="profile.id"
          :data-profile-id="profile.id"
          :data-current="profile.current ? 'true' : 'false'"
          data-testid="profile-row"
        >
          <div class="profile-heading">
            <h2>{{ profile.name }}</h2>
            <span v-if="profile.current" data-testid="profile-current">{{ CURRENT_MARK }}</span>
          </div>
          <p class="muted" data-testid="profile-kind">
            {{ profile.kind === 'local' ? PROFILE_LOCAL : PROFILE_SUBSCRIPTION }}
          </p>
          <p v-if="profile.source.includes('://')" class="muted">{{ profile.source }}</p>
          <p v-if="profile.last_success_ms" data-testid="profile-success">
            {{ PROFILE_SUCCESS }} {{ formatSuccess(profile.last_success_ms) }}
          </p>
          <p v-if="showsUsage(profile.used, profile.total)" data-testid="profile-usage">
            {{ USAGE_USED }} {{ profile.used }} {{ USAGE_TOTAL }} {{ profile.total }}
          </p>
          <p v-if="showsExpire(profile.expire)" data-testid="profile-expire">
            {{ USAGE_EXPIRE }} {{ formatExpire(profile.expire ?? 0) }}
          </p>
          <p v-if="profile.current && profiles.mixed_port != null" data-testid="effective-value">
            {{ EFFECTIVE_LABEL }} {{ profiles.mixed_port }}
          </p>
          <p v-if="profile.failure" class="notice" data-testid="profile-failure" role="alert">{{ profile.failure }}</p>
          <div class="row-actions" data-testid="profile-actions">
            <button v-if="!profile.current" type="button" data-action="enable" @click="emit('enable', profile.id)">
              {{ PROFILE_ENABLE }}
            </button>
            <button
              v-if="profile.current && profile.kind === 'subscription'"
              type="button"
              data-action="update"
              @click="emit('update', profile.id)"
            >
              {{ PROFILE_UPDATE }}
            </button>
            <button
              type="button"
              data-action="advanced"
              @click="openAdvanced(profile.id, profile.override_text)"
            >
              {{ PROFILE_ADVANCED }}
            </button>
          </div>
        </li>
      </ul>
      <div v-if="advancedProfile" class="dialog" data-testid="override-editor" role="dialog">
        <h2>{{ OVERRIDE_TITLE }}</h2>
        <textarea :value="draft" @input="onDraft" />
        <div class="row-actions">
          <button type="button" data-testid="override-save" @click="saveAdvanced">{{ ACTION_SAVE }}</button>
          <button type="button" data-testid="override-close" @click="closeAdvanced">{{ ACTION_CLOSE }}</button>
        </div>
        <p v-if="advancedProfile.override_error" class="notice" data-testid="override-error" role="alert">
          {{ advancedProfile.override_error }}
        </p>
      </div>
    </article>
    <article class="card">
      <h2>{{ THEME_TITLE }}</h2>
      <div class="choices" role="radiogroup" aria-label="主题">
        <label
          v-for="option in THEME_OPTIONS"
          :key="option.id"
          class="choice"
          :class="{ selected: modelValue === option.id }"
        >
          <input
            type="radio"
            name="theme"
            :value="option.id"
            :checked="modelValue === option.id"
            @change="emit('update:modelValue', option.id)"
          />
          <span>{{ option.label }}</span>
        </label>
      </div>
    </article>
    <article class="card" data-testid="kernel-channel">
      <h2>{{ KERNEL_TITLE }}</h2>
      <div class="choices" role="radiogroup" aria-label="内核渠道" :data-current="channel">
        <label
          v-for="option in KERNEL_OPTIONS"
          :key="option.id"
          class="choice"
          :class="{ selected: channel === option.id }"
        >
          <input
            type="radio"
            name="kernel-channel"
            :value="option.id"
            :checked="channel === option.id"
            @change="emit('update:channel', option.id)"
          />
          <span>{{ option.label }}</span>
        </label>
      </div>
      <p v-if="failure" class="notice" data-testid="kernel-failure" role="alert">{{ failure }}</p>
    </article>
    <article class="card" data-testid="about">
      <h2>{{ ABOUT_TITLE }}</h2>
      <p>{{ ABOUT_TEXT }}</p>
    </article>
  </section>
</template>
