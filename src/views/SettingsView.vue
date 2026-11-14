<script setup lang="ts">
import { ref } from 'vue'
import {
  ABOUT_TEXT,
  ABOUT_TITLE,
  ACTION_ADD,
  ACTION_CLOSE,
  ACTION_SAVE,
  ADD_LOCAL,
  ADD_SUBSCRIPTION,
  CURRENT_MARK,
  EFFECTIVE_LABEL,
  KERNEL_OPTIONS,
  KERNEL_TITLE,
  OVERRIDE_TITLE,
  PROFILE_ADVANCED,
  PROFILE_ENABLE,
  PROFILE_UPDATE,
  PROFILES_EMPTY,
  SETTINGS_TITLE,
  SUBSCRIPTION_PLACEHOLDER,
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
import { formatExpire, showsExpire, showsUsage, type ProfileSnapshot } from '../profile'
import { THEME_OPTIONS } from '../theme'

defineProps<{
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
  'add-subscription': [url: string]
  'add-local': [name: string, content: string]
}>()

const subscriptionUrl = ref('')
const advancedId = ref<string | null>(null)
const draft = ref('')

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

function addSubscription() {
  emit('add-subscription', subscriptionUrl.value)
  subscriptionUrl.value = ''
}

async function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  emit('add-local', file.name, await file.text())
}
</script>

<template>
  <section class="screen" data-screen="settings">
    <h1 class="page-title">{{ SETTINGS_TITLE }}</h1>
    <article class="card" data-testid="profiles">
      <form data-testid="add-subscription" @submit.prevent="addSubscription">
        <label>
          <span>{{ ADD_SUBSCRIPTION }}</span>
          <input v-model="subscriptionUrl" type="url" name="subscription-url" :placeholder="SUBSCRIPTION_PLACEHOLDER" />
        </label>
        <button type="submit" class="btn">{{ ACTION_ADD }}</button>
      </form>
      <label data-testid="add-local" class="file-field">
        <span>{{ ADD_LOCAL }}</span>
        <input type="file" @change="onFile" />
      </label>
      <p v-if="profiles.input_error" class="notice" data-testid="profile-input-error" role="alert">
        {{ profiles.input_error }}
      </p>
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
      <p v-if="profiles.profiles.length === 0">{{ PROFILES_EMPTY }}</p>
      <ul v-else class="profile-list">
        <li
          v-for="profile in profiles.profiles"
          :key="profile.id"
          :data-profile-id="profile.id"
          :data-current="profile.current ? 'true' : 'false'"
          data-testid="profile-row"
        >
          <div class="profile-heading">
            <h2>{{ profile.name }}</h2>
            <span v-if="profile.current" data-testid="profile-current">{{ CURRENT_MARK }}</span>
          </div>
          <p v-if="profile.source.includes('://')" class="muted">{{ profile.source }}</p>
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
            <button type="button" data-action="enable" @click="emit('enable', profile.id)">{{ PROFILE_ENABLE }}</button>
            <button type="button" data-action="update" @click="emit('update', profile.id)">{{ PROFILE_UPDATE }}</button>
            <button
              type="button"
              data-action="advanced"
              @click="openAdvanced(profile.id, profile.override_text)"
            >
              {{ PROFILE_ADVANCED }}
            </button>
          </div>
          <div v-if="advancedId === profile.id" data-testid="override-editor">
            <h2>{{ OVERRIDE_TITLE }}</h2>
            <textarea :value="draft" @input="onDraft" />
            <div class="row-actions">
              <button type="button" data-testid="override-save" @click="saveAdvanced">{{ ACTION_SAVE }}</button>
              <button type="button" data-testid="override-close" @click="closeAdvanced">{{ ACTION_CLOSE }}</button>
            </div>
            <p v-if="profile.override_error" class="notice" data-testid="override-error" role="alert">
              {{ profile.override_error }}
            </p>
          </div>
        </li>
      </ul>
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
