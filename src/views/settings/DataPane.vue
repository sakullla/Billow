<script setup lang="ts">
import BackupSection from '../../components/BackupSection.vue'

defineProps<{ compact?: boolean }>()
</script>

<template>
  <BackupSection :compact="compact" />
</template>
