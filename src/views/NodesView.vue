<script setup lang="ts">
import { NODES_EMPTY, NODES_TITLE } from '../copy'
</script>

<template>
  <section class="screen" data-screen="nodes">
    <h1 class="page-title">{{ NODES_TITLE }}</h1>
    <article class="card">
      <p>{{ NODES_EMPTY }}</p>
    </article>
  </section>
</template>
