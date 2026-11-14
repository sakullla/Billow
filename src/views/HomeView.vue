<script setup lang="ts">
import { HOME_HINT, HOME_STATUS, PRODUCT_NAME } from '../copy'
</script>

<template>
  <section class="screen" data-screen="home">
    <p class="product">{{ PRODUCT_NAME }}</p>
    <h1 class="status-word">{{ HOME_STATUS }}</h1>
    <article class="card">
      <p>{{ HOME_HINT }}</p>
    </article>
  </section>
</template>
