<script setup lang="ts">
import {
  NODE_SORTS,
  NODES_AUTO,
  NODES_EMPTY,
  NODES_FAILED,
  NODES_MANUAL,
  NODES_NOW,
  NODES_SEARCH,
  NODES_SELECTED,
  NODES_TEST,
  NODES_TITLE,
  NODES_UNKNOWN,
} from '../copy'
import type { NodeGroup, NodeItem } from '../profile'

defineProps<{
  groups: NodeGroup[]
  query: string
  notice: string | null
  error: string | null
  searchable: boolean
}>()

const emit = defineEmits<{
  query: [value: string]
  sort: [group: string, sort: string]
  select: [group: string, node: string]
  test: [group: string]
}>()

function delayLabel(node: NodeItem): string {
  if (node.failed) return NODES_FAILED
  if (node.delay_ms == null) return ''
  return String(node.delay_ms)
}

function onQuery(event: Event) {
  emit('query', (event.target as HTMLInputElement).value)
}
</script>

<template>
  <section class="screen" data-screen="nodes">
    <h1 class="page-title">{{ NODES_TITLE }}</h1>
    <input
      v-if="searchable"
      class="node-query"
      data-testid="node-query"
      type="search"
      :value="query"
      :aria-label="NODES_SEARCH"
      :placeholder="NODES_SEARCH"
      @input="onQuery"
    />
    <p v-if="error" class="notice" data-testid="nodes-error">{{ error }}</p>
    <p v-if="notice" class="card" data-testid="nodes-notice">{{ notice }}</p>
    <p v-else-if="groups.length === 0" class="card" data-testid="nodes-notice">{{ NODES_EMPTY }}</p>
    <article
      v-for="group in groups"
      :key="group.name"
      class="card node-group"
      data-testid="node-group"
      :data-group="group.name"
      :data-kind="group.kind"
      :data-sort="group.sort"
    >
      <div class="group-meta">
        <h2>{{ group.name }}</h2>
        <span>{{ group.kind === 'manual' ? NODES_MANUAL : NODES_AUTO }}</span>
        <span data-testid="group-now">{{ NODES_NOW }} {{ group.now || NODES_UNKNOWN }}</span>
      </div>
      <div class="group-tools">
        <div class="sort-choices" role="radiogroup" aria-label="排序">
          <button
            v-for="option in NODE_SORTS"
            :key="option.id"
            type="button"
            class="choice"
            :class="{ selected: group.sort === option.id }"
            role="radio"
            :aria-checked="group.sort === option.id ? 'true' : 'false'"
            :data-sort="option.id"
            @click="emit('sort', group.name, option.id)"
          >
            {{ option.label }}
          </button>
        </div>
        <button type="button" class="btn" data-action="test" @click="emit('test', group.name)">
          {{ NODES_TEST }}
        </button>
      </div>
      <ul class="node-list">
        <li v-for="node in group.nodes" :key="node.name">
          <button
            v-if="group.kind === 'manual'"
            type="button"
            class="node-row"
            :data-node="node.name"
            :data-selected="node.selected ? 'true' : 'false'"
            :aria-current="node.selected ? 'true' : undefined"
            @click="emit('select', group.name, node.name)"
          >
            <span class="node-check">{{ node.selected ? NODES_SELECTED : '' }}</span>
            <span class="node-name">{{ node.name }}</span>
            <span class="node-delay" :data-failed="node.failed ? 'true' : 'false'">{{ delayLabel(node) }}</span>
          </button>
          <div
            v-else
            class="node-row"
            data-selectable="false"
            :data-node="node.name"
            data-selected="false"
          >
            <span class="node-check"></span>
            <span class="node-name">{{ node.name }}</span>
            <span class="node-delay" :data-failed="node.failed ? 'true' : 'false'">{{ delayLabel(node) }}</span>
          </div>
        </li>
      </ul>
    </article>
  </section>
</template>
