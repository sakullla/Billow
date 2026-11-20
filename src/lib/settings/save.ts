import { computed, ref } from 'vue'
import { useStore } from '../store'
import type { KernelSettings } from '../types'

/**
 * Shared save path for the settings panes. Each save sends the whole settings
 * object; while one is in flight the next patch builds on it, so two quick
 * toggles never undo each other.
 *
 * Saves are quiet: a switch, choice or field that applies in place already shows
 * its new state, and an editor dialog closing says the same. Failures still toast.
 */
export function useSettingsSave() {
  const store = useStore()
  const pending = ref<KernelSettings | null>(null)
  const current = computed(() => pending.value ?? store.snapshot.value.settings)

  /** `announce` toasts on success, for explicit actions such as a reset. */
  function save(patch: Partial<KernelSettings>, announce?: string) {
    const next: KernelSettings = { ...current.value, ...patch }
    pending.value = next
    return store.saveSettings(next, { quiet: true, message: announce }).finally(() => {
      if (pending.value === next) pending.value = null
    })
  }

  return { current, save }
}

/** Which option a list summary shows: the first entry and how many more. */
export function listSummary(items: readonly string[] | null | undefined, empty: string): string {
  if (!items?.length) return empty
  const first = items[0]!.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '')
  return items.length > 1 ? `${first} +${items.length - 1}` : first
}
