export interface PoolOptions<T> {
  /** Maximum total concurrent workers. */
  concurrency: number
  /** Optional group key (e.g. upstream hostname) to cap per-host load. */
  groupKey?: (item: T) => string
  /** Maximum concurrent workers sharing the same non-empty `groupKey`. */
  maxPerGroup?: number
  /** Checked before starting each queued item; stops pulling new items when true. */
  shouldStop?: () => boolean
  /** Invoked after each item finishes with cumulative `(done, failed, ok)`. */
  onProgress?: (done: number, failed: number, ok: boolean, item: T) => void
}

/**
 * Bounded work-stealing pool for batch subscription and provider updates.
 * Keeps concurrency capped, avoids hammering a single upstream host, and isolates
 * individual failures so healthy items finish without waiting on slow ones.
 */
export async function runPool<T>(
  items: readonly T[],
  options: PoolOptions<T>,
  worker: (item: T, index: number) => Promise<boolean>,
): Promise<{ done: number; failed: number }> {
  const total = items.length
  if (total === 0) return { done: 0, failed: 0 }

  const limit = Math.max(1, Math.min(options.concurrency, total))
  const maxPerGroup = options.maxPerGroup && options.maxPerGroup > 0 ? options.maxPerGroup : limit
  const pending = items.map((item, index) => ({
    item,
    index,
    group: options.groupKey?.(item) || '',
  }))
  const activePerGroup = new Map<string, number>()
  const waiters: (() => void)[] = []

  let done = 0
  let failed = 0

  function notifyWaiters() {
    while (waiters.length > 0) {
      waiters.shift()?.()
    }
  }

  function takeNext(): { item: T; index: number; group: string } | null {
    for (let i = 0; i < pending.length; i += 1) {
      const candidate = pending[i]!
      if (!candidate.group) {
        pending.splice(i, 1)
        return candidate
      }
      const inFlight = activePerGroup.get(candidate.group) ?? 0
      if (inFlight < maxPerGroup) {
        pending.splice(i, 1)
        activePerGroup.set(candidate.group, inFlight + 1)
        return candidate
      }
    }
    return null
  }

  async function loop() {
    while (pending.length > 0) {
      if (options.shouldStop?.()) return
      const next = takeNext()
      if (!next) {
        // Remaining items are temporarily throttled by `maxPerGroup`; wait for a slot to free up.
        await new Promise<void>((resolve) => waiters.push(resolve))
        continue
      }
      let ok = false
      try {
        ok = await worker(next.item, next.index)
      } catch {
        ok = false
      } finally {
        if (next.group) {
          const prev = activePerGroup.get(next.group) ?? 1
          if (prev <= 1) activePerGroup.delete(next.group)
          else activePerGroup.set(next.group, prev - 1)
        }
        done += 1
        if (!ok) failed += 1
        options.onProgress?.(done, failed, ok, next.item)
        notifyWaiters()
      }
    }
  }

  await Promise.all(Array.from({ length: limit }, () => loop()))
  return { done, failed }
}
