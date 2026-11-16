import { setTimeout as delay } from 'node:timers/promises'

// Consume the body inside the retry: interrupted transfers must never enter the cache.
export async function downloadBytes(url, { headers, timeout = 600000, fetchImpl = fetch, retryDelay = 1000 } = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeout) })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return Buffer.from(await response.arrayBuffer())
    } catch (cause) {
      if (attempt === 2) throw new Error(`Build resource download failed: ${new URL(url).pathname}`, { cause })
      console.warn(`Retrying build resource download (${attempt + 1}/2): ${new URL(url).pathname}`)
      await delay(retryDelay * (attempt + 1))
    }
  }
}
