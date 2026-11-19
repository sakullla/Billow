import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDemoBackend } from '../lib/demo'
import type { DnsQueryResult, DnsQueryType } from '../lib/types'
import DnsQueryDialog from './DnsQueryDialog.vue'

afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
})

function body() {
  return document.body
}

function find(selector: string) {
  return body().querySelector<HTMLElement>(selector)
}

async function typeName(value: string) {
  const input = find('[data-testid="dns-query-name"]') as HTMLInputElement
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await flushPromises()
}

async function submit() {
  find('[data-testid="dns-query-form"]')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await flushPromises()
}

/** A demo backend whose kernel is running, so `dnsQuery` answers. */
async function runningDemo() {
  const backend = createDemoBackend()
  await backend.connect()
  return backend
}

function mountDialog(props: { running: boolean; query: (name: string, qtype: DnsQueryType) => Promise<DnsQueryResult> }) {
  return mount(DnsQueryDialog, { attachTo: body(), props })
}

describe('DnsQueryDialog', () => {
  it('shows each answer with its TTL and the elapsed time', async () => {
    vi.useFakeTimers()
    const backendPromise = runningDemo()
    await vi.runAllTimersAsync()
    const backend = await backendPromise
    const query = vi.fn(backend.dnsQuery)
    mountDialog({ running: true, query })
    await flushPromises()

    await typeName('example.com')
    await submit()
    await vi.advanceTimersByTimeAsync(200)
    await flushPromises()

    expect(query).toHaveBeenCalledWith('example.com', 'A')
    const answers = body().querySelectorAll('[data-testid="dns-query-answer"]')
    expect(answers.length).toBeGreaterThanOrEqual(1)
    expect(answers[0]!.textContent).toMatch(/A\s*\d+\.\d+\.\d+\.\d+\s*\d+ 秒/)
    expect(find('[data-testid="dns-query-meta"]')!.textContent).toMatch(/耗时 \d+ ms/)
    expect(find('[data-testid="dns-query-error"]')).toBeNull()
  })

  it('rejects an invalid or empty name without calling the backend', async () => {
    const query = vi.fn(async () => ({ name: '', qtype: 'A', status: 0, answers: [], elapsed_ms: 0, error: null }))
    mountDialog({ running: true, query })
    await flushPromises()

    await submit()
    expect(find('[data-testid="dns-query-input-error"]')!.textContent).toContain('请输入域名')

    await typeName('not a domain')
    await submit()
    expect(find('[data-testid="dns-query-input-error"]')!.textContent).toContain('格式无效')
    expect(query).not.toHaveBeenCalled()

    // Editing the name clears the hint until the next attempt.
    await typeName('example.com')
    expect(find('[data-testid="dns-query-input-error"]')).toBeNull()
  })

  it('opens while the kernel is down but disables the query and says why', async () => {
    const query = vi.fn()
    mountDialog({ running: false, query })
    await flushPromises()

    const button = find('[data-testid="dns-query-submit"]') as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(find('[data-testid="dns-query-blocked"]')!.textContent).toContain('内核没有运行')
    await typeName('example.com')
    await submit()
    expect(query).not.toHaveBeenCalled()
  })

  it('shows the kernel reason and status code when no record comes back', async () => {
    const query = vi.fn(async () => ({
      name: 'missing.example',
      qtype: 'A',
      status: 3,
      answers: [],
      elapsed_ms: 12,
      error: '没有找到记录（NXDOMAIN）',
    }))
    mountDialog({ running: true, query })
    await flushPromises()
    await typeName('missing.example')
    await submit()

    expect(find('[data-testid="dns-query-error"]')!.textContent).toContain('没有找到记录（NXDOMAIN）')
    expect(find('[data-testid="dns-query-meta"]')!.textContent).toContain('状态码 3')
    expect(body().querySelectorAll('[data-testid="dns-query-answer"]')).toHaveLength(0)
  })
})
