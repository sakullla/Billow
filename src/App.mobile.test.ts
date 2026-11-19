import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'

// Phone layout regressions: grouped settings, one-row tool headers and readable fact lines.

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

async function mountPhone(options: Parameters<typeof createDemoBackend>[0] = {}) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width: 390 }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountPhone>>['wrapper']

function storeOf(wrapper: Wrapper) {
  return (wrapper.vm as unknown as { store: Store }).store
}

function body() {
  return new DOMWrapper(document.body)
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  vi.useRealTimers()
})

describe('phone layout', () => {
  it('keeps the whole general settings page in grouped list rows', async () => {
    const { wrapper, backend } = await mountPhone()
    storeOf(wrapper).go('settings')
    await flushPromises()

    const behavior = wrapper.find('[data-testid="node-switch-settings"]')
    expect(behavior.classes()).toContain('settings-list')
    // The subscription User-Agent folds into the same list as a row with its current value.
    const fold = behavior.find('[data-testid="subscription-settings"]')
    expect(fold.element.tagName).toBe('DETAILS')
    expect(fold.find('summary .nav-row-value').text()).toBe('默认')

    const save = vi.spyOn(backend, 'saveSettings')
    const input = fold.find('[data-testid="global-subscription-user-agent"]')
    await input.setValue('phone-client/1')
    await input.trigger('blur')
    await settle(300)
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ subscription_user_agent: 'phone-client/1' }))
    expect(fold.find('summary .nav-row-value').text()).toBe('已自定义')

    // Update status sits in the about group as a row; the version is not repeated in a separate card.
    const about = wrapper.find('[data-testid="settings-about"]')
    expect(about.find('[data-testid="app-update"]').classes()).toContain('update-row')
    expect(wrapper.findAll('.page.settings > section.card:not(.settings-list):not(.tool-grid)')).toHaveLength(0)
  })

  it('folds rarer log actions into one menu so the header stays on one row', async () => {
    const { wrapper } = await mountPhone()
    await connect(wrapper)
    storeOf(wrapper).go('logs')
    await settle(1200)

    expect(wrapper.find('[data-testid="pause-logs"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="copy-logs"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="clear-logs"]').exists()).toBe(false)

    const openMenu = async () => {
      await wrapper.find('[data-testid="log-more"]').trigger('click')
      await flushPromises()
    }
    await openMenu()
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).not.toContain('no-wrap')
    await wrapper.find('[data-menu-item="wrap"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).toContain('no-wrap')

    await openMenu()
    expect(wrapper.find('[data-menu-item="wrap"]').text()).toContain('开启自动换行')
    await wrapper.find('[data-menu-item="clear"]').trigger('click')
    await flushPromises()
    expect(body().find('[data-testid="confirm-clear-logs"]').exists()).toBe(true)
  })

  it('pairs the connection scope with a sort sheet and keeps summary facts whole', async () => {
    const { wrapper } = await mountPhone()
    await connect(wrapper)
    storeOf(wrapper).go('connections')
    await settle(1100)

    const summary = wrapper.find('[data-testid="connection-summary"]')
    expect(summary.classes()).toContain('meta-line')
    // Separators are drawn by CSS after each fact, never typed as text that could start a line.
    expect(summary.text()).not.toContain('·')
    expect(summary.findAll(':scope > span').length).toBeGreaterThanOrEqual(3)

    const sort = wrapper.find('[data-testid="connection-sort"]')
    expect(sort.text()).toContain('按时间')
    await sort.trigger('click')
    await flushPromises()
    await body().find('.option-row[data-option-value="download"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="connection-sort"]').text()).toContain('按下载')
  })
})
