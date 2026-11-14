import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import { KERNEL_OPTIONS, NAV_ITEMS } from './copy'
import { createMemoryKernelPort, type KernelPort } from './kernel-port'
import { resolveKernelChannel } from './kernel'
import { createMemoryPort } from './port'

async function mountApp(kernelPort: KernelPort = createMemoryKernelPort()) {
  const wrapper = mount(App, {
    props: { initialWidth: 900, port: createMemoryPort(), kernelPort },
  })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  return wrapper
}

describe('内核渠道', () => {
  it('默认稳定版，配置页可以切到预览版，主导航不增加入口', async () => {
    expect(KERNEL_OPTIONS.map((option) => option.label)).toEqual(['稳定版', '预览版'])
    expect(resolveKernelChannel(null)).toBe('stable')
    expect(resolveKernelChannel('deadbeef')).toBe('stable')
    expect(resolveKernelChannel('preview')).toBe('preview')
    expect(NAV_ITEMS.map((item) => item.label)).toEqual(['首页', '节点', '配置'])

    const kernelPort = createMemoryKernelPort()
    const wrapper = await mountApp(kernelPort)
    expect(wrapper.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])
    await wrapper.get('[data-entry="settings"]').trigger('click')
    const channel = wrapper.get('[data-testid="kernel-channel"]')
    expect(channel.text()).toContain('内核渠道')
    expect(channel.text()).toContain('稳定版')
    expect(channel.text()).toContain('预览版')
    expect(channel.findAll('input[type="radio"]')).toHaveLength(2)
    expect(channel.find('input[type="text"]').exists()).toBe(false)
    expect(channel.get('[role="radiogroup"]').attributes('data-current')).toBe('stable')

    const radios = channel.findAll('input[name="kernel-channel"]')
    await radios[1]!.trigger('change')
    await flushPromises()
    expect(channel.get('[role="radiogroup"]').attributes('data-current')).toBe('preview')
    expect((await kernelPort.load()).channel).toBe('preview')
    expect(wrapper.findAll('.nav-button').map((button) => button.text())).toEqual(['首页', '节点', '配置'])
  })

  it('切换下载失败时仍显示原渠道和失败', async () => {
    const kernelPort: KernelPort = {
      async load() {
        return { channel: 'stable', failure: null, ready: true }
      },
      async setChannel() {
        return { channel: 'stable', failure: '内核下载失败', ready: true }
      },
    }
    const wrapper = await mountApp(kernelPort)
    await wrapper.get('[data-entry="settings"]').trigger('click')
    const radios = wrapper.findAll('input[name="kernel-channel"]')
    await radios[1]!.trigger('change')
    await flushPromises()
    expect(wrapper.get('[data-testid="kernel-channel"] [role="radiogroup"]').attributes('data-current')).toBe(
      'stable',
    )
    expect(wrapper.get('[data-testid="kernel-failure"]').text()).toContain('失败')
  })
})
