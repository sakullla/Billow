import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import { NODES_FAILED, NODES_KERNEL_DOWN, NODES_NEED_PROFILE, NODES_NO_MATCH } from './copy'
import { createMemoryPort } from './port'
import { createMemoryProfilePort, type ProfilePort } from './profile-port'
import type { NodeGroup } from './profile'

const groups: NodeGroup[] = [
  {
    name: '手动组',
    kind: 'manual',
    now: '甲',
    sort: 'default',
    nodes: [
      { name: '甲', delay_ms: 30, failed: false, selected: true },
      { name: '乙', delay_ms: null, failed: true, selected: false },
      { name: '丙', delay_ms: 10, failed: false, selected: false },
    ],
  },
  {
    name: '自动组',
    kind: 'auto',
    now: '丙',
    sort: 'default',
    nodes: [{ name: '丙', delay_ms: null, failed: false, selected: false }],
  },
]

function profilePort(): ProfilePort {
  return createMemoryProfilePort({
    profiles: [
      {
        id: 'p1',
        name: '已保存',
        kind: 'local',
        source: '',
        current: true,
        failure: null,
        override_text: '',
        override_error: null,
        used: null,
        total: null,
        expire: null,
        last_success_ms: null,
      },
    ],
    node_groups: groups,
    kernel_running: false,
  })
}

async function openNodes(port: ProfilePort = profilePort()) {
  const wrapper = mount(App, {
    props: { initialWidth: 900, port: createMemoryPort(), profilePort: port },
  })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  await flushPromises()
  await wrapper.get('[data-entry="nodes"]').trigger('click')
  await flushPromises()
  return wrapper
}

function rowNames(wrapper: Awaited<ReturnType<typeof openNodes>>, group: string): string[] {
  return wrapper
    .get(`[data-group="${group}"]`)
    .findAll('[data-node]')
    .map((row) => row.attributes('data-node') ?? '')
}

describe('节点', () => {
  it('没有本地配置时说明需要先添加或更新，不显示切换成功', async () => {
    const wrapper = await openNodes(createMemoryProfilePort())
    expect(wrapper.get('[data-testid="nodes-notice"]').text()).toContain(NODES_NEED_PROFILE)
    expect(wrapper.find('[data-selected="true"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="node-query"]').exists()).toBe(false)
  })

  it('已保存配置按组列出，筛选和排序不改已保存节点', async () => {
    const port = profilePort()
    const wrapper = await openNodes(port)
    expect(wrapper.get('[data-group="手动组"]').text()).toContain('手动')
    expect(wrapper.get('[data-group="自动组"]').text()).toContain('自动')
    expect(wrapper.get('[data-group="手动组"] [data-testid="group-now"]').text()).toContain('甲')
    expect(wrapper.get('[data-node="乙"] [data-failed="true"]').text()).toBe(NODES_FAILED)
    expect(wrapper.get('[data-node="丙"] .node-delay').text()).toBe('10')
    expect(wrapper.get('[data-group="自动组"] [data-node="丙"]').element.tagName).toBe('DIV')

    let selects = 0
    const selectNode = port.selectNode.bind(port)
    port.selectNode = async (group, node) => {
      selects += 1
      return selectNode(group, node)
    }
    await wrapper.get('[data-group="自动组"] [data-node="丙"]').trigger('click')
    await flushPromises()
    expect(selects).toBe(0)

    await wrapper.get('[data-group="手动组"] [data-node="丙"]').trigger('click')
    await flushPromises()
    expect(selects).toBe(1)
    expect(wrapper.get('[data-group="手动组"] [data-node="丙"]').attributes('data-selected')).toBe('true')
    expect(wrapper.get('[data-group="手动组"] [data-node="甲"]').attributes('data-selected')).toBe('false')
    expect(wrapper.get('[data-group="手动组"] [data-testid="group-now"]').text()).toContain('丙')

    await wrapper.get('[data-group="手动组"] [data-sort="delay"]').trigger('click')
    await flushPromises()
    expect(rowNames(wrapper, '手动组')).toEqual(['丙', '甲', '乙'])
    expect(wrapper.get('[data-node="乙"] .node-delay').text()).toBe(NODES_FAILED)
    await wrapper.get('[data-group="手动组"] [data-sort="default"]').trigger('click')
    await flushPromises()
    expect(rowNames(wrapper, '手动组')).toEqual(['甲', '乙', '丙'])

    await wrapper.get('[data-testid="node-query"]').setValue('乙')
    await flushPromises()
    expect(wrapper.find('[data-node="甲"]').exists()).toBe(false)
    expect(wrapper.find('[data-group="手动组"] [data-node="乙"]').exists()).toBe(true)
    const kept = await port.load()
    expect(kept.profiles).toHaveLength(1)
    expect(kept.profiles[0]?.name).toBe('已保存')
    expect(kept.node_catalog[0]?.nodes.map((node) => node.name)).toEqual(['甲', '乙', '丙'])

    await wrapper.get('[data-testid="node-query"]').setValue('没有这个')
    await flushPromises()
    expect(wrapper.get('[data-testid="nodes-notice"]').text()).toContain(NODES_NO_MATCH)
    expect(wrapper.find('[data-testid="node-group"]').exists()).toBe(false)
    const still = await port.load()
    expect(still.profiles).toHaveLength(1)
    expect(still.node_catalog[0]?.nodes).toHaveLength(3)
    expect(still.node_catalog[1]?.nodes.map((node) => node.name)).toEqual(['丙'])
  })

  it('只打开节点页不测试延迟，内核未运行时失败结果还在', async () => {
    const port = profilePort()
    let tests = 0
    const testGroup = port.testGroup.bind(port)
    port.testGroup = async (group) => {
      tests += 1
      return testGroup(group)
    }
    const wrapper = await openNodes(port)
    expect(tests).toBe(0)
    expect(wrapper.get('[data-node="乙"] .node-delay').text()).toBe(NODES_FAILED)
    expect(wrapper.get('[data-node="丙"] .node-delay').text()).toBe('10')

    await wrapper.get('[data-group="手动组"] [data-action="test"]').trigger('click')
    await flushPromises()
    expect(tests).toBe(1)
    expect(wrapper.get('[data-testid="nodes-error"]').text()).toContain(NODES_KERNEL_DOWN)
    expect(wrapper.get('[data-node="乙"] .node-delay').text()).toBe(NODES_FAILED)
    expect(wrapper.get('[data-node="甲"] .node-delay').text()).toBe('30')
    expect(wrapper.get('[data-node="丙"] .node-delay').text()).toBe('10')
  })
})