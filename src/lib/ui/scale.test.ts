import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { autoScaleFor, createUiScale, fitScale, scaleLabel, type ScaleDriver, type Size } from './scale'

function fakeDriver(monitor: Size | null, window: Size) {
  const applied: number[] = []
  const resized: Size[] = []
  let zoom = 1
  const driver: ScaleDriver = {
    apply: async (factor) => {
      applied.push(factor)
      zoom = factor
    },
    monitor: async () => monitor,
    windowSize: async () => ({ ...window }),
    resizeWindow: async (size) => {
      resized.push(size)
      window = { ...size }
    },
  }
  return { driver, applied, resized, zoom: () => zoom }
}

afterEach(() => {
  localStorage.clear()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('ui scale', () => {
  it('picks a factor from the monitor short side', () => {
    expect(autoScaleFor(null)).toBe(1)
    expect(autoScaleFor({ width: 1920, height: 1080 })).toBe(1)
    expect(autoScaleFor({ width: 1512, height: 982 })).toBe(1)
    expect(autoScaleFor({ width: 2560, height: 1440 })).toBe(1.1)
    expect(autoScaleFor({ width: 3440, height: 1440 })).toBe(1.1)
    expect(autoScaleFor({ width: 3200, height: 1800 })).toBe(1.25)
    expect(autoScaleFor({ width: 3840, height: 2160 })).toBe(1.5)
  })

  it('never zooms a small window out of the desktop layout', () => {
    expect(fitScale(1.5, { width: 1800, height: 1100 })).toBe(1.5)
    expect(fitScale(1.5, { width: 1200, height: 1100 })).toBe(1.3)
    expect(fitScale(1.5, { width: 700, height: 500 })).toBe(1)
    expect(fitScale(0.9, { width: 700, height: 500 })).toBe(0.9)
    expect(scaleLabel(1.25)).toBe('125%')
  })

  it('enlarges the default window on a 4K screen and zooms it', async () => {
    const fake = fakeDriver({ width: 3840, height: 2160 }, { width: 960, height: 680 })
    const scale = createUiScale(fake.driver)
    await scale.install()
    expect(scale.supported.value).toBe(true)
    expect(fake.resized).toEqual([{ width: 1440, height: 1020 }])
    expect(scale.applied.value).toBe(1.5)
    expect(fake.applied).toEqual([1.5])
    scale.uninstall()
  })

  it('keeps a restored window size and persists manual steps', async () => {
    const fake = fakeDriver({ width: 2560, height: 1440 }, { width: 1400, height: 900 })
    const scale = createUiScale(fake.driver)
    await scale.install()
    expect(fake.resized).toEqual([])
    expect(scale.target.value).toBe(1.1)
    expect(scale.step(1)).toBe(1.25)
    expect(localStorage.getItem('billow.ui-scale')).toBe('1.25')
    expect(scale.step(-1)).toBe(1.1)
    scale.set(2)
    expect(scale.step(1)).toBeNull()
    scale.reset()
    expect(scale.preference.value).toBe('auto')
    scale.uninstall()
    expect(createUiScale(null).preference.value).toBe('auto')
  })

  it('does not attach listeners or resize after an asynchronous install is uninstalled', async () => {
    let resolve!: (size: Size | null) => void
    const monitor = new Promise<Size | null>((done) => { resolve = done })
    const fake = fakeDriver(null, { width: 960, height: 680 })
    fake.driver.monitor = () => monitor
    const listen = vi.spyOn(window, 'addEventListener')
    const scale = createUiScale(fake.driver)
    const installing = scale.install()
    scale.uninstall()
    resolve({ width: 3840, height: 2160 })
    await installing
    expect(fake.resized).toEqual([])
    expect(fake.applied).toEqual([])
    expect(listen.mock.calls.filter(([name]) => name === 'resize')).toHaveLength(0)
    expect(scale.supported.value).toBe(false)
  })

  it('coalesces rapid zoom changes while a native apply is pending', async () => {
    const fake = fakeDriver(null, { width: 2400, height: 1600 })
    const scale = createUiScale(fake.driver)
    await scale.install()
    let finish!: () => void
    const pending = new Promise<void>((done) => { finish = done })
    const apply = vi.spyOn(fake.driver, 'apply').mockImplementationOnce(async () => { await pending })
    scale.set(1.1)
    await flushPromises()
    scale.set(1.25)
    scale.set(1.5)
    scale.set(2)
    expect(apply.mock.calls).toEqual([[1.1]])
    finish()
    await flushPromises()
    expect(apply.mock.calls).toEqual([[1.1], [2]])
    expect(scale.applied.value).toBe(2)
    scale.uninstall()
  })

  it('restores the current zoom when a previous lifecycle apply completes late', async () => {
    const fake = fakeDriver(null, { width: 2400, height: 1600 })
    const scale = createUiScale(fake.driver)
    await scale.install()
    let finish!: () => void
    const pending = new Promise<void>((done) => { finish = done })
    const apply = vi.spyOn(fake.driver, 'apply').mockImplementationOnce(async () => { await pending })
    scale.set(1.5)
    await flushPromises()
    scale.uninstall()
    scale.set(1)
    const installing = scale.install()
    await flushPromises()
    finish()
    await installing
    expect(apply.mock.calls).toEqual([[1.5], [1]])
    expect(scale.applied.value).toBe(1)
    scale.uninstall()
  })

  it('drops pending size reads and resize timers on uninstall', async () => {
    vi.useFakeTimers()
    const fake = fakeDriver(null, { width: 2400, height: 1600 })
    const scale = createUiScale(fake.driver)
    await scale.install()
    let finish!: (size: Size | null) => void
    fake.driver.windowSize = () => new Promise((done) => { finish = done })
    scale.set(1.5)
    window.dispatchEvent(new Event('resize'))
    scale.uninstall()
    finish({ width: 2400, height: 1600 })
    await vi.advanceTimersByTimeAsync(500)
    expect(fake.applied).toEqual([])
    expect(vi.getTimerCount()).toBe(0)
  })

  it('reads a saved preference and ignores junk', () => {
    localStorage.setItem('billow.ui-scale', '1.25')
    expect(createUiScale(null).preference.value).toBe(1.25)
    localStorage.setItem('billow.ui-scale', '7')
    expect(createUiScale(null).preference.value).toBe('auto')
  })
})
