import { describe, expect, it, vi } from 'vitest'
import { createAppUpdater, type AppUpdate, type UpdateDriver } from './appUpdate'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

function setup() {
  const offer: AppUpdate = {
    version: '0.2.0', body: 'A new release', kind: 'desktop',
    download: vi.fn(async (progress) => {
      progress({ event: 'Started', data: { contentLength: 100 } })
      progress({ event: 'Progress', data: { chunkLength: 100 } })
    }),
    install: vi.fn(async () => {}), close: vi.fn(async () => {}),
  }
  const driver: UpdateDriver = {
    check: vi.fn(async () => offer), beforeInstall: vi.fn(async () => {}), restart: vi.fn(async () => {}),
  }
  return { offer, driver, update: createAppUpdater(driver) }
}

describe('application updates', () => {
  it('checks once without downloading or interrupting the connection', async () => {
    const { update, driver, offer } = setup()
    await Promise.all([update.check(true), update.check()])
    expect(driver.check).toHaveBeenCalledTimes(1)
    expect(update.status.value).toBe('available')
    expect(offer.download).not.toHaveBeenCalled()
    expect(driver.beforeInstall).not.toHaveBeenCalled()
    update.stop()
    expect(offer.close).toHaveBeenCalledTimes(1)
  })

  it('downloads before disconnecting, then installs and offers restart', async () => {
    const { update, driver, offer } = setup()
    await update.check()
    await Promise.all([update.install(), update.install()])
    expect(offer.download).toHaveBeenCalledTimes(1)
    expect(vi.mocked(offer.download).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(driver.beforeInstall).mock.invocationCallOrder[0]!)
    expect(vi.mocked(driver.beforeInstall).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(offer.install).mock.invocationCallOrder[0]!)
    expect(update.downloaded.value).toBe(100)
    expect(update.status.value).toBe('ready')
    expect(offer.close).toHaveBeenCalledTimes(1)
    expect(driver.restart).not.toHaveBeenCalled()
    await update.restart()
    expect(driver.restart).toHaveBeenCalledTimes(1)
  })

  it('does not install if download verification or proxy cleanup fails, and allows retry', async () => {
    const { update, driver, offer } = setup()
    await update.check()
    vi.mocked(offer.download).mockRejectedValueOnce(new Error('Invalid signature'))
    await update.install()
    expect(update.error.value).toContain('Invalid signature')
    expect(driver.beforeInstall).not.toHaveBeenCalled()
    expect(offer.install).not.toHaveBeenCalled()
    vi.mocked(driver.beforeInstall).mockRejectedValueOnce(new Error('Proxy still active'))
    await update.install()
    expect(offer.install).not.toHaveBeenCalled()
    await update.install()
    expect(update.status.value).toBe('ready')
  })

  it('keeps automatic failures quiet but reports manual check failures', async () => {
    const { update, driver } = setup()
    vi.mocked(driver.check).mockRejectedValue(new Error('Offline'))
    await update.check(true)
    expect(update.error.value).toBeNull()
    expect(update.status.value).toBe('idle')
    await update.check()
    expect(update.status.value).toBe('error')
    expect(update.error.value).toContain('Offline')
  })

  it('releases offers returned after stop', async () => {
    const { update, driver, offer } = setup()
    const pending = deferred<AppUpdate | null>()
    vi.mocked(driver.check).mockReturnValue(pending.promise)
    const checking = update.check()
    update.stop()
    pending.resolve(offer)
    await checking
    expect(update.offer.value).toBeNull()
    expect(offer.close).toHaveBeenCalledTimes(1)
  })

  it('does not install a download that finishes after stop', async () => {
    const { update, offer } = setup()
    await update.check()
    const pending = deferred<void>()
    vi.mocked(offer.download).mockReturnValue(pending.promise)
    const installing = update.install()
    update.stop()
    expect(offer.close).not.toHaveBeenCalled()
    pending.resolve()
    await installing
    expect(offer.install).not.toHaveBeenCalled()
    expect(offer.close).toHaveBeenCalledTimes(1)
  })

  it('opens Android downloads without disconnecting or restarting', async () => {
    const { update, offer, driver } = setup()
    offer.kind = 'android'
    await update.check()
    await update.install()
    expect(offer.install).toHaveBeenCalledTimes(1)
    expect(driver.beforeInstall).not.toHaveBeenCalled()
    expect(driver.restart).not.toHaveBeenCalled()
    expect(update.status.value).toBe('available')
    update.stop()
  })
})
