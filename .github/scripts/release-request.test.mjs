import { test } from 'node:test'
import assert from 'node:assert/strict'
import request from './release-request.cjs'
const { releaseRequest } = request

test('matching version tag builds every supported installer', () => {
  const result = releaseRequest({ eventName: 'push', ref: 'refs/tags/v0.1.16', version: '0.1.16' })
  assert.equal(result.tag, 'v0.1.16')
  assert.deepEqual(result.matrix.map(target => target.platform), ['windows', 'macos', 'linux', 'android'])
})

test('recovery selects only failed platforms without changing the target version', () => {
  const result = releaseRequest({ eventName: 'workflow_dispatch', ref: 'refs/heads/main', version: '0.1.16',
    inputs: { tag: 'v0.1.16', platforms: 'macos,linux', appimage_compression: 'zstd', macos_runner: 'macos-15' } })
  assert.deepEqual(result.matrix.map(target => target.platform), ['macos', 'linux'])
  assert.equal(result.matrix[0].target, 'aarch64-apple-darwin')
  assert.equal(result.matrix[0].os, 'macos-15')
  assert.equal(result.matrix[1].appimageCompression, 'zstd')
})

test('release and recovery reject mismatched versions, untrusted events, and arbitrary runners', () => {
  const valid = { eventName: 'workflow_dispatch', ref: 'refs/heads/main', version: '0.1.16', inputs: { tag: 'v0.1.16' } }
  for (const change of [
    { eventName: 'pull_request' }, { version: '0.1.16-beta' },
    { eventName: 'push' }, { inputs: { tag: 'main' } }, { inputs: { tag: 'v0.1.15' } },
    { inputs: { tag: 'v0.1.16', platforms: 'other' } },
    { inputs: { tag: 'v0.1.16', macos_runner: 'self-hosted' } },
    { inputs: { tag: 'v0.1.16', appimage_compression: 'unknown' } },
  ]) assert.throws(() => releaseRequest({ ...valid, ...change }))
})

test('prebuilt recovery is explicit, checksummed, and limited to macOS', () => {
  const inputs = { tag: 'v0.1.16', platforms: 'macos,linux', macos_manifest_sha256: 'a'.repeat(64) }
  const options = { eventName: 'workflow_dispatch', ref: 'refs/heads/main', version: '0.1.16', inputs }
  const result = releaseRequest(options)
  assert.equal(result.matrix[0].prebuiltMacos, true)
  assert.equal(result.matrix[0].os, 'ubuntu-22.04')
  assert.equal(result.matrix[1].prebuiltMacos, false)
  assert.throws(() => releaseRequest({ ...options, eventName: 'push', ref: 'refs/tags/v0.1.16' }))
  assert.throws(() => releaseRequest({ ...options, inputs: { ...inputs, macos_manifest_sha256: 'bad' } }))
  assert.throws(() => releaseRequest({ ...options, inputs: { ...inputs, platforms: 'linux' } }))
})

test('rejects compressors absent from the distributed AppImage tool', () => {
  for (const appimage_compression of ['gzip', 'xz']) {
    assert.throws(() => releaseRequest({ eventName: 'workflow_dispatch', version: '0.1.16',
      inputs: { tag: 'v0.1.16', platforms: 'linux', appimage_compression } }), /compression/)
  }
})
