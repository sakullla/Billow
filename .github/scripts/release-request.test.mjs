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
    inputs: { tag: 'v0.1.16', platforms: 'macos,linux', appimage_compression: 'gzip', macos_runner: 'macos-15' } })
  assert.deepEqual(result.matrix.map(target => target.platform), ['macos', 'linux'])
  assert.equal(result.matrix[0].target, 'aarch64-apple-darwin')
  assert.equal(result.matrix[0].os, 'macos-15')
  assert.equal(result.matrix[1].appimageCompression, 'gzip')
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
