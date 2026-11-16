import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import verification from './prebuilt-macos.cjs'
const { verifyMacosManifest } = verification
const base = { version: '0.1.16', sourceCommit: 'commit', architecture: 'aarch64',
  nativeChecks: { sourceClean: true, codesign: true, offlineKernel: true },
  files: { 'Billow_0.1.16_aarch64.app.tar.gz': 'a'.repeat(64), 'Billow_0.1.16_aarch64.dmg': 'b'.repeat(64) } }
function check(value, override = {}) {
  const bytes = Buffer.from(JSON.stringify(value))
  return verifyMacosManifest(bytes, { expectedHash: createHash('sha256').update(bytes).digest('hex'), version: '0.1.16', commit: 'commit', ...override })
}
test('native-validated macOS recovery binds exact source, architecture and artifact names', () => {
  assert.equal(check(base).length, 2)
  assert.throws(() => check(base, { expectedHash: '0'.repeat(64) }), /checksum/)
  for (const patch of [{ sourceCommit: 'other' }, { version: '0.1.15' }, { architecture: 'x86_64' },
    { nativeChecks: { codesign: true } }, { nativeChecks: { sourceClean: true, codesign: 'true', offlineKernel: true } }, { files: { '../other': 'a'.repeat(64) } }]) {
    assert.throws(() => check({ ...base, ...patch }))
  }
})
