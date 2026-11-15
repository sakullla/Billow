import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createManifest } from './release-manifest.mjs'

function fixture() {
  const names = ['Billow_0.1.0_x64-setup.exe', 'Billow_0.1.0_aarch64.dmg',
    'Billow_0.1.0_aarch64.app.tar.gz', 'Billow_0.1.0_amd64.AppImage',
    'Billow_0.1.0_amd64.deb', 'Billow_0.1.0_arm64.apk']
  const signed = names.filter((name) => !/\.(dmg|apk)$/.test(name))
  const assets = [...names, ...signed.map((name) => `${name}.sig`)].map((name) => ({
    name, size: 100, browser_download_url: `https://github.com/sakullla/Billow/releases/download/v0.1.0/${name}`,
  }))
  return {
    release: { draft: true, tag_name: 'v0.1.0', assets, body: 'Notes' },
    signatures: Object.fromEntries(signed.map((name) => [`${name}.sig`, 'c2lnbmF0dXJl'])),
  }
}

test('all installer types map to their matching updater packages', () => {
  const { release, signatures } = fixture()
  const result = createManifest(release, signatures, 'sakullla/Billow', '0.1.0')
  assert.equal(Object.keys(result.platforms).length, 7)
  assert.match(result.platforms['linux-x86_64-deb'].url, /\.deb$/)
  assert.match(result.platforms['darwin-aarch64'].url, /\.app\.tar\.gz$/)
})

for (const mutation of [
  (release) => { release.assets = release.assets.filter((a) => !a.name.endsWith('.apk')) },
  (release) => { release.assets = release.assets.filter((a) => !a.name.endsWith('.exe.sig')) },
  (release) => { release.assets[0].browser_download_url = 'https://example.com/app.exe' },
  (release) => { release.assets[0].size = 0 },
  (release) => { release.draft = false },
  (release) => { release.assets.push(release.assets[0]) },
]) {
  test(`incomplete or invalid release is rejected: ${mutation}`, () => {
    const { release, signatures } = fixture()
    mutation(release)
    assert.throws(() => createManifest(release, signatures, 'sakullla/Billow', '0.1.0'))
  })
}
