import { prepareGeo } from './prepare_geo.mjs'
import { fileURLToPath } from 'node:url'

await prepareGeo(fileURLToPath(new URL('../src-tauri/gen/android/app/src/main/assets/billow-geo', import.meta.url)))
