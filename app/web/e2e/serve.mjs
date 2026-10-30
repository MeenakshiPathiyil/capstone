// One fake model server for the Playwright suite (playwright.config.ts starts
// one per mode). Builds the web app into FAKE_WEB_DIST_DIR when the sources
// are newer than the last build, empties the server's analysis store, then
// runs e2e/fake_model_server.py in the foreground until Playwright stops it.
//
// Every setting comes from the environment playwright.config.ts passes in
// (see e2e/support/env.ts): FAKE_SCENARIO_*, FAKE_WEB_DIST_DIR, E2E_PYTHON.

import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'

const webDir = path.resolve(import.meta.dirname, '..')
const distDir = required('FAKE_WEB_DIST_DIR')
const cacheDir = required('FAKE_SCENARIO_CACHE_DIR')
const python = required('E2E_PYTHON')
const stampFile = path.join(distDir, '.e2e-build-stamp')

/** Everything a production build depends on. */
const BUILD_INPUTS = [
  'src',
  'public',
  'index.html',
  'vite.config.ts',
  'tsconfig.app.json',
  'package-lock.json',
]

function required(name) {
  const value = process.env[name]
  if (!value) {
    console.error(`e2e/serve.mjs: ${name} is not set; run the suite through playwright.config.ts.`)
    process.exit(2)
  }
  return value
}

/** Newest modification time under the build inputs, in ms. */
function newestInput() {
  let newest = 0
  const visit = (file) => {
    const stat = fs.statSync(file, { throwIfNoEntry: false })
    if (!stat) return
    newest = Math.max(newest, stat.mtimeMs)
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(file)) visit(path.join(file, entry))
    }
  }
  for (const input of BUILD_INPUTS) visit(path.join(webDir, input))
  return newest
}

async function buildIfStale() {
  // Taken before building: an edit made while vite runs still counts as newer next time.
  const inputs = newestInput()
  const built = fs.existsSync(path.join(distDir, 'index.html')) && fs.existsSync(stampFile)
  if (built && Number(fs.readFileSync(stampFile, 'utf8')) >= inputs) {
    console.log(`e2e/serve.mjs: web build in ${distDir} is up to date`)
    return
  }
  console.log(`e2e/serve.mjs: building the web app into ${distDir}`)
  const { build } = await import('vite')
  await build({
    root: webDir,
    configFile: path.join(webDir, 'vite.config.ts'),
    logLevel: 'warn',
    build: { outDir: distDir, emptyOutDir: true },
  })
  fs.writeFileSync(stampFile, String(inputs))
}

await buildIfStale()

fs.rmSync(cacheDir, { recursive: true, force: true })
fs.mkdirSync(cacheDir, { recursive: true })

const server = spawn(python, [path.join(webDir, 'e2e', 'fake_model_server.py')], {
  cwd: path.resolve(webDir, '..', '..'),
  env: process.env,
  stdio: 'inherit',
})

// Playwright signals the whole process group; pass it on in case it only reaches us.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.kill(signal))
}

server.on('exit', (code, signal) => {
  process.exit(code ?? (signal ? 1 : 0))
})
