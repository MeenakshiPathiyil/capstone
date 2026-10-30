import { defineConfig, devices } from '@playwright/test'

import { baseUrl, portFor, SERVER_MODES, serverEnv, type ServerMode } from './e2e/support/env'

const CI = Boolean(process.env.CI)

/**
 * The browser suite runs the production web build against the real API, with
 * only the model Space faked (e2e/fake_model_server.py). The fake's mode is
 * fixed per process, so each mode the specs need gets its own server and
 * project. Ports start at E2E_PORT (default 8040).
 */
function scenarioProject(mode: Exclude<ServerMode, 'ok'>) {
  return {
    name: `scenario-${mode}`,
    testMatch: /scenario-modes\.spec\.ts/,
    grep: new RegExp(`@${mode}\\b`),
    use: { baseURL: baseUrl(portFor(mode)) },
  }
}

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
    toHaveScreenshot: {
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
      // Tolerates sub-pixel font rasterisation; a moved or missing element is far more.
      maxDiffPixelRatio: 0.01,
    },
  },
  forbidOnly: CI,
  retries: CI ? 1 : 0,
  reporter: CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'light',
    permissions: ['clipboard-read', 'clipboard-write'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'app',
      testIgnore: /scenario-modes\.spec\.ts/,
      // One analysis slot on the server: a second upload while one runs gets 503 by design.
      workers: 1,
      use: { baseURL: baseUrl(portFor('ok')) },
    },
    scenarioProject('truncated'),
    scenarioProject('error'),
    scenarioProject('off'),
  ],
  // Started one after another, so only the first one builds the web app.
  webServer: SERVER_MODES.map((mode) => ({
    name: `fake-${mode}`,
    command: 'node e2e/serve.mjs',
    url: `${baseUrl(portFor(mode))}/`,
    env: serverEnv(mode, portFor(mode)),
    reuseExistingServer: !CI,
    timeout: 180_000,
    stdout: 'ignore' as const,
    stderr: 'pipe' as const,
    gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 5_000 },
  })),
})
