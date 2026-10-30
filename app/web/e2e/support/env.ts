/**
 * Where the e2e servers live. Shared by playwright.config.ts and the specs,
 * so both sides agree on ports, the web build and the analysis store.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** app/web */
export const WEB_DIR = path.resolve(import.meta.dirname, '../..')
export const REPO_ROOT = path.resolve(WEB_DIR, '../..')

/** The production build the fake servers serve; separate from dist so `npm run build` cannot race it. */
export const DIST_DIR = path.join(WEB_DIR, 'dist-e2e')

/** One fake model server per mode the suite needs, on consecutive ports from E2E_PORT. */
export const SERVER_MODES = ['ok', 'truncated', 'error', 'off'] as const
export type ServerMode = (typeof SERVER_MODES)[number]

const BASE_PORT = Number(process.env.E2E_PORT ?? '8040')

export function portFor(mode: ServerMode): number {
  return BASE_PORT + SERVER_MODES.indexOf(mode)
}

/** A second "ok" server started by a spec over the same store, to prove saved analyses survive a restart. */
export const RESTART_PORT = BASE_PORT + 9

export function baseUrl(port: number): string {
  return `http://127.0.0.1:${String(port)}`
}

/** The analysis and scenario store of the server on `port`; wiped when the suite starts that server. */
export function cacheDirFor(port: number): string {
  return path.join(os.tmpdir(), 'capstone-e2e', String(port))
}

const VENV_PYTHON = path.join(REPO_ROOT, 'app', '.venv', 'bin', 'python')

/** E2E_PYTHON, else the app venv, else python3 on PATH (CI installs the API there). */
export const PYTHON =
  process.env.E2E_PYTHON ?? (fs.existsSync(VENV_PYTHON) ? VENV_PYTHON : 'python3')

export const FAKE_SERVER_SCRIPT = path.join(WEB_DIR, 'e2e', 'fake_model_server.py')

/** Seconds the fake Space takes per generation, per mode: long enough to see "running" in ok. */
export const GENERATION_DELAY_S: Record<ServerMode, number> = {
  ok: 4,
  truncated: 1,
  error: 1,
  off: 1,
}

/** Environment for one fake model server, as e2e/serve.mjs and the restart spec start it. */
export function serverEnv(mode: ServerMode, port: number): Record<string, string> {
  return {
    FAKE_SCENARIO_MODE: mode,
    FAKE_SCENARIO_HOST: '127.0.0.1',
    FAKE_SCENARIO_PORT: String(port),
    FAKE_SCENARIO_DELAY_S: String(GENERATION_DELAY_S[mode]),
    FAKE_SCENARIO_CACHE_DIR: cacheDirFor(port),
    FAKE_WEB_DIST_DIR: DIST_DIR,
    E2E_PYTHON: PYTHON,
  }
}
