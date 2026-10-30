# Attack path analyser (web app)

A local web app on top of the analysis pipeline. Upload a CloudFormation
template, inspect findings and ranked attack paths, explore the graphs, try
fixes, download a PDF assessment, and optionally generate scenarios with the
fine-tuned model.

- `api/` - FastAPI backend.
- `web/` - React + Vite frontend.
- `model_space/` - the Hugging Face Space that serves the model.
- `scripts/` - the dev launcher and the deployment and cache scripts.
- `deploy/` - the container entrypoint, Cloud Run settings and seed scenarios
  (see [`DEPLOY.md`](DEPLOY.md)).

## Setup

Run everything from the repo root.

You need Python 3.12 and Node 22 or newer.

```bash
python3.12 -m venv app/.venv
app/.venv/bin/pip install -r app/api/requirements.txt -r app/api/requirements-test.txt
(cd app/web && npm ci)
```

The PDF report uses WeasyPrint, which needs Pango on the system. Without it the
app still runs and reports the PDF as unavailable.

```bash
# macOS
brew install pango

# Debian or Ubuntu
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0
```

## Run

```bash
app/scripts/dev
```

Open http://localhost:5173. The script starts the API on `127.0.0.1:8000` and
the Vite dev server on `5173` (which proxies `/api` to the API), prefixes each
line of output with `[api]` or `[web]`, and stops both on Ctrl-C. The API
reloads when Python or data files change.

To use other ports, set `API_PORT` and `WEB_PORT`. The script passes the API
address to Vite (`VITE_API_PROXY` in `web/vite.config.ts`), so the proxy follows.
`app/scripts/dev --help` prints the usage.

```bash
API_PORT=8095 WEB_PORT=5195 app/scripts/dev
```

The API only accepts browser POSTs from origins it lists (`cors_origins` in
`api/config.py`), and the Vite proxy forwards the page's origin. The script sets
`CAPSTONE_CORS_ORIGINS` (a JSON list) to `http://localhost:$WEB_PORT` and
`http://127.0.0.1:$WEB_PORT` unless you set it yourself. If you start the API
without the script on a non-default web port, set it the same way:
`CAPSTONE_CORS_ORIGINS='["http://localhost:5195"]'`.

Requests whose Host header is not `127.0.0.1`, `localhost` or `testserver` get
400, which stops a DNS rebinding page from reading a local server. Set
`CAPSTONE_ALLOWED_HOSTS` (a JSON list of names without ports) to add the public
name when the app is deployed. A POST whose Origin is neither listed nor the
app's own is refused with 403; requests with no Origin (curl) pass.

To serve the production build from the API alone:

```bash
(cd app/web && npm run build)
app/.venv/bin/uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

The API serves `app/web/dist` at `/` when it exists. Open http://127.0.0.1:8000.

Saved analyses and cached scenarios live in `app/.cache/` (gitignored).

## Tests

```bash
# Core pipeline and scenario generation
app/.venv/bin/python -m pytest -q tests scenario_generation/tests

# API
app/.venv/bin/python -m pytest -q app/api/tests

# Web: lint, types, unit tests (run from app/web)
cd app/web
npm run lint && npm run typecheck && npm test -- --run

# End-to-end (Playwright, run from app/web, starts its own servers)
npx playwright install chromium
npx playwright test
```

CI runs the same four checks (`.github/workflows/tests.yml`). The e2e job is not
required yet.

Notes on the e2e run:

- It starts four servers on ports 8040 to 8043, one per fake model mode, and a
  restart spec starts a fifth on 8049. Set `E2E_PORT` to move the whole range
  (it is the first port, default 8040).
- The servers run on `app/.venv/bin/python` if it exists, else `python3`. Set
  `E2E_PYTHON` to use another interpreter, as CI does.
- The first run builds the web app into `app/web/dist-e2e` (gitignored), so it is
  slower. Later runs rebuild only when the sources change.
- The visual tests compare screenshots recorded on macOS and are skipped on
  other platforms.

Some tests skip when an optional package is missing, and the default setup does
not install either package:

- 4 tests in `app/api/tests/test_model_space.py` need `gradio`.
- 1 test in `scenario_generation/tests/test_held_out_split.py` needs `datasets`.

CI does not install them either, so those tests skip there too.

`npm ci` may print `npm warn install-scripts ... fsevents`. It is harmless.

The API job also regenerates the OpenAPI document and compares it with the
committed snapshot, and the web job regenerates the TypeScript types from that
snapshot. After an API change that alters the schema:

```bash
app/.venv/bin/python -m app.scripts.export_openapi --output app/api/tests/fixtures/openapi.json
(cd app/web && npm run types)
```

## Configuration

Everything works without configuration, except live scenario generation. To
turn it on, put these in `app/api/.env` (gitignored) or the environment. Live
generation is on only when all of `SPACE_ID`, `HF_TOKEN`, `BASE_REVISION`,
`ADAPTER_REPO`, `ADAPTER_REVISION` and `LOADING_RECIPE` are valid. Otherwise
cached scenarios still show and `/api/health` says what is missing.

| Variable | Default | Meaning |
|---|---|---|
| `SPACE_ID` | unset | The model Space, `OWNER/NAME` |
| `HF_TOKEN` | unset | Hugging Face token with access to the Space. Never logged or returned. |
| `BASE_MODEL_ID` | `mistralai/Mistral-7B-Instruct-v0.3` | Base model. Must be this value. It is not gated. |
| `BASE_REVISION` | unset | Full 40-character commit SHA of the base model |
| `ADAPTER_REPO` | unset | The private adapter repo, `OWNER/NAME` |
| `ADAPTER_REVISION` | unset | Full 40-character commit SHA of the adapter repo |
| `LOADING_RECIPE` | unset | `nf4-dq-unmerged`, the evaluated recipe |
| `SCENARIO_PROMPT_FORMAT` | `structured-p1` | Prompt format for new generations: `structured-p1` or `training`. See "Verifying the live model". |

Example, with placeholders:

```
SPACE_ID=your-name/capstone-scenario-model
HF_TOKEN=hf_xxxxxxxxxxxxxxxx
BASE_REVISION=<40-character SHA>
ADAPTER_REPO=your-name/capstone-adapter
ADAPTER_REVISION=<40-character SHA>
LOADING_RECIPE=nf4-dq-unmerged
```

Other settings (limits, timeouts, cache location) use a `CAPSTONE_` prefix, for
example `CAPSTONE_CACHE_DIR`. See `api/config.py`.

## Going live with the model

You need a Hugging Face account. Log in with `hf auth login` or set `HF_TOKEN`.
Run `--help` on each script for all flags, and use `--dry-run` first.

1. Upload the adapter to a private model repo. It prints the commit SHA.

   ```bash
   app/.venv/bin/python -m app.scripts.upload_adapter --repo-id your-name/capstone-adapter
   ```

2. Deploy the private Space with pinned revisions. Get the base model SHA from
   the model page on Hugging Face.

   ```bash
   app/.venv/bin/python -m app.scripts.deploy_model_space \
     --space-id your-name/capstone-scenario-model \
     --adapter-repo your-name/capstone-adapter \
     --base-revision <base model SHA> \
     --adapter-revision <adapter SHA from step 1>
   ```

3. In the Space settings, choose ZeroGPU hardware, and add a secret `HF_TOKEN`
   (a token that can read the adapter repo). The base model needs no licence
   acceptance.

4. Fill in `app/api/.env` as above and restart `app/scripts/dev`.

More in [`model_space/README.md`](model_space/README.md). To put the whole app
online (the model, then the web app on Cloud Run), follow
[`DEPLOY.md`](DEPLOY.md).

## Verifying the live model

The app can send the model one of two prompts. `structured-p1` (the default) is the team's
structured prompt: five facts lines, the OBJECTIVE and a PROMPT FOCUS block. `training` is
the exact text the adapter was trained on: the same system instruction and five facts lines,
with no OBJECTIVE and no PROMPT FOCUS. Neither has been evaluated through the app yet, so
check them on the deployed Space before choosing.

After deploying, run the check. It needs a Hugging Face token from `HF_TOKEN` or
`hf auth login`, which it never prints. Each generation spends ZeroGPU quota. The default run
makes 5 calls: two sample paths (AP-001 and AP-019) in both formats, plus one control, the
held-out record C0027 in the training format.

```bash
app/.venv/bin/python -m app.scripts.check_live_model \
  --space-id your-name/capstone-scenario-model \
  --adapter-repo your-name/capstone-adapter \
  --adapter-revision <adapter SHA> \
  --base-revision <base model SHA>
```

`--base-revision` defaults to `c170c708c41dac9275d15a8fff4eca08d52bab71`, the main of
`mistralai/Mistral-7B-Instruct-v0.3` before training. Use `--paths AP-003 AP-010` to pick other
sample paths from `scenario_generation/evaluation/inputs/attack_paths.json`.

The script first reads `/metadata` and stops, without spending quota, if the Space does not
carry the revisions you gave. It then prints one row per generation: format, path, prompt
tokens, new tokens, finish reason, seconds, missing sections, whether the model wrote text
before the first header, and the first 300 characters. The full outputs go to a JSON file
under `app/.cache/live_check/` (change it with `--output`).

Compare the formats. Good signs are finish reason `eos`, no missing sections, no preamble and
a narrative that follows the path. The control shows what the adapter does in the format it
knows best. If it is good and `structured-p1` is not, the extra OBJECTIVE and PROMPT FOCUS
lines are hurting, and `training` is the better choice. Then set the winner in
`app/api/.env` and restart:

```
SCENARIO_PROMPT_FORMAT=training
```

Results already saved keep the format they were made with. Each scenario shows its prompt
version in its footer, and the cache key includes it, so switching hides nothing. A path
that already has a saved scenario keeps showing it; the new format applies to paths without
one. Pass `--import` to the check to store the valid results in the app cache, so a path with
the same prompt shows them without another generation. For Kaggle pre-generation, give
`export_records` the same format with `--prompt-format`.

## Troubleshooting

- `npm ci` or `npx playwright install` fails with `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`
  or `unable to get local issuer certificate`: Node does not trust the
  certificate it was given. This happens behind a TLS-intercepting proxy, or
  when Node cannot see the system CA store. Run the command with
  `NODE_EXTRA_CA_CERTS=/etc/ssl/cert.pem` (macOS; use your system bundle
  elsewhere). A warm npm cache can hide the problem until something is
  downloaded.
- `app/scripts/dev` says a port is in use: stop whatever holds 8000 or 5173
  (`lsof -nP -iTCP:8000 -sTCP:LISTEN`), or pick other ports with `API_PORT` and
  `WEB_PORT`.
- The health response says WeasyPrint cannot load its libraries: install Pango
  as shown in Setup.
