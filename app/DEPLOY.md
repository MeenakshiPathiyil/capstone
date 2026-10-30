# Deploying the app

This guide takes the app from your laptop to a public URL, with the fine-tuned
model behind it. It is written to be followed top to bottom once, and the last
part covers updates and day-to-day running.

Commands run from the repo root unless a step says otherwise.

## What gets deployed where

```
Browser
  │ https
  ▼
Google Cloud Run: one container (Dockerfile at the repo root)
  - the React build, served at /
  - the FastAPI backend at /api
  - the analysis pipeline and the PDF renderer, in-process
  │ gradio_client, with your Hugging Face token from Secret Manager
  ▼
Hugging Face Space, private, ZeroGPU (app/model_space/)
  - Mistral-7B-Instruct-v0.3, 4-bit NF4, with the LoRA adapter unmerged
  │ reads
  ▼
Hugging Face model repo, private: the LoRA adapter
```

The frontend and backend are one service on one origin, so there is no CORS
setup and no second deployment. The model is separate because it needs a GPU.

### Why these hosts

| Need | Host | Why |
|---|---|---|
| GPU for the model | Hugging Face ZeroGPU Space | Free for personal accounts, up to 2 Spaces. Docker and CPU Spaces now need a paid plan, so the web app cannot live on Hugging Face for free. |
| The web app | Google Cloud Run | Free tier of 180,000 vCPU-seconds, 360,000 GiB-seconds and 2 million requests a month, which is about 50 hours of active use. 1 vCPU and 1 GiB, scales to zero, builds from source without Docker on your machine. Needs a billing account with a card. |
| The HF token for the backend | Google Secret Manager | Stays out of the image, the repo and the env file. Free at this size. |
| Pre-generating scenarios | Kaggle notebook (optional) | Free T4 GPU, about 30 hours a week. |

If you cannot add a card to Google Cloud, the same Dockerfile runs on Render's
free web service. See "Without a card" at the end. It is slower (512 MB and a
fraction of a CPU) and has not been tested.

### What the free tiers mean in practice

- **GPU quota is the real limit.** A free Hugging Face account gets 5 minutes of
  ZeroGPU time a day, and every live generation from the deployed app spends
  your quota, because the backend calls the Space with your token. One
  scenario takes roughly 1 to 2 minutes of GPU time (measure it in step 1.6),
  so expect about 3 live scenarios a day for the whole site. The quota resets
  24 hours after its first use that day. PRO ($9 a month) raises it to 40
  minutes.
- **That is why scenarios are pre-generated.** Part 2 fills the image with
  scenarios for the bundled samples, so visitors see them instantly and the
  quota is kept for new uploads.
- **Saved analyses do not survive a restart.** Cloud Run keeps files in memory
  and replaces the container after about 15 idle minutes. A link to an analysis
  stops working after that; uploading the template again recreates it. Seeded
  scenarios are copied back in on every start.
- **The first request after idle takes a few seconds** while the container
  starts. The model Space sleeps after 48 idle hours; the backend restarts it
  on the next generation, which then waits a few minutes. Open the Space page
  before a demo to wake it.

## Before you start

- [ ] A Hugging Face account with a verified email, older than 30 days (the
      ZeroGPU rule for free accounts). This guide uses the `nisschay` account.
- [ ] A personal Google account where you can create a Cloud project and add a
      card. Not a work account: there the project lands in your employer's
      organisation, under its billing and policies, and those policies often
      block public services.
- [ ] Optional: a Kaggle account with phone verification (needed for GPUs).
- [ ] The local setup from `app/README.md` works: `app/scripts/dev` runs and the
      tests pass.
- [ ] The team has agreed to a public deployment. The adapter repo and the
      Space stay private either way, but the scenarios the model writes become
      public through the app.

Tokens and keys never go into chat, the repo or a file in the repo. You type
them into the Hugging Face login prompt, the Space settings page, the Kaggle
secrets panel and the `gcloud secrets` command below, and nowhere else.

## Part 1: the model on Hugging Face

### 1.1 Log in

```bash
app/.venv/bin/hf auth login
```

Create the token at https://huggingface.co/settings/tokens as a **Write**
token (the scripts create repos and upload). It is saved under
`~/.cache/huggingface/`, and the scripts read it from there. You can delete it
after part 1.

### 1.2 Upload the adapter

The adapter weights are `scenario_generation/fine_tuning/output/adapter_model.safetensors`
(gitignored, about 27 MB). Check first, then upload:

```bash
app/.venv/bin/python -m app.scripts.upload_adapter --repo-id nisschay/capstone-adapter --dry-run
app/.venv/bin/python -m app.scripts.upload_adapter --repo-id nisschay/capstone-adapter
```

The repo is created private. The script prints a 40-character commit SHA. Write
it down: it is `ADAPTER_REVISION` from here on.

### 1.3 Deploy the Space

```bash
app/.venv/bin/python -m app.scripts.deploy_model_space \
  --space-id nisschay/capstone-scenario-model \
  --adapter-repo nisschay/capstone-adapter \
  --base-revision c170c708c41dac9275d15a8fff4eca08d52bab71 \
  --adapter-revision <ADAPTER_REVISION> \
  --dry-run
```

Read what it would do, then run it again without `--dry-run`. The base revision
above is the commit of `mistralai/Mistral-7B-Instruct-v0.3` the adapter was
trained against; keep it.

### 1.4 Hardware and secret, in the Space settings

Open https://huggingface.co/spaces/nisschay/capstone-scenario-model/settings.

1. **Hardware:** choose ZeroGPU. Without it the Space has no GPU.
2. **Secret `HF_TOKEN`:** create a fine-grained token that can only read the
   adapter repo (Repositories permissions: `nisschay/capstone-adapter`, Read)
   and add it under Variables and secrets as a secret named `HF_TOKEN`.

The deploy script already set the variables `BASE_REVISION`, `ADAPTER_REPO`,
`ADAPTER_REVISION` and `LOADING_RECIPE`. Do not edit them by hand; rerun the
script instead.

### 1.5 Wait for it to start

The Space builds, downloads the base model (about 15 GB) and loads it. The
first start can take 10 to 20 minutes. Watch the Logs tab until the status is
Running.

If it fails, the logs say why. The one risk known in advance is bitsandbytes
4-bit loading on ZeroGPU's Blackwell GPUs, which nobody has tried with this
recipe. If the logs show a bitsandbytes or CUDA kernel error, stop here: the
fix is a code change (a different loading recipe), not a setting.

### 1.6 Check the live model and pick the prompt format

```bash
app/.venv/bin/python -m app.scripts.check_live_model \
  --space-id nisschay/capstone-scenario-model \
  --adapter-repo nisschay/capstone-adapter \
  --adapter-revision <ADAPTER_REVISION> \
  --paths AP-001
```

With one path this makes 3 generations (both formats plus a control), which
fits in a free day's quota. The default (two paths, 5 generations) may not.
It reads `/metadata` first and spends nothing if the Space carries other
revisions.

Read the table it prints, as described in `app/README.md` under "Verifying the
live model". Note two numbers for later: the seconds per generation (your GPU
cost per scenario) and which format gave the better output. Expect some
outputs to stop before the `[ATTACK GRAPH]` section: training cut examples at
1024 tokens, so the adapter often never learned to write it. The app shows
that honestly.

### 1.7 Pin what the Space actually runs

`app/model_space/requirements.txt` has versions marked "CONFIRM AT
DEPLOYMENT". The check above saves the Space's `/metadata` in its output JSON
(under `app/.cache/live_check/`). Copy the library versions it reports into the
requirements file and redeploy with step 1.3, so a rebuild cannot drift.

## Part 2: pre-generate scenarios for the samples

Do this once per adapter revision and prompt format. Either way ends with
cache entries in `app/.cache/scenarios/`, which you copy into the image.

**With the deployed Space, a few a day.** Put the model settings in
`app/api/.env` (see `app/README.md`, Configuration), start `app/scripts/dev`,
open each sample, and press Generate on its top paths. Each one spends quota.

**With Kaggle, all at once.** Analyse a sample locally, then:

```bash
app/.venv/bin/python -m app.scripts.export_records \
  --analysis-id <analysis id from the URL> \
  --out /tmp/capstone-bundle \
  --prompt-format <the format you chose in 1.6> \
  --base-revision c170c708c41dac9275d15a8fff4eca08d52bab71 \
  --adapter-repo nisschay/capstone-adapter \
  --adapter-revision <ADAPTER_REVISION>
```

Upload `/tmp/capstone-bundle` as a private Kaggle dataset, open
`app/scripts/pregenerate_kaggle.ipynb` on Kaggle, add the dataset, add a Kaggle
secret `HF_TOKEN` (read access to the adapter repo), pick a T4 GPU and run all.
Download `scenarios.jsonl` and import it:

```bash
app/.venv/bin/python -m app.scripts.import_scenarios ~/Downloads/scenarios.jsonl
```

Then, either way:

```bash
cp app/.cache/scenarios/*.json app/deploy/scenarios/
```

Entries only show when their revisions, recipe and prompt match the deployed
settings, so stale ones are ignored, not shown wrongly.

## Part 3: the web app on Google Cloud Run

### 3.1 Install and log in

```bash
brew install --cask gcloud-cli
echo 'export PATH=/opt/homebrew/share/google-cloud-sdk/bin:"$PATH"' >> ~/.zshrc
exec zsh
gcloud auth login
```

`gcloud-cli` is already installed on this Mac; only the PATH line and the
login are left.

### 3.2 Create the project and turn on billing

```bash
gcloud projects create capstone-attack-paths-<something unique> --name "Capstone"
gcloud config set project capstone-attack-paths-<something unique>
gcloud config set run/region us-central1
```

Link a billing account at https://console.cloud.google.com/billing (Billing ->
Link a billing account). Then set a budget so a surprise cannot get expensive:
Billing -> Budgets and alerts -> Create budget, amount $1, alerts at 50%, 90%
and 100%. The deploy below caps the service at one instance, which keeps a
normal month inside the free tier.

`us-central1` is a tier 1 region with the full free tier. Pick another tier 1
region if you prefer (`us-east1`, `us-west1`, `europe-west1`, `europe-north1`,
`asia-northeast1`), and use it everywhere below.

### 3.3 Turn on the services

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com
```

### 3.4 Store the backend's Hugging Face token

The backend needs its own token to call the private Space, restart it when it
sleeps, and read the remaining GPU quota. Create a fine-grained token at
https://huggingface.co/settings/tokens with:

- Repositories permissions: `nisschay/capstone-scenario-model`, Read and Write
  (write is what allows the restart).
- User permissions: billing read, if offered (for the quota shown in the app).
  Without it the app still works and shows the quota as unknown.

Store it in Secret Manager. The first line reads it without echoing it, so it
never lands in your shell history:

```bash
read -rs HF_APP_TOKEN
printf '%s' "$HF_APP_TOKEN" | gcloud secrets create capstone-hf-token \
  --replication-policy automatic --data-file=-
unset HF_APP_TOKEN
```

Let the Cloud Run runtime read it:

```bash
PROJECT_NUMBER=$(gcloud projects describe "$(gcloud config get-value project)" --format 'value(projectNumber)')
gcloud secrets add-iam-policy-binding capstone-hf-token \
  --member "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role roles/secretmanager.secretAccessor
```

### 3.5 Fill in the settings

Edit `app/deploy/cloudrun.env.yaml`:

```yaml
SPACE_ID: "nisschay/capstone-scenario-model"
ADAPTER_REPO: "nisschay/capstone-adapter"
ADAPTER_REVISION: "<ADAPTER_REVISION>"
SCENARIO_PROMPT_FORMAT: "<the format you chose in 1.6>"
```

Leave the rest as it is. The file holds no secrets.

### 3.6 Deploy

```bash
app/deploy/cloudrun_deploy.sh
```

The first run asks to create an Artifact Registry repository; answer yes. It
uploads the checkout (minus what `.gcloudignore` leaves out: secrets, virtual
environments, node_modules, weights), builds the image with Cloud Build, and
deploys it. The build takes about 5 minutes. The last line is the URL.

To deploy before the model is ready, set `SPACE_ID` to `""` and run
`WITH_MODEL=0 app/deploy/cloudrun_deploy.sh`. Everything except live
generation works.

What the script sets, and why:

| Setting | Value | Why |
|---|---|---|
| `--max-instances` | 1 | The analysis slot, scenario queue and saved analyses live in one process's memory. Also caps cost. |
| `--min-instances` | 0 | Scales to zero when idle, so idle time is free. |
| `--cpu`, `--memory` | 1, 1Gi | The pipeline is light; the PDF renderer is the largest user. |
| `--execution-environment` | gen2 | Full Linux, for the analysis worker processes. |
| `--timeout` | 300 | Covers the 120 s PDF limit with room to spare. |
| `ANALYSER_COMMIT` | your current commit | Printed in the PDF footer; the image has no git history. |
| `HF_TOKEN` | from Secret Manager | Mounted as an environment variable at start, never in the image. |

### 3.7 Check it

```bash
URL=$(gcloud run services describe capstone --format 'value(status.url)')
curl -s "$URL/api/health" | python3 -m json.tool
```

The health response should show the PDF renderer available, and, with the
model configured, the Space stage and the remaining quota. Then in a browser:

1. Open the URL, analyse the sample, and check the counts match local runs.
2. Open AP-001 and check the scenario shows (seeded in part 2) without a wait.
3. Download the PDF report.
4. Generate one scenario on a path without one, if the quota allows.
5. Upload a broken YAML file and check the error is readable.

## Part 4: running it

### Updating

Commit, then rerun `app/deploy/cloudrun_deploy.sh`. Each deploy is a new
revision; traffic moves when it is healthy. To go back:

```bash
gcloud run revisions list --service capstone
gcloud run services update-traffic capstone --to-revisions <REVISION>=100
```

A model change (new adapter, new Space code) is part 1 again: upload, deploy
the Space, update `ADAPTER_REVISION` in `cloudrun.env.yaml`, regenerate seed
scenarios, redeploy the app.

### Logs

```bash
gcloud run services logs read capstone --limit 100
```

The Space's logs are on its page on Hugging Face (Logs tab).

### Limits that protect the quota and the instance

The deployed app turns on per-visitor limits (`CAPSTONE_RATE_LIMITS_ENABLED`).
A visitor over one sees the reason and when to try again; nothing retries on
its own. Only real work counts: a cached scenario, a repeat PDF download or a
refused upload costs nothing.

| Limit | Variable | Default |
|---|---|---|
| New analyses and fix-impact runs | `CAPSTONE_RATE_LIMIT_ANALYSES` | 20 per 10 minutes |
| PDF renders | `CAPSTONE_RATE_LIMIT_REPORTS` | 10 per 10 minutes |
| Live scenario generations | `CAPSTONE_RATE_LIMIT_SCENARIOS` | 4 per hour |

Each value is `[requests, seconds]` as JSON, for example
`CAPSTONE_RATE_LIMIT_SCENARIOS: "[2, 3600]"` in `cloudrun.env.yaml`. The
overview computes fix impact on its own, so a new analysis uses 2 of the 20.

Visitors are told apart by the address Cloud Run's front end appends to
`X-Forwarded-For` (`CAPSTONE_TRUSTED_PROXY_HOPS: "1"`). If you ever put a Google
load balancer in front of the service, it adds an entry of its own: set it to
`"2"`.

On top of the limits, the backend checks the remaining GPU quota before each
live generation and says when it resets instead of failing halfway.

### What visitors' uploads mean

Uploaded templates are kept in the container's memory until it restarts, and
nowhere else. Templates can contain secrets in parameter defaults, so treat
the public app as a demo: say so wherever you share the link.

### Costs to watch

- Cloud Run: inside the free tier for demo traffic; the $1 budget alert tells
  you otherwise.
- Artifact Registry: each deploy stores an image of a few hundred MB. Storage
  past 0.5 GB is billed at cents a month; delete old images in the console
  (Artifact Registry -> cloud-run-source-deploy) now and then.
- Hugging Face: nothing on a free account; the quota simply runs out for the
  day.

### Taking it down

```bash
gcloud run services delete capstone
```

Pause the Space in its settings. Deleting the project removes everything on
the Google side.

## Troubleshooting

- **The deploy fails with a permission error from Cloud Build** (often
  `storage.objects.get` or `artifactregistry` denied). New projects sometimes
  do not give the build account the roles a source deploy needs. Grant them
  and deploy again:

  ```bash
  gcloud projects add-iam-policy-binding "$(gcloud config get-value project)" \
    --member "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role roles/run.builder
  ```

- **The deploy says the secret cannot be accessed.** Step 3.4's
  `add-iam-policy-binding` was skipped or used another project number.
- **Every page answers "Invalid host header".** The Host is not in
  `CAPSTONE_ALLOWED_HOSTS`. With a custom domain, add it to the list in
  `cloudrun.env.yaml` and redeploy.
- **The health response says the Space is not configured.** One of the
  settings in 3.5 is empty or `WITH_MODEL=0` was used; the message names which.
- **Generation fails with a quota message.** The day's GPU time is used up.
  The message says when it resets.
- **Generation waits a long time, then works.** The Space was asleep and the
  backend restarted it. Open the Space page before a demo.
- **The Space shows "Runtime error" after a rebuild.** Read its logs. A version
  drift in `app/model_space/requirements.txt` is the usual cause; step 1.7
  pins it.

## Without a card: Render

Render's free web service builds the same Dockerfile from a GitHub repo it can
read. It sleeps after 15 idle minutes (about a minute to wake), has 512 MB of
memory and a small share of a CPU, so analyses and PDFs will be slower and the
30 s analysis limit may need raising (`CAPSTONE_ANALYSIS_TIMEOUT_S`). Set the
same variables as `cloudrun.env.yaml` in the Render dashboard, plus `HF_TOKEN`
as a secret and `CAPSTONE_TRUSTED_PROXY_HOPS=1`, and set
`CAPSTONE_ALLOWED_HOSTS` to `["<name>.onrender.com"]`. This needs the code on
GitHub, so it waits for the team's PRs to merge.

## Running the image locally

To check the container before deploying (needs Docker or Colima):

```bash
docker build -t capstone .
docker run --rm -p 8080:8080 -e CAPSTONE_ALLOWED_HOSTS='["localhost"]' capstone
```

Open http://localhost:8080. Add `--env-file app/api/.env` to try live
generation.
