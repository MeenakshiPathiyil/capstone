#!/bin/sh
# Build the image from this checkout with Cloud Build and deploy it to Cloud Run.
# Run from the repo root after the one-time setup in app/DEPLOY.md, part 3:
#
#   app/deploy/cloudrun_deploy.sh
#
# SERVICE (default capstone) and REGION (default us-central1) can be set in the
# environment. Set WITH_MODEL=0 to deploy without the HF_TOKEN secret.
set -eu

SERVICE="${SERVICE:-capstone}"
REGION="${REGION:-us-central1}"
WITH_MODEL="${WITH_MODEL:-1}"

cd "$(git rev-parse --show-toplevel)"

# The PDF footer names the commit the analyser ran from; the image has no .git.
commit="$(git rev-parse --short=12 HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    commit="$commit+dirty"
fi

env_file="$(mktemp)"
trap 'rm -f "$env_file"' EXIT
cat app/deploy/cloudrun.env.yaml > "$env_file"
printf '\nANALYSER_COMMIT: "%s"\n' "$commit" >> "$env_file"

secrets=""
if [ "$WITH_MODEL" = "1" ]; then
    secrets="--set-secrets=HF_TOKEN=capstone-hf-token:latest"
fi

# One instance at most: the analysis slot, the scenario queue and the saved
# analyses live in that instance's memory, and a second one would not see them.
# shellcheck disable=SC2086
gcloud run deploy "$SERVICE" \
    --source . \
    --region "$REGION" \
    --allow-unauthenticated \
    --execution-environment gen2 \
    --cpu 1 \
    --memory 1Gi \
    --cpu-boost \
    --min-instances 0 \
    --max-instances 1 \
    --concurrency 40 \
    --timeout 300 \
    --env-vars-file "$env_file" \
    $secrets

gcloud run services describe "$SERVICE" --region "$REGION" --format 'value(status.url)'
