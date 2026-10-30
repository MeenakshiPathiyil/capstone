#!/bin/sh
# Container entrypoint (see the Dockerfile and app/DEPLOY.md).
set -eu

# Scenarios baked into the image start every container's empty cache, so the
# bundled samples show them without spending GPU quota. Entries are named by
# their cache key, and one already there is never replaced.
seed="app/deploy/scenarios"
target="$CAPSTONE_CACHE_DIR/scenarios"

if ls "$seed"/*.json >/dev/null 2>&1; then
    mkdir -p "$target"
    chmod 700 "$target"
    cp -n "$seed"/*.json "$target"/
fi

# One worker: the analysis slot, the scenario queue and the PDF cache live in
# this process's memory.
exec uvicorn app.api.main:app --host 0.0.0.0 --port "${PORT:-8080}" --workers 1 --no-server-header
