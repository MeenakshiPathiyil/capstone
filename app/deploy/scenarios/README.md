# Seed scenarios

Cache entries (`<cache_key>.json`) copied into each container's cache when it
starts, so the bundled samples show their scenarios without a GPU call. The
deployed cache lives in memory and is lost whenever Cloud Run replaces the
container; these files are what survives.

To fill it, generate scenarios with the local app pointed at the deployed model
(or import a Kaggle run with `app/scripts/import_scenarios.py`), then copy the
entries from the local cache and redeploy:

```bash
cp app/.cache/scenarios/*.json app/deploy/scenarios/
```

An entry is only shown when its model provenance (base and adapter revisions,
loading recipe) and prompt match the deployed configuration, so entries from
an older adapter are ignored rather than shown wrongly.
