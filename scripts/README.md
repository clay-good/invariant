# `scripts/`

Operational scripts for running the 15M campaign, uploading results, and
checking spend against budget.

## `run_15m_campaign.sh`

Drives a full 15M-episode campaign as one shard per profile.

### Environment variables (v12-N-7)

| Variable     | Default | Meaning |
|--------------|---------|---------|
| `MAX_USD`    | `40`    | Hard ceiling on projected total spend in USD. Before each shard, the runner calls `check_spend.py` to extrapolate the final cost from elapsed time. Projected total > `MAX_USD` aborts the campaign cleanly with exit 2. Set to `0` for a dry-run abort that verifies the wiring without starting any shard. |
| `HOURLY_USD` | `2.50`  | Operator's per-hour cost assumption (RunPod RTX 4090 ballpark). Document the assumed rate alongside the invocation so it can be reconciled against the invoice after the campaign closes. |
| `RESUME_DIR` | unset   | If set, the runner reuses this directory as `OUTPUT_DIR`. Shards with a `<profile>.complete` marker are skipped; shards with a `<profile>.in-progress.json` marker are resumed (the campaign runner is responsible for picking up partial state inside `${RESUME_DIR}/${PROFILE}/`). |

### Signal handling

A `SIGTERM` or `SIGINT` during shard execution causes the runner to flush a
`<profile>.in-progress.json` marker and exit 130. A subsequent invocation
with `RESUME_DIR=<that directory>` picks up where the previous run left off.

`SIGKILL` cannot be trapped — but the runner pre-emptively writes the
in-progress marker before starting each shard, so even a hard kill leaves a
recoverable trace.

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | All shards passed (or were resumed from a previous complete marker). |
| 1    | One or more shards failed. Check `${OUTPUT_DIR}/campaign.log`. |
| 2    | Projected spend exceeded `MAX_USD`. Re-run with `RESUME_DIR=${OUTPUT_DIR}` after raising the ceiling. |
| 130  | Interrupted by SIGTERM/SIGINT. An in-progress marker has been written; re-run with `RESUME_DIR` to continue. |

### Quick start

```sh
# Dry run that verifies wiring without burning compute.
MAX_USD=0 bash scripts/run_15m_campaign.sh

# Real run with a custom rate and ceiling.
HOURLY_USD=3.20 MAX_USD=60 bash scripts/run_15m_campaign.sh

# Resume an interrupted run.
RESUME_DIR=results/invariant_15m_proof_20260514_120000 \
  bash scripts/run_15m_campaign.sh
```

## `check_spend.py`

Pure-Python module used by `run_15m_campaign.sh` to project total spend. Also
usable as a CLI:

```sh
python3 scripts/check_spend.py \
  --elapsed-seconds 3600 --fraction-complete 0.5 \
  --hourly-usd 2.5 --max-usd 40
```

Exit codes: 0 = under ceiling, 1 = ABORT (projection over ceiling or
`max_usd=0` dry-run), 2 = invalid input.

Tests live in `test_check_spend.py`:

```sh
python3 -m unittest scripts.test_check_spend -v
```

## `upload_results.py`

Uploads a campaign output directory to HuggingFace. See the script header for
the full flag list.

## `runpod_setup.sh`

One-shot pod bootstrap (apt deps, CUDA env, Python venv).
