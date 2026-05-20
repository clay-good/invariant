# spec-v12 verification report

**Date:** 2026-05-19
**Sources:** [docs/robotics/spec-v12.md](robotics/spec-v12.md),
[docs/history/robotics/spec-v11.md](history/robotics/spec-v11.md),
[docs/spec-v11-verification.md](spec-v11-verification.md),
[PROGRESS.md](../PROGRESS.md)
**Workspace state:** `cargo test --workspace` 3 256 tests passing, 0
failures (53 serve tests including 6 new B2/B3/B4 request-boundary tests
landing in this verification cycle); `cargo clippy -p invariant-cli
--lib --tests -- -D warnings` clean.

## How to read this

Per the P-FINAL prompt, this is the one-page roll-up of every v12 prompt
(N-1 … N-20 + P-FINAL) plus a "what changed since v11" summary. Each row
links to the v12 tracking-table entry that holds the detailed change
log; this document is the authoritative closure record.

`DONE` = work shipped end-to-end. As of 2026-05-19 every v12 prompt
(N-1 … N-20 + P-FINAL) is `DONE`, including N-9 (spec consolidation),
which landed last per the v12 execution order.

## v12 prompt resolution

| ID   | Title                                         | Status | Source of truth |
|------|-----------------------------------------------|--------|-----------------|
| N-1  | `Scenario::all()` + spec-ID coverage          | DONE   | spec-v12 row N-1 — exhaustive `spec_id()` (no `_` arm); coverage test prints non-failing gap list |
| N-2  | Spec-ID ↔ `ScenarioType` mapping              | DONE   | spec-v12 row N-2 — `docs/scenario-id-map.md` + binding doctest |
| N-3  | Per-shard determinism fixture                 | DONE   | spec-v12 row N-3 — 1000-episode `Baseline` shard digest pinned at `crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256` |
| N-4  | Audit JSONL `schema_version`                  | DONE   | spec-v12 row N-4 — `CURRENT_SCHEMA_VERSION = 2`; v1 records round-trip; mixed-version warning |
| N-5  | Proof-package `format_version`                | DONE   | spec-v12 row N-5 — `ProofPackageError::UnsupportedFormat`; v1 fixture committed |
| N-6  | `campaign assemble --resume`                  | DONE   | spec-v12 row N-6 — sidecar `<output>.assemble-state.json` with fsync after each shard; 6 new tests including byte-identical-output assertion vs. one-shot run |
| N-7  | `run_15m_campaign.sh` cost ceiling + SIGTERM  | DONE   | spec-v12 row N-7 — `MAX_USD` / `HOURLY_USD` / `RESUME_DIR` env vars, `*.in-progress.json` markers, `scripts/check_spend.py` (18 unit tests) |
| N-8  | `docs/shadow-deployment.md` runbook           | DONE   | spec-v12 row N-8 — cross-linked from README Roadmap |
| N-9  | Archive v1–v12 specs under `docs/history/`    | DONE (2026-05-19) | spec-v12 row N-9 — `docs/robotics/spec-v1.md` … `spec-v11.md` + `spec-v12.md` + `spec-gaps.md` moved under `docs/history/robotics/`; each archived file carries a `> Superseded by docs/robotics/spec.md as of 2026-05-19. Kept for historical reference.` redirect on line 1; `docs/robotics/spec-v12.md` is now a one-line redirect to `docs/robotics/spec.md` + the archive copy + the closure report. New `docs/history/README.md` documents the archive layout. README "Outstanding spec work" bullet replaced with closure-report links. PROGRESS.md + both verification reports rewritten so every `docs/robotics/spec-v{1..11}.md` and `docs/robotics/spec-gaps.md` link points at its `docs/history/robotics/…` archive path. |
| N-10 | Poisoned-mutex regression test                | DONE   | spec-v12 row N-10 — `digital_twin_mutex_recovers_after_poison` |
| N-11 | Audit-rotation Merkle continuity test         | DONE   | spec-v12 row N-11 — cross-segment inclusion proofs for indices 500 (pre-rotation) and 1500 (post-rotation) |
| N-12 | Bridge fuzz target                            | DONE   | spec-v12 row N-12 — `fuzz/fuzz_targets/bridge_handle_line.rs` + 8 corpus seeds; exposes panic-free `fuzz_bridge_handle_line` from `bridge.rs` |
| N-13 | `keygen --store` taxonomy fail-fast           | DONE   | spec-v12 row N-13 — `StoreKind` parsed before any I/O; 6 new unit tests |
| N-14 | `serve` mode B1–B4 replay rejection           | DONE (2026-05-19) | spec-v12 row N-14 — promoted from PARTIAL → DONE by the request-boundary B2/B3/B4 follow-up (see below) |
| N-15 | `intent` ↔ PCA round-trip property test       | DONE   | spec-v12 row N-15 — 256 randomised cases, seeded `StdRng`; counter-examples persisted to `tests/regressions/` |
| N-16 | `eval` rubric → guardrail pipeline e2e        | DONE   | spec-v12 row N-16 — `pipeline_e2e.rs` + good/bad trace fixtures under 200 lines each |
| N-17 | `--fail-on-audit-error` regression            | DONE   | spec-v12 row N-17 — Linux-gated `/dev/full` test + serve coverage for the named flag |
| N-18 | Coordinator partition-merge soundness         | DONE   | spec-v12 row N-18 — 4-robot scenario at exact `MIN_SEPARATION_M=0.5`; `±EPS` perturbation flips the verdict |
| N-19 | Version-drift CI check                        | DONE   | spec-v12 row N-19 — `scripts/check_version_drift.sh` + `version-drift` job |
| N-20 | Seed `fuzz/` corpora                          | DONE   | spec-v12 row N-20 — `fuzz/seed_corpora.sh` populates ≥8 seeds per target |
| P-FINAL | v12 closure verification                   | DONE (this report) | This document |

**Net effect:** all 21 v12 prompts closed. N-9 landed on 2026-05-19
as the very last task per the v12 execution order; P-FINAL closure
landed alongside the N-14 promotion below and is being refreshed now
to fold in the N-9 result.

## v11 prompt status carried forward

The v11 roll-up at [spec-v11-verification.md](spec-v11-verification.md)
is authoritative. Since that report was written (2026-05-19), the
following v11/v12 rows moved:

| ID         | Before                       | After                  | Delta |
|------------|------------------------------|------------------------|-------|
| v12 N-14   | PARTIAL (B1 request boundary) | **DONE**              | B2 / B3 / B4 request-boundary enforcement added — see §"What changed since v11" |
| v11 1.2    | PARTIAL (opt-in detection)   | **DONE**              | Promoted PARTIAL → DONE on 2026-05-19. `verify_chain` now enforces the A3 predecessor binding mandatorily; new `link_chain_digests` helper auto-computes parent digests for multi-hop chain builders; six multi-hop test sites migrated. Workspace: 3 256 tests passing, 0 failures. |
| v11 4.1    | OPEN                         | **DESCOPED → v13**     | OS keyring / TPM / YubiHSM backends still return `KeyStoreError::Unavailable`. Formally descoped 2026-05-19 per v12 §5 rationale: hardware-attached tests require physical devices; shipping production backends without the harness puts un-exercised code into the trust boundary. Structural fail-fast covered by v12 N-13. |
| v11 4.2    | OPEN                         | **DESCOPED → v13**     | S3 + webhook witness still return `ReplicationError::Unavailable`. Formally descoped 2026-05-19: needs `aws-sdk-s3` + `reqwest` + MinIO/`httpmock` integration harness + resume-from-sidecar contract. Alert-sink half shipped under v11 4.3. |

## What changed since v11

The headline change in this verification cycle is the **v12 N-14
promotion from PARTIAL → DONE**, achieved without a `Command`
wire-format change.

[crates/invariant-cli/src/robotics/commands/serve.rs](../crates/invariant-cli/src/robotics/commands/serve.rs)
`handle_validate` now reads three additional optional HTTP headers —
parallel in shape to the B1 `X-Invariant-Session-Id` header that
already shipped — and rejects with HTTP 400 + a typed `Bn …` reason on
mismatch:

- **B2** — `X-Invariant-Executor-Id`: must match the in-body
  `command.source` or reject `B2 executor binding: header executor_id
  <X> does not match command source <Y> — cross-executor replay
  rejected`.
- **B3** — `X-Invariant-Monotonic-Nanos`: parsed as `u64`, compared
  against the new
  `AppState.request_monotonic: Mutex<HashMap<String, u64>>` keyed by
  `command.source`. Stale value → `B3 monotonic binding: header
  monotonic_nanos <N> is not strictly greater than last observed value
  <P> for executor <E> — replay rejected`. Malformed (non-`u64`) →
  `B3 monotonic binding: header monotonic_nanos … is not a u64`.
  Tracking is **per-executor**: a fresh executor starts at 0 and is
  unaffected by another executor's history.
- **B4** — `X-Invariant-Wall-Clock`: RFC 3339 timestamp; absolute skew
  vs `Utc::now()` greater than `B4_MAX_WALL_CLOCK_SKEW_SECS = 300`
  rejects `B4 wall-clock binding: header wall_clock <T> skews from
  server clock by <S>s (>300s) — stale replay rejected`. Malformed
  RFC 3339 → `B4 wall-clock binding: header wall_clock … is not
  RFC 3339`.

All three new checks run immediately after the existing B1 check,
**before** incident-lockdown / sequence / validation / audit — a
captured request replayed under a different executor identity, with a
stale monotonic, or to a different wall-clock is rejected with zero
state mutation. Absent headers preserve the legacy code path
(backward-compatible with pre-v12-N-14 clients).

Six new tests in `serve::tests`:
`cross_executor_replay_rejected_by_b2_header`,
`stale_monotonic_replay_rejected_by_b3_header`,
`b3_monotonic_is_per_executor`,
`stale_wall_clock_rejected_by_b4_header`,
`fresh_wall_clock_accepted_by_b4_header`,
`malformed_b3_header_is_rejected`. All 53 serve tests pass; full
workspace `cargo test --workspace` 3 256 tests green; `cargo clippy -p
invariant-cli --lib --tests -- -D warnings` clean.

## Smoke-run reference

The v11 6.1 report's proof-loop smoke and RFC 6962 empty-tree root
remain pinned and unchanged at HEAD; see
[spec-v11-verification.md](spec-v11-verification.md) §"Smoke-run
reference" for the reproducible 10 k-episode dry-run command and the
fixed Merkle root `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Deferred follow-ups (queued after v12)

These were called out as v12 out-of-scope (§5 "Out of scope for v12")
or carried forward unchanged from v11. They do not block v12 closure:

1. **v11 4.1 hardware-backed key stores** — DESCOPED → v13. `os-keyring`,
   `tpm`, `yubihsm` features need real hardware (or `swtpm`) to be
   integration-testable. Structural fail-fast already locked by v12
   N-13.
2. **v11 4.2 S3 + webhook witness** — DESCOPED → v13. `aws-sdk-s3` +
   `reqwest` integration-tested against MinIO + `httpmock`.
3. **v11 5.7 / 5.8** — physics property tests, end-to-end proof-loop
   smoke (the smoke harness exists; expanding to property-based
   physics coverage is a follow-up).
4. **Category N wire-shape rows** — CLOSED 2026-05-19. All six bound
   to libFuzzer targets: N-06 → `fuzz_json_bomb` (new), N-07 →
   `fuzz_cose_envelope` (new), N-03/N-04/N-05/N-09 → existing
   `fuzz_command_json` / `fuzz_validate_pipeline` per the map in
   `fuzz/README.md`.

---

**Closure statement.** All 21 v12 prompts are DONE. N-9 landed
2026-05-19 as the very last task per the v12 execution order — the
robotics v1 … v12 spec lineage and `spec-gaps.md` are archived under
`docs/history/robotics/` with redirect headers, `docs/robotics/spec-v12.md`
is now a one-line redirect to `docs/robotics/spec.md`, and a new
`docs/history/README.md` documents the archive. v11 1.2 was also
promoted PARTIAL → DONE this cycle (mandatory `verify_chain`
predecessor enforcement is now live, with `link_chain_digests`
exported as the production-ready chain builder). v11 2.11 was
promoted PARTIAL → DONE in the same cycle by binding the six
wire-shape Category N rows to libFuzzer targets in `fuzz/` (two new:
`fuzz_cose_envelope` for N-07, `fuzz_json_bomb` for N-06; four bound
to existing targets per the map in `fuzz/README.md`). Only DESCOPED →
v13 rows (4.1, 4.2) remain unresolved, both with documented
hardware-attached-test rationale. Workspace tests: 3 256 passing, 0
failing; clippy clean across the surfaces touched by this cycle.
