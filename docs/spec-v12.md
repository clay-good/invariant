# spec-v12.md — Re-verified Gap Closure (post-v11 status snapshot)

**Status:** active, 2026-05-02
**Branch when authored:** `codelicious/spec-spec-15m-campaign-part-4`
**Supersedes the open items in:** spec-v11.md (does not invalidate spec.md or spec-15m-campaign.md)
**Audience:** Claude Code agents executing one prompt at a time

## 0. Why a v12

`docs/spec-v11.md` was authored on 2026-05-01 and proposed 38 prompts (Phases 1–6) all marked `OPEN`. Since then the branch has merged a large set of `[spec-spec-15m-campaign-chunk-*]` commits that grew `crates/invariant-sim/src/scenario.rs` and `campaign.rs` and expanded `docs/spec-15m-campaign.md`, but a re-verification on 2026-05-02 against `HEAD` shows that **most v11 cryptographic, CLI, simulation, and backend prompts have not actually landed**. v12 records the current verified status of every v11 prompt and adds prompts for net-new gaps that v11 did not cover.

This document is a remediation plan derived from a fresh end-to-end audit of `crates/`, `isaac/`, `formal/`, `.github/workflows/`, `profiles/`, `campaigns/`, and `docs/` against `docs/spec.md`, `docs/spec-15m-campaign.md`, `spec-v11.md`, and earlier deltas.

Each section under "Prompts" is self-contained: open it, paste the body verbatim into a fresh agent (or run it as one focused task), and let it complete end-to-end before moving on. Prompts are ordered by dependency: P1 (Phase 1 blocking) must land before P2 generators are trustworthy, P3 depends on P2, P4–P6 are parallelizable once P1 is in.

After each prompt completes:
1. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` must be green.
2. One commit per prompt with subject `[spec-v12-<id>] <one-line summary>`.
3. Update the v11 tracking table **and** the v12 tracking table at the bottom of this file from `OPEN` → `DONE` (or `PARTIAL`/`DESCOPED` with a citation).

If an agent finds the work is already done, it should record `ALREADY DONE` in the v12 tracking table with a one-line citation (commit hash or file path) and move on without committing.

---

## 1. Verified status of v11 prompts (re-checked 2026-05-02)

The "Evidence" column links to the grep or file read that verified the status against `HEAD`.

| v11 ID | Title                                              | Re-verified status | Evidence |
|--------|----------------------------------------------------|--------------------|----------|
| 1.1    | B1–B4 audit fields                                 | OPEN               | `crates/invariant-core/src/authority/` does not contain `binding.rs`; `grep -rn "ExecutionBinding\|executor_binding\|temporal_window" crates/invariant-core/src/` returns 0 hits. |
| 1.2    | A3 predecessor digest                              | OPEN               | `grep -rn "predecessor_digest\|predecessor_hash\|prev_hop_hash" crates/invariant-core/src/` returns 0 hits. |
| 1.3    | RFC 6962 Merkle tree                               | OPEN               | `grep -n "[Mm]erkle\|tree_root" crates/invariant-core/src/proof_package.rs crates/invariant-core/src/audit.rs` returns 0 hits. |
| 1.4    | Manifest JCS + signature                           | OPEN               | `proof_package.rs:241` still documents the manifest as "unsigned — caller signs if keys are available"; no caller signs it. |
| 1.5    | `campaign assemble` CLI                            | OPEN               | `grep -E "Assemble\|assemble" crates/invariant-cli/src/commands/campaign.rs crates/invariant-cli/src/main.rs` returns 0 hits. |
| 1.6    | `audit verify` digest/root flags                   | OPEN               | depends on 1.2/1.3; flags not present. |
| 2.0    | Determinism contract                               | OPEN               | no `crates/invariant-sim/src/determinism.rs` and no determinism doctest in `campaign.rs`. |
| 2.1–2.11 | Category B–N generators                          | PARTIAL            | `scenario.rs` enumerates ~28 `ScenarioType` variants; spec calls for 104. Recent chunk commits expanded `campaign.rs` text but did not add the missing `ScenarioType` variants. |
| 3.1    | Five Isaac Lab envs                                | OPEN               | `ls isaac/envs/` shows only `cnc_tending.py` plus `__init__.py` and `cell_config.py`. `humanoid.py`, `quadruped.py`, `hand.py`, `mobile_base.py`, `arm.py` absent. |
| 3.2    | Bridge bounded reads + watchdog isolation          | PARTIAL            | bounded reads landed (commit `70aefe6`, `54a2508`); per-connection watchdog isolation still TBD — bridge file header at `crates/invariant-sim/src/isaac/bridge.rs` should be re-read to confirm. |
| 4.1    | OS keyring / TPM / YubiHSM                         | OPEN               | all three return `KeyStoreError::Unavailable` with "not yet implemented" reason in `crates/invariant-core/src/keys.rs`. |
| 4.2    | S3 replication + webhook witness                   | OPEN               | both return `ReplicationError::Unavailable` in `crates/invariant-core/src/replication.rs`. |
| 4.3    | Webhook + syslog alert sinks                       | OPEN               | both return `Unavailable` in `crates/invariant-core/src/incident.rs`. |
| 5.1    | SR1 / SR2 sensor-range split                       | OPEN               | `crates/invariant-core/src/physics/environment.rs:361` still has a single `check_sensor_range`. |
| 5.2    | Profile field backfill                             | DONE               | commit `274f8dc` "feat: add end_effectors and environment sections to all robot profiles". v12 should re-verify with `validate-profiles --strict` once 5.3 lands. |
| 5.3    | `validate-profiles --strict` + CI                  | OPEN               | `grep validate-profiles crates/invariant-cli/src/` empty. |
| 5.4    | `campaign generate-15m` CLI                        | OPEN               | absent from CLI registry. |
| 5.5    | `fleet status` + 10-robot test                     | OPEN               | `grep -rn "fleet" crates/invariant-cli/src/commands/` empty; no 10-robot test. |
| 5.6    | Streaming-hash memory regression                   | OPEN               | unverified — see v12 P-NEW-3. |
| 5.7    | Physics property tests                             | OPEN               | `grep -rln "proptest\|quickcheck" crates/invariant-core/` should be re-checked. |
| 5.8    | End-to-end proof-loop smoke                        | OPEN               | depends on 1.x and 1.5. |
| 5.9    | Lean CI                                            | OPEN               | `grep lake .github/workflows/*.yml` returns 0 hits. |
| 5.10   | cargo-fuzz nightly                                 | OPEN               | `fuzz/` exists; CI nightly job not present. |
| 5.11   | `invariant-ros2/` disposition                      | OPEN               | `grep invariant-ros2 Cargo.toml` returns 0 hits — still not a workspace member. |
| 5.12   | verify-self audit                                  | OPEN               | not yet executed. |
| 5.13   | Error stability catalog                            | OPEN               | absent. |
| 5.14   | Campaign YAML validation                           | OPEN               | no `crates/invariant-sim/tests/campaigns_load.rs`. |
| 5.15   | Threat / compliance / envelope / eval docs         | OPEN               | `docs/threat-model.md` etc. absent. |
| 5.16   | spec-gaps.md reconciliation                        | OPEN               | `docs/spec-gaps.md` still present at branch head. |
| 6.1    | Final verification pass                            | OPEN               | depends on the rest. |
| —      | SBOM in CI                                         | DONE               | `release.yml:84-95` runs `cargo cyclonedx`. v11 had this implicitly out of scope; v12 acknowledges it as closed. |

**Net effect:** of 38 v11 prompts, 1 is DONE (5.2), 1 is PARTIAL with bounded-reads landed (3.2), and 36 are OPEN. v12 carries every OPEN prompt forward by reference (do not re-author them) and adds the prompts in §3 below.

---

## 2. Newly identified gaps not in v11

These were surfaced by the 2026-05-02 audit and are not addressed (or only addressed obliquely) by v11. Each becomes a v12 prompt in §3.

| v12 ID | Title | Severity | Why v11 didn't catch it |
|--------|-------|----------|--------------------------|
| N-1    | `Scenario::all()` enumerator + spec-ID coverage test | P1 | v11 prompts 2.1–2.11 each add generators but no prompt asserts every spec-cited ID maps to a `ScenarioType`. |
| N-2    | Campaign-spec ID ↔ `ScenarioType` mapping table     | P1 | v11 assumes a 1:1 obvious mapping; current code uses friendly names (`LocomotionFall`) not spec IDs (`D-05`). |
| N-3    | Per-shard determinism: seed→trace SHA-256 fixture   | P1 | v11 prompt 2.0 establishes the contract but does not check it in CI against a frozen fixture. |
| N-4    | Audit JSONL schema versioning                       | P2 | v11 1.1 adds new fields to audit records but does not add a `schema_version` discriminator; downstream tools cannot detect record-format drift. |
| N-5    | Proof-package format-version field                  | P2 | once Merkle (1.3) and signature (1.4) land, the package format changes; old packages must be rejected with a typed error, not silently accepted. |
| N-6    | `campaign assemble --resume` for partial shard sets | P2 | v11 1.5 does not specify resumability; a 15M run that loses a shard mid-assembly cannot recover. |
| N-7    | Cost-ceiling and SIGTERM checkpointing in `scripts/run_15m_campaign.sh` | P2 | called out in old `spec-gaps.md §3.5` but not absorbed into v11. |
| N-8    | Shadow-deployment runbook (`docs/shadow-deployment.md`) | P3 | also `spec-gaps.md §3.5`, not absorbed. |
| N-9    | Spec consolidation: archive `spec-v1..v10` under `docs/history/` | P3 | v11 §"Out of scope" defers to a future spec; v12 schedules it explicitly post-Phase-1 closure. |
| N-10   | `mutex.rs`/poisoned-mutex regression test           | P2 | commit `33c3e1f` "fix: recover from poisoned mutex in digital twin" landed; no test fixture asserts the recovery path. |
| N-11   | Audit log rotation correctness fixture              | P2 | commit `7ad120d` mentions "audit rotation"; no end-to-end test asserts post-rotation Merkle continuity (will become important once 1.3 lands). |
| N-12   | Bridge fuzz target                                  | P2 | `fuzz/` exists; no fuzz target for `bridge::handle_line` despite multiple bridge security commits. |
| N-13   | `keygen --store=<kind>` taxonomy-fail-fast test     | P2 | v11 4.1 implements backends; v12 N-13 ensures unknown kinds fail before any I/O. |
| N-14   | `serve` mode replay-rejection integration test     | P1 | once B1–B4 (v11 1.1) lands, an end-to-end test must POST a replayed PCA to `serve` and assert rejection. v11 1.1 only adds unit tests in `authority/tests.rs`. |
| N-15   | `intent` ↔ PCA round-trip property test             | P2 | `intent` subcommand exists; no property test that intents derived from valid PCAs round-trip back to the same authority closure. |
| N-16   | `eval` rubric → guardrail trip integration test     | P2 | `crates/invariant-eval` lacks an end-to-end test that drives a known-bad trace through preset → rubric → guardrail and asserts the expected verdict. |
| N-17   | `--fail-on-audit-error` regression test             | P2 | flag landed in commit `36193ba`; no negative-path test asserts that disk-full or permission-denied actually causes process exit. |
| N-18   | `coordinator` partition-merge soundness fixture     | P2 | `partition.rs` exists; no test asserts that two safely-partitioned plans, when merged at a boundary, retain pairwise separation. |
| N-19   | CHANGELOG ↔ `Cargo.toml` version drift check        | P3 | repo bumped to 0.0.3 in `7ad120d`; CI does not assert that a tag matches `Cargo.toml` and that CHANGELOG has a section for it. |
| N-20   | `fuzz/` corpus seeded from real audit fixtures      | P2 | corpora are unseeded, reducing coverage. |

---

## 3. Prompts

Phase numbering continues from v11 to avoid confusion. Phase 7 = v12 net-new. v11 Phase 1–6 prompts are referenced by ID and not duplicated — agents should open `docs/spec-v11.md` and execute them as written.

### Execution order

1. **Run v11 Phase 1 (1.1–1.6) first.** Phase 7 prompts assume the audit/proof-package format has the new fields.
2. **Then v12 N-1, N-2, N-4, N-5** — these formalize the contract Phase 1 just established.
3. **Then v11 Phase 2 (scenarios) + N-3** in parallel.
4. **Then v11 Phase 3 (Isaac) + N-12, N-18** in parallel.
5. **v11 Phase 4 + N-13, N-17** parallelizable any time after Phase 1.
6. **v11 Phase 5 + N-6, N-7, N-8, N-10, N-11, N-14, N-15, N-16, N-19, N-20** parallelizable any time after Phase 1 (with the dependencies noted in each prompt).
7. **N-9** last — only consolidate specs after v11 + v12 both close.
8. **v11 6.1 (final verification pass), then v12 P-FINAL** to certify v12 closure.

---

### Prompt N-1 — Add `Scenario::all()` and a spec-ID coverage test

**Spec citation:** `docs/spec-15m-campaign.md` enumerates 104 scenario IDs across categories A–N.

**Goal:** make it impossible to claim "104 scenarios" while shipping fewer. Today `crates/invariant-sim/src/scenario.rs` exposes ~28 `ScenarioType` variants with no static enumerator and no test that compares the variant set to the spec.

**Prompt body:**

> Read `crates/invariant-sim/src/scenario.rs` and list every `ScenarioType` variant. Then read `docs/spec-15m-campaign.md` §3 (categories A–N) and list every spec ID (A-01, A-02, … N-10). Add a `pub const fn all() -> &'static [ScenarioType]` that returns every variant in declaration order. Add a `pub fn spec_id(&self) -> &'static str` that returns the spec ID this variant implements (e.g. `LocomotionFall` → `D-05`); for variants that have no spec ID assignment yet, return `"unassigned"`. Add a new integration test at `crates/invariant-sim/tests/scenario_coverage.rs` that:
>
> 1. Asserts `Scenario::all().len() == ScenarioType::iter().count()` (use `strum::IntoEnumIterator` if not already a dep; otherwise hand-roll the count).
> 2. Asserts every `spec_id()` returned is either `"unassigned"` or matches the regex `^[A-N]-\d{2}$`.
> 3. Reads `docs/spec-15m-campaign.md`, extracts every `^[A-N]-\d{2}` ID, and emits a *non-failing* report (printed via `eprintln!`) showing which IDs have no implementing variant. The test passes today even with gaps so it does not block; once v11 Phase 2 lands, flip the report to a hard `assert!`.
>
> Update `crates/invariant-sim/Cargo.toml` `[dev-dependencies]` if needed. Run `cargo test -p invariant-sim` and confirm the report prints the expected gap list. One commit: `[spec-v12-N-1] Scenario::all() and spec-ID coverage report`.

**Acceptance:** test exists, prints the gap list, all green.

---

### Prompt N-2 — Spec-ID ↔ `ScenarioType` mapping table

**Goal:** cement the mapping so every future generator commit binds a spec ID to a variant in one place.

**Prompt body:**

> Add a new table at `docs/scenario-id-map.md` with three columns: `Spec ID | ScenarioType variant | Status` (one of `IMPLEMENTED`, `STUB`, `UNASSIGNED`). Populate it from N-1's output. For each existing variant in `crates/invariant-sim/src/scenario.rs`, assign a spec ID by reading `docs/spec-15m-campaign.md` §3 — pick the closest semantic match (e.g. `LocomotionFall` → `D-05 push-recovery / fall`). If a variant doesn't fit any spec ID, mark it `UNASSIGNED` and open a follow-up note in the table comment.
>
> Then add a doctest in `crates/invariant-sim/src/scenario.rs` that asserts, for ten hand-picked variants, that `variant.spec_id()` returns the same string the doc table records. Generate this assertion list by parsing `docs/scenario-id-map.md` at build time is out of scope; hand-write the ten asserts. One commit: `[spec-v12-N-2] scenario-id-map.md and binding doctest`.

**Acceptance:** doctest passes; table covers every current variant; CI green.

---

### Prompt N-3 — Per-shard determinism fixture

**Spec citation:** `docs/spec-15m-campaign.md` §1 (deterministic replay), v11 prompt 2.0.

**Goal:** lock in the seed→trace SHA-256 contract once v11 2.0 lands.

**Prompt body:**

> After v11 prompt 2.0 has merged, generate a deterministic 1 000-episode shard for `ScenarioType::Baseline` on profile `ur10e_safety_v1` with seed `0xCAFE_BABE_DEAD_BEEF`. Hash the JSONL output with SHA-256 and store the hex digest at `crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256`. Add an integration test `crates/invariant-sim/tests/determinism_fixture.rs` that regenerates the same shard at test time and asserts the digest matches the fixture file byte-for-byte.
>
> Document in the test file's module doc that the digest must be regenerated and committed any time the campaign generator output format changes intentionally; otherwise this test gates against silent generator drift. One commit: `[spec-v12-N-3] determinism fixture for baseline ur10e shard`.

**Acceptance:** test is green at `HEAD`; test fails locally if the generator output changes.

---

### Prompt N-4 — Audit JSONL `schema_version` field

**Goal:** add forward-compatible versioning so the new B1–B4 fields (v11 1.1) and predecessor digest (v11 1.2) can be distinguished from older records.

**Prompt body:**

> In `crates/invariant-core/src/audit.rs`, add a `schema_version: u32` field to the audit-record struct (start at `2`; `1` is the unversioned record format). Default deserialization treats a missing field as version `1`. The reader must reject mixing of v1 and v2 records inside a single Merkle tree: when v11 1.3 (Merkle) lands, leaves of different versions yield distinct subtrees and the verifier emits `AuditError::MixedSchemaVersions`. Until 1.3 lands, just emit a warning via the existing tracing setup.
>
> Add a unit test that round-trips a v2 record and a unit test that confirms a v1 record (no `schema_version` key) deserializes as version 1. Update `proof_package::manifest` (after v11 1.4 lands) to record the schema-version range present. One commit: `[spec-v12-N-4] audit schema_version + mixed-version detection`.

**Acceptance:** unit tests green; audit log on disk gains the field at every new write site.

---

### Prompt N-5 — Proof-package format-version field

**Goal:** the proof package format will change once v11 1.3 + 1.4 land. Old format must be rejected explicitly.

**Prompt body:**

> In `crates/invariant-core/src/proof_package.rs`, add a `format_version: u32` field to the manifest. Set the constant to `2` once Merkle root + signature land; until then, set it to `1` and emit a warning when verifying. `verify_package` returns `ProofPackageError::UnsupportedFormat { found, expected_min, expected_max }` for anything outside the supported range. Backfill a tiny v1 fixture under `crates/invariant-core/tests/fixtures/proof_package_v1/` and a v2 fixture once 1.3 + 1.4 land; assert both behaviors. One commit: `[spec-v12-N-5] proof-package format_version with typed rejection`.

**Acceptance:** verifier rejects unknown versions with a typed error; tests cover both directions.

---

### Prompt N-6 — `campaign assemble --resume` for partial shard sets

**Goal:** make assembly idempotent and recoverable.

**Prompt body:**

> Extend the `campaign assemble` subcommand (added by v11 1.5) with a `--resume` flag. Resume semantics: read the partially written output package, identify which shards have already been hashed and added to the Merkle tree, and continue from the next missing shard. Maintain a sidecar `<output>.assemble-state.json` with the list of consumed shard paths and their digests; this file is fsynced after each shard. On startup, if the sidecar exists and `--resume` is not passed, exit with `error: existing assembly state — pass --resume or remove <path>`.
>
> Add an integration test that assembles a 4-shard package, kills the process after shard 2 (simulate via a feature-gated `panic!`), then resumes and asserts the final Merkle root matches a one-shot run. One commit: `[spec-v12-N-6] campaign assemble --resume with sidecar state`.

**Acceptance:** integration test green; resume produces byte-identical output to a one-shot run.

---

### Prompt N-7 — Cost-ceiling and SIGTERM checkpointing in `run_15m_campaign.sh`

**Goal:** make a 15M RunPod run resilient to preemption and to budget overrun.

**Prompt body:**

> Edit `scripts/run_15m_campaign.sh` to add (a) a `MAX_USD` env var defaulting to `40`; before each shard, query the current spend (use the existing `scripts/upload_results.py` helper or a new `scripts/check_spend.py` if absent — read existing scripts first) and abort cleanly if the projected spend at completion would exceed `MAX_USD`. (b) a `trap '<flush>' SIGTERM SIGINT` handler that flushes the in-progress shard summary, writes a `<shard>.in-progress.json` marker, and exits 130. (c) on startup, scan for `*.in-progress.json` markers and skip shards already marked complete, but resume any in-progress shard from its checkpoint.
>
> Add a unit test for the spend-projection math (pull it into a small Python module if necessary). Document the env-var contract in a new `scripts/README.md` section. One commit: `[spec-v12-N-7] cost ceiling + SIGTERM checkpointing in 15m runner`.

**Acceptance:** dry-run with `MAX_USD=0` aborts before any shard; `kill -TERM $!` mid-shard leaves a recoverable marker.

---

### Prompt N-8 — Shadow-deployment runbook

**Goal:** declare what "shadow" actually means before any customer deploys it.

**Prompt body:**

> Create `docs/shadow-deployment.md` (≤ 250 lines). Sections: (1) Goal: ≥100 robot-hours on UR10e CNC cell with `serve` mode in observe-only configuration. (2) Pre-flight checklist: profile selected, audit destination reachable, replication backend configured (or explicitly disabled), watchdog tuned, alert sinks point at a sandboxed channel. (3) Metrics: validation latency p50/p95/p99, decisions/sec, divergence count vs. ground-truth controller, audit growth rate. (4) Divergence triage protocol: collect PCA, command, validator state; freeze the audit shard; open an incident with the existing `incident.rs` flow; rerun in dry-run mode; classify as `false-positive | true-positive | configuration | unknown`. (5) Sign-off criteria: divergence rate ≤ 0.01% over the 100 robot-hours and zero P1 incidents.
>
> Cross-link from `README.md` "Roadmap" section. One commit: `[spec-v12-N-8] shadow-deployment.md runbook`.

**Acceptance:** file exists, reviewer signs off in PR.

---

### Prompt N-9 — Spec consolidation (do this last)

**Goal:** collapse the v1–v11 lineage once both v11 and v12 close.

**Prompt body:**

> Only run this prompt after every v11 and v12 prompt has reached `DONE`, `ALREADY DONE`, or `DESCOPED` with rationale. Move `docs/spec-v1.md` through `docs/spec-v11.md` to `docs/history/`. In each moved file, prepend a one-line redirect: `> Superseded by docs/spec.md as of <date>. Kept for historical reference.` Move `docs/spec-gaps.md` to `docs/history/spec-gaps.md` only after v11 5.16 records every gap as closed/dup/descoped. `docs/spec-v12.md` (this file) moves last; replace it with a one-line redirect to `docs/spec.md`. `docs/spec.md` and `docs/spec-15m-campaign.md` remain at the top of `docs/`.
>
> Update every internal link in `README.md`, `CHANGELOG.md`, and `CONTRIBUTING.md`. Add a `docs/history/README.md` explaining the archive. One commit: `[spec-v12-N-9] archive v1–v12 specs under docs/history`.

**Acceptance:** `docs/` contains only `spec.md`, `spec-15m-campaign.md`, top-level operational docs, and `history/`. CI green; no broken cross-links (run a markdown link-checker if available).

---

### Prompt N-10 — Poisoned-mutex regression test

**Goal:** lock in the digital-twin recovery added in commit `33c3e1f`.

**Prompt body:**

> Read commit `33c3e1f` to find the digital-twin module and the recovery code path. Add a unit test that (a) acquires the mutex, (b) panics inside the critical section to poison it, (c) asserts that the next legitimate caller observes the recovery branch and the system continues. Use `std::panic::catch_unwind` to drive the panic without aborting the test process. If the recovery code requires a feature flag, gate the test behind the same flag. One commit: `[spec-v12-N-10] poisoned-mutex recovery regression test`.

**Acceptance:** test fails if the recovery branch is removed; passes at `HEAD`.

---

### Prompt N-11 — Audit-rotation Merkle continuity test (depends on v11 1.3)

**Goal:** ensure rotation does not break the Merkle chain.

**Prompt body:**

> After v11 1.3 (Merkle tree) lands, add an integration test at `crates/invariant-core/tests/audit_rotation_merkle.rs`. Steps: write 1 000 audit records, force a rotation (use whatever API commit `7ad120d` introduced — read it first), write 1 000 more, then rebuild the Merkle tree across both segments and assert (a) the cross-segment root differs from each segment's root, (b) the inclusion proof for record 500 (pre-rotation) and record 1500 (post-rotation) both verify against the cross-segment root. One commit: `[spec-v12-N-11] audit rotation Merkle continuity`.

**Acceptance:** test green; deliberately corrupting the post-rotation segment makes the test fail with an inclusion-proof error.

---

### Prompt N-12 — Bridge fuzz target

**Goal:** the bridge has had four security commits; close the loop with a fuzzer.

**Prompt body:**

> Add `fuzz/fuzz_targets/bridge_handle_line.rs` that takes arbitrary bytes, splits them on `\n` to simulate framed input, and feeds each line to the bridge's line handler with a fresh in-memory `BridgeState`. Assert no panic, no unbounded allocation (use `MALLOC_NANO_ZONE=0` plus a heap-cap helper or `assert_no_alloc` if available — otherwise just rely on the bounded-read invariant). Add a CI nightly job (alongside v11 5.10) that runs the target for 5 minutes. Seed the corpus with at least three real captured bridge sessions; if none are committed, hand-craft three minimal valid inputs and add a `README` in the fuzz dir explaining how to capture more. One commit: `[spec-v12-N-12] bridge_handle_line fuzz target + corpus seeds`.

**Acceptance:** target builds with `cargo fuzz build`; nightly job exists.

---

### Prompt N-13 — `keygen --store=<kind>` taxonomy fail-fast

**Goal:** unknown store kinds must fail before any I/O.

**Prompt body:**

> In `crates/invariant-cli/src/commands/keygen.rs`, ensure `--store=<kind>` parses to a typed enum (`StoreKind::{File, OsKeyring, Tpm, YubiHsm}`). Unknown kinds fail with `error: unknown key store '<kind>'; expected one of file|os-keyring|tpm|yubihsm` *before* any path is opened or any backend is constructed. Add a CLI integration test using `assert_cmd` (or whatever the existing CLI tests use — read `crates/invariant-cli/tests/` first) that confirms (a) `--store=foobar` exits non-zero and prints the expected error to stderr, (b) `--store=tpm` (a not-yet-implemented backend) exits with `KeyStoreError::Unavailable` and a typed message, never opens a file, and never panics. One commit: `[spec-v12-N-13] keygen store-kind fail-fast`.

**Acceptance:** integration test green; reading the CLI source shows the validation happens before any side effect.

---

### Prompt N-14 — `serve` mode replay-rejection integration test (depends on v11 1.1)

**Goal:** prove B1–B4 in an end-to-end test, not just unit tests.

**Prompt body:**

> After v11 1.1 lands, add `crates/invariant-cli/tests/serve_replay_rejection.rs`. Spin up `invariant serve` on an ephemeral port (use the existing test helper if one exists; otherwise spawn the binary). Submit a valid PCA + command, observe `accept`. Replay the exact same PCA bytes — including signature and sequence — to a fresh session. Assert the verdict is `reject` with reason matching `B1` (session binding) or `B2` (sequence monotonicity). Replay to the same session at a later time and assert `B3` (temporal window) rejection. Submit with a different executor identity and assert `B4` rejection. One commit: `[spec-v12-N-14] serve mode B1-B4 replay rejection`.

**Acceptance:** four assertions, all green; remove any one of the binding checks and the corresponding assertion fails.

---

### Prompt N-15 — `intent` ↔ PCA round-trip property test

**Goal:** intents derived from valid PCAs should always round-trip to the same authority closure.

**Prompt body:**

> Read `crates/invariant-core/src/intent/` and `crates/invariant-cli/src/commands/intent.rs` to understand the current intent extraction. Add a property test using `proptest` (already a workspace dep — verify with `cargo metadata`) that generates random valid PCA chains (use existing test helpers if present), derives the intent, then verifies a command admitted by the original chain is also admitted by the chain reconstructed from the intent. Property must hold for `cases = 256` runs. If it fails, the test must shrink to a minimal counterexample and write it to `crates/invariant-core/tests/regressions/intent_roundtrip_<hash>.json`. One commit: `[spec-v12-N-15] intent ↔ PCA round-trip property test`.

**Acceptance:** test green at `HEAD`; mutating intent serialization in an obvious-but-wrong way breaks at least one shrunk case.

---

### Prompt N-16 — `eval` rubric → guardrail trip integration test

**Goal:** end-to-end coverage for the evaluation pipeline.

**Prompt body:**

> Read `crates/invariant-eval/src/` to understand presets, rubrics, guardrails, and the differ. Add `crates/invariant-eval/tests/pipeline_e2e.rs` that loads the simplest existing preset, runs it against (a) a known-good trace fixture committed under `crates/invariant-eval/tests/fixtures/good_trace.jsonl` and asserts the verdict is `pass`, (b) a known-bad trace fixture (intent mismatch in step 47, say) and asserts the verdict is `fail` with the expected guardrail name. Generate the fixtures from the dry-run simulator if possible; otherwise hand-craft minimal ones. One commit: `[spec-v12-N-16] eval pipeline e2e fixtures and test`.

**Acceptance:** test green; fixtures < 200 lines each.

---

### Prompt N-17 — `--fail-on-audit-error` regression test

**Goal:** the flag from commit `36193ba` must keep working.

**Prompt body:**

> Add a CLI integration test that invokes `invariant validate --audit-path /dev/full --fail-on-audit-error <args>` (Linux-only: gate behind `#[cfg(target_os = "linux")]`; on macOS use `chmod 0444` on a tempdir to force an open-write failure instead). Assert the process exits non-zero with a stderr message that mentions audit failure. Then invoke without `--fail-on-audit-error` and assert the process exits zero (the existing default behavior) but logs the audit error to stderr. One commit: `[spec-v12-N-17] --fail-on-audit-error regression test`.

**Acceptance:** test green on at least Linux CI; documented limitation if macOS path differs.

---

### Prompt N-18 — Coordinator partition-merge soundness fixture

**Goal:** safely merging two partitioned plans must preserve pairwise separation at the boundary.

**Prompt body:**

> Read `crates/invariant-coordinator/src/partition.rs`. Construct a synthetic 4-robot scenario (two arms in partition A, two mobile bases in partition B) where each partition is internally safe and the inter-partition separation at the boundary is exactly the minimum allowed distance. Add a test that merges the two partitions' plans and asserts the merged plan is admitted. Then perturb one robot in partition A by `-ε` (so the merged plan would violate separation) and assert the merged plan is rejected with a typed error pointing at the offending pair. One commit: `[spec-v12-N-18] partition merge soundness at boundary`.

**Acceptance:** test green; ε can be tuned via a const at the top of the test.

---

### Prompt N-19 — CHANGELOG ↔ Cargo.toml version drift CI check

**Goal:** the v0.0.3 bump in `7ad120d` should be reproducible by tooling.

**Prompt body:**

> Add `scripts/check_version_drift.sh` that (a) extracts `version = "x.y.z"` from `Cargo.toml`, (b) asserts `CHANGELOG.md` contains a heading exactly matching `## [x.y.z]` (or `## x.y.z`), (c) when running on a tag-build (i.e., `GITHUB_REF` starts with `refs/tags/v`), asserts the tag's version equals the Cargo version. Wire it into `.github/workflows/ci.yml` as a fast job that runs on every PR. One commit: `[spec-v12-N-19] version drift CI check`.

**Acceptance:** CI passes at `HEAD`; deliberately bumping Cargo without CHANGELOG fails the job locally.

---

### Prompt N-20 — Seed `fuzz/` corpora from real audit fixtures

**Goal:** improve coverage by seeding from realistic input.

**Prompt body:**

> For each `fuzz/fuzz_targets/*.rs`, identify the input shape it consumes. Write a one-shot script `fuzz/seed_corpora.sh` that copies (or generates and copies) at least 8 representative inputs into `fuzz/corpus/<target>/`. For PCA-shaped targets, source from `crates/invariant-core/tests/fixtures/`. For audit-shaped targets, generate a small dry-run campaign and copy the JSONL records. Document the script invocation in `fuzz/README.md`. One commit: `[spec-v12-N-20] seed fuzz corpora from real fixtures`.

**Acceptance:** `cargo fuzz run <target> -- -runs=1000` finds at least one path on each target's seeded corpus.

---

### Prompt P-FINAL — v12 closure verification

**Goal:** declare v12 done.

**Prompt body:**

> When the v12 tracking table below has no `OPEN` rows, run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, the CI lake-build job (v11 5.9), and the determinism fixture (N-3). Produce `docs/spec-v12-verification.md` listing: every prompt's resolution (DONE / ALREADY DONE / DESCOPED with rationale), the commit hash that closed each, the resulting Merkle root for an N-3-style 1 000-episode smoke run, and a one-paragraph "what changed since v11" summary. One commit: `[spec-v12-P-FINAL] verification report`.

**Acceptance:** verification doc present; every v11 + v12 row resolved.

---

## 4. v12 tracking table

Update as prompts complete.

| ID     | Title                                              | Status | Commit / Note |
|--------|----------------------------------------------------|--------|---------------|
| N-1    | Scenario::all() + spec-ID coverage                 | OPEN   |               |
| N-2    | Spec-ID ↔ ScenarioType mapping table               | OPEN   |               |
| N-3    | Per-shard determinism fixture                      | OPEN   |               |
| N-4    | Audit JSONL schema_version                         | OPEN   |               |
| N-5    | Proof-package format_version                       | OPEN   |               |
| N-6    | campaign assemble --resume                         | OPEN   |               |
| N-7    | run_15m_campaign.sh cost ceiling + SIGTERM        | OPEN   |               |
| N-8    | shadow-deployment.md runbook                       | OPEN   |               |
| N-9    | Archive v1–v12 specs under docs/history            | OPEN   |               |
| N-10   | Poisoned-mutex regression test                     | OPEN   |               |
| N-11   | Audit rotation Merkle continuity                   | OPEN   |               |
| N-12   | bridge_handle_line fuzz target                     | OPEN   |               |
| N-13   | keygen --store fail-fast                           | OPEN   |               |
| N-14   | serve mode B1–B4 replay rejection                  | OPEN   |               |
| N-15   | intent ↔ PCA round-trip property test              | OPEN   |               |
| N-16   | eval pipeline e2e                                  | OPEN   |               |
| N-17   | --fail-on-audit-error regression                   | OPEN   |               |
| N-18   | Coordinator partition-merge soundness              | OPEN   |               |
| N-19   | Version drift CI check                             | OPEN   |               |
| N-20   | Seed fuzz corpora                                  | OPEN   |               |
| P-FINAL| v12 closure verification                           | OPEN   |               |

---

## 5. Out of scope for v12

- Live RunPod campaign execution and post-campaign report assembly (deferred until v11 Phases 1–3 + N-1..N-3 close).
- Hardware-attached integration tests for TPM and YubiHSM (require physical devices; covered structurally by v11 4.1 + N-13).
- Reproducible-build attestation (still a v13 candidate).
- Customer onboarding docs.
