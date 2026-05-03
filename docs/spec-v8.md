# spec-v8 — Deep Gap Analysis & Closure Prompts (post-v7 verification)

**Status:** Active
**Date:** 2026-05-01
**Branch context:** `codelicious/spec-spec-15m-campaign-part-4`
**Supersedes:** none (companion to `docs/spec-v7.md`)
**Companion to:** `docs/spec.md`, `docs/spec-15m-campaign.md`, `docs/spec-v7.md`, `docs/public-release-polish.md`

This document is a **fresh deep gap analysis** performed after spec-v7 was authored on the same date. It exists because:

1. Verification against the tree at `HEAD = 9a16dc9` shows that **almost every spec-v7 prompt is still open** — the v7 doc was a plan, not a record of work done. The recent `chunk-06 Category B: Joint Safety` commit added 2,189 lines to `crates/invariant-sim/src/campaign.rs` (category metadata, episode allocation tables) but added **zero new `ScenarioType` variants** to `crates/invariant-sim/src/scenario.rs` (still 22 variants — none of `PositionBoundarySweep`, `VelocityBoundarySweep`, etc. exist). Category B scenarios are not yet executable.
2. Several substantive gaps are **not** captured anywhere in spec-v7 or spec-gaps.md. Phase 8 below is the new work.

Each section is a self-contained Claude Code prompt. Conventions are inherited from spec-v7 §"Conventions used in every prompt". Read those before starting.

---

## Verified ground truth (2026-05-01, after v7)

Confirmed by reading the tree at HEAD `9a16dc9`:

- `crates/invariant-sim/src/scenario.rs` lines 51–120: **22** `ScenarioType` variants. None of B-01..B-08, C-01..C-06, D-01..D-10, E-01..E-06, F-01..F-08, G-03..G-10, H-01..H-06, I-01..I-10 are present as variants. `grep -n 'PositionBoundarySweep\|VelocityBoundarySweep\|TorqueBoundarySweep\|AccelerationRamp\|MultiJointCoordinated\|RapidDirection\|IEEE754\|GradualDrift' crates/invariant-sim/src/scenario.rs` returns **no matches**. The chunk-06 commit added Category B *metadata*, not generators.
- `crates/invariant-core/src/audit.rs` and `crates/invariant-core/src/models/audit.rs`: `grep -n 'session_id\|predecessor_digest\|merkle'` returns **no matches**. spec-v7 prompts 1.1, 1.2, 1.3 are entirely open.
- `crates/invariant-core/src/jcs.rs` and `crates/invariant-core/src/audit/merkle.rs` (or `audit_merkle.rs`): **do not exist**. spec-v7 prompts 1.3 and 1.4 are entirely open.
- `crates/invariant-cli/src/commands/`: 21 files; **no `assemble.rs`**, **no `sign_package.rs`**. There is a `verify_package.rs`, but it cannot verify what no command produces.
- `crates/invariant-core/src/keys.rs` lines 413, 462, 510: `OsKeyringStore`, `TpmStore`, `YubiHsmStore` all return `KeyStoreError::Unavailable`. spec-v7 prompts 3.1 and 3.2 entirely open.
- `crates/invariant-core/src/replication.rs` lines 169, 257, 289: `S3ReplicationSink::publish_batch` and `WebhookSink::publish_witness` return `ReplicationError::Unavailable`. spec-v7 prompts 3.3 and 3.4 entirely open.
- `isaac/envs/` contains exactly one Isaac Lab environment: `cnc_tending.py`. The five envs spec-v7 §5.1 references (`humanoid_walk.py`, `quadruped_locomotion.py`, `dexterous_hand_pinch.py`, `mobile_base_navigation.py`, `bimanual_arms.py`) **do not exist**.
- `profiles/` contains 35 entries (34 JSON + 1 URDF), matching the campaign claim.
- `crates/invariant-cli/src/commands/audit_gaps.rs` exists — a sequence-gap detector that reads `SignedAuditEntry` from JSONL. Not referenced in any of the v6/v7 specs. Its semantics need to be reconciled with the spec-v7 §1.2 multi-source sequence model where gaps are *allowed*.
- The Cargo workspace has six members. **`invariant-ros2/` (a ROS 2 / colcon package with `package.xml`, `CMakeLists.txt`, `msg/`, `launch/`, `test/`) is in the repo root but is NOT a workspace member and is not built or tested by CI.** No spec acknowledges it.
- `.github/workflows/` has `ci.yml` and `release.yml` only. No `nightly-fuzz.yml`, no `cargo-deny.yml`, no MSRV matrix, no `cargo udeps` job. spec-v7 prompt 6.2 is open.
- `formal/` contains a Lean 4 project (`Invariant.lean`, `lakefile.lean`). Not referenced in v6/v7. Its proof obligations vs. the Rust validator are unverified.
- `crates/invariant-fuzz/` exists with cognitive/protocol/system attack modules but **no `fuzz_targets/` directory and no `cargo-fuzz` config anywhere in the repo**. spec-v7 prompt 4.5 is entirely open.
- `examples/demo.sh` and `campaigns/*.yaml` exist; the YAML campaigns reference scenarios by snake_case name. Need to verify the scenarios they reference still exist after Phase 2 lands (currently they all do, because Phase 2 hasn't started).
- `scripts/run_15m_campaign.sh` exists; **does not** call `invariant campaign assemble` (because it doesn't exist) and **does not** call `verify-package`. spec-v7 prompt 7.1 is partially open.
- No `invariant campaign generate-15m` CLI subcommand exists (`grep` returns nothing). The function `generate_15m_configs` exists in `campaign.rs` but is not wired to clap.

The remainder of this document organizes closure work as Claude Code prompts. **Phase 8 contains gaps not present in spec-v7.** Phases 1–7 here are short pointers back to spec-v7 with verified status; do not duplicate the prompts — execute v7's prompt and mark closure in v7's tracking table.

---

## Phase A — Reconciliation (P0, do this first)

### Prompt A.1 — Update spec-v7 tracking table with verified status

You are reconciling the v7 plan with the current tree before any new work begins.

**Read first:** `docs/spec-v7.md` §"Tracking" (the table at the bottom). `docs/spec-v8.md` §"Verified ground truth (2026-05-01, after v7)".

**Task:** For each row in the v7 tracking table, look at the actual code paths cited in that prompt and decide one of three states: `OPEN`, `PARTIAL: <one line>`, or `CLOSED: <commit-sha>`. Edit the v7 table in place to add a `Status` column populated with these values. Do not modify the prompt bodies. Pay special attention to:

- **2.1 (Category B)** — the chunk-06 commit message claims completion, but `scenario.rs` has no new variants and no new generators for B-01..B-08. Mark `PARTIAL: campaign metadata wired in commit 9a16dc9; ScenarioType variants and generators still missing`.
- **1.1, 1.2, 1.3, 1.4, 1.5** — confirm `OPEN` by grepping for `session_id`, `predecessor_digest`, `merkle`, `jcs`, `assemble.rs` and showing they return no relevant hits.
- **3.1, 3.2, 3.3, 3.4** — confirm `OPEN` by reading the `Unavailable` returns.
- **5.1** — `PARTIAL` only if any of the five new envs exist in `isaac/envs/`; otherwise `OPEN`.

**Acceptance:** the v7 tracking table now shows a per-prompt status column. One commit, message `gap-A1: reconcile v7 tracking with HEAD`.

---

### Prompt A.2 — Resolve the chunk-06 Category B mismatch

**Read first:** commit `9a16dc9` (`git show 9a16dc9 --stat`); `crates/invariant-sim/src/campaign.rs` lines for `category_b`; `crates/invariant-sim/src/scenario.rs` lines 51–220; spec-v7 §"Prompt 2.1".

**Problem:** The chunk-06 commit allocates 1,500,000 episodes to Category B with per-scenario tables in `campaign.rs`, but the eight scenario types it allocates to **do not exist** as `ScenarioType` variants. If `generate_15m_configs` is run today against the new metadata, it must currently fall back to a stub or panic. Verify which.

**Task:**
1. Run `cargo test -p invariant-robotics-sim -- --nocapture campaign` and capture the failure modes.
2. If `generate_15m_configs` references B-01..B-08 by an enum that does not include them, decide one of:
   - (preferred) Implement spec-v7 §2.1 in full (8 new variants + generators + 24 dry-run tests) **before** the chunk-06 metadata is merged to main, so the metadata has something to point at.
   - (fallback) Revert the Category B metadata block in `campaign.rs` until the generators land. The spec is only credible if `generate_15m_configs` returns runnable configs.
3. Whichever path you take, leave `campaign.rs::generate_15m_configs` in a state where `cargo test` passes and `invariant campaign --help` does not advertise scenarios that cannot be generated.

**Acceptance:** `cargo test` green; one commit per choice with message `gap-A2: implement Category B generators` or `gap-A2: revert Category B metadata until generators land`.

---

## Phase B — Pointer to spec-v7 (do not re-prompt; execute v7)

For the gaps already enumerated in spec-v7, do **not** rewrite the prompts here. Use the v7 prompts directly. Cross-reference, with verified status:

| v7 Prompt | Status (2026-05-01) | Notes |
|-----------|---------------------|-------|
| 1.1 B1–B4 audit binding | OPEN | no `session_id`/`executor_id`/`monotonic_nanos` in audit.rs |
| 1.2 A3 predecessor digest | OPEN | no `predecessor_digest` anywhere |
| 1.3 Merkle tree | OPEN | no `audit/merkle.rs` |
| 1.4 Ed25519 + JCS sign | OPEN | no `jcs.rs`; proof_package has no `signature` field |
| 1.5 `campaign assemble` | OPEN | no `commands/assemble.rs` |
| 2.1 Category B (8) | PARTIAL | metadata only; generators absent |
| 2.2–2.11 Categories C–N | OPEN | no new variants for any |
| 2.12 generate_15m_configs to 106 | BLOCKED on 2.1–2.11 |
| 3.1 OS keyring | OPEN | stub returns Unavailable |
| 3.2 TPM/YubiHSM | OPEN | stubs |
| 3.3 S3 sink | OPEN | stub |
| 3.4 Webhook sink | OPEN | stub |
| 4.1 Bridge bounded reads | LIKELY-CLOSED | commit `7ad120d` "harden bridge with bounded reads" — verify in Prompt 8.1 below |
| 4.2 Profile schema validator | OPEN | no `validate_consistency` method on `RobotProfile` |
| 4.3 Profile end_effectors/environment backfill | LIKELY-CLOSED | commit `274f8dc` claims this; verify in Prompt 8.2 below |
| 4.4 Validator property tests | OPEN | no `proptest` in core |
| 4.5 cargo-fuzz targets | OPEN | no `fuzz/` directory exists |
| 4.6 Dead-code/TODO sweep | OPEN | not run |
| 5.1 New Isaac envs | OPEN | only cnc_tending.py exists |
| 5.2 Differential regression suite | OPEN | not present |
| 6.1 Compliance matrix doc | OPEN | not present |
| 6.2 CI matrix expansion | OPEN | only ci.yml + release.yml |
| 6.3 Reconcile public-release-polish.md | OPEN | not done |
| 7.1 RunPod launcher | PARTIAL | `scripts/run_15m_campaign.sh` exists but does not call assemble/verify-package |
| 7.2 RC PR | BLOCKED on everything |

Execute these from spec-v7 directly. The remaining phases below are NEW gaps.

---

## Phase 8 — New gaps not captured in spec-v7

### Prompt 8.1 — Verify or close the bridge-read-bound regression

**Read first:** commit `7ad120d` (`git show 7ad120d -- crates/invariant-sim/src/isaac/`); `crates/invariant-sim/src/isaac/bridge.rs`; spec-v7 §"Prompt 4.1".

**Task:** spec-v7 §4.1 says "verify that commit did not already fix this; if it did, retire this prompt." Do that verification. Specifically:

1. Find the read loop. Confirm it uses `BufRead::take(MAX_LINE).read_until(...)` or equivalent, not unbounded `read_line`.
2. If yes, write a regression test at `crates/invariant-sim/tests/bridge_oversize_frame.rs` that pipes a 4 MiB stream with no newline through the bridge and asserts the bridge errors within bounded memory **and** the connection is dropped.
3. Mark v7 prompt 4.1 `CLOSED: 7ad120d` in the v7 table and add this regression test as the closing artifact.
4. If no — re-open as v7 prompt 4.1 and execute it.

**Acceptance:** one commit either closing v7-4.1 with a new regression test, or executing v7-4.1.

---

### Prompt 8.2 — Verify the profile end_effectors/environment backfill is complete

**Read first:** commit `274f8dc`; every file under `profiles/*.json`.

**Task:** Write a one-off auditor (in `tests/profile_schema_complete.rs` of `invariant-core` — keep, don't delete) that walks `profiles/*.json` and asserts every profile has both `end_effectors` and `environment` populated with non-empty objects. spec-v7 §"Verified ground truth" line says "several profiles still lack `end_effectors` and `environment` schema blocks despite commit `274f8dc`". Confirm that observation by listing offenders in the test failure message. Then either:

- Backfill the missing blocks (preferred path; one commit per profile, message `gap-8.2: profile X end_effectors+environment`), or
- Document in the test why a particular profile cannot have these blocks (extremely rare; expect zero).

**Acceptance:** the auditor test is green; spec-v7 §4.3 marked `CLOSED`.

---

### Prompt 8.3 — Add `invariant-ros2` to CI or remove it

**Read first:** `invariant-ros2/package.xml`, `invariant-ros2/CMakeLists.txt`, `invariant-ros2/msg/`, `invariant-ros2/test/`. The repo root `Cargo.toml` does **not** include `invariant-ros2/` as a member. CI does not build it. No spec mentions it.

**Problem:** A ROS 2 colcon package exists in the repo with no documentation, no build coverage, and no spec coverage. It is either (a) an early integration artifact that should be deleted, or (b) a real interface surface that needs to be in CI and in the spec.

**Task:**
1. Read every file under `invariant-ros2/` and decide which case applies. Look for: dependencies on `invariant-core`/`invariant-cli`, recently-modified files, and whether `msg/` files refer to types defined in `invariant-core`.
2. If (a): delete the directory. One commit `gap-8.3: remove unused invariant-ros2 colcon package`.
3. If (b):
   - Add a `.github/workflows/ros2.yml` workflow that runs `colcon build` and `colcon test` against ROS 2 Humble in a container.
   - Add a section to `docs/spec.md` describing the ROS 2 surface, the topics/services exposed, and how it relates to `invariant-cli serve`.
   - Add an integration test that publishes a sample command on the relevant topic and asserts validation passes/fails as expected.

**Acceptance:** one of the two outcomes shipped, with rationale in the commit message. CI is no longer silently ignoring an entire directory.

---

### Prompt 8.4 — Reconcile `audit-gaps` with the multi-source sequence model

**Read first:** `crates/invariant-cli/src/commands/audit_gaps.rs`; `crates/invariant-core/src/audit.rs` sequence model; spec-v7 §"Prompt 2.7" line "per-source monotonic, gaps allowed".

**Problem:** `invariant audit-gaps` flags any non-contiguous sequence as a gap. The spec model is *per-source monotonic with gaps allowed across sources*. So the current detector will produce a flood of false positives once multi-source PCA chains are in use.

**Task:**
1. Read `audit_gaps.rs` end-to-end. Its current behavior treats sequence as a single global counter.
2. Either teach it to bucket per `executor_id` / source identifier (after spec-v7 §1.1 lands, since that introduces `executor_id`) and only report gaps within a bucket, or — if gaps are *allowed* per the spec everywhere — replace the tool with a "show-me-the-sequence-distribution" reporter and document why a "gaps detector" is the wrong concept.
3. Update `docs/spec.md` §10.4 (the section the file references) to match whichever behavior you chose.
4. Add unit tests for: same-source contiguous (no gaps), same-source missing seq (gap reported), cross-source interleaving (no gap reported).

**Acceptance:** clarity. The spec, the CLI, and the tests agree on what a "gap" means.

---

### Prompt 8.5 — Determinism contract for the campaign harness

**Read first:** `crates/invariant-sim/src/campaign.rs`, `scenario.rs`, `orchestrator.rs`, `injector.rs`. spec-v7 §"Pattern for every scenario in this phase" requires determinism.

**Problem:** The campaign harness must be byte-reproducible given a seed; otherwise the proof package is not a proof, it is just data. Today many scenario generators use `rand::thread_rng()` (or equivalent process-global RNG) implicitly. There is no test that asserts byte-equality across two runs.

**Task:**
1. Audit `crates/invariant-sim/` for every direct or transitive use of `thread_rng`, `SystemTime::now`, `Instant::now` (when used for randomness), or any other ambient-state source. Record findings in the commit body.
2. Establish a single `CampaignRng` (a `ChaCha20Rng` seeded from a per-episode `episode_seed: u64`) and thread it through all generators. Forbid `thread_rng` in `crates/invariant-sim/src/` via a `clippy.toml` rule or a `#![deny(...)]` lint where feasible.
3. Add an integration test `crates/invariant-sim/tests/determinism.rs` that runs a 100-episode dry-run campaign twice with the same seed and asserts byte-equality of the output `audit.log`, `seeds.json`, and `summary.json`.
4. Document the seed → episode mapping (suggest `episode_seed = blake3(campaign_id || shard_id || episode_index)`) in `crates/invariant-sim/src/campaign.rs` doc-comment.

**Acceptance:** determinism test green, lint enforces the rule. This unblocks the 15M proof claim.

---

### Prompt 8.6 — Streaming hash regression coverage

**Read first:** commit `7ad120d` mentions "streaming hashes". Find the implementation by `git show 7ad120d -- crates/invariant-core/src/audit.rs` and grep for `Hasher` or `streaming`.

**Task:**
1. Verify whether the audit hash preimage is constructed via streaming (`sha2::Sha256::update`) or by buffering the whole preimage (`Sha256::digest(&buf)`). For large payloads (e.g. L-02 1M-step episodes), buffering blows memory.
2. Add a test that hashes a 100 MiB payload entry without exceeding 16 MiB resident-set increase (use `crates/invariant-core/tests/audit_streaming_memory.rs`; gate with `#[ignore]` if needed but include the assertion).
3. If the implementation buffers, refactor to streaming. The hash output bytes must match before/after — add a known-vector test against a small golden hash.

**Acceptance:** memory test passes; one commit `gap-8.6: streaming audit hash regression`.

---

### Prompt 8.7 — `serve` hardening surface tests

**Read first:** `crates/invariant-cli/src/commands/serve.rs`; commit `33c3e1f` "serve hardening tests"; `crates/invariant-core/src/digital_twin.rs` (the poisoned-mutex fix from the same commit).

**Task:** Audit `serve.rs` for:
- Body size limits on incoming validation requests.
- Per-IP rate limits.
- Connection caps.
- Request timeouts.
- Behavior on `Mutex` poisoning beyond `digital_twin.rs` (replication.rs, audit.rs).

For each missing protection, add a test under `crates/invariant-cli/tests/serve_hardening_*.rs`. Reuse `wiremock`/`hyper` patterns. The goal is a documented threat surface — a single doc-comment block on `serve::run` listing each protection and the test that exercises it.

**Acceptance:** every protection has a test; `serve::run` doc-comment lists them.

---

### Prompt 8.8 — Cycle the formal Lean proofs against the validator

**Read first:** `formal/Invariant.lean`, `formal/Invariant/`, `formal/lakefile.lean`. No spec mentions this directory.

**Task:**
1. Document what is proven in Lean today: list every theorem name and one-line summary in a new `formal/PROOFS.md`.
2. For each Lean theorem, identify the Rust function it claims to model. Add a `// formal: proof of <Theorem>` comment above that Rust function.
3. Add `formal/` to CI: a workflow that runs `lake build` on Lean toolchain version pinned in `lean-toolchain`. CI must fail if Lean proofs do not compile.
4. If any Lean theorem is **aspirational** (proves a property the Rust code does not actually satisfy), surface it in a `formal/OPEN_PROOFS.md` with the gap.

**Acceptance:** Lean is in CI; every theorem has a documented Rust counterpart.

---

### Prompt 8.9 — Dependency policy: cargo-deny + SBOM in CI

**Read first:** `deny.toml` (exists); `.github/workflows/ci.yml`; spec-v7 §"Prompt 6.2".

**Task:**
1. Verify `deny.toml` has rules for: yanked deps, GPL/AGPL contamination (assuming MIT is the project license — confirm against `LICENSE`), advisories, and duplicate-version policy.
2. Add `cargo deny check` as a required CI job. Block PRs on advisory failures.
3. Generate an SBOM at release time using `cargo cyclonedx` (or `cargo sbom`); attach to the GitHub release artifacts in `.github/workflows/release.yml`.
4. Document the policy in `SECURITY.md`.

**Acceptance:** `cargo deny check` green; release pipeline emits SBOM; `SECURITY.md` documents the supply-chain stance.

---

### Prompt 8.10 — Public error-type stability review

**Read first:** every `pub enum *Error` in `crates/invariant-core/src/`; the published version (`0.0.3`) in workspace `Cargo.toml`.

**Problem:** The crate is pre-1.0, but the proof-package consumer needs a stable error contract because exit codes and audit-log error strings are part of the verifiable artifact. Today error variants are added/changed freely.

**Task:**
1. Inventory all `pub` error enums and their variants. Output a table in `docs/error-stability.md` listing: enum, variant, when added (`git log -S`), whether it is referenced by any audit-log payload, and whether the variant string is in any test golden fixture.
2. For every error variant referenced by audit-log payloads, add a `#[non_exhaustive]` guarantee and a doc-comment: `// stability: variant string MUST NOT change — appears in audit logs`.
3. Add a test `crates/invariant-core/tests/error_stability.rs` that snapshots every variant's `Display` string. Snapshot file lives in-tree; PR review is the change-control mechanism.

**Acceptance:** any future variant rename trips the snapshot test, forcing a documented decision.

---

### Prompt 8.11 — Wire `invariant campaign generate-15m` to the CLI

**Read first:** `crates/invariant-sim/src/campaign.rs::generate_15m_configs`; `crates/invariant-cli/src/commands/campaign.rs`. spec-v7 §"Prompt 7.1" line 472 references `invariant campaign generate-15m --shards 8` but the subcommand does not exist.

**Task:** Add the subcommand. Flags:
- `--total <N>` (default 15_000_000)
- `--shards <N>` (default 8)
- `--output <DIR>` (writes `shard-0.yaml`..`shard-{N-1}.yaml`)
- `--dry-run` (prints the per-scenario allocation table; writes nothing)
- `--seed <HEX>` (campaign-id seed for the determinism contract from Prompt 8.5; default a date-stamped constant)

The subcommand calls into `generate_15m_configs` and writes one YAML per shard. Output format must be readable by the existing dry-run YAML loader.

**Acceptance:** integration test that invokes the binary with `--total 1000 --shards 4 --dry-run` and asserts the printed allocation sums to 1000 across 4 shards.

---

### Prompt 8.12 — Add a smoke-replay test that closes the loop end-to-end

**Read first:** the architecture: a campaign runs, emits an audit log, the assembler produces a proof package, the verifier validates it. There is no test that exercises this whole loop.

**Task:** Add `crates/invariant-cli/tests/proof_loop_smoke.rs` that:

1. Generates a 100-episode dry-run campaign for one profile, one scenario.
2. Runs it to completion under `tempdir`.
3. Calls `invariant campaign assemble` (Prompt v7-1.5) on the output.
4. Calls `invariant campaign verify-package` on the resulting tarball.
5. Tampers with one byte of the tar (a) inside an audit entry, (b) inside the manifest, (c) inside the signature; for each tamper, asserts `verify-package` exits non-zero with a distinct error message.

**Depends on:** v7 prompts 1.1, 1.2, 1.3, 1.4, 1.5. List those as blockers in the test's doc-comment.

**Acceptance:** loop test green when blockers land. Until then, mark `#[ignore = "blocked on v7-1.1..1.5"]` and the ignore reason.

---

### Prompt 8.13 — Document the PCA chain envelope on the wire

**Read first:** `crates/invariant-core/src/envelopes.rs`; `crates/invariant-core/src/keys.rs`; any test that constructs a real PCA chain.

**Problem:** The campaign N-07 fuzzer in spec-v7 §2.11 wants to corrupt COSE/CBOR PCA-chain envelopes. To fuzz them you have to know what they look like on the wire. The repo has no canonical document of the PCA chain envelope format — encoding, fields, version byte, length limits, what a `Strip` looks like vs. a forged signature, etc.

**Task:** Write `docs/pca-chain-envelope.md` that specifies:
- Outer encoding (COSE_Sign1? raw CBOR? base64 of what?).
- Field-by-field byte layout, with a hex example of a real one-link chain and a real two-link chain.
- Version negotiation rules.
- Maximum envelope size and how to enforce it on read.
- The exact set of malformations N-07 must produce (list ≥10 mutation classes).

Cross-reference from `docs/spec.md` and `docs/spec-15m-campaign.md` §"Category N".

**Acceptance:** spec-v7 §2.11 N-07 has something to implement against.

---

### Prompt 8.14 — Reconcile `docs/spec-gaps.md` with v7 and v8

**Read first:** `docs/spec-gaps.md` (561 lines, pre-existing); `docs/spec-v7.md`; this file.

**Task:** Walk every gap in `spec-gaps.md`. For each:
- If it is now closed by a commit, mark it `CLOSED: <sha>`.
- If it duplicates a v7 or v8 prompt, mark it `→ v7 X.Y` or `→ v8 8.Z`.
- If it is genuinely unique and still open, lift it into a new `Phase 9` of this file as a fresh prompt and remove the duplicate from `spec-gaps.md`.

End state: `spec-gaps.md` is either deleted (if fully reconciled) or contains only historical context with a header `Status: superseded by spec-v7.md and spec-v8.md`.

**Acceptance:** no orphaned gap docs. One source of truth per active gap.

---

### Prompt 8.15 — Public-release polish reconciliation (executes v7 §6.3)

**Read first:** `docs/public-release-polish.md` and this document.

**Task:** spec-v7 §6.3 describes this work but defers it. Do it now:

1. For every item in `public-release-polish.md`, classify as `DUP-OF-V7-X.Y`, `DUP-OF-V8-8.Z`, `CLOSED: <sha>`, or `NEW`.
2. Remove duplicates from `public-release-polish.md`.
3. For each `NEW` item, add a fresh prompt in this document under `Phase 9`.
4. Replace `public-release-polish.md` with a one-paragraph pointer to spec-v7 + spec-v8.

**Acceptance:** one place to look for remaining release-blocking work.

---

### Prompt 8.16 — Threat-model document refresh

**Read first:** `crates/invariant-core/src/threat.rs`; `SECURITY.md`; the attack categories implemented in `crates/invariant-fuzz/`.

**Task:** Produce `docs/threat-model.md` (STRIDE-style) covering: protocol attacks, system attacks (RNG manipulation, replay, time skew), cognitive attacks (prompt injection, gradual drift, distraction flooding), supply-chain (covered in Prompt 8.9), and physical-side-channel (out of scope — say so explicitly). For each threat, cite the validator P/A invariant that mitigates it and the fuzz scenario that exercises it. Cross-link to the campaign categories.

**Acceptance:** every fuzz module under `crates/invariant-fuzz/` has at least one corresponding row in the threat model with a mitigation citation.

---

### Prompt 8.17 — Campaigns YAML schema validation

**Read first:** `campaigns/*.yaml`; the YAML loader in `crates/invariant-sim/src/`.

**Problem:** The 14 campaign YAMLs reference scenarios by snake_case name. After Phase 2 lands new scenarios and possibly renames old ones, these YAMLs will break silently — there is no schema check that runs against them.

**Task:**
1. Add a `tests/campaigns_load.rs` integration test in `invariant-sim` that loads every `campaigns/*.yaml` and asserts it parses, every referenced scenario name resolves to a `ScenarioType`, every profile name resolves to a builtin, and every numeric field is in a sensible range.
2. Wire this into CI as part of the standard `cargo test` run (no special features).

**Acceptance:** breaking a campaign YAML breaks CI immediately, not at run time.

---

### Prompt 8.18 — `eval` and `differ` documentation gap

**Read first:** `crates/invariant-eval/src/{presets,rubric,guardrails,differ}.rs`. There is no user-facing doc explaining how presets compose with rubrics, what guardrails do, or the differ semantics.

**Task:** Add `docs/eval.md` covering:
- The preset → rubric → guardrail → differ pipeline with a worked example.
- Rubric rule semantics (any/all/threshold, tie-breaking).
- The differ's exact invariants (deterministic? stable across struct field order? pinned to JCS?).
- A trace → rubric-score example with hand-computed numbers a reader can verify.

**Acceptance:** a new contributor can read `docs/eval.md` and understand the pipeline without reading the source.

---

### Prompt 8.19 — Coordinator multi-robot test surface

**Read first:** `crates/invariant-coordinator/src/{monitor,partition}.rs`; `crates/invariant-coordinator/Cargo.toml`. Spec coverage of multi-robot is in `docs/spec.md` §"Coordinator" (locate exactly).

**Problem:** Coordinator covers separation/partitioning but the campaign categories reference multi-robot scenarios (A-08, J-08). Coverage of the *coordinator path* in those scenarios is unverified.

**Task:**
1. Inventory the public API of `invariant-coordinator`: separation checks, partition logic, the events it emits.
2. Ensure A-08 and J-08 scenarios actually exercise the coordinator (search `crates/invariant-sim/` for any reference to `invariant-coordinator` — likely zero today).
3. Add a coordinator integration test that runs a 2-robot scenario, generates a separation violation, and asserts the validator rejects via the coordinator path (not just the per-robot path).

**Acceptance:** coordinator is on the call graph from at least one campaign scenario and has integration coverage.

---

### Prompt 8.20 — Self-verification subcommand audit

**Read first:** `crates/invariant-cli/src/commands/verify_self.rs`.

**Task:** `invariant verify-self` is referenced in spec but its actual checks are not documented. List them. Compare to the spec's "self-test" requirements. Gap-fill missing checks. The output of `verify-self` should include: binary SHA-256, embedded build profile, commit hash, and a one-line summary per built-in profile load. Add an integration test that runs the subcommand and asserts the binary hash matches `sha256sum` of the test binary.

**Acceptance:** `invariant verify-self` is a credible self-test, and its output is part of the proof package (cross-link to v7 §1.5 step 5).

---

## Tracking

When you finish a Phase 8 prompt, append to the table below.

| Prompt | Closed by commit | Date | Notes |
|--------|------------------|------|-------|
| A.1 | | | |
| A.2 | | | |
| 8.1 | | | |
| 8.2 | | | |
| 8.3 | | | |
| 8.4 | | | |
| 8.5 | | | |
| 8.6 | | | |
| 8.7 | | | |
| 8.8 | | | |
| 8.9 | | | |
| 8.10 | | | |
| 8.11 | | | |
| 8.12 | | | |
| 8.13 | | | |
| 8.14 | | | |
| 8.15 | | | |
| 8.16 | | | |
| 8.17 | | | |
| 8.18 | | | |
| 8.19 | | | |
| 8.20 | | | |

For Phase 1–7 (spec-v7) closure, edit the v7 tracking table — do not duplicate here.
