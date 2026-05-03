# spec-v9 — Gap Closure Prompts (post-v8 deep audit)

**Status:** Active
**Date:** 2026-05-01
**Branch context:** `codelicious/spec-spec-15m-campaign-part-4`
**Companion to:** `docs/spec.md`, `docs/spec-15m-campaign.md`, `docs/spec-v7.md`, `docs/spec-v8.md`, `docs/spec-gaps.md`

This document is a fresh deep-gap audit performed at HEAD `9a16dc9`. It re-verifies the open gaps tracked in spec-v7/spec-v8/spec-gaps and adds newly discovered gaps. Every section below is a self-contained **Claude Code prompt** — paste the section into a fresh agent. Prompts contain no code snippets; they describe intent, files, acceptance criteria, and tests. The implementer is expected to read existing code before editing.

## Conventions used in every prompt

1. **Read before writing.** Open the cited files end-to-end before editing. If a struct, function, or test referenced here has been renamed, prefer the current name and note the divergence in your commit message.
2. **One commit per prompt.** Commit message prefix `[spec-v9 P<n>.<m>]`. Never push to `main`.
3. **Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` before declaring done.** If you add a feature flag, also run `cargo test --workspace --all-features`.
4. **Determinism.** No `thread_rng()`, no `SystemTime::now()` in scenario or campaign code. Use the seed plumbed in.
5. **No backwards-compat shims.** Pre-1.0; rename freely. Update call sites, do not keep a deprecated alias unless asked.
6. **Tests next to behavior.** Unit tests in the same file. Integration tests in `crates/<crate>/tests/`.
7. **Don't fabricate spec citations.** If a referenced line range looks wrong, re-grep the spec file and update the citation in your commit message.
8. **Stop at the prompt boundary.** Do not opportunistically fix unrelated gaps; file them as new prompts at the end of this doc.

The prompts are ordered by the closure sequence on the critical path to a 15M-episode proof package. Phase 1–2 are blocking. Phase 3 is parallelizable across multiple agents. Phase 4–5 is release hygiene.

---

## Phase 1 — Audit chain integrity (BLOCKING)

These prompts close the structural cryptographic gaps in the audit chain. None of the proof-package work is meaningful until Phase 1 lands.

### Prompt 1.1 — Add execution-binding fields B1–B4 to `AuditEntry`

**Goal:** Make every audit entry bind to a session, an executor identity, a monotonic clock, and a wall-clock timestamp, so cross-session replay and executor impersonation are structurally impossible.

**Context:** spec.md §3.3 (lines 394–403) defines invariants B1–B4. spec-v7 Prompt 1.1 specifies the canonical hash preimage order. The current `AuditEntry` in [crates/invariant-core/src/models/audit.rs](crates/invariant-core/src/models/audit.rs) has only `sequence: u64` and `previous_hash: String`.

**Read first:**
- `crates/invariant-core/src/models/audit.rs` (struct + serde)
- `crates/invariant-core/src/audit.rs` (logger, hashing, append path)
- `docs/spec.md` §3.3 and §10
- `docs/spec-v7.md` Prompt 1.1

**Do:**
1. Add fields `session_id: [u8; 16]`, `executor_id: String`, `monotonic_nanos: u64`, `wall_clock: chrono::DateTime<Utc>` to `AuditEntry`. Decide on serde representations that round-trip cleanly (hex for `session_id`, RFC3339 for wall clock).
2. Update `AuditEntry::compute_hash` to fold these fields into the SHA-256 preimage in spec-v7 §1.1's exact order. Centralize the preimage construction in a single function with a doc-comment that lists field order so the formal model and audit verifier have one source of truth.
3. Plumb the new fields through `AuditLogger::append`. The logger is constructed with a session id, an executor id, and a monotonic clock source; reject append if the supplied monotonic value is not strictly greater than the previous entry's value with a new `AuditAppendError::ClockRegression` variant.
4. Update every existing test fixture and call site so the workspace compiles.
5. Add unit tests:
   - clock regression rejected
   - session-id mismatch on append rejected
   - hash preimage order is stable (snapshot test on a fixed entry)
   - 16-thread × 1k-entry concurrent append produces a strictly monotonic sequence with no collisions
6. Update `crates/invariant-cli/src/commands/audit_gaps.rs` so its multi-source sequence model is aware of `executor_id` (the gap-detector should partition by executor — gaps within an executor are real, gaps across executors are not).

**Acceptance:**
- `cargo test --workspace` green.
- New error variant referenced in `docs/error-stability.md` (create if missing — see Prompt 5.5).
- Concurrent-append test deterministically passes 100 runs.

---

### Prompt 1.2 — Add `predecessor_digest` to PCA chain (A3 binding)

**Goal:** Make the PCA chain non-spliceable by binding each hop to the SHA-256 of its predecessor's canonical bytes.

**Context:** spec.md lines 230–232 and 388–392 require PoC_i to be a "valid causal successor of PCA_{i-1}". `verify_chain` in [crates/invariant-core/src/authority/chain.rs](crates/invariant-core/src/authority/chain.rs) currently checks signatures, monotonic narrowing, and `p_0` immutability — it does not enforce a digest binding. Cross-chain splice (campaign attack G-09) is not structurally prevented.

**Read first:**
- `crates/invariant-core/src/authority/chain.rs` (whole file)
- `crates/invariant-core/src/models/authority.rs` (Pca struct)
- spec.md §3.2 and §3.3
- spec-v7 Prompt 1.2

**Do:**
1. Add `predecessor_digest: [u8; 32]` to `Pca`. Genesis hop uses all-zeros. Update serde, canonical-bytes serialization, and signature payload accordingly.
2. Update `verify_chain` to check `hop[i].predecessor_digest == sha256(canonical_bytes(hop[i-1]))` after the existing checks. On mismatch return a typed `AuthorityError::PredecessorDigestMismatch { index }`.
3. Update every helper that constructs PCA chains (test builders, fuzz harness, examples) to compute the digest correctly.
4. Add `AuditLogger::resume(predecessor_digest: [u8; 32])` so a restarted process binds to its prior chain head. Reject resume if the on-disk last-entry digest does not match.
5. Tests:
   - `g09_cross_chain_splice_rejected` — attempt to substitute a hop from chain B into chain A; verify error.
   - genesis chain accepts all-zero predecessor.
   - resume with correct predecessor succeeds; with wrong predecessor errors.
   - tamper one byte of a non-final hop; subsequent verification fails at that index.

**Acceptance:** Workspace builds; new tests pass; existing chain fuzz suite still passes.

---

### Prompt 1.3 — Implement RFC 6962 Merkle tree over audit entries

**Goal:** Provide an inclusion-provable Merkle root over the audit JSONL, so an auditor with a tampered partial log can detect the tampering without the original.

**Context:** spec-15m-campaign.md §371–407 mandates `audit/merkle_root.txt` in the proof package. spec-v7 Prompt 1.3 specifies RFC 6962 with domain separators. No Merkle implementation exists in the tree today.

**Read first:**
- `crates/invariant-core/src/audit.rs` (entry layout)
- `crates/invariant-core/src/proof_package.rs`
- spec-v7 Prompt 1.3
- RFC 6962 §2.1 (the leaf/inner hashing rules)

**Do:**
1. Create `crates/invariant-core/src/audit/merkle.rs` (or `audit_merkle.rs` if module structure prefers). Implement RFC 6962 with domain separator `0x00` for leaves and `0x01` for inner nodes.
2. Public surface: `merkle_root(entries: &[Entry]) -> [u8;32]`, `inclusion_proof(entries, index) -> Vec<[u8;32]>`, `verify_inclusion(root, leaf, index, proof) -> bool`. Use streaming hashing; do not buffer the whole tree if leaves stream from disk.
3. Wire `AuditLogger` to maintain a running tree state so `merkle_root_so_far()` is O(log n) per append.
4. Tests:
   - empty tree → defined zero-root constant; document it.
   - 1, 2, 3, 4, 7, 1024-leaf trees produce roots matching hand-computed test vectors.
   - inclusion proof verifies for every leaf in a 1024-leaf tree; tampering any byte breaks verification.
   - streaming variant matches batch variant for the same input.

**Acceptance:** Module covered, root constants checked into the test as fixtures, no use of `std::collections::HashMap` in the hot path.

---

### Prompt 1.4 — Sign proof-package manifest and write `merkle_root.txt`

**Goal:** Make the proof package self-verifying with a single trust root.

**Context:** [crates/invariant-core/src/proof_package.rs](crates/invariant-core/src/proof_package.rs) at line 241 documents the manifest as "unsigned — caller signs if keys are available." No caller does. The existing `ProofPackageManifest` has `file_hashes: HashMap<String, String>` only.

**Read first:** `crates/invariant-core/src/proof_package.rs` (entire file), `crates/invariant-core/src/keys.rs` (Ed25519 surface).

**Do:**
1. Add `merkle_root: String` (hex) and `manifest_signature: String` (hex Ed25519 over canonical-JSON of all other fields) to `ProofPackageManifest`. Define a precise canonicalization (sorted keys, no whitespace, fixed numeric encoding) — reuse JCS from spec-v7 if it has landed; otherwise implement minimum viable JCS in a sibling module.
2. In `proof_package::assemble`, after writing the audit JSONL, compute the Merkle root from Prompt 1.3, write it to `audit/merkle_root.txt` (hex with trailing newline), populate the field in the manifest, then sign the manifest with the supplied Ed25519 signing key.
3. Update `verify_package.rs` to: rebuild the Merkle tree from the JSONL on disk, compare to `merkle_root.txt`, compare to the manifest field, then verify the manifest signature using the campaign's public key (path passed via flag, defaulting to `${INVARIANT_PACKAGE_PUBKEY}`).
4. Tests:
   - happy path: assemble + verify-package succeeds.
   - flip a byte in a JSONL entry; verify-package rejects with `MerkleRootMismatch`.
   - flip a byte in `merkle_root.txt`; rejects.
   - flip a byte in the manifest; signature verification fails.
   - mismatched public key; signature verification fails.

**Acceptance:** Round-trip test on a 100-entry proof package green; tampering tests above all error with distinct, typed errors.

---

### Prompt 1.5 — Wire `invariant campaign assemble` CLI subcommand

**Goal:** Expose the proof-package assembly through the CLI so `scripts/run_15m_campaign.sh` and external runners can produce signed packages.

**Context:** `proof_package::assemble` is an internal API but has no CLI surface. `crates/invariant-cli/src/commands/` has 21 commands; no `assemble.rs`. spec-15m-campaign.md §6 step 6 specifies the flags.

**Read first:** an existing simple CLI command file like `crates/invariant-cli/src/commands/verify_package.rs` for layout and clap conventions.

**Do:**
1. Create `crates/invariant-cli/src/commands/assemble.rs`. Subcommand: `invariant campaign assemble`. Flags: `--shards <DIR>` (multiple), `--output <PATH>`, `--key <PATH>` (Ed25519 signing key), `--public-key <PATH>` (for embedding), `--metadata <KEY=VALUE>` (repeatable, free-form). Exit 0 on success, 2 on input error, 1 on assembly error.
2. Wire to `clap` in `crates/invariant-cli/src/main.rs` under `campaign` subgroup.
3. Integration test in `crates/invariant-cli/tests/assemble_e2e.rs`: generate a 2-shard fixture (10 episodes each), call `assemble`, then call `verify-package`, asserting success. Tamper one fixture file; assert verify-package fails.
4. Update `scripts/run_15m_campaign.sh` to call `invariant campaign assemble` after shards complete, then `invariant verify-package` as a sanity gate.

**Acceptance:** CLI command available; e2e test green; help text reviewed for clarity.

---

## Phase 2 — Scenario coverage (BLOCKING, parallelizable)

[crates/invariant-sim/src/scenario.rs](crates/invariant-sim/src/scenario.rs) currently has 22 `ScenarioType` variants. The 15M campaign requires ~106 scenario slots across categories A–N. Category A (8 scenarios) is implemented. Categories B–N (≈98 scenarios) are not. The `chunk-06 Category B` commit added category metadata to `campaign.rs` but added zero scenario generators — those metadata entries currently allocate episodes to scenarios that do not exist.

The prompts below split the work by category. Each can run in parallel in a worktree. Each prompt is the same shape; do not bundle categories together unless instructed.

### Prompt 2.1 — Implement Category B (Joint Safety, 8 scenarios)

**Goal:** Make the 1,500,000 episodes already allocated to Category B in `campaign.rs` actually executable.

**Context:** spec-15m-campaign.md §3 enumerates B-01..B-08 (boundary sweeps, multi-joint coordinated, rapid direction reversal, IEEE-754 edge values, gradual drift, etc.). The Category B metadata was added to `crates/invariant-sim/src/campaign.rs` in commit `9a16dc9` but the generators were not. `grep -n 'PositionBoundarySweep\|VelocityBoundarySweep' crates/invariant-sim/src/scenario.rs` returns nothing.

**Read first:**
- `crates/invariant-sim/src/scenario.rs` (existing 22 variants, especially Category A generators)
- `crates/invariant-sim/src/campaign.rs` lines that allocate Category B episodes
- spec-15m-campaign.md §3 (full Category B section)

**Do:**
1. For each of B-01..B-08, add a `ScenarioType` variant with descriptive name (e.g. `PositionBoundarySweep`, `VelocityBoundarySweep`, `TorqueBoundarySweep`, `AccelerationRamp`, `MultiJointCoordinatedBoundary`, `RapidDirectionReversal`, `IEEE754EdgeValues`, `GradualDrift` — match the spec text).
2. Implement command-stream generation for each in `ScenarioGenerator::generate_commands`. Use the supplied seed only — no clock-based randomness.
3. For each scenario, write 2–4 positive tests (commands stay within profile limits) and 2–4 adversarial tests (commands cross limits and the validator rejects them with the expected error variant). Tests live in `scenario.rs::tests`.
4. Update the campaign config loader so the YAML names referenced from `campaigns/*.yaml` resolve to the new variants.
5. Run a 100-episode dry-run smoke for each new scenario; assert zero validator panics.

**Acceptance:** All 8 generators implemented and tested; campaign config for Category B parses; dry-run smoke green.

### Prompts 2.2 – 2.11 — Implement Categories C through N

Repeat the Prompt 2.1 template for the remaining categories. Each prompt should target one category, name the scenarios from spec-15m-campaign.md §3, and follow the same acceptance criteria.

- **Prompt 2.2** — Category C (Velocity & Jerk, 6 scenarios)
- **Prompt 2.3** — Category D (Workspace & Geometry, 10 scenarios)
- **Prompt 2.4** — Category E (Self-Collision, 6 scenarios)
- **Prompt 2.5** — Category F (Environment & Payload, 8 scenarios)
- **Prompt 2.6** — Category G (Authority & Replay, 8 remaining; G-01–G-02 already covered)
- **Prompt 2.7** — Category H (Sensor Integrity, 6 scenarios)
- **Prompt 2.8** — Category I (Watchdog & Liveness, 10 scenarios)
- **Prompt 2.9** — Category J (Coordination & Multi-Robot, 8 scenarios)
- **Prompt 2.10** — Category K–L (Cognitive & Protocol Fuzz, 10 scenarios) — overlaps with `invariant-fuzz`; ensure scenarios call into the fuzz crate rather than duplicating logic
- **Prompt 2.11** — Categories M (Hardware Faults, 6 scenarios) and N (Mixed Long-Horizon, 10 scenarios)

For each, the agent must (a) read the relevant spec-15m-campaign.md section, (b) re-verify which generators are missing by `grep`, (c) only add what is genuinely missing, (d) leave one commit per category.

---

## Phase 3 — Simulation surface (parallelizable)

### Prompt 3.1 — Add five Isaac Lab environment classes

**Goal:** Make the campaign actually drive five robot morphologies (humanoid, quadruped, dexterous hand, mobile base, bimanual arm), not just CNC tending.

**Context:** [isaac/envs/](isaac/envs/) currently contains only `cnc_tending.py`. The 15M campaign expects sensor traces from all five morphologies. `crates/invariant-cli/src/commands/campaign.rs:24-35` exits 2 when asked to run live Isaac Lab.

**Read first:** `isaac/envs/cnc_tending.py` (for the existing env contract); `docs/runpod-simulation-guide.md`; spec-15m-campaign.md §3 lines 80–87.

**Do:**
1. Create `isaac/envs/humanoid_walk.py`, `isaac/envs/quadruped_locomotion.py`, `isaac/envs/dexterous_hand_pinch.py`, `isaac/envs/mobile_base_navigation.py`, `isaac/envs/bimanual_arms.py`. Each implements the same `reset(seed) → obs`, `step(cmd) → (obs, info)`, `observe() → SensorPayload` contract as `cnc_tending.py`.
2. Use Isaac Lab built-in robots where possible. Keep the deterministic seed plumbing through every RNG. No `time.time()` for any value that flows into a sensor payload.
3. Build a thin `isaac/run_campaign.py` headless driver that takes a campaign config file (the one produced by `invariant campaign generate-15m`) and writes per-episode JSON traces compatible with `campaign assemble`.
4. Smoke test (1k Category A episodes per morphology) documented in a README in `isaac/envs/`. Smoke does not need to run in CI but should be invokable by a single command in the runpod docs.

**Acceptance:** Five new env files; smoke output schema-validates against the trace schema; `run_campaign.py` produces N JSON files for an N-episode config.

### Prompt 3.2 — Bound bridge reads and add per-connection watchdog

**Goal:** Close GAP-M4 and GAP-M5 from the deep audit. Bridge must not allocate unbounded memory, and a misbehaving second client must not starve the first.

**Read first:** `crates/invariant-sim/src/isaac/bridge.rs` (entire file). Verify whether commit 7ad120d already used `BufRead::take(MAX_LINE)`; if yes, Phase 3.2.a is just a regression test.

**Do:**
1. If reads are not already bounded, replace the read path with `take(MAX_LINE)` + `read_until(b'\n')`. Choose `MAX_LINE = 1 MiB` and document why in a comment.
2. Add per-connection watchdog state. If two clients connect, the second receives `BridgeError::SecondClient` and is closed immediately; the first is unaffected. Make this typed; do not panic.
3. Tests in `crates/invariant-sim/tests/bridge_oversize_frame.rs` and `bridge_second_client.rs`. The oversize test pipes 4 MiB without a newline and asserts the bridge errors and disconnects within 16 MiB resident-set increase.

**Acceptance:** Both regression tests green; bridge module documents its size limits in a header comment.

---

## Phase 4 — Production keys, replication, alerts

### Prompt 4.1 — Implement OS keyring, TPM, and YubiHSM key stores

**Context:** [crates/invariant-core/src/keys.rs](crates/invariant-core/src/keys.rs) lines 419–539 are stubs returning `KeyStoreError::Unavailable`. Spec.md §6.1 (line ~838) requires production backends.

**Do:**
1. Three feature flags: `os-keyring`, `tpm`, `yubihsm`. Default features unchanged.
2. `os-keyring`: use the `keyring` crate; round-trip an Ed25519 signing key. Cover macOS Keychain, Linux Secret Service, Windows Credential Manager. Integration tests gated on `--features os-keyring` and skipped on CI runners that have no keyring; document the skip.
3. `tpm`: use `tss-esapi`; persist keys under the owner hierarchy with caller-provided handle; document attestation requirements separately (do not implement attestation yet).
4. `yubihsm`: use the `yubihsm` crate; session auth via password from env var; key handles persisted by label.
5. Wire `keygen --store=<kind>` to select at runtime; previously-stub paths now route to real backends. Replace stub tests with feature-gated integration tests; keep one test per backend that asserts `Unavailable` is *not* returned when the feature is on.

**Acceptance:** Workspace compiles with `--all-features`; backend-specific tests are gated correctly; SECURITY.md gains a one-paragraph section per backend.

### Prompt 4.2 — Implement S3 audit replication and webhook witness

**Context:** [crates/invariant-core/src/replication.rs](crates/invariant-core/src/replication.rs) lines 257–292 are stubs.

**Do:**
1. `replication-s3` feature: use `aws-sdk-s3`. Object naming `{prefix}/{epoch_ms:013}-{seq:020}.jsonl.zst`. Require SSE-KMS and Object Lock to be configured on the bucket; assert their presence on first push and fail loud if missing.
2. Resume-from-last: store the last-replicated sequence on a small sidecar object so restarts do not re-push.
3. Backoff: exponential with jitter; bounded retry queue with disk spillover under `<state>/replication-spool/`.
4. Webhook witness: POST `{merkle_root, count, signature}` JSON on every Merkle-root rotation. Signature header `X-Invariant-Signature: HMAC-SHA256=<hex>` over the request body using a shared secret loaded from env or keystore.
5. Live tests against MinIO + a local hyper webhook receiver. Chaos: kill the process mid-push and restart; assert no loss and no duplicate within the same sequence.

**Acceptance:** Both sinks return success on the live tests; sidecar resume test green; HMAC verification on receiver side covered.

### Prompt 4.3 — Implement webhook and syslog alert sinks

**Context:** [crates/invariant-core/src/incident.rs](crates/invariant-core/src/incident.rs) lines 175–197 are stubs.

**Do:**
1. Webhook sink: HMAC-SHA256 signed POST with retry queue and disk spillover, mirroring Prompt 4.2's webhook witness — extract a shared `SignedHttpClient`.
2. Syslog sink: RFC 5424 over UDP and TCP+TLS. Carry verdict id and severity in the structured-data field. Connection pool with per-target backoff.
3. Run sinks on a separate Tokio task; the validator hot path enqueues and returns. Document the bounded queue size and the drop policy when full.
4. HIL test against an `rsyslog` Docker container and a local hyper receiver; assert verdicts surface within 1s under nominal load.

**Acceptance:** Hot-path latency unaffected by alert pressure (microbench within 5% of baseline); receivers see signed, parseable messages.

---

## Phase 5 — Release hygiene & documentation

### Prompt 5.1 — Split SR1 / SR2 sensor range checks

**Context:** [crates/invariant-core/src/physics/environment.rs](crates/invariant-core/src/physics/environment.rs) lines 361–427 collapse two distinct invariants (env-state vs. payload sensor range) into a single check named `sensor_range`. Coverage tables key off check names.

**Do:** Split into `check_sensor_range_env` (SR1) and `check_sensor_range_payload` (SR2) with distinct names and `CheckResult` ids. Update registration in `physics/mod.rs:326`. Update compliance/coverage CLI to count them independently. Add tests that assert each name appears in the verdict for the appropriate failure.

### Prompt 5.2 — Profile completeness pass

**Context:** Nine profiles in [profiles/](profiles/) lack `end_effectors`. `agility_digit.json` is a real bug (Digit has hands). Locomotion-only profiles need a `platform_class` declaration to opt out cleanly.

**Do:**
1. Add real `end_effectors` block to `agility_digit.json` (use vendor-published values; cite source in commit message).
2. Add `platform_class: "locomotion-only"` plus `end_effectors: []` to `anybotics_anymal.json`, `quadruped_12dof.json`, `spot.json`, `unitree_a1.json`, `unitree_go2.json`.
3. Add `"adversarial": true` to the four adversarial fixture profiles.
4. Add `invariant validate-profiles --strict` CLI subcommand that fails when a profile permits manipulation but declares no `end_effectors`. Adversarial-flagged profiles are exempt.
5. Wire `validate-profiles --strict` to CI as a required job.

### Prompt 5.3 — Fleet (N-robot) coordinator coverage

**Context:** [crates/invariant-coordinator/](crates/invariant-coordinator/) only has pairwise tests. Spec.md lines 534–538 require fleet-scale.

**Do:** Add a 10-robot integration test (8 arms + 2 mobile bases) running 60s of synthetic scripted traffic. Assert zero false positives, zero missed near-misses on the scripted near-collisions. Add `invariant fleet status` CLI subcommand that aggregates per-robot watchdog state and prints a table.

### Prompt 5.4 — Drive `cargo deny`, SBOM, reproducible build into CI

**Do:**
1. Verify `deny.toml` rules cover yanked deps, GPL/AGPL, advisories, duplicates. If gaps, add.
2. Add `cargo deny check` as a required CI job in `.github/workflows/ci.yml`.
3. Add `cargo cyclonedx` to `.github/workflows/release.yml`; attach SBOM to the GitHub release.
4. Add `scripts/repro.sh` that builds inside the published Dockerfile and asserts the binary digest matches a checked-in `RELEASES.sha256`. Document usage in `SECURITY.md`.
5. Emit `docs/test-count.txt` from CI (`cargo test --workspace 2>&1 | grep "test result"`). Replace hard-coded counts in `README.md`, `CHANGELOG.md`, and any spec doc with a reference to the file.

### Prompt 5.5 — Stable error type catalog

**Do:** Create `docs/error-stability.md`. Walk every `pub enum *Error` in `invariant-core`. Mark variants emitted into audit logs or exit codes as load-bearing; annotate them with `#[non_exhaustive]` and a stability doc-comment. Add `crates/invariant-core/tests/error_stability.rs` snapshotting `Display` strings for every load-bearing variant. Document the bump policy: changing a load-bearing string is a major version bump.

### Prompt 5.6 — Determinism contract for the campaign harness

**Context:** Without byte-reproducibility from a seed, the proof package is data, not proof.

**Do:**
1. Audit the sim crate for `thread_rng()`, `SystemTime::now()`, `Instant::now()` (the latter is fine for timing telemetry but must not flow into recorded traces). Replace with a single seeded `CampaignRng` (ChaCha20Rng) plumbed from `episode_seed: u64`.
2. Add `crates/invariant-sim/tests/determinism.rs`: run 100 episodes twice with the same seed; assert byte-equality of `audit.log`, `seeds.json`, and `summary.json`.
3. CI job runs the determinism test on every PR.

### Prompt 5.7 — Wire `invariant campaign generate-15m`

**Do:** Add the subcommand wrapping the existing `generate_15m_configs` function. Flags: `--total <N>` default 15M, `--shards <N>` default 8, `--output <DIR>`, `--dry-run`, `--seed <HEX>`. Integration test: generate 1k-episode dry-run, assemble, verify-package — end-to-end smoke. Mark the smoke test `#[ignore = "blocked on Phase 1.1–1.5 + Phase 2"]` until blockers land; remove the ignore after.

### Prompt 5.8 — Lean proofs in CI

**Context:** [formal/](formal/) is a Lean 4 project with `1` `sorry` (Authority) and axiomatized hash collision resistance and convex-polygon membership. Not built in CI.

**Do:**
1. Pin Lean toolchain in `lean-toolchain`.
2. Add a non-blocking CI job running `lake build` from `formal/`.
3. Create `formal/PROOFS.md` listing every theorem with status `proved | sorry | axiom` and a link to the Rust function that depends on it (use `// formal: proof of <Theorem>` comments in Rust where possible).
4. Replace the `monotonicity_transitive` `sorry` or descope and document.
5. Soften spec.md §8 from "proves" to "specifies; mechanized proofs in progress" where appropriate.

### Prompt 5.9 — Cargo-fuzz targets

**Context:** [crates/invariant-fuzz/](crates/invariant-fuzz/) has attack modules but no `cargo-fuzz` config.

**Do:** Create `fuzz/` directory with `cargo-fuzz` config. Targets: PCA chain forgery, sensor payload deserialization, command parser. Add `.github/workflows/nightly-fuzz.yml` running for 30 min per target on a schedule; surface findings as issues.

### Prompt 5.10 — ROS 2 disposition

**Context:** [invariant-ros2/](invariant-ros2/) is in the repo root but is not a workspace member and not built or tested.

**Do:** Decide with the user. Default recommendation: delete unless a near-term consumer is identified. If kept, add `.github/workflows/ros2.yml` running `colcon build` in a ROS 2 Humble container and add a `docs/ros2.md` describing the surface. Whichever path is taken, file one PR that resolves the ambiguity.

### Prompt 5.11 — Documentation: threat model, eval pipeline, PCA envelope, compliance matrix

These are independent docs prompts. One commit per doc.

- `docs/threat-model.md`: STRIDE table over protocol, system, cognitive, supply-chain, side-channel categories. Each row cites the invariant id (P/A/B/L) and the campaign scenario id that exercises it.
- `docs/eval.md`: preset → rubric → guardrail → differ pipeline with a worked end-to-end example and a hand-computed trace.
- `docs/pca-chain-envelope.md`: byte-level layout of the on-the-wire PCA envelope, with hex examples for 1-link and 2-link chains, version negotiation rules, and the malformation classes the fuzzer targets.
- `docs/compliance-matrix.md`: every invariant id (P1–P25, A1–A3, B1–B4, L1–L4) → implementing check → covering scenario id(s).

### Prompt 5.12 — Spec consolidation

**Do:** Move `spec-v1.md`..`spec-v6.md` into `docs/history/` with a one-line header at top of each: "Archived YYYY-MM-DD; see docs/spec.md for current spec." `spec.md` becomes the single live spec. `spec-15m-campaign.md` stays as the campaign addendum until scenario coverage completes, then folds into `spec.md`. After every prompt in spec-v7.md / spec-v8.md / spec-v9.md is closed or rejected, delete those files. Update any cross-link in `README.md`, `CONTRIBUTING.md`, and `CLAUDE.md`.

---

## Phase 6 — Verification gate

### Prompt 6.1 — End-to-end proof loop smoke

**Goal:** Continuous green signal that the proof loop is real.

**Do:** Create `crates/invariant-cli/tests/proof_loop_smoke.rs`. Steps:
1. `invariant campaign generate-15m --total 1000 --shards 2 --output <tmp>` (dry-run, deterministic seed).
2. Run the dry-run sim driver against the configs.
3. `invariant campaign assemble --shards <tmp>/shard-* --output <tmp>/proof.tar --key <test-key>`.
4. `invariant verify-package --input <tmp>/proof.tar --public-key <test-pub>` succeeds.
5. Mutate one byte of one audit entry inside the package; rerun verify; assert it errors with `MerkleRootMismatch`.
6. Mutate the manifest signature; assert it errors with `SignatureInvalid`.

This test is the canary. It runs in CI on every PR after Phases 1, 2, 3.1, 5.7 land. While blockers are open, mark `#[ignore = "blocked"]` and reference this prompt.

---

## Tracking

| ID | Title | Phase | Status |
|----|-------|-------|--------|
| 1.1 | B1–B4 execution binding | 1 | open |
| 1.2 | A3 predecessor digest | 1 | open |
| 1.3 | RFC 6962 Merkle tree | 1 | open |
| 1.4 | Signed manifest + merkle_root.txt | 1 | open |
| 1.5 | `campaign assemble` CLI | 1 | open |
| 2.1 | Category B generators | 2 | open |
| 2.2–2.11 | Categories C–N generators | 2 | open |
| 3.1 | Five Isaac Lab envs | 3 | open |
| 3.2 | Bounded reads + per-conn watchdog | 3 | open |
| 4.1 | OS keyring / TPM / YubiHSM | 4 | open |
| 4.2 | S3 replication + webhook witness | 4 | open |
| 4.3 | Webhook + syslog alert sinks | 4 | open |
| 5.1 | SR1/SR2 split | 5 | open |
| 5.2 | Profile completeness | 5 | open |
| 5.3 | Fleet coordinator coverage | 5 | open |
| 5.4 | cargo deny + SBOM + repro | 5 | open |
| 5.5 | Error stability catalog | 5 | open |
| 5.6 | Determinism contract | 5 | open |
| 5.7 | `generate-15m` CLI | 5 | open |
| 5.8 | Lean proofs in CI | 5 | open |
| 5.9 | cargo-fuzz targets | 5 | open |
| 5.10 | ROS 2 disposition | 5 | open |
| 5.11 | Threat / eval / envelope / compliance docs | 5 | open |
| 5.12 | Spec consolidation | 5 | open |
| 6.1 | E2E proof-loop smoke | 6 | open |

Critical path to a credible 15M proof package: 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 2.* (parallel) → 3.1 (parallel) → 5.6 → 5.7 → 6.1. Estimated 8–12 weeks of focused work.
