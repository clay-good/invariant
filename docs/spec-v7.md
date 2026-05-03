# spec-v7 — 15M Campaign Readiness & Gap Closure

**Status:** Active
**Date:** 2026-05-01
**Branch context:** `codelicious/spec-spec-15m-campaign-part-4`
**Supersedes:** `docs/spec-v6.md` (gaps from v6 that remain open are restated here with current line numbers)
**Companion to:** `docs/spec.md`, `docs/spec-15m-campaign.md`

This document is a **deep gap analysis** of the current Rust workspace against the cumulative specs (spec.md → spec-v6.md plus spec-15m-campaign.md) and an **executable closure plan** written as Claude Code prompts.

Each section below is a self-contained prompt you can paste into Claude Code (or invoke via the `Agent` tool with `subagent_type="builder"`). Prompts are ordered so that earlier ones unblock later ones — Phase 2's scenario implementations depend on Phase 1's audit/proof-package surface, etc.

**Conventions used in every prompt:**
- Always run `cargo build`, `cargo test`, and `cargo clippy -- -D warnings` after a change.
- Always read the cited files before modifying them.
- One commit per prompt, message format `gap-NN: <title>` with optional `[part-K]` suffix when the prompt is split across PRs.
- If a prompt says "extend X", first re-read X to see what already exists; do not duplicate.
- Never add backwards-compatibility shims. The repo has no public-API stability commitment yet.
- No `unwrap()` / `expect()` / `panic!` in non-test code unless the invariant is provably unreachable; if it is, leave a one-line comment with the reason.

---

## Verified ground truth (2026-05-01)

These observations were confirmed by reading the tree and form the basis of the gaps below. Line numbers are accurate at HEAD `9a16dc9`.

- `crates/invariant-sim/src/scenario.rs` defines **22 `ScenarioType` variants** (lines 51–120). The 15M campaign spec (`docs/spec-15m-campaign.md`) defines **106 detailed scenarios** (B-01..B-08, C-01..C-06, D-01..D-10, E-01..E-06, F-01..F-08, G-01..G-10, H-01..H-06, I-01..I-10, J-01..J-08, K-01..K-06, L-01..L-04, M-01..M-06, N-01..N-10). Roughly **80 scenarios are unimplemented**. Most of Categories B, C, E, M, N have **zero** wired generators.
- `crates/invariant-sim/src/campaign.rs` has detailed metadata for `category_a` (lines 1217–1450) and a `scenario_categories` enum with descriptive metadata for B–N (lines 986–1206), but **no per-scenario generator wiring beyond Category A** and the 22 enum variants.
- `crates/invariant-core/src/audit.rs` and `models/audit.rs` track `sequence: u64` and a prev-hash chain but have **no `session_id`, no temporal binding, no executor identity, no predecessor digest**. Spec-v6 Phase 1 prompts 1.1 and 1.2 are still **not landed**.
- `crates/invariant-core/src/keys.rs` lines around 413, 462, 510 — OS keyring, TPM, and YubiHSM stores remain documented stubs returning `KeyStoreError::Unavailable`.
- `crates/invariant-core/src/replication.rs` lines around 169, 257, 289 — S3 and webhook replication sinks return `ReplicationError::Unavailable`.
- `crates/invariant-cli/src/commands/` has 23 subcommand files; **no `assemble.rs`** for `invariant campaign assemble` (proof-package builder).
- `proof_package.rs` exists but has **no Merkle root**, **no Ed25519 manifest signature**, **no causal-binding A3**.
- `profiles/` directory contains the 30 real-world JSON files plus 4 synthetic adversarial profiles plus one URDF (`ur10e.urdf`) — total 34 JSON profiles, matching the campaign claim, but several profiles still lack `end_effectors` and `environment` schema blocks despite commit `274f8dc`.
- `crates/invariant-sim/` has only `cnc_tending.py` Isaac Lab env. The spec-v5/v6 references humanoid, quadruped, dexterous-hand, mobile-base envs.
- `crates/invariant-fuzz/` has scenarios but coverage relative to the campaign's 106 scenario IDs is sparse.

---

## Phase 1 — Audit, proof-package, and signing surface (P0)

These gaps are blockers for the 15M campaign because the campaign output **is** a signed, hash-chained, Merkle-rooted, replayable package. Without them we have data, not proof.

### Prompt 1.1 — Implement execution-binding invariants B1–B4

You are closing a P0 safety gap. The cumulative spec defines four execution-binding invariants the audit log must enforce, but only a partial form (prev-hash chain + monotonic sequence) is implemented today.

**Read first:**
- `docs/spec.md` — search for "B1", "B2", "B3", "B4", "execution binding".
- `crates/invariant-core/src/audit.rs`
- `crates/invariant-core/src/models/audit.rs`

**Task:** Extend `AuditEntry` and `AuditLogger` so that every appended entry carries:
- **B1 — Session binding:** a `session_id: [u8; 16]` (UUIDv4-style, generated when the logger is constructed) included in the canonical hash preimage.
- **B2 — Sequence monotonicity:** the existing `sequence` field, but the append path must use a single critical section (a `Mutex` or an `AtomicU64` compare-exchange paired with a write lock for the file) so that two concurrent appends cannot interleave the `seq → preimage → hash → write` steps. Add a regression test that spawns 16 threads each appending 1k entries and asserts no gap, no duplicate, total = 16k. The current code has a TOCTOU window between `self.sequence += 1` and the hash computation — fix it.
- **B3 — Temporal binding:** include a monotonic timestamp (`std::time::Instant`-derived nanos since logger start) **and** a wall-clock `chrono::DateTime<Utc>` in the preimage. Reject append if the wall clock would step backward more than the configured skew tolerance (default 5s) — return a new `AuditAppendError::ClockRegression` variant.
- **B4 — Executor identity:** include `executor_id: String` (operator/process identity) in the preimage. Pass it in via `AuditLogger::new` so it is fixed for the lifetime of the logger.

**Hash preimage order** (document this in a doc-comment on `AuditEntry::compute_hash`):
`previous_hash || sequence_be || session_id || executor_id_len_be || executor_id_bytes || monotonic_nanos_be || wall_clock_rfc3339 || payload_canonical_json`

**Backward compatibility:** none required. Older audit logs without these fields are rejected by the verifier. Update all `AuditEntry` test fixtures.

**Acceptance:**
- New unit tests for each of B1–B4 (4 tests minimum, plus the 16-thread concurrency stress test).
- `cargo clippy -- -D warnings` passes.
- `invariant audit verify` (CLI) still works against a freshly-written log.
- Module-level doc-comment on `audit.rs` documents the four invariants in `# B1 Session`, `# B2 Sequence`, `# B3 Temporal`, `# B4 Executor` subsections.

---

### Prompt 1.2 — Add causal binding A3 (predecessor digest)

**Read first:** `docs/spec.md` for "A3", "causal binding", "predecessor digest"; `crates/invariant-core/src/audit.rs`; any `proof_package.rs` references.

**Problem:** Today the audit chain self-binds (entry N references hash of entry N-1), but there is no binding from a *new* chain back to the most recent entry of the *previous* chain when a logger is rotated or a new session begins. This permits a "chain splice" attack where two valid chains are presented for the same execution.

**Task:**
1. In `AuditLogger::resume(...)` (the function that lets you continue from a known sequence/hash) require an additional parameter `predecessor_digest: [u8; 32]`. Store it on the logger.
2. The first entry produced by `resume` (or the genesis entry from `new`) must include `predecessor_digest` in its hash preimage. For a fresh genesis chain, use `[0u8; 32]`.
3. Verifier (`AuditLogger::verify`) takes a new arg `expected_predecessor: Option<[u8; 32]>`. If `Some`, verify entry 0 used it as predecessor; if `None`, require `[0u8; 32]`.
4. Wire this into the proof package: `manifest.json` records `predecessor_digest` for each chain segment, and `invariant audit verify --predecessor <hex>` is added to the CLI.

**Acceptance:** unit tests for genesis, resume-with-correct-predecessor, resume-with-wrong-predecessor (must fail). Update `crates/invariant-cli/src/commands/audit.rs` for the new flag.

---

### Prompt 1.3 — Merkle tree over audit entries

**Read first:** `crates/invariant-core/src/audit.rs`, `crates/invariant-core/src/proof_package.rs`. Browse `docs/spec-v6.md` Prompt 2.1 — that is the original definition; this prompt restates it because it is still open.

**Task:** Add a new module `crates/invariant-core/src/audit/merkle.rs` (create the directory if `audit` is currently a single file — convert it to a module folder).

- Implement an RFC 6962-style Merkle tree over the **canonical hash** of each audit entry. Use SHA-256.
- Domain separators: `0x00` prefix for leaves, `0x01` prefix for internal nodes. Document this prominently — the lack of domain separation is a classic forgery vector.
- Public API:
  - `pub fn merkle_root(entries: &[AuditEntry]) -> [u8; 32]`
  - `pub fn inclusion_proof(entries: &[AuditEntry], index: usize) -> Vec<[u8; 32]>`
  - `pub fn verify_inclusion(leaf_hash: [u8; 32], index: usize, proof: &[[u8; 32]], root: [u8; 32]) -> bool`
- The proof package's `manifest.json` must record the Merkle root over the entire audit log. The `invariant audit verify` CLI gains a `--merkle-root <hex>` flag that recomputes the root and compares.

**Acceptance:** ≥3 unit tests (single-entry tree, balanced tree, unbalanced tree at non-power-of-two sizes), plus a property test using `proptest` that a randomly-chosen valid proof verifies and any single-bit flip in the proof fails verification.

---

### Prompt 1.4 — Sign the proof-package manifest (Ed25519 + JCS)

**Read first:** `crates/invariant-core/src/proof_package.rs` (current `ProofPackageManifest` struct), `crates/invariant-core/src/keys.rs` (existing Ed25519 key handling).

**Task:**
1. Add fields to `ProofPackageManifest`: `signing_key_fingerprint: String` (SHA-256 of the public key, hex), `signature: Option<String>` (base64 Ed25519, optional only because unsigned drafts must round-trip during construction; final packages must be signed).
2. Implement `sign(&mut self, signer: &dyn KeySigner)` and `verify(&self, verifier: &dyn KeyVerifier) -> Result<(), ProofPackageError>`.
3. The signing preimage is the manifest in **JSON Canonicalization Scheme (JCS, RFC 8785)** with the `signature` field excluded. Add a minimal JCS implementation in a new `crates/invariant-core/src/jcs.rs` (sort object keys by code-point, escape per RFC 8785; do not pull in a heavy dep). Property-test: any field reordering produces the same canonical bytes.
4. CLI: `invariant campaign sign-package <path>` and `invariant campaign verify-package <path>`. The verify command exits with status 0 only if the signature, Merkle root, audit chain, and predecessor digest all check out.

**Acceptance:** sign/verify round-trip test; tampered-manifest test (flip one byte in any field, verify must fail); JCS canonicalization property test.

---

### Prompt 1.5 — Add the `invariant campaign assemble` subcommand

**Read first:** `crates/invariant-cli/src/commands/` (note the existing pattern: each command is a `pub fn run(args) -> Result<...>` with a clap struct). `docs/spec-15m-campaign.md` §6 "Proof Package" — that section's directory layout is the target output.

**Task:** Add `crates/invariant-cli/src/commands/assemble.rs`. Wire it under `invariant campaign assemble` with flags:
- `--results <DIR>` (input directory of shard outputs; required)
- `--output <PATH>` (output `.tar.zst` path; required)
- `--signing-key <PATH>` (Ed25519 private key file; required)
- `--executor-id <STR>` (required, embedded in manifest)
- `--predecessor-digest <HEX>` (optional)

**Behavior:**
1. Walk `--results` for `shard-*/audit.log`, `shard-*/seeds.json`, `shard-*/summary.json`.
2. Verify each shard's audit chain end-to-end (use the verifier from 1.1/1.2).
3. Compute the global Merkle root over all entries from all shards in deterministic shard-then-sequence order.
4. Aggregate `summary.json` files into `results/summary.json` with category/profile/per-check breakdowns matching the layout in spec §6.
5. Build the directory tree exactly as spec §6 specifies. Include `invariant_binary_hash.txt` (SHA-256 of the running binary, read from `/proc/self/exe` or argv[0]).
6. Sign `manifest.json` (1.4) and tar+zstd the whole directory.

**Acceptance:** an integration test that runs a tiny 100-episode dry-run campaign (using the existing `campaign dry-run` machinery), feeds the output directory to `assemble`, then runs `verify-package` on the resulting tarball. Must complete in < 30s on CI.

---

## Phase 2 — Campaign scenario coverage (P0/P1)

The 15M campaign's authority depends on the 106 scenarios in spec-15m-campaign §3 actually being executable. Today only ~22 distinct generators exist, and many scenarios that share a generator name have very different parameter sweeps in the spec. This phase implements the missing scenarios.

**Pattern for every scenario in this phase:**
- Add a `ScenarioType` enum variant in `crates/invariant-sim/src/scenario.rs` named after the scenario ID (`PositionBoundarySweep` for B-01, etc.).
- Add a generator method on `ScenarioGenerator` that takes the same `(count, pca_chain_b64, ops)` parameters and returns `Vec<Command>`.
- Wire snake_case name into the dry-run YAML parser.
- Wire the scenario into `campaign.rs::generate_15m_configs` with the spec's episode allocation.
- Add a dry-run test that produces the spec-required pass/reject distribution. Tag scenarios as `pure_pass`, `pure_reject`, or `mixed` by extending `is_expected_reject` (already used in `dry_run_*` tests).
- Each generator must be **deterministic given a seed** — accept an `episode_seed: u64` parameter (extend the generator API; do not regress existing scenarios). Two runs with the same seed produce byte-identical command streams.

### Prompt 2.1 — Implement Category B (Joint Safety, 8 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category B: Joint Safety" (B-01..B-08 detailed specs at lines ~308–551). `crates/invariant-sim/src/scenario.rs::baseline` and `aggressive` for the existing pattern.

**Task:** Implement these 8 scenarios as new `ScenarioType` variants and generators:
- **B-01 PositionBoundarySweep** — for each joint, cycle 4 values: `[min_j, max_j, min_j - ε, max_j + ε]` where `ε = max(1e-6, pos_margin × range)`. Steps 0,1 PASS; steps 2,3 REJECT.
- **B-02 VelocityBoundarySweep** — three levels per joint: `max_vel_eff`, `max_vel_eff + ε`, `2 × max_vel_eff`. Episode index modulo 3 selects the level; level 0 PASS, levels 1,2 REJECT.
- **B-03 TorqueBoundarySweep** — analogous, three levels at `max_torque_eff − ε`, `max_torque_eff`, `max_torque_eff + ε`. First two PASS, third REJECT.
- **B-04 AccelerationRamp** — 300 steps ramping `r × 3 × max_velocity_j` linearly. The first step at which `|Δv/Δt| > max_acceleration_j` must REJECT; assert in the test that rejection occurs no later than step 100.
- **B-05 MultiJointCoordinatedViolation** — first half of the episode at 99% of effective limits across all joints (PASS), second half at 101% (REJECT). Verifies the validator does not short-circuit.
- **B-06 RapidDirectionReversal** — alternating `+v_eff_j` and `−v_eff_j` per step. Step 0 PASS, every subsequent reversal REJECT (P4).
- **B-07 IEEE754SpecialValues** — corpus of 8 values (`NaN`, `±Inf`, `±0.0`, smallest subnormal, `±1e308`) injected into joint position / velocity / effort / `delta_time` / EE position fields in rotation. PASS only when the injected value is `±0.0` and the field is velocity/effort or a position joint where 0.0 is in range; otherwise REJECT.
- **B-08 GradualDriftAttack** — target joint position = `max_j + i × 0.0001` rad. Step 0 PASS, step 1 REJECT, all subsequent steps REJECT.

**Acceptance:** for each scenario, a dry-run unit test that asserts the exact verdict pattern across at least 20 episodes per profile on franka_panda, ur10, and one synthetic adversarial profile. Total ≈ 24 new tests. `cargo clippy -- -D warnings`.

**Recommended split:** one PR for B-01..B-04, one for B-05..B-08. Two commits.

---

### Prompt 2.2 — Implement Category C (Spatial Safety, 6 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category C". Existing `exclusion_zone` and `cnc_tending_full_cycle` generators in `scenario.rs` are the closest pattern.

**Task:** Implement:
- **C-01 WorkspaceBoundarySweep** — EE at every face/edge/corner of the workspace AABB ± 1mm. Inside PASS, outside REJECT.
- **C-02 ExclusionZonePenetration** — for each exclusion zone, approach from 6 axis-aligned directions; first step inside REJECTs.
- **C-03 ConditionalZoneStateMachine** — toggle each conditional zone through its enable/disable transitions during a CNC cycle; verify mixed pass/reject per the state.
- **C-04 SelfCollisionApproach** — for each `collision_pair`, drive the link COMs from 5× `min_collision_distance` toward 0; REJECT at the first step where distance ≤ `min_collision_distance`.
- **C-05 OverlappingZoneBoundaries** — EE at the geometric intersection of multiple zones; verify the firewall identifies and applies the most restrictive zone.
- **C-06 CorruptSpatialData** — `NaN`/`Inf` in workspace corners, zone bounds, EE positions. REJECT all (fail-closed).

Use the same seed/determinism rules as 2.1. Add 18 dry-run tests (3 per scenario, varying profile).

---

### Prompt 2.3 — Implement Category D (Stability & Locomotion, 10 scenarios)

**Read first:** existing locomotion variants (`LocomotionRunaway`, `LocomotionSlip`, `LocomotionTrip`, `LocomotionStomp`, `LocomotionFall`) in `scenario.rs` — five of the ten exist as primitives but are not parameterized to spec §"Category D". `docs/spec-15m-campaign.md` §"Category D" rows D-01..D-10.

**Task:** Either rename and extend the existing variants to fit the D-01..D-10 IDs, or add new variants and deprecate the old. The end state must be one variant per scenario row, with parameter sweeps matching the spec (COM sweep, gait validation, speed ramp to 3× max, foot clearance sweep, stomp ramp, friction cone violation, step overextension, heading spinout, push recovery, incline ramp 0°–30°). Implement with the same seed/determinism contract as 2.1.

**Acceptance:** 10 new or refactored dry-run tests, run only on legged profiles (`spot`, `quadruped_12dof`, `unitree_h1`, `unitree_g1`, `humanoid_28dof`). The `is_expected_reject` classifier must be updated.

---

### Prompt 2.4 — Implement Category E (Manipulation Safety, 6 scenarios)

**Read first:** `crates/invariant-core/src/validator.rs` for P11–P14 implementations; `docs/spec-15m-campaign.md` §"Category E".

**Task:** Implement E-01 ForceLimitSweep, E-02 GraspForceEnvelope, E-03 ForceRateSpike, E-04 PayloadOverload, E-05 IsoHumanProximityForce (force applied while in human-critical zone, REJECT above 65 N face limit), E-06 BimanualCoordination. The E-05 implementation requires the human-proximity zone to be modelled as a proximity zone with a reduced force ceiling — verify `validator.rs` exposes that and extend if not.

**Acceptance:** 18 dry-run tests (3 per scenario across arms + cobots).

---

### Prompt 2.5 — Implement Category F (Environmental Hazards, 8 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category F". Existing `EnvironmentFault` variant is too coarse for the 8 distinct sweeps.

**Task:** Add F-01 TemperatureRamp, F-02 BatteryDrain, F-03 LatencySpike, F-04 EstopCycle, F-05 SensorRangePlausibility, F-06 SensorPayloadRange, F-07 SensorFusionInconsistency, F-08 CombinedEnvironmental. Each must exercise the derate-then-reject behavior where applicable (P22, P23, P24 have warning zones before reject). The `EnvironmentFault` variant may be retired once all eight are wired.

---

### Prompt 2.6 — Implement Category G (Authority & Crypto, 10 scenarios)

**Read first:** `crates/invariant-core/src/authority.rs` (or equivalent — search for `Pca`, `chain`, `verify_chain`). Existing variants `AuthorityEscalation` and `ChainForgery` cover 2 of 10. Spec G-01..G-10.

**Task:** Add G-01 ValidAuthorityChain (positive control), G-02 EmptyPcaChain, G-03 ForgedSignature, G-04 KeySubstitution, G-05 PrivilegeEscalation (rename of existing `AuthorityEscalation`; keep the variant but adjust to spec parameters), G-06 ProvenanceMutation, G-07 WildcardExploitation, G-08 ExpiredChain, G-09 CrossChainSplice, G-10 GarbageCose.

**Acceptance:** every G-NN scenario must produce a deterministic, recordable verdict for which the dry-run test asserts both the categorical outcome and the rejection reason string (so a regression that returns the wrong error class is caught).

---

### Prompt 2.7 — Implement Category H (Temporal & Sequence, 6 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category H"; `crates/invariant-core/src/validator.rs` sequence-tracking code.

**Task:** Add H-01 SequenceReplay, H-02 SequenceRegression, H-03 SequenceGap (PASS — gaps allowed), H-04 DeltaTimeAttack (`dt = 0`, `dt < 0`, `dt = NaN`, `dt = Inf`), H-05 StaleCommand (`dt > max_delta_time`), H-06 FutureDatedSensor (sensor timestamp 10s in the future).

Each scenario must tolerate the multi-source sequence model (per-source monotonic, gaps allowed) — use `coord_agent_alpha`/`coord_agent_beta` patterns from A-08 where multiple sources are needed.

---

### Prompt 2.8 — Implement Category I (Cognitive Escape, 10 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category I". Existing `PromptInjection` covers 1 of 10.

**Task:** Add I-01 GradualDrift (10000-step trajectory, 0.0001 rad/step toward unauthorized zone), I-02 DistractionFlooding (999 valid + 1 invalid × 100 cycles per episode), I-03 SemanticConfusion (joint name swap), I-04 AuthorityLaundering, I-05 ErrorMining, I-06 WatchdogManipulation, I-07 ProfileProbing, I-08 MultiAgentCollusion, I-09 TimingExploitation, I-10 RollbackReplay. Several of these require multi-source PCA chains; reuse the chain-construction helpers from G-* once those are in.

---

### Prompt 2.9 — Implement Category J (Compound Attacks, 8 scenarios)

**Read first:** existing `Compound*` variants (J-01, J-02, J-05, J-07 are stubs; J-03, J-04, J-06, J-08 are unimplemented).

**Task:** Add J-03 NaNInjectionAuthorityBypass, J-04 WatchdogTimeoutReplay, J-06 ProfileProbingTargetedAttack, J-08 MultiRobotCoordinationAttack. Then revisit J-01/J-02/J-05/J-07 to ensure their parameters match spec §"Category J" exactly (some current implementations are placeholders).

---

### Prompt 2.10 — Implement Categories K and L (Recovery & Long-Running, 10 scenarios)

**Read first:** existing `Recovery*` and `LongRunning*` variants.

**Task:** K-03 EstopCycle (separate from F-04 — this one tests recovery state, not just rejection), K-05 ProfileReloadDuringOperation (hot-reload with tighter limits), K-06 ValidatorRestart. L-02 OneMillionAuditEntries (1M-step episodes), L-03 CounterSaturation (pre-set counters near `u64::MAX`).

K-05 may require a profile-reload API on the validator that does not exist today — if so, add the API and a unit test before implementing the scenario.

---

### Prompt 2.11 — Implement Categories M and N (Cross-platform Stress & Adversarial, 16 scenarios)

**Read first:** `docs/spec-15m-campaign.md` §"Category M" and §"Category N".

**Task:** M-01..M-06 are throughput/payload-shape stress tests — most do not need new generators, just CampaignConfig wiring with specific command-shape constraints (256 joints, 1 joint, 1000 cmds/sec). M-04 may exceed `MAX_EPISODES_PER_ENV` and needs sharding logic.

N-01..N-10 are the adversarial fuzzers. Wire these into `crates/invariant-fuzz/` if not already present:
- N-01 generation-based proptest
- N-02 mutation-based (bit flip, field swap, signature corrupt)
- N-03 grammar-based JSON
- N-04 coverage-guided libFuzzer (`cargo-fuzz`)
- N-05 differential against `invariant-eval` Python reference
- N-06 JSON bomb (depth, size)
- N-07 COSE/CBOR malformed envelopes
- N-08 Unicode adversarial (zero-width, RTL, homoglyph)
- N-09 type confusion
- N-10 integer boundary

Each fuzzer must run inside the campaign harness for a bounded episode count and emit verdicts compatible with the standard summary aggregator.

---

### Prompt 2.12 — Update `generate_15m_configs` to allocate to all 106 scenarios

**Read first:** `crates/invariant-sim/src/campaign.rs::generate_15m_configs` (line 1694) and `category_a` (line 1217). The function currently distributes episodes across 22 scenarios. After Phase 2.1–2.11 there are 106. The episode totals per scenario in the spec must match exactly.

**Task:**
1. Extract `category_b` through `category_n` modules in `campaign.rs`, each modelled on `category_a`. Each module exposes `SCENARIOS: &[ScenarioSpec]` with `(id, scenario_type, steps, episodes, profiles, invariants_exercised)`.
2. `generate_15m_configs(total, shards)` walks all 14 category modules and produces the cross-product of `(profile, scenario, shard)` configs. Episode counts must sum to exactly `total` (allocate rounding remainders to the largest scenario in the largest profile bucket — document this).
3. Add a test that asserts `sum(c.scenario_episodes) == 15_000_000` for `total=15_000_000, shards=8`.
4. Add a test that every `ScenarioType` variant appears in exactly one category module — no scenario is unallocated, no scenario is double-allocated.

**Acceptance:** all `dry_run_*` tests still pass; a new `15m_allocation_exact` test enforces the total.

---

## Phase 3 — Production hardening (P1)

These gaps block production deployment but not the 15M campaign run itself. They can land in parallel with Phase 2 if engineers are available.

### Prompt 3.1 — OS keyring `KeyStore` implementation

**Read first:** `crates/invariant-core/src/keys.rs` around line 413 (search for `KeyStoreError::Unavailable`); the `KeyStore` trait definition.

**Task:** Replace the stub with a real implementation backed by the `keyring` crate (cross-platform: macOS Keychain, Linux Secret Service / kwallet, Windows Credential Manager). Service name: `"invariant-robotics"`; account name = the key fingerprint hex. Storage format: bincode-encoded `KeyMaterial` struct (already exists). Reject any account name that does not match `^[0-9a-f]{64}$`.

**Acceptance:** an `#[ignore]`-by-default integration test that round-trips a key on the developer's local keychain. CI runs the unit tests only. Add a `--features os-keyring` cargo feature so the keyring dep is not pulled into pure-no-network builds.

---

### Prompt 3.2 — TPM and YubiHSM `KeyStore` implementations

**Read first:** `crates/invariant-core/src/keys.rs` around 462 and 510.

**Task:** Behind feature flags `tpm` and `yubihsm` respectively, implement using `tss-esapi` and `yubihsm` crates. Hardware tests are `#[ignore]` by default. Document the persistent-handle layout (TPM) and the slot-id assignment (YubiHSM) in the module doc-comment.

This is a large prompt. Recommend splitting: 3.2a TPM, 3.2b YubiHSM as two separate PRs.

---

### Prompt 3.3 — S3 audit replication sink

**Read first:** `crates/invariant-core/src/replication.rs` around 169, 257.

**Task:** Implement an `S3ReplicationSink` using `aws-sdk-s3`. Each batch is uploaded as `s3://<bucket>/<prefix>/<session_id>/<seq_start>-<seq_end>.bin.zst` with conditional `If-None-Match: *` to be idempotent. On retry, re-issue the same key — duplicate detection is the bucket's job. Use AWS_PROFILE / IRSA / instance profile credential resolution by default.

**Acceptance:** an integration test using `localstack` (gated behind `--features s3-integration`).

---

### Prompt 3.4 — Webhook replication and alert sink

**Read first:** `crates/invariant-core/src/replication.rs` around 289.

**Task:** Implement a `WebhookSink` that POSTs each batch as JSON with an `X-Invariant-Signature` header containing `HMAC-SHA256(shared_secret, body)` in hex. Exponential backoff with jitter; max 5 retries; circuit-break after 10 consecutive failures and surface via the existing telemetry hook. Use `wiremock` for tests.

Add a parallel `AlertWebhookSink` for *individual* high-severity rejections (not batch replication) — payload is a single `AlertRecord` with the verdict, scenario id, and chain hash.

---

## Phase 4 — Robustness, fuzz, and parser surfaces (P2)

### Prompt 4.1 — Bound the Isaac Lab bridge read buffer

**Read first:** the bridge read loop in `crates/invariant-sim/src/isaac/` (search for `read_line` or `BufRead`).

**Task:** Replace any unbounded `read_line` with `BufRead::take(MAX_LINE).read_until(b'\n', ...)`. `MAX_LINE` should be a small const (default 1 MiB). Lines exceeding the limit return `BridgeError::FrameTooLarge` and the connection is dropped. Add a regression test that pipes 4 MiB of bytes with no newline and verifies the bridge returns the error within bounded memory.

(Note: commit `7ad120d` mentions "bridge timeouts" — verify that commit did not already fix this; if it did, retire this prompt.)

---

### Prompt 4.2 — Profile schema validator

**Read first:** `crates/invariant-core/src/profiles.rs`.

**Task:** Add a `validate_consistency(&self) -> Result<(), ProfileError>` method on `RobotProfile` that checks cross-field invariants:
- `max_velocity ≥ cruise_velocity` for every joint where cruise is defined.
- Inertia tensors are positive semi-definite (eigenvalues ≥ 0).
- Workspace AABB has `min < max` per axis.
- Every `collision_pair`'s links exist in `links`.
- Every `proximity_zone` AABB lies within or overlaps the workspace AABB.
- Every named `end_effector` has a corresponding link entry.

Run the validator on every builtin profile in a unit test (parametric: one test per builtin name). Failing profile = test failure.

---

### Prompt 4.3 — Backfill `end_effectors` and `environment` blocks on all profiles

**Read first:** any profile that already has these sections (e.g., `franka_panda.json`) — that is the schema target.

**Task:** Audit `profiles/*.json`. Any profile missing `end_effectors` or `environment` gets the appropriate block added with values consistent with the robot. Update the profile-schema validator to **require** both fields (after backfill).

This is mechanical but error-prone — one commit per profile, message `gap-NN: profile X end_effectors+environment`. Prefer adding the validation requirement only after every profile is updated, to keep tests green throughout.

---

### Prompt 4.4 — Property tests for the validator kernel

**Read first:** `crates/invariant-core/src/validator.rs`.

**Task:** Add `proptest`-based property tests with ≥256 cases each:
- For every `P*` invariant, generate random commands across the whole numeric domain and assert: a command at exactly the limit PASSES; a command above the limit (by any margin > floating-point epsilon × limit) REJECTS.
- For every `A*` invariant, generate random PCA chains and assert: a properly signed chain with monotone scopes PASSES; any single-bit mutation REJECTS.
- Determinism: validating the same `(command, profile, state)` twice produces the same verdict (sanity for caching bugs).

Place tests under `crates/invariant-core/tests/properties/`.

---

### Prompt 4.5 — `cargo-fuzz` targets for parser surfaces

**Read first:** existing `crates/invariant-fuzz/`.

**Task:** Add `cargo-fuzz` targets (under `crates/invariant-core/fuzz/` if absent) for: profile JSON deserialization, audit log parser, manifest parser, COSE/CBOR PCA-chain envelope, URDF parser (if used). Each target must run for ≥10 minutes on CI nightly without finding a panic. Document the run command in `CONTRIBUTING.md`.

---

### Prompt 4.6 — Dead-code and TODO sweep

**Task:** Run `cargo +nightly udeps` and `rg -n 'TODO|FIXME|XXX|unimplemented!|todo!' crates/`. For every hit:
- If the function is genuinely dead: delete it.
- If it is a stub that is intentionally left for later: ensure there is a corresponding gap in this document (this file). If not, add one.
- If it is a `TODO` referencing a fix that has landed: delete the comment.

One commit, message `gap-NN: dead code & stale TODO sweep`.

---

## Phase 5 — Simulation coverage (P3)

### Prompt 5.1 — Additional Isaac Lab environments

**Read first:** `crates/invariant-sim/cnc_tending.py` for the env pattern.

**Task:** Add: `humanoid_walk.py`, `quadruped_locomotion.py`, `dexterous_hand_pinch.py`, `mobile_base_navigation.py`, `bimanual_arms.py`. Each env publishes the same observation/command bridge protocol as `cnc_tending.py`, with profile defaults matching the corresponding builtin (`humanoid_28dof`, `spot`, `shadow_hand`, `pal_tiago`, `franka_panda` × 2 respectively).

Recommend one PR per env. No regression test required beyond a 10-step smoke launch in CI.

---

### Prompt 5.2 — Differential evaluator regression suite

**Read first:** `crates/invariant-eval/`.

**Task:** Add tests in `crates/invariant-eval/tests/differential_*.rs`:
- Determinism: same trace evaluates to the same rubric result twice.
- Continuity: a one-bit-flip mutation in a verdict produces a different rubric result (the differ is sensitive).
- Stability: 1000 random traces evaluate without panic.

---

## Phase 6 — Release engineering (P3)

### Prompt 6.1 — Compliance matrix document

**Read first:** the per-`ProfileSpec` and per-validator references to ISO/IEC standards.

**Task:** Create `docs/compliance-matrix.md` with one section per standard (IEC 61508, ISO 10218-1/2, ISO/TS 15066, NIST AI 600-1) and a table mapping each clause to the validator code path or test that demonstrates compliance. Cross-link to the proof-package `compliance/` directory (spec §6).

---

### Prompt 6.2 — CI matrix expansion

**Read first:** `.github/workflows/`.

**Task:** Ensure CI runs on `stable`, `beta`, and the MSRV pinned in `rust-toolchain.toml`. Run `cargo test --all-features`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo deny check`. Add a nightly `cargo +nightly udeps` job. Add a separate job for `cargo-fuzz` smoke runs (≤2 min per target).

---

### Prompt 6.3 — Public-release polish for the campaign artifacts

**Read first:** `docs/public-release-polish.md` (existing punch list).

**Task:** Reconcile that document with this one. Anything in `public-release-polish.md` that is duplicated here gets removed there; anything there that is **not** here gets a new prompt added in the appropriate phase of this document.

---

## Phase 7 — RunPod execution (the actual 15M run) (P0, depends on Phase 1 and 2)

### Prompt 7.1 — Ship the RunPod 8×A40 deployment script

**Read first:** `docs/runpod-simulation-guide.md`, `crates/invariant-sim/src/campaign.rs::generate_15m_configs`, and `Dockerfile`.

**Task:** Produce `scripts/runpod_15m_launch.sh` (or extend an existing script) that:
1. Builds and pushes the Docker image with the proof-package signing key mounted (not baked).
2. Generates 8 shard configs via `invariant campaign generate-15m --shards 8 --output campaigns/15m/shard-{0..7}.yaml`.
3. Launches 8 RunPod pods, one per shard, each pinned to a single A40 with affinity for deterministic execution.
4. Polls each pod for completion, downloads `shard-N/` outputs.
5. Calls `invariant campaign assemble` (Prompt 1.5) to produce `invariant-proof-15m.tar.zst`.
6. Calls `invariant campaign verify-package` and exits non-zero on failure.

Document the expected run time (4–6 hours) and cost ($30–40 in spec §1.1) in the script header.

**Do not run the actual 15M campaign as part of this prompt** — only deliver the launch script and a 10-episode smoke run that exercises the same pipeline end-to-end.

---

### Prompt 7.2 — Final acceptance gate

**Task:** Once all preceding prompts are complete and merged to `main`, open a release-candidate PR titled `release: 15M campaign ready`. The PR description must include:
- A checklist with every prompt above and a link to its closing commit.
- The output of `invariant campaign generate-15m --shards 8 --dry-run` showing the 15,000,000 episode total.
- A 10-episode smoke run of the assemble + verify-package pipeline.

Merging this PR is the signal to schedule the actual RunPod run.

---

## Tracking

When you finish a prompt, append a one-line entry to the table below. Do not edit prompts retroactively — if a gap requires re-work, add a new prompt at the bottom of the appropriate phase.

| Prompt | Closed by commit | Date | Notes |
|--------|------------------|------|-------|
| 1.1 | | | |
| 1.2 | | | |
| 1.3 | | | |
| 1.4 | | | |
| 1.5 | | | |
| 2.1 | | | |
| 2.2 | | | |
| 2.3 | | | |
| 2.4 | | | |
| 2.5 | | | |
| 2.6 | | | |
| 2.7 | | | |
| 2.8 | | | |
| 2.9 | | | |
| 2.10 | | | |
| 2.11 | | | |
| 2.12 | | | |
| 3.1 | | | |
| 3.2a | | | |
| 3.2b | | | |
| 3.3 | | | |
| 3.4 | | | |
| 4.1 | | | |
| 4.2 | | | |
| 4.3 | | | |
| 4.4 | | | |
| 4.5 | | | |
| 4.6 | | | |
| 5.1 | | | |
| 5.2 | | | |
| 6.1 | | | |
| 6.2 | | | |
| 6.3 | | | |
| 7.1 | | | |
| 7.2 | | | |
