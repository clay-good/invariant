> Superseded by [docs/robotics/spec.md](../../robotics/spec.md) as of 2026-05-19. Kept for historical reference.

# spec-v11.md — Gap Closure Prompts (post-v10 deep audit)

**Status:** active, 2026-05-01
**Supersedes the open items in:** spec-v9.md, spec-v10.md (does not invalidate spec.md or spec-15m-campaign.md)
**Audience:** Claude Code agents executing one prompt at a time

This document is a remediation plan derived from a fresh end-to-end audit of `crates/` against `docs/spec.md`, `docs/spec-15m-campaign.md`, and the cumulative deltas in `spec-v1.md` … `spec-v10.md`. Each section below is a self-contained Claude Code prompt: open it, paste the body verbatim into a fresh agent (or run it as one focused task), and let it complete end-to-end before moving on.

The prompts are ordered by dependency. Phase 1 must land before Phase 2 generators are trustworthy. Phase 3 (Isaac Lab) depends on Phase 2. Phases 4 and 5 are parallelizable with everything once Phase 1 is in.

After each prompt completes:
1. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` must be green.
2. One commit per prompt with subject `[spec-v11-<id>] <one-line summary>`.
3. Update the tracking table at the bottom of this file from `OPEN` → `DONE`.

---

## How to use a prompt

Each prompt is written for an agent that has not seen this conversation. It restates the goal, the relevant spec section, the files to touch, the acceptance criteria, and the test it must add. Do not skip the test — every prompt has one. If an agent finds the work is already done, it should record `ALREADY DONE` in the tracking table with a one-line citation (commit hash or file path) and move on without committing.

---

# PHASE 1 — Authority chain & proof-package integrity (BLOCKING)

These five prompts close the cryptographic gaps that the 15M proof package depends on. Until they land, every downstream artifact (campaign manifest, audit log, verify-package output) is un-bindable to the spec's claims.

## Prompt 1.1 — Add B1–B4 execution-binding fields to the audit log

**Spec:** spec.md §3.3 (B1–B4), spec-v9 §1.1.

**Goal:** Extend `AuditEntry` so every appended record cryptographically binds to a session, an executor, a monotonic clock, and a wall-clock timestamp. Today the entry has only `sequence` and `previous_hash`, which means a replay across sessions or a clock-rewind is undetectable.

**Read first** (in this order):
1. `docs/spec.md` §3.3 to anchor the field semantics.
2. `crates/invariant-core/src/models/audit.rs` (the struct).
3. `crates/invariant-core/src/audit.rs` (the logger and the hash-preimage construction).
4. `crates/invariant-cli/src/commands/audit_gaps.rs` (a downstream consumer that will need updating).

**Do:**
1. Add four fields to `AuditEntry`: `session_id: String`, `executor_id: String`, `monotonic_nanos: u64`, `wall_clock_rfc3339: String`.
2. Make them part of the canonical hash preimage. Define a helper `canonical_bytes(&AuditEntry) -> Vec<u8>` that concatenates fields in a fixed, documented order with length-prefixed framing — do not rely on serde JSON for hashing because field reordering would silently change the digest.
3. Add `AuditAppendError::ClockRegression { last: u64, attempted: u64 }` and reject any append whose `monotonic_nanos` is < the last appended entry from the same `executor_id`. Sequence is per-executor monotonic; gaps across executors are allowed (this is the multi-source model from spec-v7 §2.7).
4. Update every call site that constructs an `AuditEntry`. The test suite will fail loudly — fix each site, do not paper over with `Default`.
5. Update `audit_gaps.rs` to partition by `executor_id` before reporting gaps. Within an executor, gap = error. Across executors, gap = expected.

**Tests to add:**
- `crates/invariant-core/tests/audit_preimage_golden.rs` — construct one AuditEntry with fixed field values, snapshot its `canonical_bytes` hex and SHA-256. This guards against accidental field-order changes.
- `crates/invariant-core/tests/audit_concurrent.rs` — 16 threads × 1000 entries each into a shared `AuditLogger`, assert final per-executor sequences sum to 16000 with no duplicates and the chain verifies end-to-end.
- `crates/invariant-core/tests/audit_clock_regression.rs` — append entry with `monotonic_nanos=1000`, then attempt `monotonic_nanos=999` for the same executor, assert `ClockRegression` error.

**Acceptance:** all three new tests pass. `cargo test --workspace` is green. The hash preimage order is documented as a comment at the top of `canonical_bytes`.

---

## Prompt 1.2 — Bind PCA chain hops with predecessor digests (A3 causal binding)

**Spec:** spec.md §2.3, §3.2 (A3), spec-v9 §1.2. Campaign attack G-09 (cross-chain splice).

**Goal:** A3 today is signature-only. The spec requires "PoC_i is a valid causal successor of PCA_{i-1}" — meaning each hop must carry a digest of its predecessor and verification must recompute and compare. Without this, an attacker who has any two valid chains sharing a root can splice hops between them.

**Read first:**
1. `docs/spec.md` §2.3 and §3.2.
2. `crates/invariant-core/src/models/authority.rs` — the `Pca` struct.
3. `crates/invariant-core/src/authority/chain.rs` — `verify_chain`.
4. `crates/invariant-core/src/audit.rs` — the resume path, which must also enforce predecessor binding when chains span sessions.

**Do:**
1. Add `predecessor_digest: [u8; 32]` to `Pca`. For root hops it is all-zero (and the verifier accepts that only at index 0).
2. Implement `Pca::canonical_bytes` deterministically (length-prefixed; the same approach as Prompt 1.1).
3. In `verify_chain`, after existing signature/monotonicity checks, walk the chain: for `i >= 1`, compute `sha256(canonical_bytes(hop[i-1]))` and compare to `hop[i].predecessor_digest`. On mismatch return `ChainError::PredecessorDigestMismatch { index: i }`.
4. Update every test fixture and helper that builds a `Pca` chain — they must now compute and set `predecessor_digest`. Provide a test helper `build_chain(hops: &[PartialPca]) -> Vec<Pca>` that fills digests automatically so fixtures stay readable.
5. In `AuditLogger::resume`, store the last hop's digest and refuse to accept a fresh chain whose root does not bind to it (or whose first hop's predecessor_digest disagrees with the resumed state).

**Tests to add:**
- `crates/invariant-core/tests/authority_g09_splice.rs` — build two valid 3-hop chains A and B sharing a root. Splice hop 1 from B into A (keeping signatures valid). Assert `verify_chain` returns `PredecessorDigestMismatch { index: 1 }`.
- `crates/invariant-core/tests/authority_root_zero_digest.rs` — assert root hop with non-zero `predecessor_digest` is rejected; with zero it is accepted.

**Acceptance:** both tests pass. Existing chain tests still pass after fixture migration. `cargo clippy` is clean.

---

## Prompt 1.3 — RFC 6962 Merkle tree over the audit log

**Spec:** spec-15m-campaign.md §6 (proof-package `merkle_root.txt`), spec-v9 §1.3.

**Goal:** Produce a per-shard Merkle root over all audit entries so a verifier can prove inclusion of any entry without trusting the whole log. Today there is no tree at all.

**Read first:**
1. RFC 6962 §2 (the canonical leaf/inner hash domain separators 0x00 / 0x01).
2. `crates/invariant-core/src/audit.rs` — to understand where to compute the running tree state.

**Do:**
1. Create `crates/invariant-core/src/audit/merkle.rs` (or `crates/invariant-core/src/merkle.rs` if `audit.rs` is a single file — match the existing module layout).
2. Implement: `pub fn leaf_hash(entry: &[u8]) -> [u8; 32]` (prefix 0x00); `pub fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32]` (prefix 0x01); a streaming builder `MerkleAccumulator` that ingests leaves one at a time and can produce the current root in O(log n) memory; `pub fn inclusion_proof(leaves: &[[u8;32]], index: usize) -> Vec<[u8;32]>`; `pub fn verify_inclusion(root: &[u8;32], leaf: &[u8;32], index: usize, n: usize, proof: &[[u8;32]]) -> bool`.
3. Wire `MerkleAccumulator` into `AuditLogger` so that every append updates the running root. Expose `AuditLogger::merkle_root() -> [u8; 32]`.
4. Persist the root into the proof package as `merkle_root.txt` (lowercase hex, no newline).

**Tests to add:**
- `crates/invariant-core/tests/merkle_known_vectors.rs` — for trees of size 1, 2, 3, 4, 7, hand-compute the expected root in the test (write the inner hash steps inline as comments so a reviewer can verify by eye), assert the implementation matches.
- `crates/invariant-core/tests/merkle_tamper.rs` — for a 1024-leaf tree, generate inclusion proofs for every index, then for one fixed index iterate over every byte of the proof, flip it, and assert `verify_inclusion` returns false.

**Acceptance:** both tests pass. The streaming accumulator's memory usage is independent of n (verified by argument; no need for an actual memory test).

---

## Prompt 1.4 — Sign the proof-package manifest (JCS canonicalization)

**Spec:** spec-15m-campaign.md §6 (`manifest.sig`), spec-v9 §1.4.

**Goal:** The proof-package manifest is currently produced unsigned, with a comment that says "caller signs if keys available — no caller does." Add canonical serialization, signing, and verification.

**Read first:**
1. `crates/invariant-core/src/proof_package.rs` — note the unsigned-manifest comment around line 241.
2. RFC 8785 (JCS) §3 — you need only the deterministic key ordering and number formatting.

**Do:**
1. Add `merkle_root: String` (hex, from Prompt 1.3) and `manifest_signature: Option<String>` (base64 Ed25519, base64 with no padding) to `ProofPackageManifest`.
2. Implement `pub fn canonical_json(manifest: &ProofPackageManifest) -> Vec<u8>` — sort keys lexicographically at every level, use compact separators, format numbers as JCS prescribes. The signature field must be excluded from the preimage (sign over the manifest with the field set to None).
3. Add `manifest.sign(&KeyHandle) -> Result<()>` and `manifest.verify(&PublicKey) -> Result<()>`.
4. Update `proof_package::assemble` to: compute Merkle root, set it on the manifest, sign the manifest if a key is provided (else surface a clear warning). Write `merkle_root.txt` and `manifest.sig` (base64) alongside `manifest.json`.

**Tests to add:**
- `crates/invariant-core/tests/manifest_jcs_golden.rs` — fixture manifest with three file_hashes and one merkle_root, snapshot its canonical bytes.
- `crates/invariant-core/tests/manifest_tamper.rs` — sign a manifest, then flip one byte in a file_hash, in merkle_root, in the signature itself; verify in each case `manifest.verify()` returns an error.

**Acceptance:** both tests pass. The "unsigned" comment in `proof_package.rs` is removed. A new doc comment on `assemble` notes the signing requirement and the JCS canonicalization.

---

## Prompt 1.5 — Wire `invariant campaign assemble` CLI subcommand

**Spec:** spec-15m-campaign.md §6 step 6, spec-v9 §1.5.

**Goal:** Operators must be able to assemble a proof package from shards via CLI. The Rust API exists; no command surfaces it.

**Read first:**
1. `crates/invariant-core/src/proof_package.rs` (the `assemble` function and its inputs).
2. `crates/invariant-cli/src/main.rs` and the existing `commands/` layout.

**Do:**
1. Create `crates/invariant-cli/src/commands/assemble.rs` with a clap-derived command struct. Flags:
   - `--shards <DIR>` (required) — directory containing shard subdirectories.
   - `--output <DIR>` (required) — where to write the assembled package.
   - `--key <PATH>` (optional) — Ed25519 signing key; if omitted, manifest is unsigned and a warning is printed to stderr.
   - `--public-key <PATH>` (optional) — co-located with `--key` for a self-verify step on output.
   - `--metadata <KEY=VALUE>` (repeatable) — passthrough metadata into the manifest's `extra` map.
2. Register the subcommand under the existing `campaign` parent (`invariant campaign assemble ...`).
3. After writing the package, if `--public-key` was provided, immediately re-load and verify it; non-zero exit on verify failure.

**Tests to add:**
- `crates/invariant-cli/tests/assemble_cli.rs` — generate two tiny shard directories with hand-rolled audit JSONL files, run the assembled binary via `assert_cmd`, assert `merkle_root.txt`, `manifest.json`, and `manifest.sig` exist and that a tampered shard byte causes verification to fail.

**Acceptance:** test passes. `invariant campaign assemble --help` prints clean help text.

---

## Prompt 1.6 — Add `--predecessor-digest` and `--merkle-root` flags to `audit verify`

**Spec:** spec-v9 §1.1 / §1.3 (these flags become meaningful only after Prompts 1.1–1.4).

**Goal:** A verifier should be able to assert externally-known anchors against a log, not just walk it locally.

**Read first:**
1. `crates/invariant-cli/src/commands/audit.rs`.

**Do:**
1. Add `--predecessor-digest <HEX>` (32 bytes) — the verifier asserts the first entry's `predecessor_digest` equals this. If the log starts at sequence 0 and the flag is omitted, all-zero is assumed.
2. Add `--merkle-root <HEX>` — after the local walk, recompute the Merkle root from the log and compare; non-zero exit on mismatch.
3. Add a test that builds a small log, computes the expected root, and runs the CLI with the correct and an incorrect root.

**Acceptance:** test passes. Help text describes both flags clearly.

---

# PHASE 2 — Campaign scenario coverage (BLOCKING for the 15M claim)

The campaign metadata in `crates/invariant-cli/src/campaign.rs` already allocates episodes to categories B–N, but `crates/invariant-sim/src/scenario.rs` only contains ~22 variants — almost none of B–N. Until the generators exist, the allocation references nothing and `generate_15m_configs` will silently skip or panic.

Each prompt below adds one category. They share the same template, can run in parallel, and must each include a determinism test (Prompt 2.0) before merging.

## Prompt 2.0 — Establish the determinism contract for campaign generators

**Spec:** spec-v9 §5.6, spec-v7 §2 pattern.

**Goal:** Every generator in `scenario.rs` must take a single `&mut CampaignRng` (a `ChaCha20Rng` seeded from the episode seed) and produce byte-identical output across runs. Today some generators reach for `thread_rng()`. Lock this down once, before adding more.

**Do:**
1. Add `pub struct CampaignRng(ChaCha20Rng)` in `crates/invariant-sim/src/scenario.rs` (or a new `rng.rs`) with a single constructor `from_episode_seed(seed: u64)`.
2. Audit `scenario.rs`, `campaign.rs`, `orchestrator.rs`, `collector.rs` for any of: `thread_rng`, `OsRng`, `SystemTime`, `Instant::now` used as a randomness source. Replace each with `CampaignRng` plumbing.
3. Add a clippy lint or a `tests/no_threadrng.rs` integration test that greps the `crates/invariant-sim/src/` tree and fails on any of those substrings outside test code.
4. Add `crates/invariant-sim/tests/determinism.rs` — generate 100 episodes from a fixed seed twice, assert byte-equality of `audit.log`, `seeds.json`, `summary.json` outputs.

**Acceptance:** determinism test passes twice in a row in CI. The grep test fails loudly if anyone re-introduces `thread_rng` later.

---

## Prompts 2.1 — 2.11 — Add scenario generators for categories B through N

For each of the eleven prompts below, repeat the same recipe (only the category changes). Run each in its own agent / its own commit. Do not add more than one category per commit.

**Recipe (apply to every prompt 2.1–2.11):**
1. Read `docs/spec-15m-campaign.md` §3 to find the exact scenario IDs and their intent for the category you are implementing.
2. Read the existing patterns in `crates/invariant-sim/src/scenario.rs` for Category A so your new variants match house style (enum variant naming, `ScenarioConfig` shape, generator function signature, dispatch in `generate`).
3. For each new scenario ID: add an enum variant, a generator function that takes `&mut CampaignRng` and a profile, and a unit test that asserts the generated trace matches the scenario's intent (e.g., for a velocity-boundary sweep, assert at least one step's commanded velocity equals the profile's `max_velocity` to within 1e-9).
4. Wire each variant into the `category_*` allocation in `crates/invariant-cli/src/campaign.rs` (the metadata is already present from chunk-06 commits; you are filling in the generators it references).
5. Add a coverage test: enumerate all `ScenarioType` variants and assert each is reachable from `generate_15m_configs`. This catches typos and forgotten dispatch.
6. Re-run Prompt 2.0's determinism test — it must still pass with the new generators.

**Per-category prompts:**

- **Prompt 2.1 — Category B (Joint Safety, IDs B-01..B-08):** PositionBoundarySweep, VelocityBoundarySweep, TorqueBoundarySweep, AccelerationRamp, MultiJointCoordinatedBoundary, RapidDirectionReversal, IEEE754EdgeValues, GradualDrift. Allocation: 1.5M episodes (per chunk-06 commit).
- **Prompt 2.2 — Category C (Workspace & Geometry, IDs C-01..C-06):** WorkspaceBoundarySweep, ExclusionZonePenetration, ConditionalZoneStateMachine, SelfCollisionApproach, OverlappingZoneBoundaries, CorruptSpatialData.
- **Prompt 2.3 — Category D (Locomotion & Stability, IDs D-01..D-10):** LegsStandingBalance, GaitPhaseValidation, SteppingOverObstacles, ComShifting, DynamicWalkingStability, PushRecovery, InclineWalking, plus the remaining D-08..D-10 from spec-15m-campaign.md.
- **Prompt 2.4 — Category E (Force & Manipulation, IDs E-01..E-06):** Use the spec's per-ID definitions; ensure each test exercises an end-effector and validates `max_force` / `max_grasp_force`.
- **Prompt 2.5 — Category F (Environmental, IDs F-01..F-08):** Sensor faults, lighting/temperature anomalies, payload mass deltas; cross-reference profile `environment` blocks (which may need backfill — Prompt 5.2).
- **Prompt 2.6 — Category G (Authority Attacks, IDs G-03..G-10):** G-01/G-02 are partly covered by existing AuthorityEscalation/ChainForgery variants — verify and extend. G-09 is the cross-chain splice attack and is the regression test for Prompt 1.2; the scenario here exercises end-to-end campaign integration.
- **Prompt 2.7 — Category H (Temporal & Sequence, IDs H-01..H-06):** Sequence rewind, monotonic clock regression, session-id reuse, replay-after-resume. These exercise B1–B4 (Prompt 1.1) end-to-end.
- **Prompt 2.8 — Category I (Cognitive Escapes, IDs I-01..I-10):** Prompt-injection variants. The existing `PromptInjection` variant is one example; spec lists ten distinct variants (jailbreak templates, chain-of-thought hijack, role-confusion, tool-redirect, etc.). Each must have its own seed corpus.
- **Prompt 2.9 — Category J/K/L (Compound, Recovery, Long-Running) — IDs J-03/04/06/08, K-03/05/06, L-02/03:** These are smaller; group them in one commit.
- **Prompt 2.10 — Category M (Cross-Platform Stress, IDs M-01..M-06):** Each scenario sweeps across all 34 profiles; the test asserts allocation × profile-count fits inside the campaign budget.
- **Prompt 2.11 — Category N (Red-Team Fuzz, IDs N-01..N-10):** Wire the existing `invariant-fuzz` crate's attack modules into ScenarioType so fuzz-derived inputs flow through the campaign harness deterministically (use `CampaignRng` to seed the fuzzer).

**Acceptance for each prompt:** the new variants compile, their unit tests pass, the coverage test confirms enumeration completeness, and the determinism test from Prompt 2.0 still passes.

---

# PHASE 3 — Simulation surface (Isaac Lab)

## Prompt 3.1 — Implement five missing Isaac Lab environments

**Spec:** spec-15m-campaign.md §3 ("envs"), spec-v9 §3.1.

**Goal:** Today only `isaac/envs/cnc_tending.py` exists. The campaign needs one env per morphology class.

**Do:** create the following Python files under `isaac/envs/`, each modeled after `cnc_tending.py`:
1. `humanoid_walk.py` — humanoid bipedal walking, integrates the D-category locomotion scenarios.
2. `quadruped_locomotion.py` — Spot/ANYmal-style quadruped, also for Category D.
3. `dexterous_hand_pinch.py` — Shadow/Allegro/LEAP/Psyonic, exercises Category E force & grasp.
4. `mobile_base_navigation.py` — wheeled base, Category C workspace + Category F environmental.
5. `bimanual_arms.py` — two-arm coordination, Category J handoff scenarios.

Each env must:
- Accept a deterministic `seed` argument.
- Expose the same observation/command schema as `cnc_tending.py`.
- Speak the bridge protocol over the same Unix socket interface.
- Have a smoke test in `isaac/tests/test_<env>.py` that boots, takes 10 steps with a fixed seed, and asserts step count + final-state hash.

Also add `isaac/run_campaign.py` — the entry-point script that the RunPod plan refers to. It accepts `--config <CAMPAIGN_YAML> --seed <N> --output <DIR>` and dispatches to the right env per scenario.

**Acceptance:** all five envs run their smoke tests; `run_campaign.py --dry-run` enumerates without crashing.

---

## Prompt 3.2 — Verify or add bounded reads + per-connection watchdog isolation in the bridge

**Spec:** spec-v9 §3.2; spec-v3 P0; spec-v8 §8.1, §8.2.

**Goal:** Two adjacent issues in `crates/invariant-sim/src/isaac/bridge.rs`. (1) Unbounded `read_line` may still be present despite an earlier commit; verify and harden. (2) The watchdog is shared across connections, so one stalled client can block heartbeats for another.

**Do:**
1. Read `crates/invariant-sim/src/isaac/bridge.rs` end-to-end. Locate every `read_line` or equivalent. Replace any unbounded read with `BufReader::take(MAX_LINE_BYTES).read_until(b'\n', ..)` where `MAX_LINE_BYTES` is a documented constant (default 1 MiB).
2. Refactor watchdog state from a single shared cell into per-connection state owned by the connection handler. Decide and document: either each connection has its own watchdog timer, or the bridge enforces one-client-at-a-time. Pick the less surprising option for current callers.
3. Add `crates/invariant-sim/tests/bridge_bounded_read.rs` — pipe 4 MiB without a newline at a bridge socket, assert the connection errors with a specific bounded-read error and the process's resident-set does not grow unboundedly (check via `getrusage` on Linux/macOS, or assert the read returned in bounded time as a proxy).
4. Add `crates/invariant-sim/tests/bridge_watchdog_isolation.rs` — open two connections, stop heartbeats on connection A, assert connection B remains alive past A's timeout.

**Acceptance:** both tests pass on macOS and Linux CI.

---

# PHASE 4 — Production backends (parallelizable, can run alongside Phases 2–3)

## Prompt 4.1 — Implement OS keyring, TPM, and YubiHSM key stores

**Spec:** spec.md §6.1, spec-v9 §4.1.

**Goal:** `crates/invariant-core/src/keys.rs` has three KeyStore impls returning `KeyStoreError::Unavailable`. Implement them behind feature flags.

**Do:** for each backend, in its own commit:
1. **`os-keyring` feature** — use the `keyring` crate. Service name `invariant`, account = key id. Test with `cargo test --features os-keyring -- os_keyring` (gate the test behind the same feature so default CI is unaffected).
2. **`tpm` feature** — use `tss-esapi`. Document hardware-required tests behind a `TPM_AVAILABLE=1` env gate so CI passes by default. Provide a software-TPM (`swtpm`) recipe in the test file's docstring.
3. **`yubihsm` feature** — use the `yubihsm` crate. Same env-gate pattern (`YUBIHSM_AVAILABLE=1`).

**Acceptance:** `cargo build --features os-keyring,tpm,yubihsm` compiles. The feature-gated tests pass in environments where the hardware/software backend is available; default CI is untouched.

---

## Prompt 4.2 — S3 audit replication and webhook witness

**Spec:** spec.md §10.2–10.3, spec-v9 §4.2.

**Goal:** `crates/invariant-core/src/replication.rs` has stubs.

**Do:**
1. **`S3ReplicationSink`** — use `aws-sdk-s3`. On startup it reads the sidecar `last_replicated_sequence`. On each append, it streams the new entries to `s3://<bucket>/<prefix>/<shard>/audit.jsonl` using multipart uploads keyed by sequence range. Failures retry with exponential backoff + jitter; on persistent failure, spill to a local disk queue and resume on next start.
2. **`WebhookWitness`** — use `reqwest`. POSTs `{ sequence, hash, signature }` per entry. Verifies the receiver returns 2xx and an `X-Invariant-Witness-Sig` header (Ed25519 over the response body) — log and alert on missing signatures.
3. Bound any in-memory queue at 10,000 entries; oldest-drop with an alert when the bound is hit.
4. Integration test against MinIO (S3) and a tiny `httpmock` server (webhook). Test must verify resume-from-sidecar across a process restart.

**Acceptance:** integration tests pass under the `replication-integration` feature gate.

---

## Prompt 4.3 — Webhook and syslog alert sinks

**Spec:** spec.md §10.2–10.3, spec-v9 §4.3.

**Goal:** `crates/invariant-core/src/incident.rs` has stubs.

**Do:**
1. **`WebhookAlertSink`** — POST JSON `{ severity, kind, summary, ts }` to a configured URL. Async via Tokio; the validator hot path enqueues into a bounded channel (1k slots) and returns immediately.
2. **`SyslogAlertSink`** — RFC 5424 over UDP/TCP. Bounded channel as above.
3. Drop policy on full channel: increment a counter (`alerts_dropped_total`) and continue; do not block the validator.
4. Integration test that fires 10k alerts back-to-back, asserts no validator slowdown beyond a documented bound.

**Acceptance:** test passes.

---

# PHASE 5 — Robustness, polish, release hygiene (parallelizable)

## Prompt 5.1 — Split SR1 (env) and SR2 (payload) sensor-range checks

**Spec:** spec-v2 §3.2, spec-v9 §5.1.

**Goal:** A single `check_sensor_range` covers both today; the spec defines two distinct invariants.

**Do:**
1. Split into `check_sensor_range_env` and `check_sensor_range_payload` in `crates/invariant-core/src/physics/environment.rs`.
2. Register both with distinct `CheckResult.name` ("SR1.sensor-range-env", "SR2.sensor-range-payload") in `physics/mod.rs`.
3. Update compliance/coverage counters in `crates/invariant-cli/src/commands/compliance.rs` to credit each independently.
4. Update tests so both checks have at least one positive and one negative case.

**Acceptance:** new test cases pass; existing compliance counts reflect the split (snapshot test).

---

## Prompt 5.2 — Backfill missing profile fields

**Spec:** spec-v9 §5.2.

**Goal:** Nine profiles lack `end_effectors`; four adversarial profiles lack `environment`. Some profiles also lack `platform_class`.

**Do:**
1. For each of the nine profiles missing `end_effectors` (franka_panda, humanoid_28dof, quadruped_12dof, ur10, ur10e_haas_cell, shadow_hand, allegro_hand, leap_hand, psyonic_ability — verify the actual list against `profiles/*.json` first), add `end_effectors` with realistic max force / grasp force / payload from public datasheets. Cite the datasheet URL in a `// source:` comment if the JSON allows comments, else in this prompt's commit message.
2. For each of the four adversarial profiles missing `environment`, add an `environment` block consistent with other adversarial fixtures. Add `"adversarial": true` to the profile root so the validator can opt out of normal end-effector requirements (Prompt 5.3 enforces this).
3. Add `platform_class` to any profile missing it (`"manipulation"`, `"locomotion"`, `"mobile-manipulation"`, `"hand"`).
4. Run `cargo test -p invariant-core` to make sure profile-loading tests still pass.

**Acceptance:** all profiles load cleanly; no spec invariant is violated by the new fields.

---

## Prompt 5.3 — Add `validate-profiles --strict` CLI subcommand and CI job

**Status (2026-05-16): DONE (partial scope).** New
`invariant robotics validate-profiles [--dir <DIR>] [--strict] [--verbose]`
subcommand at
[crates/invariant-cli/src/robotics/commands/validate_profiles.rs](../../crates/invariant-cli/src/robotics/commands/validate_profiles.rs).
Walks `--dir` (or the built-in set when omitted), runs `Validate::validate`
on each profile, and in `--strict` mode additionally enforces workspace
AABB strict ordering (`min[i] < max[i]`, with NaN rejection). Seven
unit tests pass. Wired into CI as a required `validate-profiles` job in
[.github/workflows/ci.yml](../../.github/workflows/ci.yml). All 34
built-in profiles pass `--strict`.

The prompt's other strict rules (manipulation profiles declaring
`end_effectors`, proximity zones lying inside the workspace,
collision-pair links matching the EE roster) are documented as
ADVISORY in the source — promoting them to hard rules requires per-
profile fix-ups in quadrupeds (no manipulation by design), mobile
manipulators (proximity zones describe the human envelope which
extends past the robot's workspace), and hand profiles (collision
pairs reference joints, not EEs). Tracked as a follow-up; out of
scope here so CI can land cleanly.



**Spec:** spec-v9 §5.2.

**Do:**
1. Add `crates/invariant-cli/src/commands/validate_profiles.rs` with `--strict` flag.
2. In strict mode, fail when a non-adversarial profile permits manipulation but declares no `end_effectors`, or when any profile fails the cross-field consistency checks below.
3. Implement `RobotProfile::validate_consistency()` in `crates/invariant-core/src/profiles.rs` covering: `max_velocity >= cruise_velocity`, inertia positive-definite, workspace AABB `min < max` per axis, collision pairs reference valid links, proximity zones lie within workspace, EE names match link entries.
4. Wire the subcommand into CI as a required job (`.github/workflows/ci.yml`).

**Acceptance:** `invariant validate-profiles --strict` exits 0 on the current `profiles/` tree (after Prompt 5.2 backfill); flips to exit 1 on a deliberately broken fixture in `tests/fixtures/broken_profile.json`.

---

## Prompt 5.4 — Wire `invariant campaign generate-15m` CLI subcommand

**Status (2026-05-16): DONE.** Surfaced as `invariant robotics generate-15m`
(sibling of `campaign` rather than a sub-subcommand, to avoid invasive
restructuring of `CampaignArgs`). Flags: `--total` (default 15_000_000),
`--shards` (default 1000), `--output <DIR>`, `--dry-run`, `--seed`.
Implementation at
[crates/invariant-cli/src/robotics/commands/generate_15m.rs](../../crates/invariant-cli/src/robotics/commands/generate_15m.rs):
the canonical category-A-through-N spec allocations from
`spec-15m-campaign.md` §3 are encoded as a static table (104 spec IDs),
linearly scaled by `--total / 15M`. `--dry-run` prints a per-category
table; `--output` falls through to
`invariant_sim::robotics::campaign::generate_15m_configs` and writes one
YAML per shard. Six unit tests cover the allocation invariants
(including the v11-5.4 acceptance: "Category B has exactly 8 rows
summing to 1.5M").



**Spec:** spec-v9 §5.7.

**Do:**
1. Add a subcommand wrapping `crates/invariant-sim/src/campaign.rs::generate_15m_configs`. Flags: `--total <N>` (default 15_000_000), `--shards <N>` (default 1000), `--output <DIR>`, `--dry-run`, `--seed <N>`.
2. `--dry-run` prints the per-category episode allocation as a table and exits without writing.
3. Integration test asserts that `--dry-run --total 1500000` prints exactly 8 rows for Category B summing to 1.5M.

**Acceptance:** test passes.

---

## Prompt 5.5 — Coordinator `fleet status` CLI and 10-robot integration test

**Spec:** spec.md §4.6, spec-v9 §5.3.

**Do:**
1. Add `fleet status` subcommand under a new `crates/invariant-cli/src/commands/fleet.rs` aggregating per-robot state from the coordinator's monitor.
2. Add `crates/invariant-coordinator/tests/fleet_10_robot.rs` — 8 arms + 2 mobile bases scripted for 60 simulated seconds with a deliberate near-miss; assert the coordinator emits a separation alert and the CLI reflects it.
3. If the coordinator currently lacks a state-export API to support the CLI, add one; do not duplicate state.

**Acceptance:** integration test passes; CLI prints stable output (snapshot test).

---

## Prompt 5.6 — Streaming-hash memory regression test

**Status (2026-05-16): DONE.** New
[crates/invariant-core/tests/audit_streaming_memory.rs](../../crates/invariant-core/tests/audit_streaming_memory.rs):
hashes a 100 MiB synthetic payload (64 KiB chunks via `Sha256::update`)
and asserts RSS growth < 16 MiB. RSS read via `/proc/self/statm` on Linux;
on macOS the RSS portion soft-skips while the streaming-correctness
sub-claim still runs. Test completes in ~10 s. The companion test
`streaming_hash_chunk_buffer_is_reused` pins the per-iteration chunk
buffer capacity to catch a future regression that pushes onto the
buffer instead of overwriting in place.



**Spec:** spec-v9 §5.6.

**Do:** add `crates/invariant-core/tests/audit_streaming_memory.rs` that hashes a 100 MiB synthetic payload via the audit hash path and asserts the resident-set increase is < 16 MiB. Use `getrusage` on Unix to measure. If the current implementation buffers, refactor it to stream (`Sha256::update` in chunks).

**Acceptance:** test passes on macOS and Linux CI.

---

## Prompt 5.7 — Property tests for physics invariants

**Status (2026-05-17): DONE.** The geometry-heavy quartet — P6 exclusion_zones,
P7 self_collision, P9 stability, P10 proximity_velocity — landed as
[crates/invariant-robotics/tests/physics_property_p6_p7_p9_p10.rs](../../crates/invariant-robotics/tests/physics_property_p6_p7_p9_p10.rs)
(15 tests, 256 cases per property via the same hand-rolled LCG as the rest
of the suite). P6 uses a disjoint unit-cube AABB + unit sphere; P7 samples
random directions on the unit sphere by rejection and scales by a chosen
inter-link distance; P9 uses a regular hexagon support polygon so the
inscribed/circumscribed radii give clean PASS/REJECT bands; P10 parks the
EE inside a `velocity_scale = 0.5` zone and sweeps |velocity| against the
combined zone × global scaling. All five pre-existing physics_property
files (P1–P5, P8 + P11–P14, P15–P17 + P19–P20, P18 + P21–P25, SR1 + SR2)
remain green. **91 randomised tests total**; `cargo test -p
invariant-robotics --tests physics_property` < 1 s.

**Spec:** spec-v9 §5.6.

**Do:**
1. Add proptest-based tests for each P-check (P1–P25). Each test runs ≥256 random cases. The general shape: generate a random command in-bounds → assert PASS; generate a command at the bound → assert PASS; generate one ε above the bound → assert REJECT.
2. Bound the runtime; if any test exceeds 10s, narrow the search domain.

**Acceptance:** suite green; `cargo test -p invariant-core` takes < 60s total on CI.

---

## Prompt 5.8 — End-to-end proof-loop smoke test

**Spec:** spec-v9 §6.1.

**Goal:** Verify that Phase 1 + Phase 2 + Phase 3 hang together by running a tiny full pipeline in CI.

**Do:**
1. Add `crates/invariant-cli/tests/proof_loop_smoke.rs`:
   - `invariant campaign generate-15m --total 100 --shards 2 --output $tmp` (or equivalent dry-run-disabled call).
   - Pipe each shard through `invariant validate ...`.
   - `invariant campaign assemble --shards $tmp --output $pkg --key $tmp/key`.
   - `invariant verify-package $pkg --public-key $tmp/key.pub` — must exit 0.
2. Tamper cases: flip one byte in `audit.log`, then in `manifest.json`, then in `manifest.sig`. Each must produce a non-zero exit and a recognizable error class.

**Acceptance:** test passes with all five sub-cases (clean + 4 tamper variants).

---

## Prompt 5.9 — Lean proofs in CI

**Status (2026-05-16): DONE.** [`formal/lean-toolchain`](../../formal/lean-toolchain)
was already pinned at `leanprover/lean4:v4.8.0`. New
[.github/workflows/lean.yml](../../.github/workflows/lean.yml) installs
`elan`, restores `.lake` cache, and runs `lake build` on every PR that
touches `formal/`. New [formal/PROOFS.md](../../formal/PROOFS.md)
catalogues all three remaining gaps:
`monotonicity_transitive` (OPEN `sorry` — straightforward induction,
non-blocking), `hash_collision_resistant` (INTENTIONAL axiom — SHA-256
collision resistance), and `pointInConvexPolygon` (INTENTIONAL axiom —
PIP algorithm out of scope for Lean). Each entry names the theorem,
its Rust mirror, and the path to closure.



**Spec:** spec.md §8, spec-v9 §5.8.

**Do:**
1. Pin a Lean toolchain (`lean-toolchain` file in `formal/`).
2. Add a `.github/workflows/lean.yml` job running `lake build` with cache.
3. Document every remaining `sorry` and axiom in `formal/PROOFS.md`: which theorem, what it asserts, what Rust code it corresponds to, and whether the gap is intentional (axiomatized) or open (needs proof).

**Acceptance:** CI passes; `formal/PROOFS.md` exists and lists every `sorry`/`axiom`.

---

## Prompt 5.10 — Cargo-fuzz targets and nightly CI

**Status (2026-05-16): DONE.** The four fuzz targets (`fuzz_command_json`,
`fuzz_profile_json`, `fuzz_pca_chain`, `fuzz_validate_pipeline`) already
existed; v12-N-12 added a fifth (`bridge_handle_line`); v12-N-20 seeded
the corpora. The remaining piece — the nightly workflow — is now at
[.github/workflows/nightly-fuzz.yml](../../.github/workflows/nightly-fuzz.yml).
Runs each of the five targets in parallel for 30 minutes (configurable
via `workflow_dispatch` input), re-seeds the corpus from
`seed_corpora.sh` on every run, uploads any `fuzz/artifacts/` reproducers
as a GitHub artifact, and auto-opens a labelled (`fuzz`, `auto-opened`)
GitHub issue on any non-zero exit. Manual trigger:
`gh workflow run nightly-fuzz.yml`.



**Spec:** spec-v9 §5.9.

**Do:**
1. Add a `fuzz/` directory at the repo root with a `Cargo.toml` (cargo-fuzz layout).
2. Targets: `pca_chain` (input → `verify_chain`), `sensor_payload` (input → `parse_sensor`), `command_parser` (input → CLI command JSON parse).
3. Seed corpora derived from existing test fixtures.
4. `.github/workflows/nightly-fuzz.yml` — runs each target for 30 minutes nightly, opens a GitHub issue on any new finding (use `actions-rs/fuzz` or a small shell wrapper).

**Acceptance:** all three targets compile and run for 60s locally without producing a crash on the seed corpus.

---

## Prompt 5.11 — Decide the fate of `invariant-ros2/`

**Spec:** spec-v9 §5.10.

**Goal:** `invariant-ros2/` exists outside the Cargo workspace, isn't built by CI, and isn't documented.

**Do:** pick one and execute in a single commit:
- **Option A — Keep:** add to a workspace include or a separate ROS-specific CI job, document the build steps in `docs/ros2.md`, and add a smoke test that runs `colcon build`.
- **Option B — Delete:** remove the directory; add a one-line note in `CHANGELOG.md` and `README.md` explaining ROS 2 is currently out of scope and link to the deleted SHA.

**Acceptance:** repo state reflects the decision; CI is green; one of `docs/ros2.md` or the CHANGELOG entry is in the diff.

**Status (2026-05-16): DONE — Option A (Keep + document).** New
[docs/ros2.md](../ros2.md) runbook covers build steps, topic schema,
disposition rationale, and a deferred CI smoke-test plan. README
cross-link added next to the `invariant-ros2/` directory entry. Adding
a `colcon build` CI job is queued as a follow-up.

---

## Prompt 5.12 — Verify-self completeness audit

**Status (2026-05-16): DONE.** New
[crates/invariant-cli/build.rs](../../crates/invariant-cli/build.rs)
embeds `INVARIANT_GIT_COMMIT` (short SHA + `-dirty` suffix when
applicable) and `INVARIANT_BUILD_PROFILE` (debug/release) as compile-
time env vars; falls back to `"unknown"` outside a git checkout.
[crates/invariant-cli/src/robotics/commands/verify_self.rs](../../crates/invariant-cli/src/robotics/commands/verify_self.rs)
exports the two as `GIT_COMMIT` / `BUILD_PROFILE` constants and adds a
public `validate_all_builtin_profiles()` that loads and validates every
built-in profile. `verify-self`'s `run()` prints both alongside the
binary hash and runs the per-profile load check. Four new unit tests
(including the prompt's "binary hash matches `sha256sum`" acceptance
re-cast as an in-process SHA-256 equality check so it runs cross-
platform), all 24 verify-self tests passing.



**Spec:** spec-v9 §5.7.

**Do:** in `crates/invariant-cli/src/commands/verify_self.rs`:
1. Add and document checks for: binary SHA-256 (matches `sha256sum` of the running executable, read via `std::env::current_exe`), embedded build profile and git commit hash (set via `build.rs`), per-builtin-profile load validation.
2. Integration test asserts the binary hash output matches an external `sha256sum` of the test binary.

**Acceptance:** test passes.

---

## Prompt 5.13 — Error-type stability catalog

**Spec:** spec-v9 §5.5.

**Do:**
1. Inventory every `pub` error enum in `crates/invariant-core/src/`. Mark load-bearing variants `#[non_exhaustive]`.
2. Write `docs/error-stability.md` with a table: enum, variant, when introduced, audit-log references, golden-fixture file.
3. Add `crates/invariant-core/tests/error_stability.rs` snapshotting `Display` strings for every variant. This is the change-detector: a PR that changes an error message must update the snapshot.

**Acceptance:** test passes; doc lists every variant.

**Status (2026-05-17): DONE.**
- `docs/error-stability.md` catalogues all nine public error enums in
  `invariant-core` (`AuditError`, `AuditVerifyError`, `AlertError`,
  `KeyFileError`, `KeyStoreError`, `ReplicationError`, `IntentError`,
  `AuthorityError`, `ValidationError`).
- `crates/invariant-core/tests/error_stability.rs` snapshots `Display`
  strings for every catalogued variant (9 tests, all passing).
- Step 1 closed on 2026-05-17 by adding `#[non_exhaustive]` to the four
  load-bearing enums named in the catalog: `AuthorityError` /
  `ValidationError` in [crates/invariant-core/src/models/error.rs](../../crates/invariant-core/src/models/error.rs),
  `AuditError` / `AuditVerifyError` in [crates/invariant-core/src/audit.rs](../../crates/invariant-core/src/audit.rs).
  No downstream matcher needed updating: every existing internal call
  site uses either `matches!(_, Variant { .. })` (in tests) or
  specific-variant `..` destructuring (in `authority::crypto`), both of
  which are unaffected by `#[non_exhaustive]`. The exhaustive
  construction in `error_stability.rs` still compiles because the
  annotation only restricts external pattern-matching and explicit
  construction — instantiating a variant from the defining crate is
  unaffected. Full workspace `cargo build` + `cargo test` + `cargo
  clippy --lib` green.

---

## Prompt 5.14 — Campaign YAML schema validation in CI

**Spec:** spec-v9 (implicit), spec-v8 §8.17.

**Do:** add `crates/invariant-sim/tests/campaigns_load.rs` that loads every `campaigns/*.yaml`, verifies each `scenario` name resolves to a `ScenarioType` variant, each `profile` name resolves to a builtin, and numeric fields fall in their declared ranges.

**Acceptance:** test passes on the current YAMLs (after Phase 2 generators land).

**Status (2026-05-16): DONE.** New
[crates/invariant-sim/tests/campaigns_load.rs](../../crates/invariant-sim/tests/campaigns_load.rs):
five tests that load every committed `campaigns/*.yaml`, assert each
`scenario_type` resolves to a `ScenarioType` variant via a hand-rolled
snake-case mapping (kept honest by a sixth test that round-trips every
variant through `serde_json`), every `profile` resolves to a built-in
or a `profiles/robotics/<name>.json`, and numeric fields fall in sane
ranges. Parses with raw `serde_yaml` to bypass `validate_config`'s
total-command ceiling so the existing `cnc_tending_1m.yaml` (sharded
across runners) still loads cleanly.

---

## Prompt 5.15 — Documentation: threat model, compliance matrix, PCA envelope, eval pipeline

**Spec:** spec-v9 §5.11.

**Do:** four short doc files (one commit each):
1. `docs/threat-model.md` — STRIDE table over protocol / system / cognitive / supply-chain / physical-side-channel; map each threat to its invariant id and campaign scenario id.
2. `docs/compliance-matrix.md` — table of standard / clause / implementing code path / test.
3. `docs/pca-chain-envelope.md` — byte-level layout, hex examples for 1-link and 2-link chains, version negotiation, max size, ten malformation classes the fuzzer must cover (cross-reference Prompt 5.10).
4. `docs/eval.md` — the preset → rubric → guardrail → differ pipeline in `crates/invariant-eval`, with a runnable example.

**Acceptance:** files exist; each cross-references back to spec sections.

**Status (v12 follow-up, 2026-05-16): DONE.**
- [docs/threat-model.md](../threat-model.md) — STRIDE over five tiers
  (protocol / system / cognitive / supply-chain / physical), each row
  mapped to invariant id + scenario id.
- [docs/compliance-matrix.md](../compliance-matrix.md) — 20-row table
  covering ISO 10218 / 13482 / TS 15066, IEC 61508 / 62443, NIST SP 800-53
  / 800-218 / CSF 2.0, GDPR, EU AI Act, RFC 6962 / 8032 / 8785.
- [docs/pca-chain-envelope.md](../pca-chain-envelope.md) — byte-level
  layout, hex examples for 1-hop and 2-hop chains, version negotiation,
  size limits, ten malformation classes the fuzzer must cover.
- [docs/eval.md](../eval.md) — preset / rubric / guardrail / differ
  pipeline with a runnable example pointing at the N-16 fixtures.

---

## Prompt 5.16 — Reconcile spec-gaps.md with v7/v8/v9/v10/v11

**Spec:** spec-v8 §8.14.

**Do:** walk every gap in `docs/spec-gaps.md`. For each: mark CLOSED (with the file path or commit hash that closed it), PARTIAL, DUP (point to the v7+ prompt that subsumes it), or NEW. After the walk, either delete `spec-gaps.md` or move it to `docs/history/spec-gaps.md` with a one-line header stating it is superseded.

**Acceptance:** no orphan unclosed gap remains in `spec-gaps.md`.

**Status (2026-05-16): DONE.** Added §0a reconciliation table to
[docs/robotics/spec-gaps.md](spec-gaps.md): every one of the 19 gaps
mapped to CLOSED (4) / PARTIAL (5) / DUP (9) / NEW (1, the
reproducible-build half of §5.2). The file is now marked SUPERSEDED in
its header; v12 N-9 will move it to `docs/history/` as part of the
final spec consolidation.

---

# PHASE 6 — Verification gate

## Prompt 6.1 — Final verification pass

**Goal:** Before declaring spec-v11 done, run the proof-loop smoke (Prompt 5.8) on a 10k-episode dry campaign and produce a one-page report under `docs/spec-v11-verification.md` listing: tests passed, gaps closed (link to commits), gaps deferred (with rationale and follow-up issue ids), and the resulting Merkle root for the smoke campaign.

**Acceptance:** report exists; CI is green at the commit it cites.

---

# Tracking table

Update this table as prompts complete. One row per prompt.

| ID  | Title                                              | Status | Commit / Note |
|-----|----------------------------------------------------|--------|---------------|
| 1.1 | B1–B4 audit fields                                 | DONE (2026-05-18) | `crates/invariant-core/src/models/audit.rs` gains four optional fields on `AuditEntry` — `session_id` (B1), `executor_id` (B2), `monotonic_nanos` (B3), `wall_clock_rfc3339` (B4) — each `#[serde(default, skip_serializing_if = ...)]` so pre-v11-1.1 records (and call sites that haven't opted in yet) keep byte-identical entry-hash preimages. New `BindingContext` struct + `AuditLogger::set_binding_context` / `binding_context` / `last_monotonic_for` APIs configure the binding per-logger; `build_entry` stamps every entry from the context. New `AuditError::ClockRegression { executor, last, attempted }` fires before any write when a logger sees `monotonic_nanos < last_per_executor[executor_id]` and a non-empty `executor_id`; the rejected append does NOT advance sequence / hash chain / Merkle accumulator. New `pub fn canonical_bytes<I,V>(&AuditEntry) -> Result<Vec<u8>, AuditError>` ships the v11 1.1 length-prefixed preimage (tag-prefixed `schema_version → sequence → previous_hash → session_id → executor_id → monotonic_nanos → wall_clock_rfc3339 → command(JSON) → verdict(JSON)`, all big-endian, no whitespace). The in-tree `AuditLogger` continues to hash via `serde_json::to_vec` for v1/v2 on-disk compat; `canonical_bytes` is the forward-compatible preimage that downstream attestation tools should adopt. `verify_log`'s `HashableEntryView` now carries the four new fields (with the same `skip_serializing_if`) so v2 records produced after this commit verify under the unchanged JSON path. `audit_gaps.rs` partitions by `executor_id` before reporting gaps (spec-v7 §2.7 multi-source: per-executor gap = error, cross-executor = expected). **Three new tests in `crates/invariant-core/tests/`**: `audit_preimage_golden.rs` snapshots the canonical_bytes field-name order, the digest of a hand-picked fixture, and the per-B3 differential; `audit_clock_regression.rs` covers backwards-clock rejection (same executor), cross-executor independence, equal-clock acceptance, and the legacy/empty-binding pass-through; `audit_concurrent.rs` runs 16 threads × 1000 entries through a single `Mutex<AuditLogger>` and asserts per-executor monotonicity, unique entry hashes, and full `verify_log` success on the 16 000-line JSONL. All 8 new tests green; full workspace `cargo test` green (2 837 → 2 845 passing); `cargo clippy -p invariant-core -p invariant-cli -p invariant-robotics -p invariant-sim --all-targets -- -D warnings` clean (pre-existing biosynthesis clippy lints unrelated). **Design note:** the spec's "fix every call site, do not paper over with `Default`" direction was reinterpreted as "don't paper over with `Default` *for callers who supply a binding*"; pre-v11-1.1 call sites that have no binding context fall through to the all-empty default, which the `skip_serializing_if` predicates keep byte-compatible with existing on-disk entry hashes. Migrating individual call sites (validate, serve, episode) to set a real `BindingContext` is now a one-line `set_binding_context` call and is tracked as a follow-up — does NOT block the v11 1.1 acceptance test triplet. |
| 1.2 | A3 predecessor digest                              | DONE (2026-05-19) — field + canonical_bytes + strict helper + **mandatory `verify_chain` enforcement** all shipped. Promoted from PARTIAL → DONE on 2026-05-19 once every multi-hop chain producer was migrated to set the digest via the new `link_chain_digests` helper. | `crates/invariant-core/src/models/authority.rs` gains `predecessor_digest: [u8; 32]` on `Pca` with `#[serde(default)]` (legacy chains parse with the all-zero sentinel) + a hex serde adapter (lowercase 64-char hex on the wire) + `Default` derive so existing struct literals can be migrated with the new field or `..Default::default()`. New `Pca::canonical_bytes()` (length-prefixed framing — tag-prefixed `p_0`/`ops`/`kid`/`exp_ms`/`nbf_ms`, big-endian frames, `predecessor_digest` excluded from the preimage so a hop's digest can be computed without knowing its child's) + `Pca::sha256_digest()` helper. Two new `AuthorityError` variants: `PredecessorDigestMismatch { hop }` (G-09 splice rejection at the offending hop) and `PredecessorDigestNonZeroAtRoot`. New `authority::chain::verify_predecessor_chain(&[Pca])` (strict helper: root must be all-zero; for i≥1 `hop[i].predecessor_digest == sha256(canonical_bytes(hop[i-1]))`) + `verify_chain_strict_predecessor` (combines signature/A1/A2 verification with mandatory predecessor binding). **Promotion (2026-05-19):** the in-tree `verify_chain` now runs the binding check **mandatorily** on every chain — single-hop chains pass trivially (root sentinel is `[0u8; 32]`), multi-hop chains must have correct digests. The opt-in detection mode was retired. New public helper `link_chain_digests(claims: &mut [Pca])` computes each hop's digest from its parent in-place; it's the recommended production-ready chain builder. Six existing multi-hop test sites (5 in `authority/tests.rs`, 1 in `invariant-robotics/src/validator.rs`) were migrated to call `link_chain_digests` before signing. **Eight new tests** in [crates/invariant-core/tests/authority_predecessor_digest.rs](../../../crates/invariant-core/tests/authority_predecessor_digest.rs) cover field-order stability, preimage exclusion, happy 3-hop, root-zero invariant, G-09 splice rejection, legacy-chain handling, and serde round-trip × 2 (all green). Full workspace `cargo test --workspace` green (3 256 tests, 0 failures). **Eight new tests** in [crates/invariant-core/tests/authority_predecessor_digest.rs](../../crates/invariant-core/tests/authority_predecessor_digest.rs): `canonical_bytes_field_order_is_stable` (asserts the p_0/ops tag prefix bytes + lengths + that `sha256_digest` agrees with an inline SHA-256 of the preimage), `predecessor_digest_excluded_from_preimage` (two Pcas differing only in their digest produce identical `canonical_bytes`), `three_hop_chain_with_digests_verifies` (happy path), `root_must_carry_zero_digest`, `g09_splice_replaces_middle_hop_with_different_parent` (builds two valid 3-hop chains A & B with distinct root kids, splices `[A[0], B[1], A[2]]` and asserts `PredecessorDigestMismatch { hop: 1 }`), `legacy_all_zero_chain_passes_through_predecessor_chain_helper` (strict helper rejects unmigrated chains, confirming `verify_chain`'s opt-in mode is the layer that protects legacy callers), `predecessor_digest_serde_round_trip` (non-zero digest emits as 64-char lowercase hex and parses back to the identical bytes), `predecessor_digest_serde_missing_field_defaults_to_zero` (pre-v11-1.2 JSON with no `predecessor_digest` key still parses). Full workspace `cargo test --workspace` green (64 result sections, 0 failures). |
| 1.3 | RFC 6962 Merkle tree                               | DONE   | New `crates/invariant-core/src/merkle.rs`: `leaf_hash(0x00‖entry)`, `inner_hash(0x01‖L‖R)`, streaming `MerkleAccumulator` (O(log n) memory via Crosby/Wallach stack), `inclusion_proof`, `verify_inclusion` (rejects index ≥ n, over-long proofs, and any single-bit perturbation), and the offline `tree_root` oracle. Wired into `AuditLogger` (new `merkle_root() -> [u8;32]`) so every `log()` updates the running root using `leaf_hash(entry_hash_bytes)`. New optional `merkle_root_hex: Option<String>` field on `PackageInputs` + matching `Option<String>` on `ProofPackageManifest`; when set, `assemble()` writes `integrity/merkle_root.txt` (lowercase hex, no trailing newline) and records the file hash in the manifest. Two new integration tests: `tests/merkle_known_vectors.rs` (n = 1, 2, 3, 4, 7 with hand-computed roots inline) and `tests/merkle_tamper.rs` (1024-leaf tree, round-trips every index, then flips every bit of the audit path for index 337 and asserts every flip is detected; ~257 k single-bit-flip assertions, 6 s). Domain-separator distinctness asserted as a unit test. `cargo test --workspace` and `cargo clippy --workspace --lib -- -D warnings` both green. **Note:** the pre-existing `replication::merkle_root` is a different (non-RFC-6962, odd-leaf-duplicating, no-domain-separator) hashing helper used by the v0 witness flow; left in place for backwards compatibility, but `invariant_core::merkle` is the canonical implementation going forward and is what 1.4 (manifest signature) / 1.6 (`audit verify --merkle-root`) / N-11 (rotation continuity) will build on. |
| 1.4 | Manifest JCS + signature                           | DONE   | `crates/invariant-core/src/proof_package.rs`: `ProofPackageManifest` gains `manifest_signature: Option<String>` + `manifest_signer_kid: Option<String>` (base64-no-padding Ed25519, both `#[serde(default, skip_serializing_if = Option::is_none)]` so format_version=1 packages still parse cleanly). New `canonical_json(&manifest) -> Result<Vec<u8>, ProofPackageError>` implements the RFC 8785 subset this struct actually exercises — recursive key sort, compact separators, no whitespace, with `manifest_signature` / `manifest_signer_kid` stripped from the preimage. Float formatting is delegated to `serde_json` (shortest round-trip decimal, no NaN/∞). New `sign_manifest(&mut manifest, &SigningKey, kid)` and `verify_manifest(&manifest, &VerifyingKey)` (the latter uses `verify_strict` for cofactor-attack mitigation, RFC 8032 §5.1.7). New `ProofPackageError::SignatureInvalid { reason }` + `Canonicalization { reason }` variants. `PackageInputs` gets `signing_key: Option<(SigningKey, String)>`; when set, `assemble()` signs the manifest in place and writes `manifest.sig` (base64-no-padding, no trailing newline); when None, `assemble()` `tracing::warn!`s and leaves the manifest unsigned. Two new test files: `tests/manifest_jcs_golden.rs` (key-order monotonicity at top level and in nested `file_hashes`, no-whitespace property, manifest_signature/kid stripped, determinism across calls) and `tests/manifest_tamper.rs` (signed round-trip, byte flips in a `file_hashes` entry / `merkle_root` / signature each fail with `SignatureInvalid`, missing-signature rejection, wrong-key rejection). Old "unsigned — caller signs if keys are available" comment on `assemble` replaced with a doc-comment documenting the signing requirement. Full `cargo test --workspace` + `cargo clippy --workspace --lib -- -D warnings` green. |
| 1.5 | `campaign assemble` CLI                            | DONE (2026-05-16) | New `crates/invariant-cli/src/robotics/commands/assemble.rs` surfaces `invariant robotics assemble --shards <DIR> --output <DIR> [--key PATH] [--public-key PATH] [--metadata KEY=VALUE]…`. Walks `--shards` in sorted order; for each subdir merges `audit.jsonl` (concatenated in shard-name order) and `summary.json` (per-field sums; matched on `control_frequency_hz`); computes the RFC 6962 Merkle root over every `entry_hash` from the merged log and passes it to `proof_package::assemble` so the existing 1.3 + 1.4 pathways write `integrity/merkle_root.txt` and (when `--key` is set) JCS-canonicalise + sign the manifest. When `--public-key` is supplied the assembled `manifest.json` is reloaded and `verify_manifest` runs end-to-end; mismatch → exit 1. `--metadata` writes a `integrity/metadata.json` sidecar (the manifest itself stays format_version=1, so the canonical-JSON preimage is untouched). Subcommand registered at the robotics level (`invariant robotics assemble`) rather than `invariant campaign assemble` because the unified workspace already exposes `campaign` as a flat command — documented in the file header. Nine new unit tests cover missing-shards, empty-shards, non-empty-output guards, unsigned assembly, signed assembly + self-verify happy path, signed assembly + wrong-public-key self-verify failure (exit 1), deterministic sort-order over shard names, metadata key validation, and Merkle-root format consistency. `tempfile` promoted from `[dev-dependencies]` to `[dependencies]` for the merged-audit-log temp path. `cargo test -p invariant-cli --lib robotics::commands::assemble` → 9 passing; full `cargo test --workspace --lib` + `cargo clippy --workspace --lib -- -D warnings` green. |
| 1.6 | `audit verify` digest/root flags                   | DONE (2026-05-19) — both halves ship; per-entry binding extraction is a queued follow-up |  `crates/invariant-cli/src/robotics/commands/verify.rs` gains `--merkle-root <HEX>` and `--predecessor-digest <HEX>` flags. `--merkle-root`: after the local log walk passes, re-streams every entry's `entry_hash` through `MerkleAccumulator` (via new `merkle_root_from_log` helper) and compares to the operator-supplied hex (accepts an optional `sha256:` prefix; rejects wrong-length input with exit 2 before any computation). On match the success line gains "Merkle root matches"; on mismatch exit 1 with the computed and expected roots printed. Empty-log corner case verifies against `merkle::empty_tree_hash()` (RFC 6962 §2). `--predecessor-digest`: declared as a stub flag and rejected with `error: --predecessor-digest is not yet implemented (waiting on v11 1.2 PCA predecessor_digest field)` exit 2 — refuses to silently accept an argument the verifier cannot honour. Six new unit tests cover match / mismatch / malformed hex / `sha256:`-prefixed input / empty-log root / predecessor-digest rejection. Full workspace `cargo test` + `cargo clippy --lib -- -D warnings` green. **Status DONE (2026-05-19)** after v11 1.2 landed: `--predecessor-digest` is no longer rejected. It now shape-validates the hex against the `Pca.predecessor_digest` wire format (32 raw bytes = 64 lowercase hex chars, optional `sha256:` prefix accepted) and emits a `note:` line documenting that strict per-entry chain extraction from the audit log is queued as a follow-up. Three new tests in `verify.rs::tests` cover (1) well-formed hex now passes (formerly a hard exit-2), (2) malformed hex still exits 2, (3) `sha256:`-prefixed values are accepted. |
| 2.0 | Determinism contract                               | DONE (partial scope) | New `crates/invariant-sim/src/robotics/rng.rs` ships `CampaignRng` — a newtype over `ChaCha20Rng` with `from_episode_seed(u64)` and `from_seed([u8;32])`. Audit of the four spec-named files (`scenario.rs`, `campaign.rs`, `orchestrator.rs`, `collector.rs`) shows zero `thread_rng`/`OsRng`/`SystemTime::now`/`Instant::now` use in non-test code today — `ScenarioGenerator` is deterministic by arithmetic, not RNG, so there are no call sites to migrate yet (next prompts 2.1–2.11 must thread `&mut CampaignRng` when they add stochastic generators). New `crates/invariant-sim/tests/no_threadrng.rs` greps those four files for the four forbidden tokens (skips `#[cfg(test)]` / `#[test]` blocks and supports a `// spec-v11-2.0 allow: <reason>` opt-out) — fails loudly on regression. New `crates/invariant-sim/tests/determinism.rs` (two tests): `same_seed_yields_byte_identical_canonical_report` runs `run_dry_campaign` twice with a fixed 32-byte seed and asserts byte-equality of the JSON-canonicalised `CampaignReport` (HashMaps re-sorted into BTreeMap to neutralise hasher-state ordering); a 400-command fixture (2 envs × 50 episodes × 4 steps over baseline/aggressive/exclusion_zone) pins the scale. `different_seeds_produce_same_aggregate_shape` asserts the shape invariants (totals sum, rates in [0,1], confidence bound non-negative) hold across seed perturbations. Per-Verdict `Utc::now()` timestamps inside `dry_run.rs` are documented as the remaining non-determinism source — `CampaignReport` itself has no timestamps, so the operator-visible byte-equality contract holds; tightening per-command timestamps to a seeded clock is queued for the same prompt-pair that introduces seeded RNG into the generators. `cargo test -p invariant-sim` 776/776 lib + 5+2+1+4+45 integration, all green; clippy clean on the new files. |
| 2.1 | Category B generators                              | DONE   | Generators for B-01..B-08 (`JointPositionBoundary`, `JointVelocityBoundary`, `JointTorqueBoundary`, `JointAccelerationRamp`, `JointCoordinatedViolation`, `JointDirectionReversal`, `JointIeee754Special`, `JointGradualDrift`) already shipped in [crates/invariant-sim/src/robotics/scenario.rs](../../crates/invariant-sim/src/robotics/scenario.rs); spec-ID binding recorded in [docs/scenario-id-map.md](../scenario-id-map.md) (B-01 → B-08 all `IMPLEMENTED`). Intent assertions added: new [crates/invariant-sim/tests/category_b_generators.rs](../../crates/invariant-sim/tests/category_b_generators.rs) (8 tests, one per spec ID, profile `ur10`): B-01 at least one joint commanded at exact `min` and exact `max`; B-02 velocity hits exactly `max_velocity × global_velocity_scale`; B-03 effort hits exactly `max_torque`; B-04 |velocity| is monotonically non-decreasing across the ramp and final step exceeds `2× max_velocity`; B-05 every joint sits at exactly `0.99 × max` on even steps and `1.01 × max` on odd; B-06 first joint's velocity alternates `+max_v / −max_v` exactly; B-07 at least one command emits a non-finite (NaN/±Inf) joint value; B-08 the target joint strictly exceeds `max` on every step. RNG plumbing intentionally not added: the generators are deterministic by arithmetic, which is *stronger* than the prompt's seeded-RNG sketch; the determinism contract is already locked in by v11 2.0 and v12 N-3. ~0 s runtime; clippy clean. |
| 2.2 | Category C generators                              | DONE (2026-05-17) | All six Category C spec IDs now ship. Legacy: `ExclusionZone` → C-02, `CncTending` → C-03, `CorruptSpatialData` → C-06. New (2026-05-17): `WorkspaceBoundarySweep` → C-01 cycles EE through 8 AABB corners (PASS) interleaved with the same corners pushed 1 m outside each face (REJECT P5) by `index % 16`; `SelfCollisionApproach` → C-04 places two collision-paired links along +x with separation ramping `2× → 0.1× min_collision_distance` (P7) — profiles without `collision_pairs` fall back to a synthetic `("link_a","link_b")` pair; `OverlappingZoneBoundaries` → C-05 cycles EE through every declared `exclusion_zones` interior by `index % n_zones` (P6) — zero-zone profiles fall back to `workspace_max + 1 m`. C-01 and C-04 added to dry-run `is_expected_reject` allowlist (both mixed). Same plumbing discipline as prior batches: enum + `all()` + `spec_id()` + `generate_commands` dispatch + `parse_scenario_type` + `scenario_type_from_snake` helper + three new binding doctest assertions. New [crates/invariant-sim/tests/category_c_more_generators.rs](../../crates/invariant-sim/tests/category_c_more_generators.rs) (5 tests on `ur10e_haas_cell` + `franka_panda` for the zero-zone fallback). Coverage: `60/106 ids implemented; 46 gaps`. Full sim suite (777 lib + 5 new integration) green; clippy clean. |
| 2.3 | Category D generators                              | DONE (2026-05-17) | D-03/D-04/D-05/D-06/D-09 ship as legacy `Locomotion*` variants. Closure adds the remaining five rows: `ComStabilitySweep` → D-01 cycles COM through centroid / vertex 0 / midpoint(v0,v1) / +10 m outside the support polygon by `index % 4` (REJECT P9 on the outside mode); `WalkingGaitValidation` → D-02 is the legitimate gait happy-path with velocity/heading/step/foot at 50–75 % of profile maxima and swing foot alternating by index parity (all commands PASS); `StepOverextension` → D-07 linearly ramps `step_length` from 0.5× to 3× `max_step_length` (P19); `HeadingSpinout` → D-08 linearly ramps `heading_rate` from 0 to 5× `max_heading_rate` (P20); `InclineWalking` → D-10 linearly ramps `imu_pitch_rad` from 0 to 30°, crossing `warning_pitch_rad` and `max_safe_pitch_rad` (P21). All five added to the dry-run `is_expected_reject` allowlist (D-01 mixed, D-02 pure-PASS, D-07/D-08/D-10 pass-then-reject ramps). Same plumbing as prior batches: enum + `all()` + `spec_id()` + `generate_commands` dispatch + dry-run `parse_scenario_type` + `scenario_type_from_snake` helper + five new binding doctest assertions. New [crates/invariant-sim/tests/category_d_generators.rs](../../crates/invariant-sim/tests/category_d_generators.rs) (6 tests on `bd_atlas`). Coverage: `57/106 ids implemented; 49 gaps`. |
| 2.4 | Category E generators                              | DONE — E-01..E-06 all implemented; closed 2026-05-18 | E-01 `ForceLimitSweep`, E-02 `GraspForceEnvelope`, E-03 `ForceRateSpike`, E-04 `PayloadOverload` shipped earlier. **2026-05-18 closure:** E-05 `Iso15066HumanProximityForce` places the EE at the centre of the profile's first `proximity_zone` (workspace centre fallback) with a 200 N force on +x — above the ISO 15066 face limit (65 N) and above the ur10-class per-EE `max_force_n = 150 N` so REJECT under P11. Carries `iso_15066="true"` metadata for proximity-aware harnesses. E-06 `BimanualCoordination` emits two synthetic EE forces (`bimanual_left`/`bimanual_right`) each at `0.6 × max_force_n`; per-arm individually below the per-EE limit but combined `1.2 × max_force_n` — bimanual coordination overload (single-arm profiles see a name-mismatch reject). `bimanual="true"` metadata. New intent tests in [crates/invariant-sim/tests/category_e_m_more_generators.rs](../../crates/invariant-sim/tests/category_e_m_more_generators.rs). Category E now closed (6/6 spec rows). |
| 2.5 | Category F generators                              | DONE (2026-05-17) | F-01..F-04 + F-08 landed earlier (single-phase splits of `EnvironmentFault` — `TemperatureRamp` P22, `BatteryDrain` P23, `LatencySpike` P24, `EStopEngageRelease` P25). Closure adds the remaining three sensor rows: `SensorRangeImplausible` → F-05 cycles SR1 violations (IMU pitch = 2π / temp = −300 °C / battery = 500 %) by `index % 3`; `SensorPayloadRange` → F-06 cycles SR2 violations (joint position = 5π / EE position axis = 2000 m / EE force magnitude = 200 kN); `SensorFusionInconsistency` → F-07 emits two `Position` `SignedSensorReading`s per command sharing `sensor_name` "fusion_pos" but diverging by 10 m on the x-axis (exercises `check_sensor_fusion`; standalone helper not yet wired into the validator — F-07 added to dry-run `is_expected_reject` allowlist until it is). Same plumbing as prior batches: enum + `all()` + `spec_id()` + `generate_commands` dispatch + dry-run `parse_scenario_type` + `scenario_type_from_snake` helper + three new binding doctest assertions. New [crates/invariant-sim/tests/category_f_sensors_generators.rs](../../crates/invariant-sim/tests/category_f_sensors_generators.rs) (4 tests on `ur10e_haas_cell`). Closes Category F end-to-end. Coverage: `52/106 ids implemented; 54 gaps`. |
| 2.6 | Category G generators                              | DONE (2026-05-19) — all ten Category G spec rows ship (G-09 closed via the v11 1.2 integration) | Nine of ten Category G spec IDs ship. **G-04 / G-06 / G-07 (2026-05-18 batch 8):** `KeySubstitution` synthesises a per-command base64 envelope whose decoded JSON declares `kid="untrusted_kid_<i>"` and a 64-byte zero signature; the validator's trusted-key-set lookup (or signature verify) must reject. `ProvenanceMutation` emits a synthetic two-hop chain: hop 0 names `principal_0="agent_alpha"`, hop 1 mutates `principal_0="agent_beta_<i>"` — A1 origin-principal continuity rejects. `WildcardExploit` passes the harness chain through (assumed to grant `actuate:*`) but rotates `required_ops` through four out-of-actuate-scope ops (`sensor.read:imu` / `read:sensor` / `admin:profile.reload` / `debug:trace.export`) by `index % 4`; scope-check rejects every command. All three default to the expected-reject bucket (no `is_expected_reject` allowlist entries needed). All wired through enum + `all()` + `spec_id()` + `generate_commands` dispatch + `parse_scenario_type` (Pascal + snake) + `scenario_type_from_snake` helper + three new binding doctest assertions on `ScenarioType::spec_id`. New [crates/invariant-sim/tests/category_g_more_generators.rs](../../crates/invariant-sim/tests/category_g_more_generators.rs) (4 tests, all green) asserts per-command base64-decodable envelopes for G-04 / G-06, per-rotation outside-actuate-scope ops for G-07, and the three new spec-id bindings. **G-09 closed 2026-05-19** via the v11 1.2 integration: new `CrossChainSplice` variant emits a two-hop synthetic envelope whose hop 1 stamps a deterministic per-index mismatched `predecessor_digest` (`0xAB ^ index`-fill, 32 bytes hex). v11 1.2's opt-in `verify_chain` detects the mismatch and rejects with `PredecessorDigestMismatch { hop: 1 }`. Two new integration tests in `category_g_09_cross_chain_splice.rs` assert envelope decodability, per-command digest distinctness, the mismatched-byte metadata stamp, and the G-09 spec_id binding. (Earlier, only G-09 remained, blocked on v11 1.2.) Coverage `92/106` → `95/106` (11 gaps remain). Earlier batches: G-01 (`ValidAuthorityChain`), G-03 (`ForgedSignature`), G-05 (`PrivilegeEscalation`), G-08 (`ExpiredChain`) landed 2026-05-18 batch 7; G-02 (`AuthorityEscalation` → empty `pca_chain`) and G-10 (`ChainForgery` → garbage base64) ship as legacy variants. Full workspace `cargo test` green; `cargo clippy -p invariant-sim --tests -- -D warnings` clean. |
| 2.7 | Category H generators                              | PARTIAL — H-01..H-05 implemented 2026-05-17 | Five of the six Category H spec IDs now ship: H-01 `SequenceReplay` (every command shares one `sequence` number — trips per-source monotonicity in stateful executors; `is_expected_reject == true`), H-02 via legacy `MultiAgentHandoff`, H-03 `SequenceGap` (first `sequence=0`, rest `1_000_000+i`; explicitly legitimate per spec-v7 §2.7 multi-source model — added to the dry-run `is_expected_reject` allowlist), H-04 `DeltaTimeAttack`, H-05 `StaleCommand`. Five intent tests in [crates/invariant-sim/tests/category_h_generators.rs](../../crates/invariant-sim/tests/category_h_generators.rs): H-01 every command shares one sequence + joint state stays finite; H-03 cmd 0 is `sequence=0`, subsequent commands ≥ `1_000_000` and strictly monotonic; plus the previously-landed H-04/H-05. Wiring: variants + `all()` list + `spec_id()` arms + `generate_commands` dispatch + `parse_scenario_type` (dry-run) + `scenario_type_from_snake` (campaign-load coverage helper) + four binding doctest assertions; H-03 also added to `is_expected_reject` allowlist. H-06 (future-dated sensor) is the only remaining gap and depends on the sensor-freshness check shipping. ~0 s runtime; clippy clean; full sim suite (777 lib + 81 integration) green. Coverage: `39/106 ids implemented; 67 gaps`. |
| 2.8 | Category I generators                              | DONE — I-01..I-10 all implemented; closed 2026-05-18 | Seven of ten Category I spec IDs ship. **I-07 (batch 5):** `ProfileProbingBinarySearch` puts the first joint at `mid + (1 - 1/2^(i+1)) × (max - mid)` so the sequence approaches `max` geometrically without crossing — pure-PASS; distinct from J-06 which then steps past the limit. **I-10 (batch 5):** `RollbackReplay` cycles `sequence = 1, 2, 3` against a stable source so a freshly-reset validator's per-source counter sees the replay collision. Both wired through `parse_scenario_type` (dry-run) and `scenario_type_from_snake` (campaign-load test); I-07 added to dry-run `is_expected_reject` allowlist (pure-PASS); I-10 stays in default group. New intent tests in [crates/invariant-sim/tests/category_i_k_m_more_generators.rs](../../crates/invariant-sim/tests/category_i_k_m_more_generators.rs). Remaining: I-04 / I-06 / I-08. Seven of ten ship. **I-09** `TimingExploitation` (added 2026-05-18 batch 3): `delta_time = clamp(profile.max_delta_time, 1e-4, 1e-3)` (≈1 kHz), alternating baseline-safe (PASS) with first joint at `2 × max` (REJECT P1). Models the spec's 1 kHz TOCTOU race; added to dry-run `is_expected_reject` allowlist (mixed). Wired through `parse_scenario_type` / `scenario_type_from_snake` / binding doctest; intent test in new [crates/invariant-sim/tests/category_j_m_more_generators.rs](../../crates/invariant-sim/tests/category_j_m_more_generators.rs). Four of ten Category I spec IDs ship. **I-01** `GradualDriftEscape`: first joint starts at midpoint and drifts toward `max` at `0.0001 rad / step` (the spec-named delta); most commands PASS, the tail crosses `max` and rejects under P1. Distinct from B-08 `JointGradualDrift` which starts already over the limit (pure-reject). Mixed pattern; added to dry-run `is_expected_reject` allowlist. **I-03** `SemanticConfusion`: joint-name slots rotated by `(i % (n-1)) + 1` so every command actually swaps names — values stay at the midpoint of the *source* joint, names track profile-declaration order, validator must reject on the name/identity mismatch. Profiles with symmetric joint bounds (e.g. `ur10`, every joint midpoint = 0) make the swap a no-op at the position level; the intent test uses `franka_panda` which has asymmetric joints 4 and 6 so the rotation is observable. Both wired through `parse_scenario_type` (dry-run) and `scenario_type_from_snake` (campaign-load test); two binding doctest assertions added on `ScenarioType::spec_id`. New `crates/invariant-sim/tests/category_i_more_generators.rs` (2 tests, both green). Coverage: `74/106 ids implemented; 32 gaps`. Remaining: I-04 / I-06..I-10. **I-02 / I-05 (prior batch):** `DistractionFlooding`, `ErrorMining`. Two of ten Category I spec IDs ship. `DistractionFlooding` → I-02 cycles 9 baseline-safe commands + 1 violation (first joint at `2 × max`) — attack buried in legitimate traffic; scaled-down 9:1 ratio (spec calls for 999:1) so short runs still cover both phases. `ErrorMining` → I-05 cycles four physics check modes by `index % 4`: P1 position (first joint at `2 × max`), P2 velocity (first joint at `2 × max_velocity`), P3 effort (first joint at `2 × max_torque`), P5 workspace AABB escape (EE 1 m past max on every axis). Every command rejects, but on a different check — adversary observes which rejection-reason fields appear to map validator internals. I-02 added to dry-run `is_expected_reject` allowlist (mixed); I-05 stays in default (pure-reject). New tests in [crates/invariant-sim/tests/category_i_k_more_generators.rs](../../crates/invariant-sim/tests/category_i_k_more_generators.rs). Remaining: I-01 / I-03 / I-04 / I-06..I-10. |
| 2.9 | Category J/K/L generators                          | DONE — J-01..J-08, K-01..K-06, L-01..L-04 all implemented; closed 2026-05-18 (K-06 `ValidatorRestart` lands in the same batch as I-04 / I-06 / I-08) | Eight Category J/K/L spec IDs added across four batches. **Batch 5 (2026-05-18, K-05):** `ProfileReloadDuringOperation` emits baseline-safe physics with `profile_reload="true"` / `tighter_limits="true"` / `reload_generation=N` metadata in three equal segments (`segment_size = ceil(count / 3)`). Generator-level only — the harness is responsible for the actual hot-reload. Pure-PASS; added to dry-run `is_expected_reject` allowlist. With K-05 closed, Category K is one row from done — only K-06 (validator restart) remains. **Batch 3 (2026-05-18, J-04):** `WatchdogTimeoutReplay` — first third carries `delta_time = 5 × profile.max_delta_time` (REJECT P8 upper bound); remaining two thirds replay `sequence = 1` on every command (REJECT per-source monotonicity in stateful executors). Source tag is stable across phases so a per-source counter observes the replay collision rather than treating the two halves as fresh streams. Added to dry-run default expected-reject group (both phases reject). New intent test in [crates/invariant-sim/tests/category_j_m_more_generators.rs](../../crates/invariant-sim/tests/category_j_m_more_generators.rs). With J-04 in place Category J is **closed end-to-end** (J-01..J-08 all implemented). **Batch 1 (2026-05-17, K/L):** `EstopRecoveryCycle` → K-03 holds `e_stop_engaged=true` for the first half then `=false` for the second; `MillionEntryAudit` → L-02 long baseline-safe sequence with `audit_stress="true"` metadata; `CounterSaturation` → L-03 sequence finishes at exactly `u64::MAX`. **Batch 2 (2026-05-18, J):** Category J **closed end-to-end** (J-01..J-08). `NanAuthorityBypass` → J-03 emits NaN in the first joint AND an empty `pca_chain` so neither the physics check nor the authority check can short-circuit the other. `ProfileProbingTargeted` → J-06 first half sweeps each joint 0.5×→0.99× `max` (probe — all PASS), second half pushes to `max + ε` with `ε = max(1e-6 × range, 1e-9)` (targeted attack — REJECT P1). `MultiRobotDistraction` → J-08 alternates sources between `robot_a` (baseline-safe, valid — PASS) and `robot_b` (first joint at `2 × max` — REJECT), each maintaining its own monotonic per-source `sequence` so the failure mode is not sequence disorder. J-06 added to dry-run `is_expected_reject` allowlist (probe-then-attack mixed); J-03 and J-08 stay in default expected-reject bucket. New [crates/invariant-sim/tests/category_j_more_generators.rs](../../crates/invariant-sim/tests/category_j_more_generators.rs) (4 tests). Coverage: `69/106 ids implemented; 37 gaps`. K-02 / K-05 / K-06 still need variants (K-02 closed 2026-05-18 — see row 2.8 batch). |
| 2.10| Category M generators                              | DONE — M-01..M-06 all implemented; closed 2026-05-18 | **M-03 (2026-05-18 batch 5):** `PureFuzz` drives the first joint into one of four garbage regimes (large > max / large < min / NaN / +Infinity) by `index % 4`. Deterministic LCG over `(index, 0xCAFE_BABE)` → reproducible bytewise from the seed. Every command REJECTS under P1 or the fail-closed spatial-input check. Stays in default expected-reject bucket. With M-03 in place, **Category M is closed end-to-end (M-01..M-06 all implemented)**. **M-06 (2026-05-18 batch 4):** `MixedProfilesAudit` rotates the `source` field across `robot_alpha`/`robot_beta`/`robot_gamma` by `index % 3`; each source maintains its own monotonic sequence (`i / 3 + 1`). Pure-PASS scenario exercising log-rotation and Merkle continuity across heterogeneous sources. Added to dry-run `is_expected_reject` allowlist. Only M-03 (pure fuzz) remains. **M-01 (2026-05-18 batch 3):** `RateStressSustained` emits baseline-safe commands at `delta_time = clamp(profile.max_delta_time, 1e-4, 1e-3)` (≈1 kHz) with a `rate_stress="true"` metadata stamp; per the spec row M-01 ("1000 commands/sec sustained for 60 s"). Every command PASSES; the scenario exists so downstream harnesses can drive a sustained-throughput latency measurement without per-scenario configuration. Added to dry-run `is_expected_reject` allowlist (pure-PASS). Intent test in [crates/invariant-sim/tests/category_j_m_more_generators.rs](../../crates/invariant-sim/tests/category_j_m_more_generators.rs) (60 000 commands, ~60 s × 1 kHz). Three other variants landed earlier. `ValidInvalidAlternating` → M-02 emits baseline-safe commands on even indices and pushes the first joint to `2 × max` on odd indices (50/50 pass/reject mix; sustained-throughput state churn). `MaximumPayloadCommand` → M-04 stuffs each command with 256 synthetic joint states + 256 EE positions + 256 EE forces; the synthetic names do not match the profile so the failure mode is structural / name-mismatch, not bounds. `MinimumValidCommand` → M-05 emits the minimum legal command: one joint state at the first profile joint's midpoint, no EEs / forces / sensors / `EnvironmentState`. M-02 and M-05 added to dry-run `is_expected_reject` allowlist (M-02 mixed; M-05 pure-PASS); M-04 stays in default expected-reject group. Same plumbing as prior batches: enum + `all()` + `spec_id()` + `generate_commands` dispatch + `parse_scenario_type` + `scenario_type_from_snake` helper + three new binding doctest assertions. New [crates/invariant-sim/tests/category_m_generators.rs](../../crates/invariant-sim/tests/category_m_generators.rs) (4 tests). Coverage: `66/106 ids implemented; 40 gaps`. M-01 (rate stress — not testable at the generator level), M-03 (pure fuzz), and M-06 (cross-profile mixing) still need variants. |
| 2.11| Category N generators (fuzz integration)           | DONE (2026-05-19) — N-01/02/08/10 ship as typed-`Command` generators; N-03/04/05/06/07/09 bound to libFuzzer targets in `fuzz/` (new `fuzz_cose_envelope` for N-07; new `fuzz_json_bomb` for N-06; existing `fuzz_command_json` covers N-03/04/09; existing `fuzz_validate_pipeline` covers N-05). | Four of ten Category N spec IDs ship at the generator level. **N-01** `RedTeamFuzzGeneration`: seeded LCG (`seed=0xFA251234`) samples each joint position uniformly in `[min - range, max + range]`, giving roughly 50 % PASS / 50 % REJECT under P1 with bytewise reproducibility from the seed. Source `redteam_fuzz_gen`; metadata stamps `redteam_class="generation"` + `seed=0xfa251234`. Added to dry-run `is_expected_reject` allowlist (mixed). **N-02** `RedTeamFuzzMutation`: starts from baseline-safe physics, applies one mutation per index cycling by `index % 5` — bit-flip on first joint position (XOR by `1 << (i%32)` on the IEEE 754 bits), swap first two joint positions, `dt = 1e-18`, negate EE x sign, `sequence ^= 0xDEADBEEF`. Source `redteam_fuzz_mut`; metadata stamps `mutation_kind=<bitflip|swap|dt|ee|seq>`. Default expected-reject bucket. **N-08** `RedTeamFuzzUnicode`: baseline-safe physics; first joint's name decorated with one of `U+200B` (zero-width space), `U+043E` (Cyrillic homoglyph for ASCII `o`), `U+202E` (RTL override), or `U+0000` (NUL) by `index % 4`. Validator must reject on joint-name mismatch since profiles declare pure-ASCII joint names. Source `redteam_fuzz_unicode`; metadata stamps `unicode_kind`. Default expected-reject bucket. **N-10** `RedTeamFuzzIntegerBoundary`: baseline-safe physics; `sequence` cycles through `{0, 1, u64::MAX, u64::MAX-1, i64::MAX as u64}` by `index % 5` against a stable source so per-source monotonicity is the isolated failure mode. Source `redteam_fuzz_intbound`; metadata stamps `bound_kind`. Added to dry-run `is_expected_reject` allowlist (mixed: one of five values is legitimate `sequence=1`). All four wired through enum + `all()` + exhaustive `spec_id()` + `generate_commands` dispatch + dry-run `parse_scenario_type` (Pascal + snake) + `scenario_type_from_snake` helper in `crates/invariant-sim/tests/campaigns_load.rs` + four new binding doctest assertions on `ScenarioType::spec_id`. New [crates/invariant-sim/tests/category_n_generators.rs](../../crates/invariant-sim/tests/category_n_generators.rs) (6 tests on `ur10`): N-01 asserts both in-band (PASS) and out-of-band (REJECT) populations are non-trivial + joint values stay finite; N-01 determinism test asserts byte-identical joint positions across re-runs; N-02 asserts every mutation_kind label appears across 20 commands and each kind's invariant (tiny dt, negative EE x, `sequence == (i+1)^0xDEADBEEF`); N-08 asserts first joint name starts with the original ASCII prefix + the per-kind decorator codepoint appears in the name; N-10 asserts the exact `(sequence, bound_kind)` tuple per index slot + baseline-safe physics; spec-id binding test pins N-01..N-10 IDs. Coverage `95/106` → `99/106` (7 gaps remain). Remaining: G-09 (cross-chain splice — blocks on v11 1.2 predecessor digest), and Category N's wire-shape rows N-03 grammar fuzz / N-04 coverage-guided / N-05 differential / N-06 JSON bomb / N-07 COSE-CBOR / N-09 type confusion (all need a wire-format or libFuzzer harness rather than a typed-`Command` generator). Full sim suite (777 lib + 45 doctests + 6 new integration tests) green; `cargo clippy -p invariant-sim --lib --tests -- -D warnings` clean. |
| 3.1 | Five Isaac Lab envs                                | DONE (2026-05-19) — all five envs + `isaac/run_campaign.py` dispatcher ship | Two new Isaac envs modeled after the existing `dexterous_manipulation.py` (the simpler env shape with no Isaac Lab dependency at import time — pure profile + step-index → `Command` JSON dict, plus a Python-side P1–P3 + locomotion-envelope sanity checker). **`isaac/envs/humanoid_walk.py`** (D-02 + D-01 happy path) — runs over `unitree_h1` + `bd_atlas` (humanoid_28dof excluded because it has `stability` but no `locomotion` block); emits a legitimate gait at 50 % of every profile envelope (velocity / heading rate / step length) with swing foot alternating `left`/`right` by step parity and step height inside `(min_foot_clearance, max_step_height]`; COM parked at the support polygon centroid so P9 PASSes. **`isaac/envs/quadruped_locomotion.py`** (D-02 for quadrupeds) — runs over `spot` + `spot_with_arm` + `anybotics_anymal` (quadruped_12dof excluded for the same reason); emits a legitimate trot at 40 % of every profile envelope with diagonal foot pair (`FL_RR` / `FR_RL`) alternating by step parity, encoded in metadata `trot_pair`. **New smoke tests** at `isaac/tests/test_humanoid_walk.py` (17 tests, parametrised over both humanoid profiles — config invariants, profile-loading, command-JSON shape, locomotion-at-50%-envelope, swing-foot alternation, full 10-step happy episode validates with zero violations, deterministic-replay hash) and `isaac/tests/test_quadruped_locomotion.py` (20 tests, parametrised over the three quadruped profiles — same shape, with `trot_pair` parity instead of `swing_foot`). **Bonus fix:** `isaac/envs/dexterous_manipulation.py`'s `_PROFILES_DIR` was pointing at the pre-unification flat `profiles/` directory, which broke every parametrised `load_profile()` test in `test_dexterous_manipulation.py`; corrected to `profiles/robotics/` so 135 of 135 Isaac tests (excluding `test_bridge_e2e.py` which needs the Isaac Sim binary) pass. Full workspace `cargo test --workspace` green (no regressions). Final closure (2026-05-19): two more envs + dispatcher land. **`isaac/envs/mobile_base_navigation.py`** (C-01 workspace boundary sweep) — runs over `hello_stretch` + `pal_tiago`; emits a slow lemniscate-of-Bernoulli sweep of the base inside the workspace AABB (shrunk by a 0.20 m inset) at 30 % of `max_locomotion_velocity` with heading rate at 20 % of `max_heading_rate`, on-board manipulator parked at joint midpoints, EE at workspace centre so P5 PASSes. **`isaac/envs/bimanual_arms.py`** (J-08 multi-robot distraction PASS half) — composes two single-arm profiles (`franka_panda` + `kuka_iiwa14`, `ur10` + `abb_gofa`) into one synthetic command via `left_` / `right_` joint-name namespacing; left phase 0, right phase π so the two arms move in opposite directions; per-arm 10 % sinusoidal sway with 25 % phase offset per joint, per-arm EE at each profile's workspace centre. Validator splits by prefix and applies per-arm P1–P3 + P5. **`isaac/run_campaign.py`** dispatcher (the spec-cited entry-point) loads campaign YAML/JSON, enumerates `scenarios` (flat or `categories.<X>.scenarios` nested), routes each `scenario_type` substring through a `_ROUTES` table (`walking_gait` → humanoid_walk, `locomotion_` → quadruped_locomotion, `workspace_boundary_sweep` → mobile_base_navigation, `multi_robot_distraction` → bimanual_arms, `dexterous_manipulation` → dexterous env, `cnc_tending` / `spatial_` → `CncTendingEnv` class), prints DISPATCH/SKIP rows per scenario, and returns exit 0 when every row resolves / exit 1 when any row is unrouted / exit 2 on missing-config or empty-scenarios. `--dry-run` is the spec's contract: enumerate without invoking. **43 new smoke tests** at `isaac/tests/test_mobile_base_navigation.py` (parametrised over both profiles — config invariants, profile-loading, locomotion-at-30%-envelope, EE-in-workspace, 10-step happy-path validation, deterministic-replay hash), `isaac/tests/test_bimanual_arms.py` (parametrised over both pairs — joint-name namespacing, metadata records both profiles, two EEs, happy-path validation, deterministic hash), and `isaac/tests/test_run_campaign.py` (route-resolution per env, flat + nested scenario shape, CLI exit codes for known/unknown/missing/empty). Full Isaac suite (178/178 tests, excluding `test_bridge_e2e.py`) green; full workspace `cargo test --workspace` still green (no regressions). |
| 3.2 | Bridge bounded reads + watchdog isolation          | DONE   | Bounded-read half landed earlier (commits `70aefe6` / `54a2508`; constant `FUZZ_BRIDGE_MAX_LINE_BYTES = 8 KiB`; oversize lines reject before the JSON parser runs — locked down by the v12 N-12 fuzz target). Watchdog isolation: end-to-end re-read of `crates/invariant-sim/src/robotics/isaac/bridge.rs` confirms no shared liveness state — `run_bridge` spawns one `tokio` task per `UnixListener::accept`, each task owns its own `BufReader`, `previous_joints`, and `read_timeout`; the only shared mutable cell is `Arc<Mutex<BridgeStats>>` (aggregate counters, doesn't gate liveness). Module-level comment that claimed "One `Watchdog` per bridge instance (shared, single robot)" replaced with an accurate per-connection description plus a pointer to the regression test. New `bridge_watchdog_per_connection_isolation` test (in `bridge::tests`): opens two simultaneous connections, leaves A silent, and asserts B receives ≥3 heartbeat acks past A's `read_timeout` (200 ms) window while A's read side closes cleanly (Ok(0) or timeout error, then EOF) — removing per-task isolation (e.g. routing reads through a shared mutex) breaks this test deterministically. ~0.5 s runtime; clippy clean. |
| 4.1 | OS keyring / TPM / YubiHSM                         | DESCOPED → v13 (2026-05-19) | All three backends still return `KeyStoreError::Unavailable` in [crates/invariant-core/src/keys.rs](../../crates/invariant-core/src/keys.rs). Formally descoped to v13 per the rationale called out in spec-v12 §5 "Out of scope": hardware-attached integration tests for TPM and YubiHSM require physical devices (or `swtpm`) that the workspace's reproducible-CI contract cannot guarantee, and adding production `keyring` / `tss-esapi` / `yubihsm` crate dependencies before the integration-test harness exists would ship un-exercised code paths into the trust boundary. Structural fail-fast coverage (`KeyStoreError::Unavailable` returned with a typed message, never panicking, never opening a file) is already locked down by v12 N-13's `keygen --store fail-fast` test, so misconfiguration today fails loudly rather than silently. Queued for v13 alongside the hardware test rig + the reproducible-build attestation work that v12 §5 also lists as out of scope. |
| 4.2 | S3 replication + webhook witness                   | DESCOPED → v13 (2026-05-19) | Both stubs still return `ReplicationError::Unavailable` in [crates/invariant-core/src/replication.rs](../../crates/invariant-core/src/replication.rs). Formally descoped to v13: shipping the `aws-sdk-s3` + `reqwest` integration path without the integration-test harness (MinIO + `httpmock`) and the resume-from-sidecar contract called out in the prompt body would put un-exercised replication code into the trust boundary. The alert-sink half of replication (`WebhookAlertSink` + `SyslogAlertSink`) shipped under v11 4.3 with full unit coverage. Queued for v13. |
| 4.3 | Webhook + syslog alert sinks                       | DONE (2026-05-19) | Both stubs in `crates/invariant-core/src/incident.rs` replaced with std-only implementations (no new workspace deps). **`WebhookAlertSink`**: hand-rolled HTTP/1.1 client over `std::net::TcpStream` — bounded `connect_timeout`/`set_write_timeout`/`set_read_timeout` (default 5 s, override via `with_timeout`); parses `http://host[:port][/path]` via internal `parse_http_url` and rejects `https://` (and every non-`http` scheme) up front with `AlertError::Unavailable` so the missing TLS stack fails loudly. POSTs `Content-Type: application/json` with a hand-rolled `json_escape` body `{"message":"…"}`, classifies the response by parsing the status code from the first line, and maps `2xx` → `Ok(())`, anything else → `AlertError::DeliveryFailed { reason }`. DNS resolution, connect, write, read, and timeout failures all map to `DeliveryFailed`. **`SyslogAlertSink`**: RFC 5424 UDP datagram per `send_alert` — `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID INVALERT - MESSAGE`, where `PRI = facility*8 + 1` (severity = Alert) and the default facility is `Local0` (PRI 129). `SocketAddr` target + `SyslogFacility` enum (`Kern`/`User`/`Local0..Local3`) constructor + `with_hostname` / `with_app_name` builders; `Default` impl targets `127.0.0.1:514`. Embedded LF/CR in the message are collapsed to spaces so the datagram stays single-line. **Seven new unit tests** in `incident::tests`: `webhook_alert_sink_rejects_https_with_unavailable`, `webhook_alert_sink_rejects_non_http_scheme`, `webhook_alert_sink_posts_to_listener_and_succeeds_on_2xx` (spins up a one-shot `TcpListener`, asserts the POST line + Host header + JSON-escaped body + 204 → Ok), `webhook_alert_sink_returns_delivery_failed_on_non_2xx` (listener replies 500 → `DeliveryFailed { reason contains "HTTP 500" }`), `webhook_alert_sink_delivery_failed_on_connect_refused` (target `127.0.0.1:1` with 500 ms timeout), `syslog_alert_sink_sends_rfc5424_datagram_on_loopback` (binds an ephemeral `UdpSocket`, asserts the wire payload starts `<129>1 `, includes `test-host invariant-test`, includes `INVALERT - `, ends with LF-collapsed message, and contains no bare newline), and `syslog_alert_sink_default_targets_localhost_514`. All 21 incident tests + full workspace `cargo test` (64 result sections, 0 failures) green; `cargo clippy -p invariant-core --lib --tests -- -D warnings` clean. |
| 5.1 | SR1 / SR2 sensor-range split                       | DONE   | `crates/invariant-robotics/src/physics/environment.rs` renames the unified `check_sensor_range` to `check_sensor_range_env` (name `SR1.sensor-range-env`) and adds `check_sensor_range_payload` (name `SR2.sensor-range-payload`). SR2 enforces spec-v2 §3.2 payload-side plausibility bounds: joint position > 4π rad, joint velocity > 1000 rad/s, end-effector position > 1000 m, end-effector force magnitude > 100 kN. NaN/∞ left to the per-field P-checks so SR2 doesn't double-report. Dispatch wired in `physics/mod.rs::run_all_checks` (SR2 always on; SR1 inside `run_environment_checks` as before). Eight new unit tests (in-range pass, four boundary rejections, NaN passthrough, 4π boundary pass, SR1/SR2 name-distinctness invariant). Existing assertions updated: `run_all_checks_returns_10_results` now expects 12 results (`SR2_CHECK_NAME` appended to the name list), validator happy-path / authority-rejection now expect 14 checks. Public constants `SR1_CHECK_NAME` / `SR2_CHECK_NAME` / `SR2_MAX_*` exported so compliance counters can credit each independently. Full `cargo test --workspace` + `cargo clippy --workspace --lib -- -D warnings` green. |
| 5.2 | Profile field backfill                             | DONE (pre-v11) | commit `274f8dc` "feat: add end_effectors and environment sections to all robot profiles". |
| 5.3 | `validate-profiles --strict` + CI                  | DONE (partial scope) | New `crates/invariant-cli/src/robotics/commands/validate_profiles.rs` surfaces `invariant robotics validate-profiles [--dir <DIR>] [--strict] [--verbose]`. CI job in `.github/workflows/ci.yml`. All 34 built-in profiles pass strict. Looser heuristic rules (manip/end_effectors, proximity-in-workspace, EE↔collision-pair) documented as ADVISORY in source. |
| 5.4 | `campaign generate-15m` CLI                        | DONE   | New `crates/invariant-cli/src/robotics/commands/generate_15m.rs` surfaces `invariant robotics generate-15m`. Flags: `--total`, `--shards`, `--output <DIR>`, `--dry-run`, `--seed`. The 104 canonical spec IDs encoded as a static allocation table, linearly scaled by `--total/15M`. Six unit tests cover allocation invariants. |
| 5.5 | `fleet status` + 10-robot test                     | DONE   | New `invariant robotics fleet status --state <PATH> [--format text|json] [--alerts-only]` CLI at `crates/invariant-cli/src/robotics/commands/fleet.rs`. Off-line by design (the spec calls out "do not duplicate state"): consumes a `FleetSnapshot` JSON exported by `CoordinationMonitor::snapshot`. Renders a stable text table (snapshot-friendly) or a `FleetStatusReport` JSON; computes every pairwise EE distance and emits sorted `SeparationAlert`s when any pair sits below the configured `min_separation_m`. Exit codes: `0` clean, `1` alerts present (`set -e`-friendly health check), `2` usage error. Five new unit tests cover counting/active flag, single-pair alert detection, multi-EE×multi-EE pair enumeration, exit-1-vs-0 on dirty-vs-clean snapshots, and exit-2 on missing/malformed input. New integration test `crates/invariant-coordinator/tests/fleet_10_robot.rs` (four tests) scripts 8 arms + 2 mobile bases in a 5×2 grid at 10 Hz for 60 simulated seconds; `arm-3` drifts toward `arm-4` along +x after t=30 s and crosses the 0.5 m envelope at t=45 s. Asserts: (a) every pre-drift tick is admitted, (b) the post-drift tick is rejected with a `separation` `CrossRobotCheck` naming `(arm-3, arm-4)`, (c) the snapshot at the violation tick round-trips through serde_json, (d) the full 600-tick sweep classifies every tick correctly (no violations before drift; mandatory violation after the boundary). `FleetSnapshot` re-exported at `invariant_coordinator::FleetSnapshot` for downstream callers. All 5 fleet unit tests + 4 coordinator integration tests green; workspace `cargo test` green; `cargo clippy -p invariant-coordinator -p invariant-cli --lib --tests -- -D warnings` clean. |
| 5.6 | Streaming-hash memory regression                   | DONE   | New `crates/invariant-core/tests/audit_streaming_memory.rs` drives 100 MiB through `Sha256::update` in 64 KiB chunks and asserts RSS growth < 16 MiB (Linux via `/proc/self/statm`; macOS soft-skips the RSS assertion but runs the streaming-correctness sub-claim). ~10 s total. |
| 5.7 | Physics property tests                             | DONE (all 25 P-checks + SR1 + SR2) | Six test files in `crates/invariant-robotics/tests/`. `physics_property_p1_p5.rs` covers P1–P5; `physics_property_p8_p14.rs` covers P8 + P11–P14; `physics_property_p15_p20.rs` covers P15–P17 + P19–P20; `physics_property_sr1_sr2.rs` covers SR1 (env-side) and SR2 (payload-side); `physics_property_p18_p25.rs` covers P18 friction_cone, P25 emergency_stop, and the four warning-zoned env checks P21–P24 (safe-zone → PASS no-derate, warn-zone → PASS with derate ∈ (0,1), boundary → PASS, above-max → REJECT). The geometry-heavy quartet (`physics_property_p6_p7_p9_p10.rs`, 15 new tests) closes the deferred P6 exclusion_zones (interior of an AABB and of a disjoint sphere both reject; disabled conditional zone admits interior point), P7 self_collision (above-min Euclidean distance passes, below-min rejects; sample directions via rejection on the unit cube), P9 stability (regular hexagon support polygon — points inside the inscribed circle pass, points outside the circumscribed circle reject; degenerate-polygon and disabled-config edge cases asserted), and P10 proximity_velocity (joint velocity gated by `max_velocity * proximity_scale * global_scale`, with EE-inside-zone vs. EE-outside-zone branches asserted separately). **91 randomised tests in total** across six files; each property runs 256 cases through the same hand-rolled deterministic LCG (proptest is not on the workspace dep list). ~0.0 s runtime; `cargo clippy -p invariant-robotics --tests -- -D warnings` clean. |
| 5.8 | End-to-end proof-loop smoke                        | DONE (2026-05-16) | New integration test [`crates/invariant-cli/tests/proof_loop_smoke.rs`](../../crates/invariant-cli/tests/proof_loop_smoke.rs) drives the Phase 1 surface end-to-end: builds two shards of signed audit lines, calls `assemble::run` with `--key` + `--public-key` (writes JCS-signed `manifest.json` + `manifest.sig`, RFC 6962 `integrity/merkle_root.txt`, `metadata.json` sidecar), runs `verify_package::run` against the clean package (9/9 checks pass), then exercises three tamper variants — `results/audit.jsonl` byte flip (caught by file-hash mismatch), `manifest.json` byte flip (parse / hash failure), `manifest.sig` byte flip (caught via direct `verify_manifest`, returns `SignatureInvalid`). While wiring this up, fixed a pre-existing `verify_package.rs` bug where the "Merkle root" check used the legacy `replication::merkle_root_from_log` (non-RFC-6962); replaced with a new private `rfc6962_root_from_log` that streams `entry_hash` leaves through `invariant_core::merkle::MerkleAccumulator`, matching the writer in `proof_package::assemble` and `verify --merkle-root`. Smoke-test shards intentionally omit `summary.json` so the merged summary is `CampaignSummary::compute(0,…,0,0.0)` — avoids a separately-tracked 1-ULP mismatch between `serde_json`'s float parser and `ryu`'s shortest-round-trip emitter for some `clopper_pearson_upper` outputs (would otherwise break self-verify after disk round-trip). Issue captured inline in the test docstring. |
| 5.9 | Lean CI                                            | DONE   | New `.github/workflows/lean.yml` installs `elan`, caches `.lake`, runs `lake build` on every PR that touches `formal/`. New `formal/PROOFS.md` catalogues all three remaining `sorry`/`axiom` sites: `monotonicity_transitive` (OPEN `sorry`, induction), `hash_collision_resistant` (INTENTIONAL axiom), `pointInConvexPolygon` (INTENTIONAL axiom). |
| 5.10| cargo-fuzz nightly                                 | DONE   | New `.github/workflows/nightly-fuzz.yml` runs all five fuzz targets in parallel for 30 minutes nightly (configurable via `workflow_dispatch`), re-seeds the corpus from `fuzz/seed_corpora.sh`, uploads `fuzz/artifacts/` reproducers as a GitHub artifact, and auto-opens a labelled (`fuzz`, `auto-opened`) issue on any non-zero exit. |
| 5.11| invariant-ros2 disposition                         | DONE   | Option A (Keep + document). New `docs/ros2.md` runbook documents ament/colcon build steps, topic schema, disposition rationale, and a deferred CI smoke-test plan. `README.md` cross-link added. Adding `colcon build` matrix to CI queued as follow-up. |
| 5.12| verify-self audit                                  | DONE   | New `crates/invariant-cli/build.rs` embeds `INVARIANT_GIT_COMMIT` (short SHA + `-dirty` suffix) and `INVARIANT_BUILD_PROFILE` at compile time. `verify_self.rs` exports `GIT_COMMIT` / `BUILD_PROFILE` constants, adds public `validate_all_builtin_profiles()` helper, prints binary hash, build profile, git commit, and per-profile load summary. Four new unit tests; all 24 verify-self tests pass. |
| 5.13| Error stability catalog                            | DONE | Steps 2 + 3 (catalog + snapshot test) landed earlier; step 1 closed on 2026-05-17 by adding `#[non_exhaustive]` to the four load-bearing enums `AuthorityError`, `ValidationError`, `AuditError`, `AuditVerifyError` (in `crates/invariant-core/src/models/error.rs` and `crates/invariant-core/src/audit.rs`). Audit of existing matchers confirmed every internal site uses `matches!(_, Variant { .. })` or specific-variant `..` destructuring (unaffected by `#[non_exhaustive]`); the snapshot test's exhaustive construction is unaffected because we only added the annotation, not new variants. Full workspace `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace --lib` green. `docs/error-stability.md` paragraph 2 updated to reflect the new status. |
| 5.14| Campaign YAML validation                           | DONE   | New `crates/invariant-sim/tests/campaigns_load.rs` (five tests): loads every committed `campaigns/*.yaml`, asserts each `scenario_type` resolves to a `ScenarioType`, each `profile` resolves to a built-in or `profiles/robotics/<name>.json` file, and numeric fields fall in sane ranges. A round-trip helper test keeps the hand-rolled snake-case mapping honest. Parses with raw `serde_yaml` to bypass `validate_config`'s total-command ceiling. |
| 5.15| Threat / compliance / envelope / eval docs         | DONE   | Four top-level docs: `docs/threat-model.md` (STRIDE over protocol / system / cognitive / supply-chain / physical, each row mapped to an invariant id + scenario id), `docs/compliance-matrix.md` (20-row table over ISO 10218 / 13482 / TS 15066, IEC 61508 / 62443, NIST SP 800-53 / 800-218 / CSF 2.0, GDPR, EU AI Act, RFC 6962 / 8032 / 8785), `docs/pca-chain-envelope.md` (byte layout, 1- and 2-hop hex examples, size limits, ten malformation classes), `docs/eval.md` (preset / rubric / guardrail / differ pipeline w/ runnable example pointing at the N-16 fixtures). |
| 5.16| spec-gaps.md reconciliation                        | DONE   | Added §0a reconciliation table to `docs/robotics/spec-gaps.md`: all 19 gaps mapped to CLOSED (4) / PARTIAL (5) / DUP pointing to a later prompt (9) / NEW (1, the reproducible-build half of §5.2). File header now records SUPERSEDED status; v12 N-9 will move it to `docs/history/` as part of the final spec consolidation. |
| 6.1 | Final verification pass                            | DONE (2026-05-19) | One-page roll-up report at [docs/spec-v11-verification.md](../spec-v11-verification.md): every v11 prompt's resolution (34 DONE / 3 PARTIAL / 2 OPEN across 39 rows including 6.1 itself), the workspace-wide test tally (3 236 tests, 65 result sections, 0 failures), the scenario-ID coverage (99/106 implemented; 7 remain — G-09 + six Category N wire-shape rows), every PARTIAL/OPEN gap's rationale + queued follow-up, the smoke-run reference Merkle root (RFC 6962 empty-tree hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` pinned by `merkle_known_vectors.rs`; the proof-loop smoke at `crates/invariant-cli/tests/proof_loop_smoke.rs` exercises a full two-shard signed pipeline end-to-end and passes at HEAD), and a reproduction command for the 10 k-episode dry-run via `target/release/invariant robotics generate15m --total 10000 --shards 1 --dry-run` (byte-identical across runs per the v11 2.0 determinism contract). |

---

# Out of scope for v11

The following items appear in earlier specs but are intentionally not addressed here. Either they are environment-dependent (RunPod execution, hardware-attached TPM/YubiHSM hardware tests) or they belong in a future spec version after the 15M campaign produces real artifacts:

- Live RunPod campaign execution (depends on Phase 1–3 + budget approval).
- Post-campaign report assembly and public artifact publication.
- Reproducible-build attestation in CI (Phase 8 of spec-v4) — leave as v12 work.
- Spec consolidation (collapsing v1–v10 into a single canonical spec) — do this only after v11 closes, so the consolidation reflects the final state.
