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

**Spec:** spec-v9 §5.2.

**Do:**
1. Add `crates/invariant-cli/src/commands/validate_profiles.rs` with `--strict` flag.
2. In strict mode, fail when a non-adversarial profile permits manipulation but declares no `end_effectors`, or when any profile fails the cross-field consistency checks below.
3. Implement `RobotProfile::validate_consistency()` in `crates/invariant-core/src/profiles.rs` covering: `max_velocity >= cruise_velocity`, inertia positive-definite, workspace AABB `min < max` per axis, collision pairs reference valid links, proximity zones lie within workspace, EE names match link entries.
4. Wire the subcommand into CI as a required job (`.github/workflows/ci.yml`).

**Acceptance:** `invariant validate-profiles --strict` exits 0 on the current `profiles/` tree (after Prompt 5.2 backfill); flips to exit 1 on a deliberately broken fixture in `tests/fixtures/broken_profile.json`.

---

## Prompt 5.4 — Wire `invariant campaign generate-15m` CLI subcommand

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

**Spec:** spec-v9 §5.6.

**Do:** add `crates/invariant-core/tests/audit_streaming_memory.rs` that hashes a 100 MiB synthetic payload via the audit hash path and asserts the resident-set increase is < 16 MiB. Use `getrusage` on Unix to measure. If the current implementation buffers, refactor it to stream (`Sha256::update` in chunks).

**Acceptance:** test passes on macOS and Linux CI.

---

## Prompt 5.7 — Property tests for physics invariants

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

**Spec:** spec.md §8, spec-v9 §5.8.

**Do:**
1. Pin a Lean toolchain (`lean-toolchain` file in `formal/`).
2. Add a `.github/workflows/lean.yml` job running `lake build` with cache.
3. Document every remaining `sorry` and axiom in `formal/PROOFS.md`: which theorem, what it asserts, what Rust code it corresponds to, and whether the gap is intentional (axiomatized) or open (needs proof).

**Acceptance:** CI passes; `formal/PROOFS.md` exists and lists every `sorry`/`axiom`.

---

## Prompt 5.10 — Cargo-fuzz targets and nightly CI

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

---

## Prompt 5.12 — Verify-self completeness audit

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

---

## Prompt 5.14 — Campaign YAML schema validation in CI

**Spec:** spec-v9 (implicit), spec-v8 §8.17.

**Do:** add `crates/invariant-sim/tests/campaigns_load.rs` that loads every `campaigns/*.yaml`, verifies each `scenario` name resolves to a `ScenarioType` variant, each `profile` name resolves to a builtin, and numeric fields fall in their declared ranges.

**Acceptance:** test passes on the current YAMLs (after Phase 2 generators land).

---

## Prompt 5.15 — Documentation: threat model, compliance matrix, PCA envelope, eval pipeline

**Spec:** spec-v9 §5.11.

**Do:** four short doc files (one commit each):
1. `docs/threat-model.md` — STRIDE table over protocol / system / cognitive / supply-chain / physical-side-channel; map each threat to its invariant id and campaign scenario id.
2. `docs/compliance-matrix.md` — table of standard / clause / implementing code path / test.
3. `docs/pca-chain-envelope.md` — byte-level layout, hex examples for 1-link and 2-link chains, version negotiation, max size, ten malformation classes the fuzzer must cover (cross-reference Prompt 5.10).
4. `docs/eval.md` — the preset → rubric → guardrail → differ pipeline in `crates/invariant-eval`, with a runnable example.

**Acceptance:** files exist; each cross-references back to spec sections.

---

## Prompt 5.16 — Reconcile spec-gaps.md with v7/v8/v9/v10/v11

**Spec:** spec-v8 §8.14.

**Do:** walk every gap in `docs/spec-gaps.md`. For each: mark CLOSED (with the file path or commit hash that closed it), PARTIAL, DUP (point to the v7+ prompt that subsumes it), or NEW. After the walk, either delete `spec-gaps.md` or move it to `docs/history/spec-gaps.md` with a one-line header stating it is superseded.

**Acceptance:** no orphan unclosed gap remains in `spec-gaps.md`.

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
| 1.1 | B1–B4 audit fields                                 | OPEN   |               |
| 1.2 | A3 predecessor digest                              | OPEN   |               |
| 1.3 | RFC 6962 Merkle tree                               | OPEN   |               |
| 1.4 | Manifest JCS + signature                           | OPEN   |               |
| 1.5 | `campaign assemble` CLI                            | OPEN   |               |
| 1.6 | `audit verify` digest/root flags                   | OPEN   |               |
| 2.0 | Determinism contract                               | OPEN   |               |
| 2.1 | Category B generators                              | OPEN   |               |
| 2.2 | Category C generators                              | OPEN   |               |
| 2.3 | Category D generators                              | OPEN   |               |
| 2.4 | Category E generators                              | OPEN   |               |
| 2.5 | Category F generators                              | OPEN   |               |
| 2.6 | Category G generators                              | OPEN   |               |
| 2.7 | Category H generators                              | OPEN   |               |
| 2.8 | Category I generators                              | OPEN   |               |
| 2.9 | Category J/K/L generators                          | OPEN   |               |
| 2.10| Category M generators                              | OPEN   |               |
| 2.11| Category N generators (fuzz integration)           | OPEN   |               |
| 3.1 | Five Isaac Lab envs                                | OPEN   |               |
| 3.2 | Bridge bounded reads + watchdog isolation          | OPEN   |               |
| 4.1 | OS keyring / TPM / YubiHSM                         | OPEN   |               |
| 4.2 | S3 replication + webhook witness                   | OPEN   |               |
| 4.3 | Webhook + syslog alert sinks                       | OPEN   |               |
| 5.1 | SR1 / SR2 sensor-range split                       | OPEN   |               |
| 5.2 | Profile field backfill                             | OPEN   |               |
| 5.3 | `validate-profiles --strict` + CI                  | OPEN   |               |
| 5.4 | `campaign generate-15m` CLI                        | OPEN   |               |
| 5.5 | `fleet status` + 10-robot test                     | OPEN   |               |
| 5.6 | Streaming-hash memory regression                   | OPEN   |               |
| 5.7 | Physics property tests                             | OPEN   |               |
| 5.8 | End-to-end proof-loop smoke                        | OPEN   |               |
| 5.9 | Lean CI                                            | OPEN   |               |
| 5.10| cargo-fuzz nightly                                 | OPEN   |               |
| 5.11| invariant-ros2 disposition                         | OPEN   |               |
| 5.12| verify-self audit                                  | OPEN   |               |
| 5.13| Error stability catalog                            | OPEN   |               |
| 5.14| Campaign YAML validation                           | OPEN   |               |
| 5.15| Threat / compliance / envelope / eval docs         | OPEN   |               |
| 5.16| spec-gaps.md reconciliation                        | OPEN   |               |
| 6.1 | Final verification pass                            | OPEN   |               |

---

# Out of scope for v11

The following items appear in earlier specs but are intentionally not addressed here. Either they are environment-dependent (RunPod execution, hardware-attached TPM/YubiHSM hardware tests) or they belong in a future spec version after the 15M campaign produces real artifacts:

- Live RunPod campaign execution (depends on Phase 1–3 + budget approval).
- Post-campaign report assembly and public artifact publication.
- Reproducible-build attestation in CI (Phase 8 of spec-v4) — leave as v12 work.
- Spec consolidation (collapsing v1–v10 into a single canonical spec) — do this only after v11 closes, so the consolidation reflects the final state.
