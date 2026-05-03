% Invariant — Gap-Closure Execution Spec (v5)
% Status: Draft
% Date: 2026-04-29
% Branch: codelicious/spec-spec-15m-campaign-part-6
% Companion to: `docs/spec-gaps.md`, `docs/spec-v4.md`, `docs/spec-15m-campaign.md`

# 0. How To Use This Document

This is a fresh gap-closure spec authored after a deep audit of the codebase
against `docs/spec.md`, `docs/spec-v1.md`–`spec-v4.md`,
`docs/spec-15m-campaign.md`, and `docs/spec-gaps.md` on
2026-04-29 against branch `codelicious/spec-spec-15m-campaign-part-6`.

It supersedes the unfinished items in v4 and adds gaps that v4 did not
cover (clippy gate failure, scenario coverage for Categories C–N, signed
manifest, fleet command, profile EE strict validation, and CI-emitted test
counts).

Each section below is a self-contained **Claude Code prompt**. Paste one
prompt at a time into a Claude Code session at the repo root and let it run
to completion before moving on. Every prompt:

- Names the gap, the spec citation, and the existing code citation so the
  agent can re-verify before editing.
- States acceptance criteria as concrete files / tests / CLI behavior.
- Ends with the verification commands that must pass.

Ordering reflects priority: P1 build-gate fixes first, then authority
binding (B1–B4 + A3), then proof-package assembly (the campaign's headline
deliverable), then scenario coverage to unlock 15M-episode execution, then
P2 polish.

Each prompt assumes:

- Working directory is the repo root.
- `cargo build`, `cargo test`, and `cargo clippy --workspace --all-targets
  -- -D warnings` are the required gates per [CLAUDE.md](../CLAUDE.md).
- One commit per prompt, message prefixed with `[v5-NN]` matching the
  section number here. Never push directly to `main`.

If a verification step fails, fix the root cause — do not weaken the
acceptance criteria, and do not commit `--no-verify`.

---

# Prompt 1 — Restore the Clippy Gate

**Gap:** `cargo clippy --workspace --all-targets -- -D warnings` currently
fails with 14 `assertions_on_constants` errors, all in
[crates/invariant-sim/src/campaign.rs](../crates/invariant-sim/src/campaign.rs)
in the range L2815–L2965, plus an `unused_imports` warning at L2497
(`use super::execution_target::*;`). [CLAUDE.md](../CLAUDE.md) declares
clippy clean as a project gate; every other prompt below relies on this
gate, so this is fixed first.

> Read `crates/invariant-sim/src/campaign.rs` around lines 2497, 2800–2970.
> Identify each `assert!(...)` whose condition is a const expression; these
> are the 14 errors clippy is reporting.
>
> For each one, decide between two equivalent fixes:
>
> 1. If the assertion is checking a static invariant about a constant
>    (e.g. an episode budget literal), wrap it in `const { assert!(...); }`
>    so it becomes a compile-time check.
> 2. If the assertion is conceptually a regression test, lift it into a
>    `#[test]` function inside the existing `#[cfg(test)] mod tests {}` in
>    the same file.
>
> Pick whichever fix preserves the original intent. Do not silence with
> `#[allow(clippy::assertions_on_constants)]` — that hides regressions.
>
> Remove the unused `use super::execution_target::*;` import at L2497 if
> truly unused; if a downstream item depends on it, replace with the
> specific `use` items needed.
>
> Verify: `cargo build --workspace`,
> `cargo clippy --workspace --all-targets -- -D warnings` (must be clean,
> no errors no warnings), `cargo test -p invariant-sim`. Commit as
> `[v5-01] sim: restore clippy gate (const-asserts + unused import)`.

---

# Prompt 2 — A3 Predecessor Digest on the Pca Struct

**Gap:** Spec at [docs/spec.md:230–232](spec.md#L230-L232) and
[docs/spec.md:388–392](spec.md#L388-L392) requires every Pca hop after the
first to bind to its predecessor's canonical bytes. The current `Pca`
struct in [crates/invariant-core/src/models/authority.rs:196](../crates/invariant-core/src/models/authority.rs#L196)
has no such field, and `verify_chain` in
[crates/invariant-core/src/authority/chain.rs:31](../crates/invariant-core/src/authority/chain.rs#L31)
checks signatures, monotonic narrowing, and `p_0` immutability only. This
allows the G-09 cross-chain-splice attack documented at
[docs/spec-15m-campaign.md:179](spec-15m-campaign.md#L179).

This prompt is identical in intent to v4 Prompt 1. If v4 Prompt 1 was
already merged, skip and verify the tests below still exist; otherwise
execute it now.

> Read `crates/invariant-core/src/models/authority.rs`, `authority/chain.rs`,
> `authority/mod.rs`, `authority/tests.rs`. Read `docs/spec.md` lines
> 230–232 and 388–392.
>
> Add a non-optional field `predecessor_digest: [u8; 32]` to `Pca`. Define
> a documented constant `GENESIS_PREDECESSOR_DIGEST` equal to
> `sha256(b"invariant.pca.genesis.v1")` (NOT all zeros — all-zero sentinels
> are forgeable). The first hop in a chain stores
> `GENESIS_PREDECESSOR_DIGEST`. Every subsequent hop stores
> `sha256(canonical_bytes(prev_hop))`, where `canonical_bytes` is the same
> canonicalization used by Pca signing today — extract a single helper
> rather than introducing a second encoding.
>
> Update `verify_chain` to recompute the expected digest at each hop and
> reject mismatches with a new `AuthorityError::PredecessorDigestMismatch
> { hop_index: usize }` (only add the variant if none of the existing ones
> fit semantically).
>
> Update every literal `Pca { ... }` construction in the workspace
> (`rg "Pca \{" crates/ examples/`) to compute and supply the field
> explicitly. Do not add a `Default` value for the field. Update fixtures
> and helpers in `crates/invariant-core/tests/`,
> `crates/invariant-sim/src/campaign.rs`, and any examples.
>
> Add tests in `crates/invariant-core/src/authority/tests.rs`:
>
> - `predecessor_digest_genesis_hop_accepted`
> - `predecessor_digest_three_hop_chain_accepted`
> - `g09_cross_chain_splice_rejected` — build two valid chains from the
>   same issuer keypair, splice hop 2 of chain B onto hop 1 of chain A,
>   assert verifier rejects with `PredecessorDigestMismatch { hop_index: 1 }`
> - `predecessor_digest_byte_mutation_rejected` — flip one byte in hop 2's
>   `predecessor_digest`; assert rejection.
>
> Verify: `cargo build`, `cargo test -p invariant-core`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-02] authority: bind PCA hops via predecessor digest (A3)`.

---

# Prompt 3 — Authority Binding Invariants B1–B4

**Gap:** Spec at [docs/spec.md:394–403](spec.md#L394-L403) defines four
binding invariants linking commands to the execution context that
authorized them: B1 session immutability, B2 sequence monotonicity vs PCA
hop index, B3 temporal window, B4 executor identity. The current
validator at [crates/invariant-core/src/validator.rs](../crates/invariant-core/src/validator.rs)
checks signature and command monotonicity only. There is no
`ExecutionContext` type. The same Pca can be replayed across sessions and
executors, defeating the campaign's G-category attacks.

> Read `docs/spec.md` lines 394–403, then read the validator entry points
> in `crates/invariant-core/src/validator.rs`, the authority module
> (`authority/mod.rs`, `authority/chain.rs`), and the serve command at
> `crates/invariant-cli/src/commands/serve.rs`.
>
> Create `crates/invariant-core/src/authority/binding.rs`. Define:
>
> - `pub struct ExecutionContext { session_id: SessionId, executor_id:
>   ExecutorId, time_window: TimeWindow }` with newtype wrappers around
>   `[u8; 32]` for ids and a `TimeWindow { not_before: u64, not_after:
>   u64 }` (Unix millis). Use existing time / id types if already present;
>   do not duplicate.
> - `pub enum BindingError { SessionMismatch, SequenceRegressed { expected:
>   u64, got: u64 }, OutsideTimeWindow { now: u64, window: TimeWindow },
>   ExecutorMismatch }`.
> - `pub fn verify_execution_binding(cmd: &Command, ctx: &ExecutionContext,
>   pca_chain: &[Pca], now_ms: u64) -> Result<(), BindingError>` enforcing:
>   - **B1:** `cmd.session_id == ctx.session_id` and the same session id is
>     embedded in every Pca hop's binding payload.
>   - **B2:** `cmd.sequence` is strictly greater than the last accepted
>     sequence in this session, AND `cmd.sequence` lies within the range
>     declared by the terminal Pca hop.
>   - **B3:** `ctx.time_window.not_before <= now_ms <= ctx.time_window.not_after`
>     and the terminal Pca hop's validity window contains `now_ms`.
>   - **B4:** `cmd.executor_id == ctx.executor_id` and matches the executor
>     declared in the terminal Pca hop.
>
> Add `Command` fields if needed (`session_id`, `executor_id`) — these are
> already implied by spec.md but may be missing on the struct; if so, add
> them as non-optional and update fixtures.
>
> Plumb `ExecutionContext` into `ValidatorConfig` (or a new
> `ValidatorRequest` wrapper if `ValidatorConfig` is meant to be static).
> Wire the binding check into the validator hot path **before** physics
> checks — a session/executor mismatch must short-circuit before P1–P25.
>
> Update `crates/invariant-cli/src/commands/serve.rs` to extract
> `session_id` and `executor_id` from connection handshake (define a
> minimal handshake message if none exists; document it in code comments
> referencing spec.md §B1–B4) and to reject commands whose binding fails
> with a clear error.
>
> Add tests in a new `crates/invariant-core/src/authority/binding_tests.rs`
> (or `binding.rs` `#[cfg(test)] mod tests`):
>
> - `b1_session_mismatch_rejected`
> - `b1_session_match_accepted`
> - `b2_sequence_regression_rejected`
> - `b2_sequence_outside_pca_window_rejected`
> - `b2_sequence_inside_window_accepted`
> - `b3_before_window_rejected`
> - `b3_after_window_rejected`
> - `b3_inside_window_accepted`
> - `b4_executor_mismatch_rejected`
> - `b4_executor_match_accepted`
>
> Verify: `cargo build`, `cargo test -p invariant-core`,
> `cargo test -p invariant-cli`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-03] authority: bind execution context (B1–B4)`.

---

# Prompt 4 — G-07 Wildcard Authority Tests

**Gap:** `docs/spec-15m-campaign.md:177` lists G-07 (wildcard exploitation)
as a required Category G attack. There are no tests asserting that
wildcards in PCA permissions do not cross verb or subsystem boundaries.

> Read `crates/invariant-core/src/authority/chain.rs` and the existing
> tests in `authority/tests.rs`. Read `docs/spec-15m-campaign.md` lines
> 170–195.
>
> Add two tests to `crates/invariant-core/src/authority/tests.rs`:
>
> - `g07_actuate_wildcard_does_not_cover_read` — build a chain whose
>   terminal hop grants `actuate:*`. Issue a command with action `read:
>   proprioception`. Assert the validator rejects the command with an
>   authority error (not a physics error).
> - `g07_subsystem_wildcard_does_not_cross_subsystem` — terminal hop
>   grants `move:arm.*`. Command requests `move:base.linear`. Assert
>   rejection.
>
> If the wildcard matcher in fact accepts these commands today, that is
> the gap — fix the matcher in `chain.rs` (or the permission check helper)
> before the tests pass. Do not introduce regex or glob libraries; the
> match should be a deterministic prefix-by-segment check on
> dot/colon-separated namespaces.
>
> Verify: `cargo test -p invariant-core authority`. Commit as
> `[v5-04] authority: enforce verb and subsystem wildcard boundaries (G-07)`.

---

# Prompt 5 — Merkle Tree Over Audit JSONL

**Gap:** [docs/spec-15m-campaign.md:371–407](spec-15m-campaign.md#L371-L407)
requires the proof package to include a Merkle root committing every audit
JSONL entry, with `audit/merkle_root.txt` written into the package and
inclusion proofs available for any entry. The current
[crates/invariant-core/src/proof_package.rs](../crates/invariant-core/src/proof_package.rs)
emits per-file SHA-256 only; no Merkle tree, no inclusion proofs.

> Read `crates/invariant-core/src/proof_package.rs` end-to-end. Read
> `crates/invariant-core/src/audit.rs` to confirm the canonical JSONL line
> format (one entry per line, deterministic field order).
>
> Create `crates/invariant-core/src/merkle.rs`:
>
> - `pub struct MerkleTree { leaves: Vec<[u8; 32]>, nodes: Vec<Vec<[u8;
>   32]>> }` (level 0 = leaves; level N = root).
> - `pub fn build_from_jsonl(path: &Path) -> io::Result<MerkleTree>` —
>   stream the file line by line; for each non-empty line, leaf =
>   `sha256(b"L" || line_bytes)` (domain-separation byte to prevent
>   second-preimage). Internal nodes use `sha256(b"N" || left || right)`.
>   For odd levels duplicate the last node; document this choice in a
>   comment referencing RFC 6962 §2.1 if you choose its convention, or
>   document deviation explicitly.
> - `pub fn root(&self) -> [u8; 32]`.
> - `pub fn proof(&self, leaf_index: usize) -> Vec<[u8; 32]>` returning
>   the audit path.
> - `pub fn verify_proof(root: [u8; 32], leaf: [u8; 32], index: usize,
>   proof: &[[u8; 32]]) -> bool`.
>
> Register the module in `crates/invariant-core/src/lib.rs` (`pub mod
> merkle;`).
>
> Update `proof_package::assemble` to call `build_from_jsonl` over each
> shard's audit log, write `audit/merkle_root.txt` (hex of root, trailing
> newline), and add the root to the manifest.
>
> Update `proof_package::verify_package` to recompute the tree from the
> packaged JSONL and compare to `merkle_root.txt`.
>
> Add tests in a new `#[cfg(test)] mod tests` in `merkle.rs`:
>
> - `merkle_single_leaf_root`
> - `merkle_three_leaf_round_trip` (build, proof, verify)
> - `merkle_inclusion_proof_round_trip_50_leaves`
> - `merkle_tampered_leaf_fails_verification`
> - `merkle_root_independent_of_io_chunking` — feed the same logical
>   content split across two file boundaries; root must match.
>
> Verify: `cargo test -p invariant-core merkle`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-05] core: Merkle tree over audit JSONL`.

---

# Prompt 6 — Signed Proof-Package Manifest

**Gap:** [docs/spec-15m-campaign.md:371–407](spec-15m-campaign.md#L371-L407)
requires the manifest to be Ed25519-signed with the campaign key. The
current `Manifest` is `HashMap<String, String>` of per-file digests with
no signature.

> Read `crates/invariant-core/src/proof_package.rs` and the keygen command
> at `crates/invariant-cli/src/commands/keygen.rs` to identify the
> existing Ed25519 helpers.
>
> Replace the ad-hoc map manifest with a strongly typed:
>
> - `pub struct Manifest { schema_version: u32, campaign_id: String,
>   created_at_ms: u64, files: BTreeMap<String, FileDigest>, merkle_root:
>   [u8; 32], signer_public_key: [u8; 32] }` — `BTreeMap` to ensure
>   deterministic serialization.
> - `pub struct FileDigest { sha256: [u8; 32], size_bytes: u64 }`.
>
> Define a canonical serialization (JSON with sorted keys; document the
> exact serializer used; if `serde_json` is used, sort the BTreeMap and
> avoid pretty-printing). Sign that exact byte sequence with the
> campaign's Ed25519 secret key. Write `manifest.json` and `manifest.sig`
> alongside in the package root.
>
> Update `proof_package::assemble` signature to accept `&SigningKey` and
> emit both files. Update `verify_package`:
>
> 1. Re-read `manifest.json` bytes verbatim.
> 2. Verify `manifest.sig` against `manifest.signer_public_key`.
> 3. Recompute every `files[*].sha256` and compare.
> 4. Recompute the Merkle root (Prompt 5) and compare to
>    `manifest.merkle_root` and to `audit/merkle_root.txt`.
>
> Update integration tests in `crates/invariant-core/tests/` (or
> wherever proof-package round-trip tests live):
>
> - `proof_package_round_trip_two_shards` — build, verify (must pass).
> - `proof_package_tampered_audit_jsonl_rejected`.
> - `proof_package_tampered_manifest_signature_rejected`.
> - `proof_package_wrong_public_key_rejected`.
>
> Verify: `cargo test -p invariant-core proof_package`,
> `cargo test -p invariant-cli verify_package`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-06] core: signed proof-package manifest with Merkle root`.

---

# Prompt 7 — `campaign assemble` CLI Subcommand

**Gap:** Spec-15m-campaign.md §6 step 6 names "assemble per-shard outputs
into a proof package" as the campaign's final deliverable. The Rust API
exists (after Prompts 5 + 6) but no CLI surface invokes it. Without this,
the 15M-episode run cannot ship its headline artifact.

> Read `crates/invariant-cli/src/main.rs` to find the `Commands` enum and
> the existing `Campaign` subcommand at
> `crates/invariant-cli/src/commands/campaign.rs`.
>
> Add an `Assemble` subcommand under `Campaign`:
>
> ```
> invariant campaign assemble \
>     --shards <DIR>          # directory containing shard-*/audit.jsonl + summary.json
>     --output <PATH>         # output package path (.tar.zst or directory)
>     --signing-key <PATH>    # Ed25519 secret key (PEM or raw 32B; match keygen)
>     --campaign-id <ID>      # required; written into manifest
> ```
>
> The subcommand must:
>
> 1. Discover all shard directories (`shard-*/`) under `--shards`.
> 2. For each shard, read `summary.json` and append per-category counts
>    (passes / fails / total).
> 3. Compute Clopper–Pearson 99.9% one-sided upper bounds per category
>    using the aggregated counts (use the existing helper if present in
>    `invariant-core`; otherwise add `clopper_pearson_upper_one_sided` to
>    `invariant-core::stats` with property tests).
> 4. Build a Merkle tree per shard (Prompt 5) and a top-level tree of
>    shard roots; the manifest's `merkle_root` is the top-level root.
> 5. Record profile fingerprints (sha256 of each profile JSON used).
> 6. Call `proof_package::assemble` (Prompt 6) to write the signed
>    package.
>
> Add an integration test under `crates/invariant-cli/tests/`:
>
> - `campaign_assemble_two_shard_round_trip` — generate a tiny synthetic
>   2-shard fixture, run `assemble`, run `verify-package` on the output,
>   assert success and that `merkle_root.txt` exists.
>
> Update `CLAUDE.md` Project Layout subcommand list to include
> `campaign assemble`.
>
> Verify: `cargo test -p invariant-cli campaign_assemble`,
> `cargo run -- campaign assemble --help` displays the new flags,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-07] cli: campaign assemble subcommand for proof packages`.

---

# Prompt 8 — Split SR1 / SR2 Sensor-Range Checks

**Gap:** [docs/spec-v2.md:139–145](spec-v2.md#L139-L145) declares SR1
(environment / proprioception range) and SR2 (payload range) as distinct
checks that must be independently coverable. The current
[crates/invariant-core/src/physics/environment.rs:361–427](../crates/invariant-core/src/physics/environment.rs#L361-L427)
implements them under a single check named `sensor_range`, so the
compliance command at `crates/invariant-core/src/physics/mod.rs:326` can
only count them together. This blocks per-check coverage tracking for
Category F.

> Read `crates/invariant-core/src/physics/environment.rs` lines 350–440
> and `physics/mod.rs` around 320–340.
>
> Split the existing `check_sensor_range` into two:
>
> - `check_sensor_range_env` (SR1) — environment, proprioception, IMU
>   ranges.
> - `check_sensor_range_payload` (SR2) — gripper / payload sensor ranges.
>
> Register both in the physics check registry with distinct identifiers
> `"sr1.sensor_range_env"` and `"sr2.sensor_range_payload"`. Update the
> compliance command and any coverage matrix to count them separately.
>
> Update existing tests for the old `sensor_range` check: either rename
> them to target SR1 vs SR2 explicitly, or add new ones. After this
> change there must be at least four tests: a positive and a negative for
> each of SR1 and SR2.
>
> Search for string occurrences of `"sensor_range"` (`rg
> '"sensor_range"'`) and update reports, profile fields, or audit emitters
> that referenced the old single name. If existing audit logs or fixtures
> contain the old name, add a one-line comment in the migration site
> noting the breaking-change date.
>
> Verify: `cargo test -p invariant-core physics`, `cargo clippy
> --workspace --all-targets -- -D warnings`. Commit as
> `[v5-08] physics: split SR1/SR2 sensor-range checks`.

---

# Prompt 9 — Profiles: end_effectors + `validate-profiles --strict`

**Gap:** Nine profiles in `profiles/` lack an `end_effectors` block. Five
are legitimately locomotion-only (anybotics_anymal, quadruped_12dof, spot,
unitree_a1, unitree_go2) but do not declare that fact, so `compliance`
cannot distinguish "missing data" from "not applicable". `validate-
profiles` does not enforce that any profile permitting manipulation
declares end-effectors.

> Read every JSON file under `profiles/`. Read
> `crates/invariant-cli/src/commands/profile_cmd.rs` (or wherever the
> `validate-profiles` subcommand lives).
>
> For each of the five locomotion-only profiles
> (anybotics_anymal.json, quadruped_12dof.json, spot.json, unitree_a1.json,
> unitree_go2.json), add:
>
> ```
> "platform_class": "locomotion-only",
> "end_effectors": []
> ```
>
> For agility_digit.json, fill in the actual end-effector data (consult
> the existing humanoid profile structure for shape).
>
> For any adversarial-fixture profiles intentionally malformed, add
> `"adversarial": true` so `--strict` can skip them.
>
> Implement `invariant validate-profiles --strict`. The flag must fail
> the command with non-zero exit if any non-adversarial profile both
> permits manipulation actions (any of `move:arm.*`, `actuate:gripper.*`,
> or category permissions implying EE use) AND has an empty / missing
> `end_effectors` block. Without `--strict`, behavior is unchanged
> (warnings only).
>
> Add tests in `crates/invariant-cli/tests/` covering: strict-passing
> humanoid profile, strict-passing locomotion-only profile,
> strict-failing profile (manipulation permission but no EE), strict
> ignores adversarial-marked profile.
>
> Verify: `cargo test -p invariant-cli validate_profiles`,
> `cargo run -- validate-profiles --strict` against every profile in
> `profiles/` (must exit 0). Commit as
> `[v5-09] profiles: declare EE blocks; validate-profiles --strict`.

---

# Prompt 10 — Category C Scenario Generators (Spatial Safety, 1M)

**Gap:** [docs/spec-15m-campaign.md §3 Category C](spec-15m-campaign.md)
enumerates C-01 … C-06 (workspace boundary, exclusion zone, conditional
zone, self-collision, overlapping zones, corrupt spatial data). None are
implemented. `crates/invariant-sim/src/scenario.rs` exposes ~22
`ScenarioType` variants — none cover Category C.

> Read `crates/invariant-sim/src/scenario.rs` to learn how an existing
> `ScenarioType` variant is defined and how its `ScenarioGenerator`
> dispatches commands. Read the Category C subsection of
> `docs/spec-15m-campaign.md`.
>
> Add six `ScenarioType` variants (`WorkspaceBoundarySweep`,
> `ExclusionZonePenetration`, `ConditionalZoneStateMachine`,
> `SelfCollisionApproach`, `OverlappingZoneBoundaries`,
> `CorruptSpatialData`). For each, implement a generator that:
>
> 1. Sets up a deterministic spatial fixture (seedable from a
>    `ScenarioSeed`).
> 2. Emits a sequence of commands that approach the relevant boundary
>    from inside, cross it, and then exit. The validator must accept
>    every inside-bounds command and reject every out-of-bounds command;
>    the generator does NOT predict the verdict — it asserts only on
>    boundary correctness in tests, not in the runner.
> 3. Records ground-truth labels per command (`expected_outcome:
>    Accept | Reject(reason)`) so the campaign runner can compute
>    pass/fail per spec-15m-campaign §6.
>
> Add unit tests for each generator: `category_c_NN_generates_at_least_K_commands`,
> `category_c_NN_round_trip_through_validator_matches_labels`. Use a small
> deterministic seed and assert exact sequence shapes where feasible.
>
> Wire the new variants into the campaign category registry in
> `crates/invariant-sim/src/campaign.rs` so Category C contributes its
> 1M-episode budget.
>
> Verify: `cargo test -p invariant-sim category_c`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-10] sim: Category C scenario generators (spatial safety)`.

---

# Prompt 11 — Category D Scenario Generators (Stability & Locomotion, 1.5M)

**Gap:** Category D (D-01 … D-10) covers COM, gait, base velocity, foot
clearance, friction cone, step length, heading rate, incline. None
implemented.

> Follow the same approach as Prompt 10 but for Category D. Reference
> physics checks P9 (COM polygon), P15–P20 (locomotion). Add ten
> `ScenarioType` variants:
>
> `COMStabilitySweep`, `WalkingGaitValidation`, `SpeedRampToRunaway`,
> `FootClearanceUnderload`, `FrictionConeBoundary`, `StepLengthOvershoot`,
> `HeadingRateSpike`, `InclineWalkingLimits`, `StepFrequencyBoundary`,
> `BaseVelocitySaturation`.
>
> Use the locomotion-only profiles from Prompt 9 (spot.json,
> unitree_a1.json, etc.) as the test fixtures.
>
> Add ten unit tests + the campaign registry wire-in. Verify and commit
> as `[v5-11] sim: Category D scenario generators (stability)`.

---

# Prompt 12 — Category E Scenario Generators (Manipulation, 750K)

**Gap:** Category E (E-01 … E-06) covers force limits, grasp envelope,
force rate spikes, payload overload, human proximity force, bimanual
coordination. None implemented.

> Follow Prompt 10 pattern. Add six `ScenarioType` variants:
> `ForceLimitSweep`, `GraspForceEnvelope`, `ForceRateSpike`,
> `PayloadOverload`, `HumanProximityForce`, `BimanualCoordination`.
> Reference physics checks P11–P14. Use franka_panda /
> universal_robots_ur5 / agility_digit profiles as fixtures.
>
> Add six unit tests + campaign registry wire-in. Verify and commit as
> `[v5-12] sim: Category E scenario generators (manipulation)`.

---

# Prompt 13 — Category F Scenario Generators (Environmental, 750K)

**Gap:** Category F (F-01 … F-08) covers temperature, battery, latency,
e-stop, sensor range, sensor fusion, combined environmental. None
implemented.

> Follow Prompt 10 pattern. Add eight `ScenarioType` variants:
> `TemperatureRamp`, `BatteryDrain`, `LatencySpike`, `EstopCycle`,
> `SensorRangeEnvPlausibility`, `SensorRangePayloadPlausibility`,
> `SensorFusionInconsistency`, `CombinedEnvironmental`.
>
> The two sensor-range scenarios must hit SR1 and SR2 independently
> (Prompt 8); confirm the campaign report differentiates their coverage.
>
> Add eight tests + campaign registry wire-in. Verify and commit as
> `[v5-13] sim: Category F scenario generators (environmental)`.

---

# Prompt 14 — Category H Scenario Generators (Temporal & Sequence, 750K)

**Gap:** Category H (H-01 … H-06) covers replay, sequence regression,
gaps, delta-time attacks, stale commands, future-dated sensors. None
implemented.

> Follow Prompt 10 pattern. Add six `ScenarioType` variants:
> `SequenceReplay`, `SequenceRegression`, `SequenceGap`,
> `DeltaTimeAttack`, `StaleCommand`, `FuturedatedSensor`. Each must
> exercise B2 / B3 binding (Prompt 3) at boundaries.
>
> Add six tests + campaign registry wire-in. Verify and commit as
> `[v5-14] sim: Category H scenario generators (temporal)`.

---

# Prompt 15 — Category I Scenario Generators (Cognitive Escape, 1.5M)

**Gap:** Category I (I-01 … I-10) is the cognitive-attack category and
the largest unmet budget. The fuzzing harness in
`crates/invariant-fuzz/src/cognitive.rs` exists but is not wired to
campaign scenarios.

> Read `crates/invariant-fuzz/src/cognitive.rs` to identify any existing
> generators (CE1–CE10). Read the Category I subsection of
> `docs/spec-15m-campaign.md`.
>
> Where existing fuzz generators map onto CE1–CE10, expose them via the
> fuzz crate's public API and consume them from new `ScenarioType`
> variants in `crates/invariant-sim/src/scenario.rs`. Where fuzz
> generators do not yet exist, add them in `invariant-fuzz` first.
>
> Add ten `ScenarioType` variants: `GradualDrift`, `DistractionFlooding`,
> `SemanticConfusion`, `AuthorityLaundering`, `ErrorMining`,
> `WatchdogManipulation`, `ProfileProbing`, `MultiAgentCollusion`,
> `TimingExploitation`, `RollbackReplay`.
>
> Add ten tests asserting that each generator produces at least one
> rejected command and that no benign baseline command is rejected.
>
> Wire into the campaign registry. Verify and commit as
> `[v5-15] sim+fuzz: Category I cognitive scenario generators`.

---

# Prompt 16 — Category M Scenario Generators (Cross-Platform Stress, 500K)

**Gap:** Category M (M-01 … M-06) covers high-frequency valid traffic,
alternating valid/invalid, pure fuzz, max-size payloads, minimal
payloads, mixed-profile audits.

> Follow Prompt 10 pattern. Add six `ScenarioType` variants:
> `HighFrequencyValid`, `AlternatingValidInvalid`, `PureFuzz`,
> `MaxSizePayload`, `MinimalPayload`, `MixedProfilesAudit`.
>
> `MaxSizePayload` must hit the validator's documented size cap (look up
> the constant; if no cap exists, add one in the validator and document
> it). `MixedProfilesAudit` must rotate among at least three profiles
> within a single shard's audit log; verify the proof-package assembly
> (Prompt 7) records all three fingerprints.
>
> Add six tests + campaign registry wire-in. Verify and commit as
> `[v5-16] sim: Category M scenario generators (stress)`.

---

# Prompt 17 — Category N Scenario Generators (Adversarial Red Team, 500K)

**Gap:** Category N (N-01 … N-10) covers generation-based fuzz,
mutation-based fuzz, grammar-based, coverage-guided, differential, JSON-
bomb, COSE/CBOR fuzz, Unicode adversarial, type confusion, integer
boundary.

> Read `crates/invariant-fuzz/src/protocol.rs`,
> `crates/invariant-fuzz/src/system.rs`, and
> `crates/invariant-fuzz/src/cognitive.rs` to inventory existing
> primitives.
>
> Add ten `ScenarioType` variants and corresponding generators. For each,
> the generator emits an adversarial input drawn from the matching
> fuzzing strategy and asserts the validator either (a) rejects the
> input, or (b) accepts it as well-formed and the resulting command
> passes physics — never panic, never accept malformed bytes silently.
>
> If `cargo-fuzz` (libFuzzer) integration does not exist for N-04,
> document the missing harness in a `// TODO(v5-17): wire libFuzzer`
> comment **and** add a long-running proptest fallback so the category
> can still consume episode budget without depending on a nightly
> toolchain.
>
> Add ten tests + campaign registry wire-in. Verify and commit as
> `[v5-17] sim+fuzz: Category N adversarial scenario generators`.

---

# Prompt 18 — `fleet status` Subcommand and 10-Robot Coordinator Test

**Gap:** [docs/spec.md:534–538](spec.md#L534-L538) calls for a fleet
view of coordinator state. The `invariant-coordinator` crate is currently
exercised pairwise only.

> Read `crates/invariant-coordinator/src/lib.rs` and any existing
> integration tests. Read `crates/invariant-cli/src/main.rs` for the
> `Commands` enum.
>
> Add a `Fleet` subcommand with at minimum:
>
> ```
> invariant fleet status --state <PATH>      # JSON dump of coordinator state
> invariant fleet status --state <PATH> --json
> ```
>
> The command reads a coordinator state file (define the format if absent;
> a serde-derived snapshot of the public coordinator API is fine) and
> prints a human-readable summary: robot count, active reservations,
> partitions, separation-violation count.
>
> Add an integration test in `crates/invariant-coordinator/tests/`:
>
> - `fleet_ten_robots_no_false_positives` — instantiate 10 robots (8
>   manipulators on shared workcells, 2 mobile bases on shared corridor),
>   run 60 seconds of simulated traffic at 100 Hz, assert zero false-
>   positive separation violations and zero true-negative misses on
>   injected near-miss events.
>
> Update `CLAUDE.md` Project Layout subcommand list to include `fleet
> status`.
>
> Verify: `cargo test -p invariant-coordinator fleet_ten_robots`,
> `cargo run -- fleet status --help`,
> `cargo clippy --workspace --all-targets -- -D warnings`. Commit as
> `[v5-18] coordinator+cli: fleet status and 10-robot test`.

---

# Prompt 19 — CI-Emitted Test Count and Doc Sync

**Gap:** README.md:392 cites "~2,047 tests"; spec-v2.md:307 cites
"2,023+"; the actual `#[test]` count is 1,881. Documentation drift makes
the spec untrustworthy. There is no CI step that emits the canonical
count.

> Read `.github/workflows/` (any CI definition). Add (or update) a CI job
> that, after `cargo test --workspace`, runs:
>
> ```
> cargo test --workspace 2>&1 | tee target/test-output.txt
> grep -E '^test result:' target/test-output.txt | \
>     awk '{ gsub("[^0-9]","",$4); s += $4 } END { print s }' \
>     > docs/test-count.txt
> ```
>
> (Adjust the awk if the `cargo test` output format on the toolchain
> pinned in `rust-toolchain.toml` differs.) Commit `docs/test-count.txt`
> with the value at HEAD. Have CI fail if the file is out of date.
>
> Update README.md, CHANGELOG.md (note as "tooling: CI now emits
> docs/test-count.txt"), and any spec section that hard-codes a literal
> count to instead reference `docs/test-count.txt`.
>
> Update `CLAUDE.md` Project Layout to enumerate the **actual** CLI
> subcommand list (run `cargo run -- --help` to confirm the canonical
> list, including the new `campaign assemble` and `fleet status` from
> Prompts 7 and 18).
>
> Verify: CI passes; `cat docs/test-count.txt` shows the correct number;
> README and CLAUDE.md no longer disagree with reality. Commit as
> `[v5-19] ci+docs: emit canonical test count; sync subcommand list`.

---

# Prompt 20 — Discharge Lean `sorry` and `axiom` Hot Spots

**Gap:** [docs/spec.md:799–831](spec.md#L799-L831) claims "proves" for
the formal model, but `formal/Invariant/Authority.lean:85–90` has a
`sorry` on `monotonicity_transitive`,
`formal/Invariant/Audit.lean:82` axiomatizes
`hash_collision_resistant`, and `formal/Invariant/Physics.lean:132`
axiomatizes `pointInConvexPolygon`. CI does not run `lake build`.

> Read each Lean file under `formal/`. For each `sorry` or `axiom`,
> decide between two paths:
>
> 1. **Discharge:** if the property is provable from existing definitions
>    plus standard mathlib lemmas, prove it. `monotonicity_transitive` is
>    the priority — this is a finite-step transitivity over a recorded
>    chain and should be tractable.
> 2. **Justify:** if the property is genuinely an external assumption
>    (e.g. cryptographic hash collision-resistance), keep it as `axiom`
>    but add a docstring naming the assumption explicitly and citing the
>    cryptographic primitive (e.g. SHA-256 collision resistance, ROM
>    model). For `pointInConvexPolygon`, prefer to *prove* it rather than
>    axiomatize — convexity arguments over rational coordinates are
>    standard.
>
> Update [docs/spec.md:799–831](spec.md#L799-L831) to qualify the
> "proves" language: list which properties are mechanically discharged
> vs. which are axiomatized assumptions, with a short justification for
> each axiom.
>
> Add a `lake-build` step to CI (`.github/workflows/`). It must fail the
> build if any `sorry` regresses (use `lake env grep -RIn 'sorry\|axiom'
> formal/` and assert against an allowlist file
> `formal/AXIOMS_ALLOWLIST.txt`).
>
> Verify: `cd formal && lake build` (must succeed locally),
> `grep -RIn 'sorry' formal/` matches the allowlist, the spec section
> reads accurately. Commit as
> `[v5-20] formal: discharge monotonicity_transitive; document axioms; CI lake-build`.

---

# Appendix A — Verification Matrix

| Prompt | Gate                                    | Spec Citation                                           |
| ------ | --------------------------------------- | ------------------------------------------------------- |
| 1      | clippy clean                            | CLAUDE.md (project gate)                                |
| 2      | A3 chain test                           | docs/spec.md:230–232, 388–392                           |
| 3      | B1–B4 binding tests                     | docs/spec.md:394–403                                    |
| 4      | G-07 wildcard tests                     | docs/spec-15m-campaign.md:177                           |
| 5      | merkle round-trip                       | docs/spec-15m-campaign.md:371–407                       |
| 6      | signed manifest round-trip              | docs/spec-15m-campaign.md:371–407                       |
| 7      | `campaign assemble` integration test    | docs/spec-15m-campaign.md §6                            |
| 8      | SR1/SR2 split coverage                  | docs/spec-v2.md:139–145                                 |
| 9      | `validate-profiles --strict`            | docs/spec-gaps.md §4.2                                  |
| 10     | Category C generators                   | docs/spec-15m-campaign.md §3 C-01..C-06                 |
| 11     | Category D generators                   | docs/spec-15m-campaign.md §3 D-01..D-10                 |
| 12     | Category E generators                   | docs/spec-15m-campaign.md §3 E-01..E-06                 |
| 13     | Category F generators                   | docs/spec-15m-campaign.md §3 F-01..F-08                 |
| 14     | Category H generators                   | docs/spec-15m-campaign.md §3 H-01..H-06                 |
| 15     | Category I generators                   | docs/spec-15m-campaign.md §3 I-01..I-10                 |
| 16     | Category M generators                   | docs/spec-15m-campaign.md §3 M-01..M-06                 |
| 17     | Category N generators                   | docs/spec-15m-campaign.md §3 N-01..N-10                 |
| 18     | 10-robot coordinator test, `fleet`      | docs/spec.md:534–538                                    |
| 19     | CI test-count + doc sync                | docs/spec-gaps.md §4.5                                  |
| 20     | Lean `lake build` clean                 | docs/spec.md:799–831                                    |

# Appendix B — Recommended Execution Order

Prompts 1, 2, 3 must merge in that order before any of 5–7 (proof
package + assemble depend on A3 + binding for the package to be
meaningful). Prompts 5, 6, 7 must merge in order. Prompt 8 can run any
time after Prompt 1. Prompts 10–17 can be parallelized across separate
branches after Prompt 1 lands, since they touch disjoint
`ScenarioType` variants — but coordinate the campaign registry merge in
`crates/invariant-sim/src/campaign.rs` to avoid serial conflicts (use
one register-this-variant function per category and wire the call last
in each PR). Prompts 18, 19, 20 are independent and can land any time.
