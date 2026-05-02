% Invariant — Gap-Closure Execution Spec (v4)
% Status: Draft
% Date: 2026-04-27
% Branch: codelicious/spec-spec-15m-campaign-part-4
% Companion to: `docs/spec-gaps.md` (gap analysis with citations)

# 0. How To Use This Document

Each section below is a self-contained **Claude Code prompt**. Paste one
prompt at a time into a Claude Code session at the repo root and let it run
to completion before moving on. Every prompt:

- Names the gap, the spec citation, and the existing code citation so Claude
  can re-verify before editing.
- States acceptance criteria as concrete files / tests / CLI behavior.
- Ends with the verification commands that must pass.

The order is the prioritized order from `spec-gaps.md §7`. Do not parallelize
prompts that touch the same module unless explicitly noted.

Each prompt assumes:

- Working directory is the repo root.
- `cargo build`, `cargo test`, and `cargo clippy -- -D warnings` are the
  required gates per [CLAUDE.md](../CLAUDE.md).
- One commit per prompt, message prefixed with `[gap-NN]` matching the
  section number here.

If a verification step fails, fix the root cause — do not weaken the
acceptance criteria, and do not commit `--no-verify`.

---

# Prompt 1 — A3 Predecessor Digest (PCA-to-PCA Causal Binding)

**Gap:** `spec-gaps.md §1.2`. Spec at [docs/spec.md:230-232](spec.md#L230-L232)
and [docs/spec.md:388-392](spec.md#L388-L392) requires PoC binding hop *i+1*
to the byte representation of hop *i*. Code at
[crates/invariant-core/src/authority/chain.rs:31](../crates/invariant-core/src/authority/chain.rs#L31)
verifies signatures, monotonic narrowing, and `p_0` immutability only.

> Read `crates/invariant-core/src/authority/chain.rs`, `mod.rs`, and
> `tests.rs`. Read `docs/spec.md` lines 230–232 and 388–392 to confirm the
> A3 wording.
>
> Add a non-optional `predecessor_digest: [u8; 32]` field to the `Pca`
> struct. The first hop in a chain stores the SHA-256 of an explicit
> "genesis" canonical byte string (define a documented constant — do not use
> all-zeros). Every subsequent hop must store
> `sha256(canonical_bytes(prev_hop))`, where `canonical_bytes` is the
> existing canonical serialization used for signing (extract a helper if
> needed; do not invent a second canonicalization).
>
> Update `verify_chain` to reject any chain where
> `hop[i].predecessor_digest != expected_digest(hop[i-1])`. Reuse the
> existing `AuthorityError` taxonomy; add a new variant
> `PredecessorDigestMismatch { hop_index: usize }` only if no existing
> variant fits.
>
> Regenerate every fixture, test helper, and example that constructs a
> `Pca` literal. Search with `rg "Pca \{" crates/ examples/` and update each
> hit. Do not silently default the field — every construction site must
> compute the digest explicitly so the test surface stays honest.
>
> Add tests in `crates/invariant-core/src/authority/tests.rs`:
>
> - `predecessor_digest_genesis_hop_accepted` — single-hop chain with the
>   genesis constant verifies.
> - `predecessor_digest_chain_accepted` — three-hop well-formed chain.
> - `g09_cross_chain_splice_rejected` — assemble two locally valid chains
>   sharing an issuer; splice them; verifier rejects on the first hop whose
>   `predecessor_digest` does not match its prior hop's canonical digest.
>   Match the campaign-spec attack at
>   [docs/spec-15m-campaign.md:179](spec-15m-campaign.md#L179).
> - `predecessor_digest_mutation_rejected` — flip one byte in
>   `predecessor_digest` of hop 2; verifier rejects.
>
> Verify: `cargo build`, `cargo test -p invariant-core`,
> `cargo clippy -- -D warnings`. Commit as
> `[gap-1] authority: bind PCA hops via predecessor digest (A3)`.

---

# Prompt 2 — B1–B4 Execution-Binding Module

**Gap:** `spec-gaps.md §1.1`. Spec at
[docs/spec.md:394-403](spec.md#L394-L403); `authority/binding.rs` does not
exist.

> Read `docs/spec.md` lines 394–403 to lock in the wording of B1 (session
> binding), B2 (sequence monotonicity vs the PCA chain), B3 (temporal-window
> enforcement), B4 (executor identity).
>
> Read the existing validator entry point at
> `crates/invariant-core/src/validator.rs` (focus on the sequence handling
> around lines 220, 300, 315) and `authority/chain.rs` so the new module
> integrates cleanly. Read `crates/invariant-cli/src/commands/serve.rs` to
> understand the connection model.
>
> Create `crates/invariant-core/src/authority/binding.rs` exposing:
>
> - `pub struct ExecutionContext { pub session_id: SessionId, pub
>   executor_id: ExecutorId, pub time_window: TimeWindow }` with serde and
>   debug derives. Define newtype wrappers for the IDs.
> - `pub enum BindingError { SessionMismatch, SequenceRegression { last:
>   u64, got: u64 }, OutOfWindow { now_ms: i64, window: TimeWindow },
>   ExecutorMismatch }` with `thiserror::Error`.
> - `pub fn verify_execution_binding(cmd: &Command, ctx: &ExecutionContext,
>   pca: &Pca) -> Result<(), BindingError>` enforcing B1–B4 in that order.
>
> Wire it into `ValidatorConfig` so it carries an optional
> `ExecutionContext`. When set, the validator calls
> `verify_execution_binding` before existing physics checks. When unset,
> behavior is unchanged for backwards compatibility with offline tools
> (this is the only acceptable default-on/off knob — document the
> reasoning in the rustdoc).
>
> Update `crates/invariant-cli/src/commands/serve.rs` to construct a
> per-connection `ExecutionContext` from the negotiated session ID, the
> executor's identity claim, and the configured temporal window. Reject
> connections that do not provide all three.
>
> Add `crates/invariant-core/tests/binding.rs` with one positive and one
> hostile test per invariant (8 tests total): valid session vs swapped
> session, monotonic vs regressed sequence, in-window vs expired, matching
> vs mismatched executor.
>
> Verify: `cargo build`, `cargo test -p invariant-core --test binding`,
> `cargo test`, `cargo clippy -- -D warnings`. Commit as
> `[gap-2] authority: B1–B4 execution-binding module`.

---

# Prompt 3 — Wildcard-Coverage Hostile Tests (G-07)

**Gap:** `spec-gaps.md §1.3` (G-07 portion — G-09 lands in Prompt 1).
Wildcard semantics are documented at
[crates/invariant-core/src/authority/operations.rs:11-14](../crates/invariant-core/src/authority/operations.rs#L11-L14)
but no targeted hostile tests exist.

> Read `crates/invariant-core/src/authority/operations.rs` to confirm the
> existing wildcard-matching rules. Read
> [docs/spec-15m-campaign.md:177](spec-15m-campaign.md#L177) (G-07) for the
> attack wording.
>
> Add to `crates/invariant-core/src/authority/tests.rs`:
>
> - `g07_wildcard_actuate_does_not_cover_read` — chain whose hop authorizes
>   `actuate:*`; verifier rejects an attempt to perform `read:proprioception`.
> - `g07_move_namespace_wildcard_does_not_cross_subsystem` — hop authorizes
>   `move:arm.*`; verifier rejects `move:base.linear`.
>
> Use existing test helpers; do not introduce new fixtures unless required.
>
> Verify: `cargo test -p invariant-core authority`,
> `cargo clippy -- -D warnings`. Commit as
> `[gap-3] authority: G-07 wildcard hostile tests`.

---

# Prompt 4 — Merkle Tree + Signed Manifest in Proof Package

**Gap:** `spec-gaps.md §3.1`. Spec at
[docs/spec-15m-campaign.md:371-407](spec-15m-campaign.md#L371-L407) requires
`audit/merkle_root.txt` and a signed manifest. Today,
[crates/invariant-core/src/proof_package.rs:241](../crates/invariant-core/src/proof_package.rs#L241)
documents the manifest as unsigned and emits per-file SHA-256 only.

> Read `crates/invariant-core/src/proof_package.rs` (full file),
> `audit.rs`, and `crates/invariant-cli/src/commands/verify_package.rs`.
> Confirm the existing `assemble` API and the verifier's expectations.
>
> Add a binary SHA-256 Merkle tree over audit JSONL leaves. Define:
>
> - `pub struct MerkleTree { root: [u8; 32], leaves: Vec<[u8; 32]> }`.
> - `pub fn merkle_proof(&self, seq: u64) -> Vec<[u8; 32]>` returning the
>   sibling path for the leaf at `seq`.
> - Determinism: leaves are hashed as `sha256(jsonl_line_bytes)`; internal
>   nodes as `sha256(0x01 || left || right)`; odd levels duplicate the last
>   leaf. Document this in the module docstring so external verifiers can
>   reimplement.
>
> During `assemble`:
>
> - Build the tree from the audit JSONL files in shard order.
> - Write the hex root to `audit/merkle_root.txt`.
> - Write `audit/chain_verification.json` with shard count, leaf count, and
>   the root.
> - Sign `manifest.json` with the supplied Ed25519 key (pass the key into
>   `assemble`; if absent, fail with a typed error rather than silently
>   skipping). Emit `manifest.sig` next to `manifest.json`.
>
> During `verify_package`:
>
> - Rebuild the Merkle tree from the JSONL files; assert the root matches
>   `audit/merkle_root.txt`.
> - Verify `manifest.sig` against a caller-supplied public key.
> - Re-check each per-file SHA-256 (existing behavior).
>
> Add `crates/invariant-core/tests/proof_package_signed.rs`:
>
> - Build a 2-shard fixture with ~20 audit entries.
> - Assemble with a generated Ed25519 key.
> - Verify with the matching public key — success.
> - Mutate one byte of one JSONL leaf — verify fails with a Merkle mismatch.
> - Mutate `manifest.json` — verify fails with a signature mismatch.
> - Mutate one byte of `manifest.sig` — verify fails.
>
> Update `crates/invariant-cli/src/commands/verify_package.rs` so its
> existing tests still pass and the new round-trip is exercised end-to-end.
>
> Verify: `cargo test -p invariant-core --test proof_package_signed`,
> `cargo test`, `cargo clippy -- -D warnings`. Commit as
> `[gap-4] proof_package: Merkle root and signed manifest`.

---

# Prompt 5 — `invariant campaign assemble` CLI Subcommand

**Gap:** `spec-gaps.md §3.2`. The Rust API is wired but no CLI surface
exists. The registry at
[crates/invariant-cli/src/main.rs:23-72](../crates/invariant-cli/src/main.rs#L23-L72)
exposes 20 subcommands today; adding this brings it to 21.

> Read `crates/invariant-cli/src/main.rs` and
> `crates/invariant-cli/src/commands/campaign.rs`. Read
> `crates/invariant-cli/src/commands/verify_package.rs` for the matching
> CLI ergonomics.
>
> Extend the existing `Campaign` subcommand with an `Assemble` action (or
> add a new top-level `CampaignAssemble` subcommand if it produces a
> cleaner help surface — pick one and document the choice in the file
> header). Required flags:
>
> - `--shards <DIR>` — directory of per-shard audit JSONL + per-shard
>   summary JSON.
> - `--output <PATH>` — proof-package output directory.
> - `--key <PATH>` — Ed25519 signing key for the manifest (PEM or the
>   project's existing on-disk format; reuse `keys::load`).
>
> Behavior:
>
> - Validate inputs exist and are well-formed before doing any I/O on
>   `--output`.
> - Call `proof_package::assemble`.
> - Compute a roll-up Clopper-Pearson 99.9% CI per category (categories A–N
>   per `spec-15m-campaign.md §2.1`); emit
>   `results/per_category/ci.json`.
> - Emit profile fingerprints to `results/per_profile/fingerprints.json`
>   (SHA-256 of canonical profile JSON used in each shard).
> - Print a summary table to stdout.
>
> Add `crates/invariant-cli/tests/cli_assemble.rs`: build a 2-shard fixture
> on disk, run the subcommand via `assert_cmd`, then run `verify-package`
> against the output and assert success. Use `tempfile`.
>
> Update README.md and `docs/spec-15m-campaign.md §7 Step 6` to reference
> the new subcommand.
>
> Verify: `cargo test -p invariant-cli --test cli_assemble`,
> `cargo test`, `cargo clippy -- -D warnings`. Commit as
> `[gap-5] cli: campaign assemble subcommand`.

---

# Prompt 6 — Profile `end_effectors` Audit + `validate-profiles --strict`

**Gap:** `spec-gaps.md §4.2`. Nine profiles lack `end_effectors`; no strict
validator exists.

> Read `docs/spec-v1.md §1.1 lines 38–97` and any current profile JSON
> under `profiles/` (run `ls profiles/`).
>
> For the five locomotion-only profiles
> (`anybotics_anymal.json`, `quadruped_12dof.json`, `spot.json`,
> `unitree_a1.json`, `unitree_go2.json`), add:
>
> ```json
> "end_effectors": [],
> "platform_class": "locomotion-only"
> ```
>
> For `agility_digit.json`, add a real `end_effectors` block matching
> Digit's hands. If you do not have a defensible source for the limits,
> document the descope by setting `platform_class: "locomotion-only"` and
> `end_effectors: []`, and note in the file's `metadata.notes` that
> manipulation operations should be denied at the policy layer until the
> EE block lands.
>
> For the four adversarial profiles, add `"adversarial": true` to their
> top-level metadata. Confirm `adversarial_max_joints.json` and
> `adversarial_single_joint.json` carry an `environment` block; add one
> with conservative defaults if missing.
>
> Add a new CLI subcommand `validate-profiles` (registered alongside the
> 21 existing subcommands — count goes to 22 alongside the new
> `campaign assemble` from Prompt 5):
>
> - `invariant validate-profiles [--strict] [PATHS...]` — defaults to
>   `profiles/*.json`.
> - Without `--strict`: schema check only.
> - With `--strict`: also fails when a profile permits a manipulation
>   operation but declares no `end_effectors`, **unless** the profile
>   carries `"adversarial": true`.
>
> Add to `.github/workflows/ci.yml` a job step
> `cargo run -p invariant-cli -- validate-profiles --strict` so the gate
> is permanent.
>
> Add a test that loads every profile and asserts strict validation
> passes.
>
> Verify: `cargo run -p invariant-cli -- validate-profiles --strict`,
> `cargo test`, `cargo clippy -- -D warnings`. Commit as
> `[gap-6] profiles: end_effectors audit + validate-profiles --strict`.

---

# Prompt 7 — Split SR1 / SR2 Sensor-Range Checks

**Gap:** `spec-gaps.md §4.1`. SR1 (env-state range) and SR2 (payload range)
are merged into a single `check_sensor_range` at
[crates/invariant-core/src/physics/environment.rs:361-427](../crates/invariant-core/src/physics/environment.rs#L361-L427).

> Read `crates/invariant-core/src/physics/environment.rs` and the
> registration at `crates/invariant-core/src/physics/mod.rs:326`.
>
> Split the function into:
>
> - `check_sensor_range_env` — SR1, env-state values (battery, temperature,
>   IMU, latency).
> - `check_sensor_range_payload` — SR2, command payload numeric ranges
>   (positions, encoders, forces, etc.).
>
> Each returns its own `CheckResult` with distinct names
> (`"sensor_range_env"`, `"sensor_range_payload"`). Update the registration
> in `physics/mod.rs` and any callers/tests. Update the `compliance`
> subcommand to count both checks independently.
>
> Add tests asserting both checks fire on the inputs they cover and never
> the other. Update existing tests that depend on the merged name.
>
> Verify: `cargo test`, `cargo clippy -- -D warnings`. Commit as
> `[gap-7] physics: split SR1/SR2 sensor-range checks`.

---

# Prompt 8 — Eliminate Test/Subcommand/Scenario Count Drift

**Gap:** `spec-gaps.md §4.5`. README, CHANGELOG, spec-v2, and
public-release-polish all cite different test counts. None matches the
current 1 881 `#[test]` markers.

> Run `cargo test --workspace 2>&1 | tail -50` and capture the aggregate
> "test result: ok. N passed" lines. Sum N across all test binaries.
>
> Add a CI step in `.github/workflows/ci.yml` that runs the workspace
> tests, parses the per-binary `test result:` lines, sums the counts, and
> writes the total to `docs/test-count.txt` (single integer + trailing
> newline). Commit the file with the current accurate count. Add a CI
> guard that fails if the file would change vs `HEAD` so contributors
> regenerate it intentionally.
>
> Update README.md, CHANGELOG.md, `docs/spec-v2.md`, and
> `docs/public-release-polish.md` to reference `docs/test-count.txt`
> rather than hard-coded literals — wording like "see
> [docs/test-count.txt](docs/test-count.txt) for the current count".
>
> Update the subcommand count to 22 (post-Prompt 5 + Prompt 6) and the
> scenario count statements where they appear, but only after Prompt 14
> has landed; if Prompt 14 has not landed when this prompt runs, leave
> scenario counts alone and note the dependency in the commit message.
>
> Verify: `cargo test`, `cat docs/test-count.txt`. Commit as
> `[gap-8] docs: eliminate count drift via generated test-count.txt`.

---

# Prompt 9 — OS Keyring Backend (`os-keyring` feature)

**Gap:** `spec-gaps.md §2.1` (one of three). Stub at
[crates/invariant-core/src/keys.rs:436-444](../crates/invariant-core/src/keys.rs#L436-L444).

> Read `crates/invariant-core/src/keys.rs` (full file). Confirm the
> `KeyStore` trait surface and existing file-backed implementation.
>
> Add a Cargo feature `os-keyring` to `crates/invariant-core/Cargo.toml`
> gating the `keyring` crate. Implement `OsKeyringKeyStore` to:
>
> - Store Ed25519 private keys under service name
>   `"io.invariant-robotics.signing"` and account = key label.
> - Round-trip via the platform default backend (Keychain on macOS,
>   Secret Service on Linux, Credential Manager on Windows).
> - Surface platform errors as `KeyStoreError::Backend { source, hint }`
>   with a hint that mentions the platform.
>
> Update CLI `keygen --store=keyring` to select the backend at runtime;
> unknown `--store` values fail with a typed error before any I/O.
>
> Replace the stub test `open_key_store_stubs` (do not augment) with a
> feature-gated `#[cfg(feature = "os-keyring")]` integration test under
> `crates/invariant-core/tests/keyring.rs` that round-trips a generated
> key. Mark with `#[ignore]` if CI cannot provide a keychain; document the
> manual run command in the file header.
>
> Verify:
> `cargo build --features os-keyring -p invariant-core`,
> `cargo test --features os-keyring -p invariant-core`, default-feature
> build still passes (`cargo test -p invariant-core`),
> `cargo clippy --features os-keyring -- -D warnings`.
> Commit as `[gap-9] keys: os-keyring backend behind feature flag`.

---

# Prompt 10 — TPM Backend (`tpm` feature)

**Gap:** `spec-gaps.md §2.1` (two of three). Stub at
[crates/invariant-core/src/keys.rs:482-491](../crates/invariant-core/src/keys.rs#L482-L491).

> Read `crates/invariant-core/src/keys.rs` and the `os-keyring` work from
> Prompt 9 to mirror its style.
>
> Add a `tpm` feature gating `tss-esapi`. Implement `TpmKeyStore`:
>
> - Persistent keys under the owner hierarchy.
> - Key identification by label, mapped to a TPM handle the store
>   tracks in a small on-disk index (`~/.invariant/tpm-index.json`,
>   permissions 0600).
> - Sign/verify Ed25519 via the TPM where supported; fall back to a typed
>   `KeyStoreError::AlgorithmUnsupported` if the device doesn't support
>   ed25519 (do not silently substitute).
>
> Document attestation requirements in the module rustdoc; do not
> implement attestation in this prompt — call it out explicitly as
> follow-up scope.
>
> Replace the stub test with a feature-gated integration test that runs
> against `swtpm` if `INVARIANT_TPM_TEST=1` is set; otherwise `#[ignore]`.
> Document the `swtpm` setup in the test file header.
>
> Verify: default build still passes; `cargo build --features tpm
> -p invariant-core` succeeds on a Linux host (gracefully fail with a
> documented compile error on unsupported platforms).
> Commit as `[gap-10] keys: tpm backend behind feature flag`.

---

# Prompt 11 — YubiHSM Backend (`yubihsm` feature)

**Gap:** `spec-gaps.md §2.1` (three of three). Stub at
[crates/invariant-core/src/keys.rs:530-539](../crates/invariant-core/src/keys.rs#L530-L539).

> Mirror Prompts 9 and 10. Feature `yubihsm` gating the `yubihsm` crate.
> Auth via password-derived session; key handles persisted by label in
> the same on-disk index pattern.
>
> Replace the stub test with a feature-gated integration test that runs
> against the YubiHSM connector mock if available; otherwise `#[ignore]`
> with header docs explaining how to point at a real device via
> `YUBIHSM_CONNECTOR_URL`.
>
> Verify: default build unaffected; `cargo build --features yubihsm
> -p invariant-core` succeeds; clippy clean. Commit as
> `[gap-11] keys: yubihsm backend behind feature flag`.

---

# Prompt 12 — S3 Audit Replication (`replication-s3` feature)

**Gap:** `spec-gaps.md §2.2` (one of two). Stub at
[crates/invariant-core/src/replication.rs:257-259](../crates/invariant-core/src/replication.rs#L257-L259).

> Read `crates/invariant-core/src/replication.rs` (full file) and `audit.rs`.
>
> Add a `replication-s3` feature gating `aws-sdk-s3`. Implement
> `S3Replicator::push`:
>
> - Object naming: `{prefix}/{epoch_ms}-{seq}.jsonl`.
> - SSE-KMS via the configured KMS key ARN; refuse to push if the key is
>   not configured.
> - S3 Object Lock retention configured per `ReplicationConfig`.
> - Exponential backoff on `ThrottlingException`, capped retries, then
>   surface as `ReplicationError::Throttled { attempts }`.
> - On startup, list the bucket prefix and resume from the highest
>   replicated sequence.
>
> Add `WebhookWitness` POST handler (also part of §2.2):
>
> - On each Merkle-root rotation (Prompt 4), POST
>   `{root, count, signature}` JSON.
> - HMAC-SHA256 signature in `X-Invariant-Signature` header.
> - Bounded in-memory retry queue with disk spillover under the audit
>   directory; surface persistent failure (≥N consecutive attempts) as an
>   `incident::Incident`.
>
> Live test: behind `INVARIANT_REPL_TEST=1`, run against MinIO + a
> local webhook receiver, then chaos-restart the replicator process and
> assert no leaf is lost. Otherwise `#[ignore]`.
>
> Document RTO/RPO assumptions in the module rustdoc.
>
> Verify: default build unaffected; feature build + tests pass; clippy
> clean. Commit as
> `[gap-12] replication: s3 + webhook witness behind feature flag`.

---

# Prompt 13 — Alert Sinks (Webhook + Syslog)

**Gap:** `spec-gaps.md §2.3`. Stubs at
[crates/invariant-core/src/incident.rs:175-180](../crates/invariant-core/src/incident.rs#L175-L180)
and `:194-197`.

> Read `crates/invariant-core/src/incident.rs`.
>
> Implement `WebhookAlertSink`:
>
> - HMAC-SHA256 signed POST.
> - Bounded retry queue with disk spillover next to the audit log.
> - Configurable per-host concurrency cap; never block the validator hot
>   path — the sink runs on its own Tokio task.
>
> Implement `SyslogAlertSink`:
>
> - RFC 5424 over UDP and TCP+TLS (selectable via config).
> - Structured-data field carries verdict ID and severity per RFC 5424
>   section 6.3.
>
> Behind `INVARIANT_ALERT_TEST=1`, HIL test against an `rsyslog` container
> and a local HTTP receiver. Verify back-pressure on the sink does not
> increase validator latency by more than 5% under a 10 kHz validation
> load.
>
> Verify: default tests pass; clippy clean. Commit as
> `[gap-13] incident: webhook + syslog alert sinks`.

---

# Prompt 14 — Scenario Coverage Expansion (22 → 104)

**Gap:** `spec-gaps.md §3.3`. The scenario list in
`crates/invariant-sim/src/scenario.rs` carries 22 variants vs the 104 IDs in
[docs/spec-15m-campaign.md §3](spec-15m-campaign.md). This prompt is large
enough to warrant a sub-plan; the agent should checkpoint with a commit per
category.

> Read `crates/invariant-sim/src/scenario.rs`,
> `crates/invariant-sim/src/orchestrator.rs`,
> `crates/invariant-sim/src/injector.rs`, and the campaign spec
> `docs/spec-15m-campaign.md` lines 80–300.
>
> Add `pub fn all() -> &'static [ScenarioType]` and a stable
> `pub const SPEC_ID: &str` accessor on each variant so coverage tests can
> map back to the campaign spec IDs (A-01..N-10).
>
> Add `crates/invariant-sim/tests/scenario_coverage.rs` that asserts every
> ID in `docs/spec-15m-campaign.md §3` (extract via a small parser, or
> hard-code the list with a comment pointing at the section) has a
> corresponding `ScenarioType`. Run it; expect failures listing the gap.
>
> Implement the missing scenarios category-by-category, in the order
> listed in `spec-gaps.md §3.3` (table). For each category:
>
> 1. Add the scenario variants and their step generators to
>    `scenario.rs`.
> 2. Wire snake_case names into the dry-run parser.
> 3. Update `is_expected_reject` / `expected_reject_classification` for
>    new variants (pass / reject / mixed).
> 4. Run `cargo test -p invariant-sim` and `cargo clippy -- -D warnings`.
> 5. Commit as `[gap-14.<cat>] sim: implement Category <cat> scenarios`.
>
> If a scenario in the spec is not implementable in dry-run alone (e.g.
> Isaac-only humanoid push-recovery), implement a faithful stub that
> exercises the validator path and document the Isaac-side follow-up in
> `docs/spec-15m-campaign.md §7`.
>
> If after honest effort the count still cannot reach 104 (e.g. because a
> scenario duplicates another), amend the campaign spec downward to the
> achievable count and re-derive the §5 Clopper-Pearson CI numbers in the
> same commit. Do not silently leave the spec inconsistent.
>
> Final verification: scenario_coverage test passes; `cargo test`;
> `cargo clippy -- -D warnings`. Final commit as
> `[gap-14] sim: scenario coverage closure (22 → N)` with the actual N
> stated in the message.

---

# Prompt 15 — Isaac Lab Env Classes Per Profile Family

**Gap:** `spec-gaps.md §3.4`. `isaac/envs/` has only `cell_config.py` and
`cnc_tending.py`; the campaign claims coverage of all profile families.

> Read existing `isaac/envs/cell_config.py` and `cnc_tending.py` for the
> task API conventions. Read
> `crates/invariant-sim/src/isaac/bridge.rs` for the bridge protocol.
>
> Add one env class per profile family under `isaac/envs/`:
>
> - `arm.py` (UR/Franka/KUKA/ABB/Kinova family).
> - `humanoid.py` (Unitree H1/G1, Digit, generic 28-DOF).
> - `quadruped.py` (Spot, ANYmal, Unitree A1/Go2, generic 12-DOF).
> - `hand.py` (Shadow Hand and similar dexterous hands).
> - `mobile_base.py` (mobile bases for whole-body motion tests).
>
> Each implements `reset / step / observe`, publishes sensor payloads
> matching the Rust-side `SensorPayload` (verify by deserializing one
> payload back through the bridge in the smoke test), and accepts
> deterministic seeds.
>
> Add `isaac/run_campaign.py` headless driver:
>
> - Consumes a campaign config (the YAML produced by
>   `generate_15m_configs`).
> - Spawns the right env class per profile.
> - Emits per-episode JSON traces compatible with the proof-package
>   `assemble` step (Prompt 5).
>
> Add `isaac/tests/test_envs_smoke.py`: 1 000 Category-A episodes for
> one humanoid (`unitree_h1`) and one arm (`franka_panda`); zero
> validator errors; full audit JSONL emitted; trace files round-trip
> through `invariant verify-package`. Mark `@pytest.mark.skipif` when
> Isaac Lab is not installed; document the local dev setup in
> `docs/runpod-simulation-guide.md`.
>
> Verify: `pytest isaac/tests/test_envs_smoke.py` (or skip if Isaac
> unavailable, but the test must collect cleanly). Commit as
> `[gap-15] isaac: env classes per profile family + smoke test`.

---

# Prompt 16 — RunPod Preempt-Recovery + Cost Ceiling

**Gap:** `spec-gaps.md §3.5` (one of two).

> Read `scripts/run_15m_campaign.sh`, `scripts/runpod_setup.sh`, and
> `scripts/upload_results.py`.
>
> Extend `scripts/run_15m_campaign.sh` (or add `scripts/runpod_fanout.sh`
> as a thin orchestrator that calls it — pick one and document) with:
>
> - SIGTERM trap that flushes the in-progress shard summary, marks the
>   shard incomplete in a `status/` directory, and exits cleanly with code
>   0 so the supervisor can restart.
> - Idempotent resume: at startup, scan `status/` and skip shards already
>   marked complete.
> - `MAX_USD` environment variable: track elapsed runtime against the per-
>   GPU price published in `scripts/runpod_setup.sh`; abort cleanly when
>   the projected spend would exceed `MAX_USD`. Default unset = no cap.
> - Status file format documented in `scripts/README.md` (create it if
>   absent).
>
> Add a shell test under `scripts/tests/` (use `bats` if already in the
> repo, otherwise plain bash with `set -e`) that exercises the SIGTERM
> path on a 5-shard local fanout with a stub binary.
>
> Verify: run the new bash test locally. Commit as
> `[gap-16] scripts: preempt-recovery and cost ceiling`.

---

# Prompt 17 — Shadow-Deployment Runbook

**Gap:** `spec-gaps.md §3.5` (two of two). `docs/runpod-simulation-guide.md`
exists but is exploratory.

> Read `docs/runpod-simulation-guide.md` for tone and the campaign-spec
> §7 lines 425–432 for the deliverable shape.
>
> Create `docs/shadow-deployment.md` covering:
>
> - **Scope:** ≥100 robot-hours on a UR10e CNC cell (matches the existing
>   `ur10e_haas_cell` profile).
> - **Setup:** wiring the validator in shadow mode (no actuation
>   blocking, audit-only) — point at the `serve` subcommand and link to
>   the relevant config keys.
> - **Metrics collected:** validator p50/p95/p99 latency, rejection rate
>   per check, divergence between sim-predicted verdicts and observed
>   robot behavior.
> - **Divergence triage protocol:** triage table mapping divergence type
>   → owner → SLO for response.
> - **Sign-off criteria:** zero unexplained divergences for 100 robot-
>   hours; <0.1% latency p99 regression vs sim; explicit sign-off by
>   Safety + Engineering leads with a checklist.
>
> Cross-link from `docs/spec-15m-campaign.md §7 Step 7` and from
> `README.md`'s deployment section.
>
> Verify: `mdformat docs/shadow-deployment.md` (or whatever formatter
> the repo uses; check `Makefile` and `.pre-commit-config.yaml`).
> Commit as `[gap-17] docs: shadow-deployment runbook`.

---

# Prompt 18 — Fleet-Scale Coordinator Test + `fleet status` Subcommand

**Gap:** `spec-gaps.md §4.3`. Coordinator only proven pairwise.

> Read `crates/invariant-coordinator/src/lib.rs`, `monitor.rs`,
> `partition.rs`. Read `crates/invariant-cli/src/main.rs` to see where to
> register a new subcommand.
>
> Add `crates/invariant-coordinator/tests/fleet_10_robot.rs`: 8 arms +
> 2 mobile bases; 60 s of synthetic traffic from a deterministic seed.
> Assert:
>
> - Zero false positives (no near-miss flagged where positions remain
>   above the configured separation).
> - Zero missed near-misses against a hand-scripted close-approach event
>   embedded in the trace.
>
> Add CLI `invariant fleet status` reading the coordinator state via the
> existing in-memory monitor API (or via a status file if the monitor is
> per-process — match the existing pattern). Output: JSON summary of
> active robots, current separations, recent partitions.
>
> The subcommand registry now exposes 23 (post-Prompts 5, 6, 18). Update
> any spec that hard-codes a count after Prompt 8 has landed.
>
> Verify: `cargo test -p invariant-coordinator --test fleet_10_robot`;
> `cargo run -p invariant-cli -- fleet status` against a stub state.
> Commit as `[gap-18] coordinator: 10-robot fleet test + fleet status CLI`.

---

# Prompt 19 — Per-Connection Watchdog

**Gap:** `spec-gaps.md §4.4`. Single shared watchdog across bridge clients.

> Read `crates/invariant-sim/src/isaac/bridge.rs` (full file) — pay
> attention to the file-header comment that documents the limitation.
>
> Refactor the bridge to maintain a `HashMap<ClientId, WatchdogState>`,
> initialized on connection accept and torn down on disconnect. Each
> heartbeat updates only its client's entry. A timeout fires safe-stop
> for that client only.
>
> Alternative: if the simpler choice is to enforce single-client at the
> protocol layer, add `BridgeError::SecondClient` and reject subsequent
> connections with a typed error. Choose based on the existing serve-mode
> use cases — document the choice in the file header and remove the
> outdated comment.
>
> Add a test that opens two simulated connections, lets one go silent,
> and asserts only that one's watchdog fires.
>
> Verify: `cargo test -p invariant-sim`; `cargo clippy -- -D warnings`.
> Commit as `[gap-19] bridge: per-connection watchdog`.

---

# Prompt 20 — Lean Formal Status Reconciliation

**Gap:** `spec-gaps.md §5.1`. Lean is sketch + axioms, not proof; spec
overclaims.

> Read `formal/Invariant.lean` and the files under `formal/Invariant/`.
>
> Create `formal/README.md` with a table:
>
> | Theorem | Status | spec.md cross-ref | Notes |
> |---------|--------|--------------------|-------|
> | `safety_guarantee` | hypothesis-discharge | spec.md:799 | Composition not proven |
> | `monotonicity_transitive` | sorry | spec.md:802 | … |
> | `hash_collision_resistant` | axiom | spec.md:810 | Standard crypto axiom |
> | `pointInConvexPolygon` | axiom | … | Geometric primitive |
>
> Attempt to discharge `monotonicity_transitive` (`Authority.lean`
> ~L85–90) by direct induction on hop indices. If the proof is not
> tractable in this prompt's scope, descope the claim by renaming it to a
> conjecture and updating the README accordingly — do not leave a `sorry`
> with no documentation.
>
> Add a `lake build` step to `.github/workflows/ci.yml` as a
> `continue-on-error: true` job. The job's purpose is to detect breakage
> in the Lean spec, not to gate merges yet.
>
> Update `docs/spec.md §8` (the master safety theorem section, currently
> ~lines 799–831) to qualify "proves" as "specifies; mechanized proofs
> in progress (see `formal/README.md`)" until the master theorems land.
>
> Verify: `cd formal && lake build`; CI workflow lints. Commit as
> `[gap-20] formal: status table + lean CI job + spec wording fix`.

---

# Prompt 21 — SBOM and Reproducible Build in CI

**Gap:** `spec-gaps.md §5.2`.

> Read `.github/workflows/ci.yml` and `release.yml`. Read the `Dockerfile`.
>
> Add to `release.yml`:
>
> - Step `cargo install cyclonedx-cargo` (or pin via the CI action).
> - Step `cargo cyclonedx --format json --output sbom.cdx.json`.
> - Step that signs `sbom.cdx.json` with the release Ed25519 key and
>   uploads both files as release assets.
>
> Add `scripts/repro.sh` that:
>
> - Builds the release binary inside the repo's `Dockerfile` with
>   `--no-cache`.
> - Computes SHA-256 of the resulting binary.
> - Compares against `docs/repro-digest.txt` (commit the current digest).
> - Exits non-zero on mismatch.
>
> Add a `make repro` target invoking the script (create `Makefile` if
> absent — keep it minimal).
>
> Add a CI job in `ci.yml` that runs `scripts/repro.sh` on PRs that
> modify `Dockerfile`, `Cargo.lock`, or `rust-toolchain.toml`.
>
> Verify: `bash scripts/repro.sh` locally; `actionlint .github/workflows/*.yml`
> if available. Commit as `[gap-21] ci: SBOM + reproducible-build verify`.

---

# Prompt 22 — ROS2 Bindings Disposition

**Gap:** `spec-gaps.md §5.3`. `invariant-ros2/` is unreferenced.

> Inspect `invariant-ros2/` and `Cargo.toml` to confirm it's not a
> workspace member.
>
> Decide between two options based on whether the bindings still build:
>
> 1. **Wire in:** add `invariant-ros2` to `Cargo.toml` `members`, fix any
>    build breakage, add a smoke test asserting one publish/subscribe
>    round-trip against a `ros2_rust` mock node.
> 2. **Move to examples:** `git mv invariant-ros2 examples/ros2-bindings`;
>    add an `examples/ros2-bindings/README.md` qualifying the integration
>    as "example, unmaintained until milestone X"; update `README.md` to
>    match.
>
> Pick the option that takes less than half a day. Document the choice
> in the commit message.
>
> Verify: `cargo build --workspace`. Commit as
> `[gap-22] ros2: <wire-in|move to examples> per disposition`.

---

# Prompt 23 — Spec Consolidation

**Gap:** `spec-gaps.md §5.4`. Multiple specs claim to supersede each other.

> Run this prompt **last** — many earlier prompts edit `docs/spec.md` and
> `docs/spec-15m-campaign.md`.
>
> Move `docs/spec-v1.md`, `docs/spec-v2.md`, `docs/spec-v3.md` into
> `docs/history/`. Replace each with a one-line redirect at the original
> path:
>
> ```markdown
> > Superseded. See [docs/spec.md](spec.md). Historical version preserved at
> > [docs/history/spec-v1.md](history/spec-v1.md).
> ```
>
> `docs/spec.md` becomes the single live spec. `docs/spec-15m-campaign.md`
> stays as the campaign-specific addendum. `docs/spec-gaps.md` and this
> file (`docs/spec-v4.md`) may be deleted once every prompt above is
> landed and its acceptance test is green in CI — see the closure
> criterion in `spec-gaps.md §8`.
>
> Update README.md, CHANGELOG.md, and any other top-level pointers to
> reference `docs/spec.md` directly.
>
> Verify: `grep -r "spec-v[123]" docs/ README.md CHANGELOG.md` returns
> only the redirect lines. Commit as
> `[gap-23] docs: consolidate to single live spec`.

---

# 1. Closure Criterion

This document, like `spec-gaps.md`, may be deleted when **every** prompt
above is landed with its verification step green in CI, or has an explicit
descope decision logged in `docs/spec.md`. Partial completion is not
closure.

# 2. Notes on Sequencing

Prompts 1–8 are the highest-leverage and have no infra dependencies — run
them first in order. Prompts 9–13 (hardware-key and replication backends)
are independent and can be parallelized across separate branches if
multiple agents are available; each lands behind its own feature flag and
does not perturb the default build. Prompts 14–17 require Isaac Lab and
RunPod access. Prompt 23 must run last because it rewrites doc paths the
earlier prompts edit.
