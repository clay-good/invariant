% Invariant — Gap-Closure Execution Spec (Claude Code Prompts)
% Status: Draft
% Date: 2026-04-28
% Branch: codelicious/spec-spec-15m-campaign-part-2
% Companion to: `docs/spec-gaps.md` (the audit) and `docs/spec-15m-campaign.md` (the deliverable)

# 0. How to use this document

Each numbered step below is a **self-contained Claude Code prompt**. Copy a step
verbatim into a fresh Claude Code session (or paste it as the body of a task)
and let the agent implement it. Steps are ordered: every step assumes the
preceding steps have landed on `main`. Each step contains:

- **Goal** — what changes after the step lands.
- **Spec citations** — what's promised, where.
- **Code citations** — files to touch (verified against `HEAD` 2026-04-28).
- **Prompt** — the exact instructions to give Claude Code.
- **Done when** — verification checklist (tests + commands).

Conventions every prompt inherits (do not repeat in the per-step prompt unless
overridden):

- Read existing files before editing them.
- After every change run, in order: `cargo build`, `cargo test --workspace`,
  `cargo clippy --all-targets -- -D warnings`. All three must pass.
- One commit per step. Commit message format:
  `<crate>: <short imperative>` followed by a body that cites the spec section.
- Never push to `main`. Land via a PR titled `spec-v4 step N: <title>`.
- Do not introduce new external dependencies unless the prompt names them.
- Do not silently change public APIs — if a signature must change, list every
  caller updated in the commit body.
- If a prompt's "Done when" check fails, do not loosen the check; surface the
  failure and stop.

Background reading required before any step:
`docs/spec.md`, `docs/spec-15m-campaign.md`, `docs/spec-gaps.md`, `CLAUDE.md`.

---

# 1. Foundations (P1 — must land before proof package or serve hardening)

## Step 1.1 — Add PCA-to-PCA causal binding (A3 predecessor digest)

**Goal:** Hops in a PCA chain are cryptographically bound to their predecessor,
closing the cross-chain splice attack (campaign G-09).

**Spec citations:** `docs/spec.md:230-232`, `docs/spec.md:388-392` (PoC, A3);
`docs/spec-15m-campaign.md:179` (G-09 Cross-chain splice).

**Code citations:**
- `crates/invariant-core/src/authority/chain.rs:31` — `verify_chain` today
  enforces signatures, monotonic narrowing, and `p_0` immutability only.
- `crates/invariant-core/src/authority/mod.rs` — `Pca` struct lives here.
- `crates/invariant-core/src/authority/tests.rs` — add the new tests here.

**Prompt:**
> Implement causal binding between PCA hops. Open
> `crates/invariant-core/src/authority/mod.rs`, find the `Pca` struct, and add a
> field `predecessor_digest: [u8; 32]`. Hop 0's predecessor digest is the
> all-zero array (document this as the genesis convention in a one-line comment
> on the field). Define a helper `Pca::canonical_bytes(&self) -> Vec<u8>` that
> serializes the hop in a deterministic byte form (reuse the existing canonical
> encoding used by signing if one exists; if not, document the encoding inline
> and use it consistently). In `crates/invariant-core/src/authority/chain.rs`
> extend `verify_chain` so that for every `i >= 1`,
> `hops[i].predecessor_digest == sha256(hops[i-1].canonical_bytes())`; on
> mismatch return a new `ChainError::PredecessorMismatch { index: usize }`
> variant. Update every fixture, builder, and test that constructs a `Pca` to
> populate the new field — do not introduce a default `Option`. In
> `authority/tests.rs` add `g09_cross_chain_splice_rejected`: build two
> independently valid 3-hop chains sharing an issuer, splice hop 2 of chain B
> onto hop 1 of chain A, assert `verify_chain` returns
> `ChainError::PredecessorMismatch { index: 2 }`. Update CHANGELOG.md under an
> "Unreleased" heading.

**Done when:**
- `cargo test -p invariant-core authority::` shows the new test passing.
- `cargo test --workspace` is green.
- No `Option<[u8;32]>` introduced for the new field.
- `grep -rn "predecessor_digest" crates/invariant-core/src/` shows the field
  in struct, helper, verifier, and at least three test fixtures.

---

## Step 1.2 — Add execution-binding invariants B1–B4

**Goal:** Reject syntactically valid PCAs replayed across sessions, executors,
or outside the issuer's temporal window.

**Spec citations:** `docs/spec.md:394-403` (B1–B4 definitions),
`docs/spec.md:478` (planned `authority/binding.rs`).

**Code citations:**
- `crates/invariant-core/src/authority/` — module list (no `binding.rs` today).
- `crates/invariant-core/src/validator.rs:220, :300, :315` — partial sequence
  handling.
- `crates/invariant-cli/src/commands/serve.rs` — needs to plumb context.

**Prompt:**
> Create `crates/invariant-core/src/authority/binding.rs`. Define
> `pub struct ExecutionContext { session_id: [u8;16], executor_id: [u8;32], now_ms: u64, window_ms: u64 }`
> and `pub enum BindingError { Session, Sequence, TemporalWindow, Executor }`.
> Define `pub fn verify_execution_binding(cmd: &Command, ctx: &ExecutionContext, pca: &Pca) -> Result<(), BindingError>`
> covering: B1 session — `cmd.session_id == ctx.session_id`; B2 sequence —
> `cmd.sequence` strictly greater than the last seen for `(session_id, pca.p_0)`
> (track via a small in-memory map injected via parameter, not a global); B3
> temporal — `pca.issued_at_ms <= ctx.now_ms <= pca.issued_at_ms + ctx.window_ms`;
> B4 executor — `pca.executor_id == ctx.executor_id`. Wire it into the validator:
> add an `ExecutionContext` field to `ValidatorConfig` (or a new `ValidatorState`
> if more appropriate — read `validator.rs` first and pick the smallest change),
> call `verify_execution_binding` after `verify_chain`, surface `BindingError`
> as a typed `RejectReason`. Update `crates/invariant-cli/src/commands/serve.rs`
> to construct one `ExecutionContext` per accepted bridge connection. Add a new
> file `crates/invariant-core/tests/binding.rs` with eight tests: one positive
> and one hostile case per invariant B1–B4. Hostile cases must come from the
> attack catalog (replay across sessions, regression seq, future-dated, wrong
> executor). Update CHANGELOG.md.

**Done when:**
- `cargo test -p invariant-core --test binding` shows 8/8 passing.
- `serve` still starts (`cargo run -p invariant-cli -- serve --help`).
- `grep -rn "BindingError" crates/invariant-core/src/validator.rs` is non-empty.

---

## Step 1.3 — Add wildcard-exploitation tests (G-07)

**Goal:** Confirm `actuate:*` does not subsume `read:*` and that namespaced
wildcards do not leak across subsystems.

**Spec citations:** `docs/spec-15m-campaign.md:177` (G-07).

**Code citations:**
- `crates/invariant-core/src/authority/operations.rs:11-14` — wildcard
  semantics documented but no targeted test.
- `crates/invariant-core/src/authority/tests.rs` — add tests here.

**Prompt:**
> In `crates/invariant-core/src/authority/tests.rs`, add two tests:
> `g07_wildcard_actuate_does_not_cover_read` — issue a chain whose root grants
> `actuate:*`, attempt a command requesting `read:proprioception`; assert the
> chain verification rejects with the existing scope-mismatch error.
> `g07_move_namespace_wildcard_does_not_cross_subsystem` — issue a chain whose
> root grants `move:arm.*`, attempt `move:base.linear`; assert rejection. Reuse
> the existing chain builders; do not add new abstractions. If the current
> wildcard matcher in `operations.rs` accepts either case (i.e., the test
> initially fails with "approved"), fix the matcher in `operations.rs` and
> document the change in the commit body.

**Done when:**
- Both tests pass.
- `cargo clippy --all-targets -- -D warnings` is clean.

---

# 2. Proof Package End-to-End (P1 — campaign deliverable depends on this)

## Step 2.1 — Add SHA-256 Merkle tree over audit JSONL

**Goal:** Make per-leaf inclusion verifiable; produce
`audit/merkle_root.txt` as listed in the campaign artifact tree.

**Spec citations:** `docs/spec-15m-campaign.md:391-396` (audit/ tree),
`docs/spec.md:124` (hash-chained audit).

**Code citations:**
- `crates/invariant-core/src/proof_package.rs:328-343` — `assemble` exists.
- `crates/invariant-core/src/proof_package.rs:241` — manifest is unsigned,
  per-file SHA-256 only.
- `crates/invariant-core/src/audit.rs` — JSONL writer.

**Prompt:**
> Implement a binary SHA-256 Merkle tree over audit log JSONL entries. Add a
> new module `crates/invariant-core/src/merkle.rs` with: `MerkleTree::from_leaves(leaves: &[[u8;32]]) -> MerkleTree`,
> `tree.root() -> [u8;32]`, `tree.proof(index: usize) -> Vec<[u8;32]>`,
> `pub fn verify_proof(leaf: [u8;32], proof: &[[u8;32]], index: usize, root: [u8;32]) -> bool`.
> Use the convention: leaf hash = `sha256(0x00 || entry_bytes)`, internal node =
> `sha256(0x01 || left || right)`; if a level has an odd count, duplicate the
> last node. Wire it into `proof_package::assemble`: read each shard's audit
> JSONL, hash each line as a leaf, build one tree per shard plus a root-of-roots
> tree across shards, write `audit/merkle_root.txt` (hex), and add a
> `merkle_root: [u8;32]` field to the in-memory manifest. Extend
> `verify_package` (`crates/invariant-cli/src/commands/verify_package.rs`) to
> rebuild the tree and assert the recorded root matches. Add three tests:
> `merkle_single_leaf`, `merkle_odd_count_duplication`, `merkle_proof_round_trip`
> in the new module, plus extend the existing `proof_package` round-trip test
> to assert tree-root presence on a 2-shard fixture.

**Done when:**
- `cargo test -p invariant-core merkle::` passes.
- The proof_package round-trip test asserts a non-zero merkle root.
- `audit/merkle_root.txt` is produced for the test fixture.

---

## Step 2.2 — Sign the manifest

**Goal:** `manifest.json` is Ed25519-signed; `manifest.sig` is emitted; the
verifier rejects tampered manifests.

**Spec citations:** `docs/spec-15m-campaign.md:373` (signed manifest).

**Code citations:**
- `crates/invariant-core/src/proof_package.rs:241` — current "unsigned" comment.
- `crates/invariant-cli/src/commands/verify_package.rs:339-460` — round-trip
  test.

**Prompt:**
> Extend `proof_package::assemble` to accept a `signing_key: &SigningKey`
> argument (Ed25519, reusing the existing key types from `crates/invariant-core/src/keys.rs`).
> After the manifest JSON is finalized, compute `sig = sign(manifest_bytes)`,
> write it to `manifest.sig`. Update the comment at line 241 to reflect signed
> status. Extend `verify_package` to take a public key path, load the manifest,
> verify `manifest.sig`, and only after that proceed to digest/Merkle checks.
> If `--key` is omitted, refuse to verify and emit a typed error
> `VerifyError::UnsignedPackage` (do not fall back to digest-only verification
> silently). Update the existing round-trip test to sign with a generated key
> and verify with its public half. Update the CLI help text for both
> `verify-package` and (after Step 2.3 lands) `campaign assemble`.

**Done when:**
- Existing round-trip test passes with signing enabled.
- A new test `verify_package_rejects_tampered_manifest` flips one byte in
  `manifest.json` and asserts verification fails with a signature error.

---

## Step 2.3 — Add `invariant campaign assemble` CLI subcommand

**Goal:** End-users can assemble a proof package from a directory of shard
outputs without writing Rust.

**Spec citations:** `docs/spec-15m-campaign.md` §6 step 6, §7 step 6.

**Code citations:**
- `crates/invariant-cli/src/main.rs:23-72` — current 20 subcommands.
- `crates/invariant-cli/src/commands/campaign.rs:39` — only dry-run today.
- `crates/invariant-core/src/proof_package.rs` — API exists.

**Prompt:**
> Add an `assemble` subcommand under `campaign`. Edit
> `crates/invariant-cli/src/commands/campaign.rs` to introduce a new clap
> subcommand `Assemble { shards: PathBuf, output: PathBuf, key: PathBuf,
> public_key: Option<PathBuf> }`. The handler must: enumerate `shards/<id>/`
> directories, validate each contains `audit.jsonl` and `summary.json`, call
> `proof_package::assemble` with the loaded signing key, emit Clopper-Pearson
> 99.9% upper bounds per category to `results/per_category/<cat>.json` (use the
> existing statistics helper if one exists; otherwise add a small
> `clopper_pearson_upper(n: u64, k: u64, alpha: f64) -> f64` function in
> `invariant-core` and unit-test it against the four reference values from
> `docs/spec-15m-campaign.md:464-470`). Update `crates/invariant-cli/src/main.rs`
> to register the subcommand if it is a top-level (otherwise just confirm the
> nested registration). Add `crates/invariant-cli/tests/cli_assemble.rs` with a
> 2-shard fixture (use `tempfile`), invoke the subcommand via `Command::cargo_bin`,
> then invoke `verify-package` and assert success. Update README.md's subcommand
> list and bump the count from 20 to 21 in any spec/doc that mentions it
> (search: `rg -n "20 subcommands"`). Update CHANGELOG.md.

**Done when:**
- `cargo run -p invariant-cli -- campaign assemble --help` prints help.
- `cargo test -p invariant-cli --test cli_assemble` passes.
- `rg -n "20 subcommands"` returns zero hits, `rg -n "21 subcommands"` returns
  the updated locations.

---

# 3. Campaign Coverage (P1 — required for the 15M statistical claim)

These steps expand `ScenarioType` from the current ~28 variants up to the 104
IDs cited in the campaign spec. They are grouped to keep PRs reviewable and
each can be done in parallel after Steps 1–2.

## Step 3.1 — Add `Scenario::all()` enumerator + coverage test

**Goal:** A single source of truth that enumerates every scenario; CI fails if
any spec ID lacks a `ScenarioType`.

**Spec citations:** `docs/spec-15m-campaign.md:69` (104 IDs total).

**Code citations:**
- `crates/invariant-sim/src/scenario.rs:51` — `pub enum ScenarioType` (~28
  variants today; verify count when you start).

**Prompt:**
> In `crates/invariant-sim/src/scenario.rs`, add `impl ScenarioType { pub fn all() -> &'static [ScenarioType] { ... } }`
> listing every variant exactly once (no `Default`, no derived enumerator —
> explicit, so the compiler flags missing entries when variants are added).
> Add a `pub fn spec_id(&self) -> &'static str` returning the campaign-spec
> identifier (e.g. `ScenarioType::Baseline => "A-01"`). For variants that map
> to multiple IDs (e.g. compound scenarios), return the primary ID; document
> the mapping in a doc comment on the function. Create
> `crates/invariant-sim/tests/scenario_coverage.rs`: parse
> `docs/spec-15m-campaign.md` (read the file at runtime — it is workspace-local;
> use `env!("CARGO_MANIFEST_DIR")`) for every `^| <ID> |` table row, build the
> set of expected IDs, and assert that every ID is covered by `ScenarioType::all`.
> Until the remaining categories land (Steps 3.2–3.7), the test will fail —
> mark it `#[ignore]` with a comment naming the steps that will un-ignore it.
> File the failing IDs in the test's docstring so future steps know what's
> outstanding.

**Done when:**
- `cargo test -p invariant-sim` passes (the new test is `#[ignore]`d).
- Running `cargo test -p invariant-sim -- --ignored scenario_coverage` prints
  the exact list of missing IDs.

---

## Step 3.2 — Implement Category B (Joint Safety) scenarios

**Goal:** Add B-01..B-08 to `ScenarioType` with deterministic step generators.

**Spec citations:** `docs/spec-15m-campaign.md:96-105`.

**Prompt:**
> For each of B-01 Position boundary sweep, B-02 Velocity boundary sweep, B-03
> Torque boundary sweep, B-04 Acceleration ramp, B-05 Multi-joint coordinated,
> B-06 Rapid direction reversal, B-07 IEEE 754 special values, B-08 Gradual
> drift attack: add a `ScenarioType` variant; implement step generation in the
> existing dry-run loop in `crates/invariant-sim/src/scenario.rs` (read the
> Locomotion or Compound implementations as templates). Each scenario must be
> seedable, deterministic, and produce a clear "expected reject" classification
> (use the existing `is_expected_reject` mapping). Add one dry-run smoke test
> per scenario in the existing `dry_run_*` test family. Update
> `Scenario::all()`, `spec_id`, and the snake_case parser. Do NOT yet remove
> the `#[ignore]` on `scenario_coverage` — that happens after the last category
> lands (Step 3.7).

**Done when:**
- `cargo test -p invariant-sim` passes.
- `Scenario::all().len()` increased by exactly 8.

---

## Step 3.3 — Implement Categories C, D, E, F additions

**Goal:** Spatial, locomotion, manipulation, environmental scenarios.

**Spec citations:** `docs/spec-15m-campaign.md:113-163`.

**Prompt:**
> Implement the missing IDs:
> - C-01 workspace-boundary sweep, C-03 conditional-zone state machine,
>   C-04 self-collision approach, C-05 overlapping-zone, C-06 corrupt-spatial
>   data (5 new).
> - D-09 push recovery, D-10 incline walking (2 new).
> - E-01..E-06 entire manipulation category (6 new).
> - F-05..F-08 sensor/environmental scenarios (4 new).
> Same conventions as Step 3.2: `ScenarioType` variant, deterministic generator,
> dry-run smoke test, `Scenario::all`, `spec_id`, parser. Profile-applicability
> filtering must follow the existing locomotion-filter pattern in
> `campaign.rs::generate_15m_configs` — manipulation scenarios skip
> locomotion-only profiles, locomotion scenarios skip arm profiles.

**Done when:**
- `Scenario::all().len()` increased by exactly 17 vs end of Step 3.2.
- `cargo test --workspace` passes.

---

## Step 3.4 — Implement Category G (Authority) remaining scenarios

**Goal:** G-02 empty chain, G-03 forged sig, G-04 key substitution, G-05
escalation, G-06 provenance mutation, G-08 expired chain, G-09 splice, G-10
garbage COSE.

**Spec citations:** `docs/spec-15m-campaign.md:170-180`.

**Prompt:**
> Add scenario variants for G-02..G-06, G-08, G-09, G-10 (G-01 valid-chain
> already exercised by Baseline, G-07 covered by Step 1.3 unit tests but add a
> scenario shell that runs the same construction at simulation scale). Each
> generator must produce a `Pca` with the targeted defect and let the validator
> reject it; assert the rejection reason matches the table's "Expected" column.
> Use the existing `ChainForgery` and `AuthorityEscalation` variants as
> templates. Coordinate with Step 1.1 (predecessor digest) — G-09 depends on
> the field existing.

**Done when:**
- `Scenario::all().len()` increased by exactly 8 vs end of Step 3.3.
- For each new variant the dry-run smoke test asserts a non-zero rejection
  count.

---

## Step 3.5 — Implement Category H (Temporal & Sequence)

**Spec citations:** `docs/spec-15m-campaign.md:188-194`.

**Prompt:**
> Implement H-01 sequence replay, H-02 sequence regression, H-03 sequence gap
> (positive case), H-04 delta-time attack, H-05 stale command, H-06
> future-dated sensor. Coordinate with Step 1.2 — H-01 and H-02 should
> exercise the new B2 binding. Add scenario variants and dry-run smoke tests
> per the conventions of 3.2.

**Done when:**
- `Scenario::all().len()` increased by exactly 6 vs end of Step 3.4.

---

## Step 3.6 — Implement Category I (Cognitive Escape)

**Spec citations:** `docs/spec-15m-campaign.md:200-212`.

**Prompt:**
> Implement I-01 gradual drift, I-02 distraction flooding, I-03 semantic
> confusion, I-04 authority laundering, I-05 error mining, I-06 watchdog
> manipulation, I-07 profile probing, I-08 multi-agent collusion, I-09 timing
> exploitation, I-10 rollback replay. Several map onto existing primitives —
> I-01 reuses gradual-drift logic from Compound scenarios; I-06 reuses
> watchdog handling. Where a primitive exists, compose it; do not duplicate.
> Critical success criterion (`docs/spec-15m-campaign.md:212` — ZERO
> bypasses): every cognitive scenario's smoke test must assert the validator
> approval count for unauthorized operations is exactly 0.

**Done when:**
- `Scenario::all().len()` increased by exactly 10 vs end of Step 3.5.
- Every Category I smoke test asserts `bypasses == 0`.

---

## Step 3.7 — Implement Categories J, K, L, M, N remaining

**Spec citations:** `docs/spec-15m-campaign.md:218-282`.

**Prompt:**
> Implement: J-03, J-04, J-06, J-08 (4 compound); K-02, K-03, K-05, K-06 (4
> recovery); L-02, L-03 (2 long-running); M-01..M-06 (6 cross-platform stress);
> N-01..N-10 (10 red-team fuzz). For Category N, prefer driving the existing
> `invariant-fuzz` crate from the simulation harness rather than reimplementing
> mutators. After this step lands, remove the `#[ignore]` from
> `tests/scenario_coverage.rs` and assert `Scenario::all().len() == 104`.
> If the count differs from 104 because the spec table actually enumerates a
> different number, file the discrepancy in the commit body and update
> `docs/spec-15m-campaign.md §5.2` to match the achieved count — do NOT silently
> drop the assertion.

**Done when:**
- `cargo test -p invariant-sim --test scenario_coverage` passes (no `--ignored`).
- `Scenario::all().len()` matches the documented total.

---

# 4. Profile Coverage and Isaac Lab Envs

## Step 4.1 — Resolve "34 profiles" claim against ~17 registered

**Goal:** Either bring profile count to 34, or amend the spec down to the
actual deployable list with explicit rationale.

**Spec citations:** `docs/spec-15m-campaign.md:34, :289-307` (34 profiles, 30
real-world + 4 synthetic).

**Code citations:**
- `profiles/*.json` — current set.
- `crates/invariant-core/src/profile.rs` (or wherever profile registration
  happens — verify with `rg -n "fn builtin_profiles"`).

**Prompt:**
> Inventory `ls profiles/*.json` and the registered builtins. Count the real
> distinct profiles (excluding the four `adversarial_*`). If the count is below
> 30, propose the missing 30−N profiles by deriving from public URDFs/specs of
> robots already named in the campaign spec table at lines 289-303 (humanoids,
> arms, quadrupeds, hands). Add the missing profile JSONs under `profiles/`
> with full `joints`, `workspace`, `manipulation.end_effectors`, `environment`
> blocks. Register each in `builtin_profiles`. Add a smoke test that loads
> every builtin profile and validates a Baseline scenario for one episode each.
> If the missing profiles are not feasible to add (no public URDF, etc.), do
> NOT pad — instead amend `docs/spec-15m-campaign.md`: change "34 built-in
> profiles" to the achievable count, regenerate the §4 distribution table so
> weights still sum to 100%, and document each removal with a one-line
> rationale.

**Done when:**
- `rg -n "34 built-in profiles" docs/` is consistent with reality (either 34
  exist, or the doc is amended).
- New profile-loading smoke test passes for every registered builtin.

---

## Step 4.2 — Profile EE / platform_class hardening

**Goal:** Reject profiles that permit manipulation operations without an EE
declaration.

**Spec citations:** `docs/spec-v1.md §1.1` (profile schema requirements).

**Code citations:**
- `profiles/*.json` — nine profiles missing `end_effectors` per
  `spec-gaps.md §4.2`.
- No `validate-profiles` subcommand exists today
  (`rg -n "ValidateProfiles" crates/invariant-cli/src/`).

**Prompt:**
> Update the five locomotion-only profiles (`anybotics_anymal.json`,
> `quadruped_12dof.json`, `spot.json`, `unitree_a1.json`, `unitree_go2.json`)
> to add `"end_effectors": []` and `"platform_class": "locomotion-only"`. Add a
> real EE block to `agility_digit.json` (Digit has hands; check public URDF for
> reach/payload/force limits). For the four `adversarial_*` profiles, add a
> top-level `"adversarial": true` flag and add the missing `environment` block
> to the two that lack one (`adversarial_max_joints.json`,
> `adversarial_single_joint.json`). Add a new CLI subcommand
> `validate-profiles --strict` in `crates/invariant-cli/src/commands/`. Its
> handler must: load every profile, and for each one that permits a
> manipulation operation (check `operations.allowed` or equivalent) but
> declares no `end_effectors` AND lacks `"adversarial": true`, fail with
> exit code 2 listing the offending profile names. Wire it into `main.rs`.
> Add a CI step (`.github/workflows/ci.yml`) that runs `invariant
> validate-profiles --strict`. Update README and bump subcommand count.

**Done when:**
- `cargo run -p invariant-cli -- validate-profiles --strict` exits 0.
- Removing `end_effectors` from any non-adversarial manipulation-capable
  profile causes exit 2.
- CI workflow includes the new step.

---

## Step 4.3 — Isaac Lab env coverage per profile family

**Goal:** Five profile-family env classes plus a headless campaign runner.

**Spec citations:** `docs/spec-15m-campaign.md:34`, §3 lines 80-87.

**Code citations:**
- `isaac/envs/` — only `__init__.py`, `cell_config.py`, `cnc_tending.py` today.
- `crates/invariant-cli/src/commands/campaign.rs:24-35` — exits 2 saying "use
  Python runner".

**Prompt:**
> Create five env classes under `isaac/envs/`: `arm.py`, `humanoid.py`,
> `quadruped.py`, `hand.py`, `mobile_base.py`. Each must implement `reset(seed)`,
> `step(action)`, `observe() -> SensorPayload`-compatible dict; the observation
> format must match the existing schema consumed by the bridge in
> `crates/invariant-sim/src/isaac/bridge.rs`. Use the existing `cnc_tending.py`
> as the structural template — do not invent a new abstraction. Add
> `isaac/run_campaign.py` that takes `--config <yaml>` (the format produced by
> `campaign::generate_15m_configs::configs_to_yaml`), iterates episodes, and
> emits per-episode JSON traces to a directory layout compatible with `campaign
> assemble` (Step 2.3). Add `isaac/tests/test_envs_smoke.py`: 1000 Category-A
> episodes for one humanoid + one arm, asserting zero validator errors. Hook
> the smoke test into the existing Python CI job (commit `7a88217` added one;
> read `.github/workflows/ci.yml` to find it). Document required Isaac Lab
> version in `docs/runpod-simulation-guide.md`.

**Done when:**
- `python -m pytest isaac/tests/test_envs_smoke.py` passes locally given Isaac
  Lab is installed.
- The smoke test is invoked by CI (or skipped with a clear reason if Isaac is
  unavailable in CI).

---

# 5. Production Backends (P1, parallelizable)

## Step 5.1 — OS keyring backend

**Goal:** `OsKeyringKeyStore` actually persists keys via OS-native APIs.

**Spec citations:** `docs/spec.md:838`; spec-v3 hardening list.

**Code citations:** `crates/invariant-core/src/keys.rs:413, :436-444`.

**Prompt:**
> Add a Cargo feature `os-keyring` to `crates/invariant-core/Cargo.toml`,
> gating a new dependency on the `keyring` crate (current stable). Replace the
> `KeyStoreError::Unavailable` body of `OsKeyringKeyStore` methods with real
> implementations: store/load Ed25519 keys keyed by label under a service
> name `invariant`. Round-trip Ed25519 sign/verify in a feature-gated
> integration test under `crates/invariant-core/tests/keys_keyring.rs`
> (gate with `#[cfg(feature = "os-keyring")]`). Remove the stub-semantics
> portion of `open_key_store_stubs` for the keyring variant. Default workspace
> build does NOT enable the feature; document the opt-in in README.

**Done when:**
- `cargo test -p invariant-core --features os-keyring --test keys_keyring`
  passes on macOS or Linux Secret Service.
- Default `cargo test --workspace` still passes (feature off).

---

## Step 5.2 — TPM and YubiHSM backends

**Goal:** Same as 5.1 for `tpm` (via `tss-esapi`) and `yubihsm` features.

**Code citations:** `crates/invariant-core/src/keys.rs:462, :482-491, :510, :530-539`.

**Prompt:**
> Mirror Step 5.1 for two more features: `tpm` (depends on `tss-esapi`,
> persistent keys under owner hierarchy; document attestation as a separate
> follow-up) and `yubihsm` (depends on `yubihsm` crate, password-derived auth
> session). Each gets its own feature-gated integration test. Provide a
> `--store {file|keyring|tpm|yubihsm}` flag on `invariant keygen` (read
> `crates/invariant-cli/src/commands/keygen.rs`), failing fast with a typed
> error before any I/O when an unbuilt store is selected.

**Done when:**
- `cargo build -p invariant-core --features tpm` and `--features yubihsm`
  succeed on a workstation with the dev libraries installed.
- `invariant keygen --store tpm` on a build without the feature exits with a
  typed error (not a panic).

---

## Step 5.3 — S3 replication and webhook witness

**Goal:** Audit replication is live, not stubbed.

**Spec citations:** `docs/spec.md:124, :410-412` (L1–L4).

**Code citations:** `crates/invariant-core/src/replication.rs:257-259, :289-292`.

**Prompt:**
> Add features `replication-s3` (depends on `aws-sdk-s3`) and
> `replication-webhook` (depends on `reqwest` rustls-only, no openssl). Replace
> the `Unavailable` returns in `S3Replicator::push` and `WebhookWitness::push`
> with real implementations. S3 object naming: `{prefix}/{epoch_ms}-{seq}.jsonl`;
> require SSE-KMS and S3 Object Lock configured server-side (assert at startup
> via `head_bucket` + `get_object_lock_configuration`; refuse to start if
> retention is missing). Webhook: POST `{root, count, signature}` JSON on each
> Merkle-root rotation (rotation hook lives in the audit module — read it
> first); HMAC-SHA256 over the body, header `X-Invariant-Signature: sha256=...`;
> bounded retry queue with disk spillover under `<audit_dir>/replication-queue/`.
> Add MinIO and a stub HTTP receiver to `docker-compose.test.yml` (create if
> missing) and add an integration test that restarts the replicator mid-stream
> and asserts no entries are lost. Update `Dockerfile` to include
> `replication-s3` only when the build arg `INVARIANT_FEATURES` includes it.

**Done when:**
- Integration test green against MinIO.
- Bringing down and back up the receiver does not drop entries.

---

## Step 5.4 — Webhook + RFC 5424 syslog alert sinks

**Code citations:** `crates/invariant-core/src/incident.rs:175-180, :194-197`.

**Prompt:**
> Behind features `incident-webhook` and `incident-syslog`, replace the
> `Unavailable` returns. Webhook: HMAC-SHA256 signed POST, bounded retry queue
> with disk spillover, configurable per-host concurrency (default 4). Syslog:
> RFC 5424 over UDP and TCP+TLS (use `rustls`, no openssl), structured-data
> field `[invariant verdict_id="..." severity="..."]`. Critical: the sink runs
> on its own Tokio task — assert by integration test that a stalled receiver
> does not block the validator hot path (`validate()` latency p99 stays under
> 1ms with a black-holed sink). Test against an `rsyslog` container.

**Done when:**
- Latency-under-stalled-sink test passes.
- Both feature builds compile and link.

---

# 6. Silent Weaknesses (P2)

## Step 6.1 — Split SR1 / SR2 into separate checks

**Spec citations:** `docs/spec-v2.md:139-145`.
**Code citations:** `crates/invariant-core/src/physics/environment.rs:361-427`,
`crates/invariant-core/src/physics/mod.rs:326`.

**Prompt:**
> Split the single `check_sensor_range` (which covers both SR1 environment-state
> range and SR2 payload range) into two functions: `check_sensor_range_env`
> returning a `CheckResult` named `"sensor_range_env"` and
> `check_sensor_range_payload` returning `"sensor_range_payload"`. Update
> registration in `physics/mod.rs:326` and any pipeline that iterates checks.
> Update `crates/invariant-cli/src/commands/compliance.rs` to count them
> independently. Add one positive and one hostile test per split check. Update
> any spec/doc that enumerates check names.

**Done when:**
- `rg -n '"sensor_range"' crates/` returns no production hits (only test
  fixtures asserting both new names).
- `cargo test --workspace` passes.

---

## Step 6.2 — Per-connection bridge watchdog

**Spec citations:** `docs/spec.md:421-424` (W1), `:434` (per-cognitive-layer
heartbeat).
**Code citations:** `crates/invariant-sim/src/isaac/bridge.rs:13-16` (single
shared watchdog documented).

**Prompt:**
> Make the bridge watchdog per-connection. Read `bridge.rs` to understand the
> current shared-state shape. The simplest change is: move the `Watchdog`
> instance from a singleton into the per-connection task state, give each
> connection its own heartbeat counter, and let an unrelated stalled client
> only trigger safe-stop on its own connection. Alternative: enforce
> single-client at the listener and return a typed `BridgeError::SecondClient`
> on a second concurrent accept; pick whichever is structurally smaller — read
> the file first and document the choice in the commit body. Add a regression
> test that opens two connections, stops heartbeats on connection A, and
> asserts connection B remains live.

**Done when:**
- New test passes.
- The header comment at line 13-16 is updated to reflect the new behavior.

---

## Step 6.3 — Multi-robot fleet test + `fleet status` subcommand

**Spec citations:** `docs/spec.md:534-538`.
**Code citations:** `crates/invariant-coordinator/src/{lib,monitor,partition}.rs`;
no `fleet` subcommand today.

**Prompt:**
> Add `crates/invariant-coordinator/tests/fleet_10_robot.rs`: 8 arms + 2 mobile
> bases, 60 seconds of synthetic traffic, scripted near-miss event. Assert zero
> false positives and zero missed near-misses. Add `invariant fleet status`
> subcommand that reads coordinator state (introduce a JSON state-export
> function in `invariant-coordinator` if none exists) and prints a tabular
> summary. Wire into `main.rs`; bump documented subcommand count.

**Done when:**
- New integration test passes.
- `invariant fleet status --help` works.

---

## Step 6.4 — Eliminate doc-count drift

**Spec citations:** README.md:392, CHANGELOG.md:63, spec-v2.md:307,
public-release-polish.md.

**Prompt:**
> Add a CI step that runs `cargo test --workspace 2>&1 | tee /tmp/tests.txt`
> and extracts the totals into `docs/test-count.txt` (committed). Replace
> hard-coded test-count literals in README.md, CHANGELOG.md, spec-v2.md, and
> public-release-polish.md with a one-line "see `docs/test-count.txt`"
> reference (or, for narrative prose, with the literal that matches reality at
> commit time plus a `<!-- generated: do not edit -->` comment that points to a
> regen script). Also normalize subcommand-count references and scenario-count
> references using the same pattern.

**Done when:**
- `rg -n "[12][0-9]{3} tests" README.md docs/` returns only references that
  match `docs/test-count.txt`.
- CI publishes the file.

---

# 7. Operational Hardening for the 15M Campaign

## Step 7.1 — Preempt-recovery + cost ceiling for RunPod fan-out

**Spec citations:** `docs/spec-15m-campaign.md §7` step 5.
**Code citations:** `scripts/run_15m_campaign.sh`, `scripts/runpod_setup.sh`,
`scripts/upload_results.py`.

**Prompt:**
> Extend `scripts/run_15m_campaign.sh` (or add `scripts/runpod_fanout.sh` —
> read the existing script first and choose). Required additions: SIGTERM trap
> that flushes the in-progress shard summary to disk; a per-shard
> `completed.marker` file used to skip on resume; a `MAX_USD` env var that
> aborts the run cleanly when the running cost estimate exceeds the cap (cost
> derived from elapsed wall time × per-GPU rate × GPU count, all configurable).
> Add a dry-run mode (`--dry-run`) that prints the planned shard list and
> exits. Add `scripts/tests/test_runpod_fanout.bats` (or a `pytest` if bats is
> not in the repo) verifying SIGTERM behavior with a fake worker.

**Done when:**
- Sending SIGTERM mid-run leaves recoverable state.
- `MAX_USD=0.01 ./scripts/run_15m_campaign.sh` aborts before significant work.

---

## Step 7.2 — Shadow deployment runbook

**Spec citations:** `docs/spec-15m-campaign.md §7` step 7.

**Prompt:**
> Create `docs/shadow-deployment.md`: target ≥100 robot-hours on a UR10e CNC
> cell; required metrics (commands/sec, p50/p99 latency, divergence rate
> sim-vs-real, near-miss count); divergence-triage protocol (rules for
> distinguishing physics-model error vs validator error vs sensor noise);
> sign-off criteria (zero unexplained divergences in the last 24 hours; p99
> latency under 1ms continuously). The doc must be operational, not
> exploratory — it should read as a runbook, not a brainstorm. Reference
> `docs/runpod-simulation-guide.md` for sim-side setup but make this doc
> stand on its own for the hardware deployment phase.

**Done when:**
- `docs/shadow-deployment.md` exists and passes a markdownlint pass.

---

# 8. Polish and Release Hygiene (P3)

## Step 8.1 — Lean formalization honesty

**Spec citations:** `docs/spec.md:799-831` (master safety theorem).
**Code citations:** `formal/Invariant.lean:54-63`, `formal/Invariant/Authority.lean`
(`sorry` at ~L85), `formal/Invariant/Audit.lean:82` (axiom),
`formal/Invariant/Physics.lean:132` (axiom).

**Prompt:**
> Create `formal/README.md` listing every theorem, its status
> (`proved | sorry | axiom`), and a cross-reference to the corresponding
> `docs/spec.md` line. Either close the `sorry` in `Authority.lean`
> (`monotonicity_transitive`) or descope the claim with a comment citing the
> reason. Add a non-blocking `lake build` job to `.github/workflows/ci.yml`
> (allow-failure: true). Until the master safety and confused-deputy theorems
> are closed, edit `docs/spec.md §8` to change "proves" wording to "specifies;
> mechanized proofs in progress" — preserve the theorem statements.

**Done when:**
- `formal/README.md` exists and is accurate.
- `lake build` runs in CI (failure does not block).
- Spec wording reflects actual proof status.

---

## Step 8.2 — SBOM and reproducible build

**Prompt:**
> Add a `cargo cyclonedx` step to `.github/workflows/release.yml`. Sign the
> generated SBOM with the existing release Ed25519 key, attach as a release
> asset. Add `scripts/repro.sh` that builds inside the published `Dockerfile`
> and asserts the resulting binary's SHA-256 matches a value committed to
> `docs/repro-digest.txt`; provide a small make-equivalent target description
> in `CONTRIBUTING.md`. The first commit lands the script and a placeholder
> digest; the second commit (after one CI run) updates the digest.

**Done when:**
- Release workflow attaches `sbom.cdx.json` and `sbom.cdx.json.sig`.
- `bash scripts/repro.sh` exits 0 in a clean Docker context.

---

## Step 8.3 — Decide ROS2 bindings status

**Code citations:** `invariant-ros2/` exists at repo root but is not in
`Cargo.toml`'s workspace.

**Prompt:**
> Read `invariant-ros2/`. Decide one of two paths and execute it:
> (a) Add it to the workspace `Cargo.toml`; add a smoke test (publish/subscribe
> a fake topic, validate one command, assert verdict signed); add a CI job
> guarded by ROS2 availability.
> (b) Move the directory to `examples/ros2-integration/` and update README.md's
> integrations list to read "example integration, unmaintained until milestone
> X" with a concrete milestone reference.
> Document the decision and rationale in the commit body.

**Done when:**
- Either workspace builds with `invariant-ros2` as a member, or
  `examples/ros2-integration/` exists and README is updated. Both states are
  acceptable; ambiguity is not.

---

## Step 8.4 — Spec consolidation

**Code citations:** `docs/spec.md` (864 L), `spec-v1.md` (1348), `spec-v2.md`
(420), `spec-v3.md` (437), `spec-15m-campaign.md` (474), `spec-gaps.md` (561),
`spec-v4.md` (this doc), `public-release-polish.md` (64).

**Prompt:**
> Move `docs/spec-v1.md`, `docs/spec-v2.md`, `docs/spec-v3.md` to
> `docs/history/`. Replace each moved file at its old path with a stub
> containing only `# Moved` and a one-line redirect to `docs/spec.md`. Resolve
> the contradiction at `spec.md:1-5` and `spec-v2.md:1-9` (both claim to
> supersede prior specs): `spec.md` becomes the single live spec. Once every
> step in this document (`spec-v4.md`) is landed AND `spec-gaps.md`'s closure
> criterion (§8) is met, delete both `spec-gaps.md` and `spec-v4.md` in a
> separate commit titled `docs: retire gap-closure specs`. `spec-15m-campaign.md`
> remains as the campaign addendum.

**Done when:**
- `ls docs/*.md` shows only: `spec.md`, `spec-15m-campaign.md`,
  `public-release-polish.md`, `runpod-simulation-guide.md`,
  `shadow-deployment.md`, `test-count.txt`, plus the v1/v2/v3 stubs.
- `docs/history/` contains the originals.

---

# 9. Cross-Cutting Acceptance Tests (must all pass after Step 8.4)

These tests exist as steps above; this section is the consolidated checklist a
reviewer can run to verify closure:

1. `cargo test -p invariant-core --test binding` (Step 1.2).
2. `cargo test -p invariant-core authority::g09_cross_chain_splice_rejected`
   (Step 1.1).
3. `cargo test -p invariant-core --test proof_package` round-trip with Merkle
   root and signature (Steps 2.1–2.2).
4. `cargo test -p invariant-sim --test scenario_coverage` (no `--ignored`)
   (Step 3.7).
5. `cargo test -p invariant-coordinator --test fleet_10_robot` (Step 6.3).
6. `cargo test -p invariant-cli --test cli_assemble` (Step 2.3).
7. `python -m pytest isaac/tests/test_envs_smoke.py` (Step 4.3).
8. `cargo test --workspace --all-features` clean.
9. `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
10. `invariant validate-profiles --strict` exits 0 against every committed
    profile (Step 4.2).

---

# 10. Closure

This document may be deleted (alongside `spec-gaps.md`) when every step in
sections 1–8 has either landed with its acceptance test passing in CI, or has
an explicit decision logged in `docs/spec.md` to descope, with rationale.
Partial completion is not closure.
