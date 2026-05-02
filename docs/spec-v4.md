# spec-v4.md — Gap-Fix Plan

A sequenced set of Claude Code prompts to close gaps identified between
`docs/spec-15m-campaign.md`, `docs/spec.md` (and v1–v3), and the current
state of `crates/`. Each section below is meant to be pasted (or
paraphrased) as a prompt for a single Claude Code session. Sections are
ordered so earlier work unblocks later work — execute roughly top-to-bottom,
but P0/P1 items are independently valuable.

## How to use this document

Each task block has:

- **Goal** — one sentence describing the target end state.
- **Context** — what to read first.
- **Prompt** — the natural-language instruction to give Claude Code.
- **Done when** — observable acceptance criteria.

Do not paste code. The prompts deliberately describe outcomes and
constraints so the implementing session designs the code to match the
existing conventions of the crate it touches.

---

## Phase 0 — Reconcile spec set and vocabulary

### Task 0.1 — Restore or supersede missing spec versions  *(P0)*

**Goal.** Resolve the broken reference chain where `spec-v4.md`..`spec-v11.md`
and `spec-gaps.md` are cited by tooling and prior work but do not exist on
disk in this worktree (only `spec.md`, `spec-v1.md`..`spec-v3.md`, and
`spec-15m-campaign.md` are present).

**Context.** `git log --all -- docs/spec-v*.md` and `git log --all -- docs/spec-gaps.md`
will show whether these files lived on another branch and were dropped, or
were never committed. The branch label in environment context (`part-4`)
also disagrees with the actual branch (`part-2`).

**Prompt.**
> Investigate what happened to `docs/spec-v4.md`..`docs/spec-v11.md` and
> `docs/spec-gaps.md`. Check `git log --all`, `git reflog`, and any other
> branches/worktrees. If the files exist elsewhere, decide with the user
> whether to (a) cherry-pick them onto this branch, (b) declare this
> `spec-v4.md` the canonical successor and add a one-paragraph "Spec
> lineage" section to `spec.md` documenting that v2/v3 were the last
> shared specs and `spec-15m-campaign.md` + `spec-v4.md` supersede the
> intervening drafts, or (c) re-derive the missing content from commit
> messages. Do not silently leave dangling references.

**Done when.** `docs/` either contains the full sequence v1..v_latest with
no missing versions, or `spec.md` documents the gap explicitly with
rationale.

---

### Task 0.2 — Unify "PIC" vs "PCA" provenance vocabulary  *(P2)*

**Goal.** A single name for the authority/provenance chain across spec and
code.

**Context.** `CLAUDE.md` and `crates/invariant-core/src/authority/` use
**PIC** (Provenance & Integrity Chain). `spec-15m-campaign.md` §3 Category G
(G-02 "Empty PCA chain", G-06 "Provenance mutation — p_0 changed") and
parts of Category I use **PCA**. The `p_0` notation also implies an older
provenance model.

**Prompt.**
> Read `CLAUDE.md`, the `authority` module in `invariant-core`, and the
> commit history of authority-related commits. Decide whether "PCA" in
> `spec-15m-campaign.md` is the same chain as "PIC" or a separate concept.
> If it is the same: rewrite all "PCA" references in the spec to "PIC",
> and replace `p_0` notation with whatever symbol the code uses for the
> root provenance entry. If it is genuinely different (e.g. PCA was a
> predecessor design), add a paragraph in `spec.md` describing the
> rename and update the spec accordingly.

**Done when.** `grep -ri pca docs/ crates/` returns no hits except in a
historical/lineage note.

---

## Phase 1 — Scenario coverage (the central campaign gap)

The 15M-episode campaign promises 104 distinct scenarios across 14
categories (A–N). Today the code defines 22 `ScenarioType` variants and
typed scenario submodules only for Category B. Phases 1.1–1.4 close this.

### Task 1.1 — Expand `ScenarioType` to cover all 104 spec scenarios  *(P0)*

**Goal.** Every numbered scenario in `spec-15m-campaign.md` §3 (A-01 …
N-10) is reachable from `crates/invariant-sim/src/scenario.rs`, either as
its own `ScenarioType` variant or as a parameterized variant whose
parameters distinguish it.

**Context.** Read `crates/invariant-sim/src/scenario.rs` (the existing 22
variants), `crates/invariant-sim/src/campaign.rs` (`all_scenario_entries`,
`ScenarioCategory`, and `joint_safety` submodule for the pattern to
mirror), and §3 of the campaign spec end-to-end before designing.

**Prompt.**
> Design a scenario catalog that spans every numbered entry in
> `spec-15m-campaign.md` §3 Categories A–N. Prefer a parameterized
> approach where natural (e.g. one `BoundarySweep` variant carrying a
> `BoundaryAxis` parameter for B-01 vs B-02 vs B-03) and explicit
> variants where the behavior is genuinely distinct (e.g. cognitive
> escapes I-01..I-10). Each spec ID must round-trip to exactly one
> `(ScenarioType, params)` pair via a new `from_spec_id` and `spec_id`
> pair of methods. Keep backwards compatibility for the 22 existing
> variants by mapping them to their canonical spec IDs. Add a unit test
> that asserts every ID listed in §3 resolves and that `spec_id` ∘
> `from_spec_id` is the identity for all 104.

**Done when.**
- A test enumerates all 104 IDs from the spec and round-trips them.
- `cargo test -p invariant-sim` passes.
- `cargo clippy -- -D warnings` is clean.

---

### Task 1.2 — Add typed scenario submodules for Categories A and C–N  *(P1)*

**Goal.** Each category mirrors the structure of `joint_safety` (Category B):
a submodule with an enum, `id`, `episodes`, `expected_verdict`,
`invariants_tested`, and `scenario_type_name`.

**Prompt.**
> Using `crates/invariant-sim/src/campaign.rs::joint_safety` as the
> reference pattern, add 13 sibling submodules: `normal_operation` (A),
> `spatial_safety` (C), `stability_locomotion` (D),
> `manipulation_safety` (E), `environmental_hazards` (F),
> `authority_crypto` (G), `temporal_sequence` (H), `cognitive_escape` (I),
> `multi_step_compound` (J), `recovery_resilience` (K),
> `long_running_stability` (L), `cross_platform_stress` (M),
> `adversarial_red_team` (N). For each: enumerate the spec scenarios
> verbatim, populate `episodes` from §3's per-scenario allocations,
> set `expected_verdict` per the spec's "Expected Result" column,
> and reference invariants from `invariant-core`. Per-category episode
> totals must match §2.1 exactly. Add a test per submodule that sums
> episodes and asserts the category total.

**Done when.** Sum of per-scenario episodes per category matches §2.1's
totals; sum across all 14 categories equals 15,000,000.

---

### Task 1.3 — Per-scenario step counts  *(P1)*

**Goal.** Step count per episode is keyed by spec scenario ID, not by a
generic type bucket.

**Context.** `campaign.rs::scenario_step_count` currently returns a
fixed-by-type count, missing scenario-specific values like A-04 walking
gait = 1000 steps.

**Prompt.**
> Replace `scenario_step_count(scenario_type)` with a function that takes
> a spec scenario ID (or the new `(ScenarioType, params)` pair) and
> returns the per-spec step count from §3's "Steps" column. Provide a
> test that walks every scenario and asserts the step count matches a
> hand-transcribed table copied from §3.

**Done when.** All 104 scenarios produce the spec's step counts; legacy
default (200) is no longer reachable.

---

### Task 1.4 — Reconcile Category A scenario count  *(P1)*

**Goal.** Resolve internal contradiction: §2.1 lists A=6, but §3's
Category A detail table lists A-01..A-08 (eight entries).

**Prompt.**
> Read `spec-15m-campaign.md` §2.1 and §3 Category A. Decide with the
> user which is canonical — six scenarios or eight. Update both the spec
> table and `ScenarioCategory.scenarios()` to agree. If the answer is 8,
> update the campaign total from 15,000,000 to whatever sum results, and
> propagate to all downstream tests, success-criteria assertions, and
> doc strings that mention the total.

**Done when.** §2.1 row A, §3 detail table, and `ScenarioCategory`
metadata all agree; campaign total recomputed.

---

## Phase 2 — Profile distribution and counts

### Task 2.1 — Reconcile profile count: 13 vs 30 real-world  *(P1)*

**Goal.** Spec and code agree on how many real-world profiles exist and
how the 15M episodes distribute across them.

**Context.** §1.1 says "30 real-world + 4 synthetic". §4 and §5.2 say
"13 + 4 synthetic". `BUILTIN_NAMES` in
`crates/invariant-core/src/profiles.rs` lists 34 (= 30 + 4) and
`execution_target::PROFILE_COUNT = 34`.

**Prompt.**
> Read `spec-15m-campaign.md` §1.1, §4 (the 13-row profile distribution
> table), §5.2, and `BUILTIN_NAMES` in `invariant-core`. Confirm with
> the user whether the canonical answer is 30 real-world profiles or 13.
> If 30: rewrite §4's distribution table to enumerate all 30 with
> per-profile weights summing to 92% (synthetic 8% unchanged), and
> rewrite §5.2's "Robot profiles tested" row. If 13: trim
> `BUILTIN_NAMES` and update `PROFILE_COUNT`, and remove the now-orphaned
> profile JSONs from `profiles/`. Either way, ensure `generate_15m_configs`'s
> per-profile allocations sum to the same 15M total used in §2.1.

**Done when.** Profile count is single-sourced; all spec rows and code
constants agree.

---

### Task 2.2 — Derive `has_locomotion` from profile data  *(P2)*

**Goal.** Stop hard-coding which profiles are legged in
`generate_15m_configs`.

**Prompt.**
> Replace the hard-coded `has_locomotion: bool` per-profile list in
> `crates/invariant-sim/src/campaign.rs` (~lines 1141–1320) with a
> derivation from `RobotProfile::load_builtin(name).locomotion.is_some()`.
> Add a test that asserts no static list of legged profiles exists in
> `campaign.rs`. If a profile's `locomotion` field needs to be added or
> corrected to make this work, do so under `profiles/` and update any
> profile-shape tests.

**Done when.** Adding a new legged profile JSON automatically routes
Category D scenarios to it without touching `campaign.rs`.

---

### Task 2.3 — Validate the 256-DOF synthetic adversarial profile  *(P2)*

**Goal.** Confirm `adversarial_max_joints.json` actually loads and is
exercised, given any DoS-cap on joint count in the validator.

**Prompt.**
> Locate the joint-count DoS cap in `crates/invariant-core/src/models/profile.rs`
> (or wherever `RobotProfile::validate` lives). Confirm it permits the
> 256-DOF synthetic adversarial profile, and that the validator's per-step
> latency on a 256-DOF command stays under the §5.1 budgets (p99 < 1ms).
> If either fails, propose a remediation to the user — raise the cap,
> downsize the synthetic profile, or relax the budget for synthetic
> profiles only.

**Done when.** A test loads `adversarial_max_joints` and runs one
representative command through the validator within budget.

---

## Phase 3 — Determinism, signing, and proof package

### Task 3.1 — Per-episode signed verdict chain  *(P1)*

**Goal.** Each episode emits one Ed25519 signature over a chain hash, per
§1.2 ("Signed verdict chain — hash-linked, Ed25519 signed").

**Context.** Today `AuditLogger` signs every entry; the per-episode
signature fields on `EpisodeOutput` (`verdict_chain_hash`,
`verdict_chain_signature`, `signer_kid`) are declared but never populated.

**Prompt.**
> Design and implement an episode finalize step. Take the ordered list of
> `AuditEntry` records produced during one episode, compute a chain hash
> (last-entry hash if the chain is already linked, otherwise a Merkle
> root over entry hashes — pick whichever the existing `AuditLogger`
> already produces and reuse it), sign that hash with Ed25519 using the
> session signer key, and populate the three fields on `EpisodeOutput`.
> Per-entry signatures should become optional, off by default for the
> 15M campaign (cite the size budget in §1.2 as justification). Add a
> test that runs a 100-step episode, verifies the chain hash equals an
> independent recomputation, and verifies the signature against the
> public key. Update the size estimate comment in `data_outputs` to
> reflect the new bytes/step number.

**Done when.** A `verify_episode(episode_output, public_key) -> bool`
function exists and passes for happy-path output, fails on tampered
audit entries.

---

### Task 3.2 — Add `replay` subcommand  *(P1)*

**Goal.** Prove the §5.1 row 4 claim ("any episode reproducible from
seed with bit-identical results") with a CLI tool.

**Prompt.**
> Add an `invariant campaign replay --seed <u64> --profile <name>
> --scenario <spec-id> [--params ...] [--expected-chain-hash <hex>]`
> subcommand to `invariant-cli`. It loads the same profile, runs the
> same scenario with the same seed, computes the verdict chain hash,
> and exits non-zero on mismatch. Add an integration test that runs an
> arbitrary episode, captures its `EpisodeOutput`, then invokes the
> replay path and asserts equality. Document any sources of
> nondeterminism currently in the simulator (timer reads, HashMap
> iteration order, parallelism) and either eliminate them or assert
> they are absent.

**Done when.** Two consecutive runs produce identical `verdict_chain_hash`
for any (seed, profile, scenario, params).

---

### Task 3.3 — Latency distribution capture and gating  *(P1)*

**Goal.** Campaign emits `latency_distribution.json` and gates pass/fail
on §5.1 rows 6–7 (p99 < 1ms, p99.9 < 2ms).

**Prompt.**
> Add per-step latency capture (use an HDR histogram crate, e.g. `hdrhistogram`,
> or a simple log-bucket sketch — pick whatever is already in `Cargo.lock`
> if present) inside `crates/invariant-sim/src/collector.rs`. Aggregate
> across the campaign in `reporter.rs` and serialize p50/p95/p99/p99.9/max
> to `latency_distribution.json` matching the proof-package layout in §6.
> The campaign exit code should be non-zero if p99 ≥ 1ms or p99.9 ≥ 2ms.
> Make the per-step capture compile out (or runtime-disable) for short
> dev runs to avoid measurement overhead distorting micro-benchmarks.
> Add a test that injects synthetic latencies and asserts the percentile
> calculations.

**Done when.** A small (10K-episode) dry run produces a valid latency
JSON file with all five percentile fields and a pass/fail gate.

---

### Task 3.4 — Proof-package layout matches §6  *(P1)*

**Goal.** `proof_package::assemble` produces every directory and file
named in §6 of the campaign spec.

**Prompt.**
> Read `crates/invariant-core/src/proof_package.rs` and §6 of
> `spec-15m-campaign.md` together. Extend `assemble` (and any helper
> structs) to produce: `results/per_category/`,
> `results/per_profile/`, `results/per_check/`,
> `results/latency_distribution.json` (from Task 3.3),
> `adversarial/{protocol,authority,cognitive,compound,total_bypass}_*.json`,
> `audit/chain_verification.json`, `audit/merkle_root.txt`,
> `audit/sample_entries/` (random-sample N entries with their
> verification status), `integrity/all_seeds.json.gz`,
> `integrity/shard_checksums.json`,
> `compliance/{iec_61508,iso_10218,iso_ts_15066,nist_ai_600_1}_mapping.md`.
> Each output is sourced from already-collected campaign data; no
> placeholder content. Add a snapshot test that runs a tiny synthetic
> campaign and asserts the directory tree matches §6 exactly.

**Done when.** A diff of "files §6 promises" vs "files `assemble` writes"
is empty.

---

### Task 3.5 — Sign the proof-package manifest  *(P1)*

**Goal.** `manifest.json` carries a verifiable Ed25519 signature, fulfilling
§6's "Signed package metadata" claim.

**Prompt.**
> Add `signature: Option<String>` and `signer_kid: Option<String>` fields
> to `ProofPackageManifest`. Add an `assemble_signed(out_dir, signing_key,
> kid)` function that runs `assemble`, then signs a canonical
> JSON-canonicalization of the manifest (excluding the signature field
> itself) with the provided key, and writes the signed manifest. Add a
> `verify_package(dir, public_key) -> Result<()>` function that
> recomputes per-file SHA-256s, recomputes the canonical manifest, and
> verifies the signature. Wire this into a new `invariant verify-package`
> CLI subcommand. Add a tampering test that mutates one byte of one
> file in the package and asserts `verify_package` fails.

**Done when.** Signed assembly and round-trip verification both work,
and tampering is detected.

---

## Phase 4 — Per-category and per-check accountability

### Task 4.1 — Per-category strict success criteria  *(P2)*

**Goal.** Extend the strict success-criteria test from Category B alone
to every category.

**Prompt.**
> Generalize `generate_15m_success_criteria_strict` in
> `crates/invariant-sim/src/campaign.rs` so it asserts a per-category
> `SuccessCriteria` for each of A..N matching §5 of the campaign spec
> (e.g. Category A demands ≥99.9% approval; Categories B–N demand zero
> violation escapes). Each per-category criterion should derive from a
> declarative table in code so the spec and code stay aligned via a
> single source of truth.

**Done when.** Test enumerates all 14 categories and asserts each
criterion; modifying any criterion produces a test failure.

---

### Task 4.2 — Enumerate L1–L4, M1, W1, SR1–SR2 invariant IDs  *(P2)*

**Goal.** §5.1 row 10 demands "every numbered invariant exercised in both
pass and fail paths". P1–P25 and A1–A3 already have IDs; the others do not.

**Prompt.**
> Read `crates/invariant-core/src/{monitors.rs,watchdog.rs,sensor.rs}`.
> Define enum constants or string IDs for L1–L4 (latency invariants from
> the spec), M1 (monitor invariant), W1 (watchdog invariant), and
> SR1–SR2 (sensor range invariants). Surface each in any
> `Verdict::Reject(reason)` or check-name field that mentions these
> categories. Add a test that for every numbered invariant, both an
> approving and a rejecting fixture exists in the test corpus.

**Done when.** `grep -E '\b(L[1-4]|M1|W1|SR[12])\b' crates/` returns
hits in both production code and test fixtures.

---

## Phase 5 — Adversarial coverage

### Task 5.1 — First-class cognitive-escape scenarios I-01..I-10  *(P1)*

**Goal.** Cognitive escapes are not aliased to compound scenarios.

**Prompt.**
> In Category I's submodule (created in Task 1.2), implement each of
> I-01..I-10 as its own scenario type or parameter combination — at
> minimum: rationalization, distraction flooding, semantic confusion,
> authority-chain probing, error mining, watchdog manipulation, profile
> probing, multi-agent collusion, timing exploitation, rollback replay.
> Per-scenario episode budgets must match §3 Category I exactly. The
> aggregate must total 1,500,000 episodes per §2.1. Remove the
> "uses compound scenarios as proxies" alias in `all_scenario_entries`.
> Each scenario's expected verdict is `Reject` (zero bypasses).

**Done when.** All 10 IDs are reachable; their summed episodes equal
the spec's total; the proxy comment is gone.

---

### Task 5.2 — Categories M and N concrete scenarios  *(P1)*

**Goal.** Cross-platform stress (M-01..M-06) and adversarial fuzzing
(N-01..N-10) are implemented and reachable from `generate_15m_configs`.

**Prompt.**
> Implement M-01..M-06 as concrete scenarios in
> `cross_platform_stress`, exercising profile loading, validator
> dispatch, and edge-case profile shapes. Wire N-01..N-10 to the
> `invariant-fuzz` crate's existing protocol/system/cognitive attack
> generators — each spec N-* scenario should map to a fuzzer
> configuration. Add an integration test that drives one episode of
> each M and N scenario through the campaign harness end-to-end.

**Done when.** `generate_15m_configs` produces shard YAMLs covering all
16 M+N entries; integration test passes.

---

### Task 5.3 — Long-running scenarios L-02 and L-03  *(P2)*

**Goal.** Add the two missing Category L scenarios.

**Prompt.**
> In `long_running_stability` (Task 1.2), add scenarios for L-02
> (1M-entry hash-chain integrity per episode) and L-03 (counter
> saturation near `u64::MAX`). Each gets the spec's 50K-episode
> allocation. Verify the validator/audit chain handles both without
> overflow or performance cliffs.

**Done when.** Both scenarios exist and their per-episode behavior is
unit-tested.

---

### Task 5.4 — Multi-robot scenarios A-08 and J-08  *(P2)*

**Goal.** The campaign exercises `invariant-coordinator` for the two
multi-robot scenarios in the spec.

**Prompt.**
> Design a multi-robot scenario type that takes a pair (or set) of
> profiles. Wire it through `invariant-coordinator`'s monitor and
> partition modules. For A-08 ("All pairs of profiles"), enumerate
> profile pairs with the §3 episode budget; for J-08 ("Multi-robot
> coordination attack"), exercise authority-chain attacks across the
> coordinator. Update `generate_15m_configs` to emit paired-profile
> shard configs.

**Done when.** A-08 and J-08 are reachable through `generate_15m_configs`;
end-to-end test runs at least one paired episode.

---

### Task 5.5 — Trusted key-set surface area for G-04  *(P2)*

**Goal.** The validator distinguishes valid signatures with trusted vs
untrusted keys, and the campaign exercises both paths.

**Prompt.**
> Audit how `crates/invariant-core/src/{keys.rs,authority/crypto.rs}`
> expose the trusted key set. If the validator API requires a trusted
> set as input, ensure it is plumbed through the campaign harness and
> through any relevant CLI subcommand (`validate`, `verify`,
> `serve`). Implement G-04's generator: produce signed commands using
> a key not in the trusted set; assert the validator rejects them with
> a specific check ID. Also exercise the happy path with a trusted
> key.

**Done when.** G-04's expected verdict matches the spec; both happy-path
and untrusted-key episodes exist as test fixtures.

---

## Phase 6 — Orchestration and CLI surface

### Task 6.1 — RunPod (or shard runner) orchestration tool  *(P2)*

**Goal.** A real entry point for §7 Step 5 ("RunPod deployment").

**Context.** `crates/invariant-sim/src/orchestrator.rs` is essentially
empty. `docs/runpod-simulation-guide.md` describes operations only.

**Prompt.**
> Decide with the user whether the orchestrator targets RunPod
> specifically or a generic batch backend (RunPod, Modal, k8s Job).
> Implement an `invariant campaign submit --shards <dir>` subcommand
> that submits each shard YAML to the chosen backend, polls for
> completion, and downloads results into the proof-package directory
> structure from Task 3.4. Add a dry-run mode that prints the
> submission plan without making network calls. Write integration
> tests against a local mock backend.

**Done when.** A small (e.g. 10-shard) campaign can be submitted,
monitored, and aggregated end-to-end.

---

## Acceptance gate (pre-PR checklist)

Before declaring this plan complete, run all of the following and ensure
each passes cleanly:

- `cargo build --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all -- --check`
- A 10K-episode dry-run campaign produces a §6-shaped proof package and
  passes `verify_package`.
- The full 15M scenario list, per-scenario step counts, and per-category
  episode totals reconcile across spec §2.1, spec §3, and the code.

---

## Out of scope for this document

- Public-facing release polish (`docs/public-release-polish.md` already
  tracks that).
- Replacing or rewriting the validator's physics checks themselves —
  only their exposure as numbered IDs (Task 4.2).
- Anything in `spec-v4.md`..`spec-v11.md` that is not also reflected
  somewhere in `spec-15m-campaign.md` or the existing crates — those
  files are missing from disk and Task 0.1 must resolve their status
  before further fixes from them are proposed.
