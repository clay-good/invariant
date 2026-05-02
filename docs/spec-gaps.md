% Invariant — Gap-Closure Specification (Verified)
% Status: Draft
% Date: 2026-04-27
% Branch: codelicious/spec-spec-15m-campaign-part-2
% Supersedes: prior `docs/spec-gaps.md` draft (2026-04-27)

# 0. Purpose & Method

This document specifies the work required to close the gap between published
commitments and the current implementation. Every gap has a **spec citation**
and a **code citation** (or grep evidence of absence). Each item was
re-verified against `HEAD` on 2026-04-27.

Sources audited:

- Specs: `docs/spec.md` (864 L), `spec-v1.md` (1 348 L), `spec-v2.md` (420 L),
  `spec-v3.md` (437 L), `spec-15m-campaign.md` (474 L),
  `public-release-polish.md`, `README.md`, `CHANGELOG.md`.
- Code: `crates/{invariant-core, invariant-cli, invariant-sim, invariant-eval,
  invariant-fuzz, invariant-coordinator}`, `isaac/`, `formal/`, `scripts/`,
  `profiles/`, `.github/workflows/`.

Items the prior draft asserted that **did not survive verification** are listed
in §9 ("Withdrawn / corrected claims") so the record stays honest.

Severity convention:

- **P1** — blocks Guardian Mode shipping or invalidates the 15M-episode proof
  package.
- **P2** — silent weakness; pipeline still runs but a documented guarantee is
  degraded or under-tested.
- **P3** — polish, documentation, or release-hygiene drift.

Out of scope: re-specifying features that already ship and are tested (the core
P1–P25 physics pipeline, validator, watchdog, audit hash-chain, differential,
intent, signed verdicts, the 20 wired CLI subcommands, dry-run simulation, and
the 22 implemented scenarios).

---

# 1. P1 — Authority & Continuity

## 1.1 Execution-binding invariants B1–B4 are unimplemented

- **Spec:** [docs/spec.md:394-403](spec.md#L394-L403) defines B1 (session
  binding), B2 (sequence monotonicity vs PCA chain), B3 (temporal-window
  enforcement), B4 (executor identity). [docs/spec.md:478](spec.md#L478) lists
  `authority/binding.rs` in the planned crate layout.
- **Code:** `ls crates/invariant-core/src/authority/` shows
  `chain.rs, crypto.rs, mod.rs, operations.rs, tests.rs` — `binding.rs` does
  not exist. `grep -rn "ExecutionBinding\|executor_binding\|temporal_window"
  crates/invariant-core/src/` and `grep -rn "B1\|B2\|B3\|B4\|binding"
  crates/invariant-core/src/authority/` both return zero production hits.
  Sequence handling is partial — the validator tracks `command.sequence`
  ([crates/invariant-core/src/validator.rs:220](../crates/invariant-core/src/validator.rs#L220),
  [:300](../crates/invariant-core/src/validator.rs#L300),
  [:315](../crates/invariant-core/src/validator.rs#L315)) but does not bind to
  PCA hop indices, sessions, or executor identity.
- **Impact:** A syntactically valid PCA can be replayed across sessions and
  across executors. Spec promises rejection.
- **Acceptance:**
  - New module `crates/invariant-core/src/authority/binding.rs` exposing
    `verify_execution_binding(cmd: &Command, ctx: &ExecutionContext, pca: &Pca)
     -> Result<(), BindingError>`.
  - `ValidatorConfig` carries an
    `ExecutionContext { session_id, executor_id, time_window }`.
  - `crates/invariant-cli/src/commands/serve.rs` plumbs per-connection context.
  - Each of B1–B4 has one positive test and one hostile test in
    `crates/invariant-core/src/authority/tests.rs`.

## 1.2 Proof-of-Continuity (A3) lacks PCA-to-PCA causal binding

- **Spec:** [docs/spec.md:230-232](spec.md#L230-L232) and
  [docs/spec.md:388-392](spec.md#L388-L392) define PoC as a "non-forgeable
  proof bound to the predecessor PCA"; A3 is "PoC_i is a valid causal successor
  of PCA_{i-1}".
- **Code:** `grep -rn "predecessor_hash\|predecessor_digest\|prev_hop_hash\|
  continuity_proven" crates/invariant-core/src/` returns zero matches.
  [crates/invariant-core/src/authority/chain.rs:31](../crates/invariant-core/src/authority/chain.rs#L31)
  `verify_chain` enforces only signature validity, monotonic operation
  narrowing, and `p_0` immutability. Hop *i+1* is not cryptographically linked
  to the byte representation of hop *i*.
- **Impact:** Cross-chain splice (campaign attack
  [docs/spec-15m-campaign.md:179](spec-15m-campaign.md#L179) — G-09) is not
  structurally prevented.
- **Acceptance:**
  - Add `predecessor_digest: [u8; 32]` to `Pca`.
  - `verify_chain` rejects when
    `hop[i].predecessor_digest != sha256(hop[i-1].canonical_bytes())`.
  - Test `g09_cross_chain_splice_rejected` in `authority/tests.rs`.
  - Migration: field is non-optional; existing fixtures regenerate.

## 1.3 G-07 wildcard exploitation and G-09 splice tests are absent

- **Spec:** [docs/spec-15m-campaign.md:177-179](spec-15m-campaign.md#L177-L179).
- **Code:** `grep -rn "G-07\|G-09\|wildcard.*exploit\|cross.*chain.*splice"
  crates/` returns zero matches.
  [crates/invariant-core/src/authority/operations.rs:11-14](../crates/invariant-core/src/authority/operations.rs#L11-L14)
  documents wildcard semantics; the targeted attacks are not exercised by
  tests.
- **Acceptance:** in `authority/tests.rs`,
  - `g07_wildcard_actuate_does_not_cover_read`: `actuate:*` chain attempting
    `read:proprioception` is rejected.
  - `g07_move_namespace_wildcard_does_not_cross_subsystem`: `move:arm.*` chain
    attempting `move:base.linear` is rejected.
  - `g09_cross_chain_splice_rejected`: assemble two locally valid chains
    sharing an issuer, splice them, verifier rejects on first hop whose
    predecessor digest does not match.

---

# 2. P1 — Production Backends Are Stubs

## 2.1 Hardware key stores

- **Spec:** [docs/spec.md:838](spec.md#L838) (root-key security); spec-v3.md
  hardening list calls out keyring/TPM/YubiHSM.
- **Code:**
  [crates/invariant-core/src/keys.rs:413](../crates/invariant-core/src/keys.rs#L413),
  [:436-444](../crates/invariant-core/src/keys.rs#L436-L444)
  (`OsKeyringKeyStore` returns `KeyStoreError::Unavailable` with reason
  "OS keyring backend not yet implemented — use file backend for development"),
  [:462](../crates/invariant-core/src/keys.rs#L462),
  [:482-491](../crates/invariant-core/src/keys.rs#L482-L491) (`TpmKeyStore`),
  [:510](../crates/invariant-core/src/keys.rs#L510),
  [:530-539](../crates/invariant-core/src/keys.rs#L530-L539)
  (`YubiHsmKeyStore`). All three are typed shells. The `open_key_store_stubs`
  test only confirms stub semantics.
- **Acceptance:**
  - `os-keyring` feature: `keyring` crate; macOS Keychain, Secret Service,
    Windows Credential Manager. Round-trip Ed25519.
  - `tpm` feature: `tss-esapi`. Persistent keys under owner hierarchy.
    Document attestation requirements separately.
  - `yubihsm` feature: `yubihsm` crate. Auth via password-derived session;
    key handles persisted by label.
  - Default build pulls none of these. CLI `keygen --store=<kind>` selects
    at runtime; unknown kinds fail with a typed error before any I/O.
  - Stub tests are replaced (not augmented) by feature-gated integration
    tests.

## 2.2 Audit replication & external witness

- **Spec:** [docs/spec.md:124](spec.md#L124),
  [docs/spec.md:410-412](spec.md#L410-L412) (L1–L4 audit invariants).
- **Code:**
  [crates/invariant-core/src/replication.rs:257-259](../crates/invariant-core/src/replication.rs#L257-L259)
  (`S3Replicator::push` returns `ReplicationError::Unavailable`),
  [:289-292](../crates/invariant-core/src/replication.rs#L289-L292)
  (`WebhookWitness`). Stub-semantics tests at
  [:443](../crates/invariant-core/src/replication.rs#L443),
  [:460](../crates/invariant-core/src/replication.rs#L460).
- **Acceptance:**
  - `S3Replicator` (`replication-s3` feature): `aws-sdk-s3`; object naming
    `{prefix}/{epoch_ms}-{seq}.jsonl`; SSE-KMS + S3 Object Lock retention;
    backoff on throttle; resume from last replicated sequence on restart.
  - `WebhookWitness`: POST `{root, count, signature}` JSON on each Merkle-root
    rotation (see §3.1); HMAC-SHA256 signature header; bounded retry queue
    with disk spillover; surface persistent failure as an incident.
  - Document RTO/RPO assumptions in module rustdoc.
  - Live test against MinIO + a local webhook receiver; chaos-restart asserts
    no loss.

## 2.3 Alert sinks

- **Spec:** [docs/spec.md:830](spec.md#L830) and the spec-v3.md incident-hooks
  section.
- **Code:**
  [crates/invariant-core/src/incident.rs:175-180](../crates/invariant-core/src/incident.rs#L175-L180)
  (`WebhookAlertSink` returns `Unavailable`),
  [:194-197](../crates/invariant-core/src/incident.rs#L194-L197)
  (`SyslogAlertSink`). The `Unavailable` variant is at
  [:120-123](../crates/invariant-core/src/incident.rs#L120-L123).
- **Acceptance:**
  - Webhook: HMAC-SHA256 signed POST; bounded retry queue with disk spillover;
    configurable per-host concurrency.
  - Syslog: RFC 5424 over UDP and TCP+TLS; structured-data field carries
    verdict ID and severity.
  - HIL test against an `rsyslog` container and a local HTTP receiver.
    Verify back-pressure does not block the validator hot path (sink runs on
    its own task).

---

# 3. P1 — 15M-Episode Proof Package Is Not End-to-End

## 3.1 Proof package has no Merkle tree and no signed manifest

- **Spec:** [docs/spec-15m-campaign.md:371-407](spec-15m-campaign.md#L371-L407)
  lists `audit/merkle_root.txt` and `audit/chain_verification.json` as required
  artifacts; [docs/spec.md:124](spec.md#L124) declares hash-chained signed
  audit.
- **Code:**
  - `proof_package::assemble` is implemented and unit-tested
    ([crates/invariant-core/src/proof_package.rs:328-343](../crates/invariant-core/src/proof_package.rs#L328-L343)),
    and a CLI verifier (`invariant verify-package`,
    [crates/invariant-cli/src/commands/verify_package.rs](../crates/invariant-cli/src/commands/verify_package.rs))
    round-trips it.
  - But the manifest is `HashMap<String, String>` of per-file SHA-256 only.
    `grep -n "[Mm]erkle\|tree_root" crates/invariant-core/src/proof_package.rs
    crates/invariant-core/src/audit.rs` returns no hits.
    [proof_package.rs:241](../crates/invariant-core/src/proof_package.rs#L241)
    explicitly documents the manifest as "unsigned — caller signs if keys are
    available", and no caller in the workspace signs it. `public_keys` is an
    optional input that is *bundled* into the package, not used to *sign* it.
- **Impact:** the campaign's headline deliverable does not match the published
  artifact list. Reviewers cannot independently verify partial-tampering
  resistance — only whole-file digests.
- **Acceptance:**
  - SHA-256 binary Merkle tree over audit JSONL entries; root written to
    `audit/merkle_root.txt`; per-leaf inclusion-proof helper
    `merkle_proof(seq) -> Vec<[u8;32]>`.
  - `manifest.json` signed with the campaign Ed25519 key; signature emitted
    as `manifest.sig`.
  - `verify_package(path, &public_key)` rebuilds the tree, verifies the
    manifest signature, and re-checks each file digest. Existing round-trip
    test extended to assert tree-root presence and signature verification
    on a 2-shard fixture.

## 3.2 `invariant campaign assemble` CLI subcommand is missing

- **Spec:** [docs/spec-15m-campaign.md §6 step 6](spec-15m-campaign.md).
- **Code:** the CLI registry
  ([crates/invariant-cli/src/main.rs:23-72](../crates/invariant-cli/src/main.rs#L23-L72))
  enumerates 20 subcommands (Validate, Audit, Verify, Inspect, Eval, Diff,
  Differential, Campaign, Keygen, Serve, Adversarial, Bench, Profile,
  Compliance, VerifyPackage, Transfer, AuditGaps, Intent, VerifySelf,
  Completions). `Campaign`
  ([commands/campaign.rs:39](../crates/invariant-cli/src/commands/campaign.rs#L39))
  only runs the dry-run orchestrator. `grep -rn "assemble\|Assemble"
  crates/invariant-cli/src/commands/campaign.rs
  crates/invariant-cli/src/main.rs` is empty.

  The Rust API `proof_package::assemble` is fully wired and used by
  `verify_package` tests
  ([commands/verify_package.rs:339-460](../crates/invariant-cli/src/commands/verify_package.rs#L339-L460)),
  so what's missing is purely the CLI surface.
- **Acceptance:**
  - Add `campaign assemble --shards <DIR> --output <PATH> --key <PATH>` (or a
    sibling top-level `CampaignAssemble`).
  - Inputs: a directory of per-shard audit JSONL + per-shard summary JSON.
  - Outputs: the §3.1 proof package, a roll-up Clopper-Pearson CI per
    category, profile fingerprints, and the signed manifest.
  - Integration test on a 2-shard fixture; round-trips through
    `verify-package`.

## 3.3 Scenario coverage: 22 of ~104 implemented

- **Spec:** [docs/spec-15m-campaign.md:69](spec-15m-campaign.md#L69) declares
  104 scenario IDs across categories A–N; §5 statistical claims
  (Clopper-Pearson) depend on this coverage.
- **Code:**
  [crates/invariant-sim/src/scenario.rs:51-107](../crates/invariant-sim/src/scenario.rs#L51-L107)
  enumerates exactly 22 `ScenarioType` variants. There is no
  `Scenario::all()` enumerator (`grep "fn all" crates/invariant-sim/src/scenario.rs`
  is empty).
- **Missing per category** (cross-checked against
  [spec-15m-campaign.md §3](spec-15m-campaign.md#L80-L300)):

  | Cat | Title          | Missing scenarios (representative)                                  |
  |-----|----------------|---------------------------------------------------------------------|
  | A   | Baseline       | A-03..A-08 (only one Baseline variant exists)                       |
  | B   | Joint sweep    | B-01..B-08 (no joint-boundary sweep)                                |
  | C   | Workspace      | C-01, C-03..C-06 (only `ExclusionZone`)                             |
  | D   | Locomotion     | D-09 push-recovery, D-10 incline                                    |
  | E   | Manipulation   | E-01..E-06 (entire category empty)                                  |
  | F   | Sensor/Env     | F-05..F-08 (no scenario layer beyond physics SR1/SR2)               |
  | G   | Authority      | G-02..G-10 (only `AuthorityEscalation`, `ChainForgery`)             |
  | H   | Temporal       | H-01..H-06 (entire category empty)                                  |
  | I   | Cognitive      | I-01..I-10 (entire category empty)                                  |
  | J   | Compound       | J-03, J-04, J-06, J-08                                              |
  | K   | Recovery       | K-02, K-03, K-05, K-06                                              |
  | L   | Long-running   | L-02, L-03                                                          |
  | M   | Multi-robot    | M-01..M-06                                                          |
  | N   | Red-team fuzz  | N-01..N-10                                                          |

- **Acceptance:**
  - Implement scenarios up to the 104 IDs cited in the campaign spec, OR amend
    the campaign spec downward to the achievable count and re-derive §5's CI.
  - Add `pub fn all() -> &'static [ScenarioType]` and a `scenario_coverage`
    integration test that asserts every cited spec ID has a corresponding
    `ScenarioType`.

## 3.4 Isaac Lab task environments cover one cell

- **Spec:** [docs/spec-15m-campaign.md:34](spec-15m-campaign.md#L34) ("All 34
  built-in profiles"); §3 lines 80–87 require humanoid / quadruped / hand
  coverage.
- **Code:** `ls isaac/envs/` returns only `__init__.py, cell_config.py,
  cnc_tending.py`. `crates/invariant-sim/src/isaac/` contains only the bridge
  and dry-run shim.
  [crates/invariant-cli/src/commands/campaign.rs:24-35](../crates/invariant-cli/src/commands/campaign.rs#L24-L35)
  prints "live Isaac Lab campaigns use the Python runner" and exits 2.
- **Acceptance:**
  - One env class per profile family under `isaac/envs/`:
    `arm.py, humanoid.py, quadruped.py, hand.py, mobile_base.py`.
  - Each implements `reset / step / observe`, publishes sensor payloads
    matching `SensorPayload`, and accepts deterministic seeds.
  - `isaac/run_campaign.py` headless driver consuming a campaign config and
    emitting per-episode JSON traces compatible with `campaign assemble`.
  - Smoke run: 1 000 Category-A episodes for one humanoid + one arm, zero
    validator errors, full audit JSONL emitted.

## 3.5 Roadmap Steps 5–7 partially landed

- **Spec:** [docs/spec-15m-campaign.md §7 lines 425-432](spec-15m-campaign.md#L425-L432).
- **Code present:**
  - `scripts/run_15m_campaign.sh` (full per-profile sharded runner with
    weighted episode counts).
  - `scripts/runpod_setup.sh` (82 L) and `scripts/upload_results.py` (174 L).
- **Code absent:**
  - No preempt-recovery / cost-ceiling logic in `run_15m_campaign.sh` (no
    `trap`/checkpointing on SIGTERM, no spend-cap check).
  - No shadow-deployment runbook in `docs/`. The existing
    `docs/runpod-simulation-guide.md` is exploratory and does not specify
    deployment metrics or sign-off criteria.
  - Step 6 is the `campaign assemble` CLI subcommand from §3.2.
- **Acceptance:**
  - Extend `scripts/run_15m_campaign.sh` (or add `scripts/runpod_fanout.sh`)
    with: SIGTERM trap that flushes shard summary, idempotent resume from
    completed-shard marker file, configurable `MAX_USD` ceiling that aborts
    cleanly.
  - `docs/shadow-deployment.md`: ≥100 robot-hours on UR10e CNC cell; metric
    collection, divergence-triage protocol, sign-off criteria.

---

# 4. P2 — Silent Weaknesses

## 4.1 Sensor-range pre-filters SR1 and SR2 share one check name

- **Spec:** [docs/spec-v2.md:139-145](spec-v2.md#L139-L145) presents SR1
  (env-state range) and SR2 (payload range) as two distinct pre-filters;
  downstream coverage tables key off check name.
- **Code:**
  [crates/invariant-core/src/physics/environment.rs:361-427](../crates/invariant-core/src/physics/environment.rs#L361-L427)
  implements both as a single `check_sensor_range` returning one
  `CheckResult` named `"sensor_range"`.
- **Acceptance:** split into `check_sensor_range_env` (SR1) and
  `check_sensor_range_payload` (SR2); update registration in
  [crates/invariant-core/src/physics/mod.rs:326](../crates/invariant-core/src/physics/mod.rs#L326);
  update the `compliance` subcommand to count them independently.

## 4.2 Profiles missing `end_effectors`

- **Spec:** [docs/spec-v1.md §1.1 lines 38-97](spec-v1.md#L38-L97) requires
  `manipulation.end_effectors` on profiles whose action surface includes
  manipulation.
- **Code:** `for f in profiles/*.json; do grep -c '"end_effectors"' $f; done`
  shows nine profiles with **zero** `end_effectors` blocks:
  - Locomotion-only (legitimate, but undeclared): `anybotics_anymal.json`,
    `quadruped_12dof.json`, `spot.json`, `unitree_a1.json`,
    `unitree_go2.json`.
  - Likely real gap: `agility_digit.json` (Digit has hands; manipulation
    operations would still be admitted).
  - Adversarial fixtures: `adversarial_max_joints.json`,
    `adversarial_max_workspace.json`, `adversarial_single_joint.json`,
    `adversarial_zero_margin.json`. Two of these
    (`adversarial_max_joints.json`, `adversarial_single_joint.json`) also
    lack an `environment` block.
- **Acceptance:**
  - Add `end_effectors: []` plus `platform_class: "locomotion-only"` to the
    five locomotion-only profiles.
  - Add a real EE block to `agility_digit.json` (or document the descope).
  - Add `validate-profiles --strict` (does not exist —
    `grep validate-profiles crates/invariant-cli/src/` is empty) which fails
    CI when a profile permits a manipulation operation but declares no EE.
  - Adversarial profiles are exempt iff they carry an explicit
    `"adversarial": true` flag; document in the validator.

## 4.3 Multi-robot coordinator only proven pairwise

- **Spec:** [docs/spec.md:534-538](spec.md#L534-L538).
- **Code:** `ls crates/invariant-coordinator/src/` shows `lib.rs, monitor.rs,
  partition.rs`. `grep -rn "fleet\|n_robots\|10.robot"
  crates/invariant-coordinator/` finds no scaled fleet test. CLI has no
  `fleet` subcommand (`grep -rn "fleet" crates/invariant-cli/src/commands/`
  is empty).
- **Acceptance:**
  - 10-robot integration test (8 arms + 2 mobile bases) running 60 s
    synthetic traffic; asserts zero false positives and zero missed near-
    misses on a scripted scenario.
  - New `invariant fleet status` subcommand reading the coordinator state.
    (Adding this brings the registered subcommand count to 21 — see §4.5.)

## 4.4 Watchdog shared across bridge connections

- **Spec:** [docs/spec.md:421-424](spec.md#L421-L424) (W1) and the
  per-cognitive-layer heartbeat at [docs/spec.md:434](spec.md#L434).
- **Code:** the bridge file header
  ([crates/invariant-sim/src/isaac/bridge.rs:13-16](../crates/invariant-sim/src/isaac/bridge.rs#L13-L16))
  documents a single shared watchdog. A second misbehaving client can starve
  the first.
- **Acceptance:** per-connection watchdog state; or single-client enforcement
  with a typed `BridgeError::SecondClient`.

## 4.5 Documentation drift on counts

- Test counts: README.md:392 cites "~2 047 tests"; CHANGELOG.md:63 cites 128
  doc-tests; spec-v2.md:307 cites "2 023+"; public-release-polish.md cites
  "1 998 passed". Workspace has **1 881** `#[test]` markers
  (`grep -rc "#\[test\]" crates/ | awk -F: '{s+=$2} END {print s}'`). The
  drift is consistent (literals were never updated) but it costs reviewer
  trust.
- Subcommand count: spec-v2.md:295 cites 20 subcommands; the registry exposes
  exactly 20 (`Validate, Audit, Verify, Inspect, Eval, Diff, Differential,
  Campaign, Keygen, Serve, Adversarial, Bench, Profile, Compliance,
  VerifyPackage, Transfer, AuditGaps, Intent, VerifySelf, Completions`).
  This number is currently accurate but will drift if §3.2 (`campaign
  assemble`) and §4.3 (`fleet`) land.
- Scenario counts: README and several specs cite 22 scenarios; matches code
  today. Will diverge as §3.3 lands.
- **Acceptance:** emit `docs/test-count.txt` from CI
  (`cargo test --workspace 2>&1 | grep "test result"` aggregated); reference
  the file rather than hard-coding a literal in README/specs. Update the
  subcommand count in lockstep with §3.2/§4.3.

---

# 5. P3 — Polish, Formal, Release Hygiene

## 5.1 Lean formalization is sketch + axioms, not proof

- **Spec:** [docs/spec.md:799-831](spec.md#L799-L831) states the master
  safety theorem as if proven; spec-v2.md:306 lists Lean 4 formal spec
  under tests.
- **Code:**
  - `formal/Invariant.lean:54-63` — `safety_guarantee` proof is
    `exact h_no_act h_reject`, i.e. discharges hypotheses the caller supplies.
    It does not prove composition.
  - `formal/Invariant/Authority.lean` contains **1** `sorry`
    (`monotonicity_transitive`, ~L85-90).
  - `formal/Invariant/Audit.lean:82` — `hash_collision_resistant` is declared
    `axiom`.
  - `formal/Invariant/Physics.lean:132` — `pointInConvexPolygon` is
    axiomatized.
  - `.github/workflows/ci.yml` has no `lake build` step
    (`grep lake .github/workflows/*.yml` is empty).
- **Acceptance:**
  - `formal/README.md` table: each theorem name, status
    (`proved | sorry | axiom`), spec.md cross-reference.
  - Replace the `sorry` in `Authority.lean` or descope the claim.
  - Add `lake build` to CI as a non-blocking job; flip to blocking once
    master safety and confused-deputy theorems are closed.
  - Until proofs land, qualify spec.md §8 from "proves" to
    "specifies; mechanized proofs in progress".

## 5.2 SBOM and reproducible-build verification missing from CI

- **Spec:** spec-v3.md release-hygiene section.
- **Code:** `.github/workflows/` contains `ci.yml` and `release.yml`. Neither
  references CycloneDX or an SBOM step (`grep -rn "cyclonedx\|sbom"
  .github/workflows/` is empty). No `make repro` target in `Makefile` (no
  Makefile present at repo root).
- **Acceptance:**
  - Add `cargo cyclonedx` step to `release.yml`; sign the SBOM with the
    release key; attach to the GitHub release.
  - Add a `make repro` (or `scripts/repro.sh`) target that builds inside the
    published `Dockerfile` and asserts a stable binary digest against a
    checked-in SHA.

## 5.3 ROS2 bindings are unreferenced

- **Spec:** README.md lists `invariant-ros2` integration as a feature.
- **Code:** `invariant-ros2/` exists at repo root but is not a workspace
  member (`grep invariant-ros2 Cargo.toml` returns no match). Nothing in
  `crates/` depends on it.
- **Acceptance:** either wire it into the workspace and add a smoke test, or
  move it under `examples/` and qualify the README claim as "example
  integration, unmaintained until milestone X".

## 5.4 Spec consolidation

- `docs/` carries `spec.md` (864 L), `spec-v1.md` (1 348 L), `spec-v2.md`
  (420 L), `spec-v3.md` (437 L), `spec-15m-campaign.md` (474 L),
  `public-release-polish.md` (64 L), and this document. Both `spec.md:1-5`
  and `spec-v2.md:1-9` independently claim to supersede prior specs.
- **Acceptance:** move v1/v2/v3 to `docs/history/`; each gets a one-line
  redirect header pointing at `docs/spec.md`. `spec.md` becomes the single
  live spec; `spec-15m-campaign.md` remains as the campaign-specific
  addendum until §3 lands; this document can be deleted per §8 below.

---

# 6. Cross-Cutting Acceptance Tests

A future commit closing this spec must add at least:

1. `crates/invariant-core/tests/binding.rs` — B1–B4 positive + hostile.
2. `crates/invariant-core/src/authority/tests.rs::g09_cross_chain_splice_rejected`.
3. `crates/invariant-core/tests/proof_package_signed.rs` — assemble + verify
   round-trip with Merkle root and signature.
4. `crates/invariant-sim/tests/scenario_coverage.rs` — every campaign-spec
   scenario ID has a `ScenarioType`.
5. `crates/invariant-coordinator/tests/fleet_10_robot.rs`.
6. `crates/invariant-cli/tests/cli_assemble.rs`.
7. `isaac/tests/test_envs_smoke.py` — humanoid + arm 1 k episodes.

---

# 7. Prioritized Execution Order

1. **§1.2** (A3 predecessor digest) — small, structural, unblocks G-09.
2. **§1.1** (B1–B4 binding module) — needed before serve-mode hardening.
3. **§3.1** (Merkle + signed manifest) — feeds existing `assemble`/`verify-
   package` API; smallest path to a defensible proof package.
4. **§3.2** (`campaign assemble` CLI) — thin wrapper over existing API.
5. **§4.2** (profile EE) and **§4.1** (SR1/SR2 split) — mechanical, raise
   compliance accuracy.
6. **§4.5** (count drift) — eliminates external-reviewer credibility hits.
7. **§2.1–§2.3** (HW keys, replication, alerts) — feature-gated,
   parallelizable.
8. **§3.3** (scenario expansion) and **§3.4** (Isaac envs) — gated on infra
   access.
9. **§3.5** (preempt-recovery, shadow runbook).
10. **§4.3** (fleet) and **§4.4** (per-conn watchdog).
11. **§5.1** (Lean) — long tail; honest spec wording can ship without it.
12. **§5.2–§5.4** (SBOM, ROS2 bindings, consolidation) — pre-tag.

---

# 8. Closure Criterion

This document may be deleted in a future commit when **every** numbered item
above is either landed (with the acceptance test passing in CI) or has an
explicit decision logged in `docs/spec.md` to descope, with rationale.
Partial completion is not closure.

---

# 9. Withdrawn / Corrected Claims

For honesty, the following claims appeared in earlier drafts and did not
survive verification:

1. **"Nine profiles missing `environment` blocks"** (prior `spec-gaps.md`).
   Re-checking shows all named profiles declare `environment`. The real
   environment-block gaps are limited to two adversarial fixtures
   (`adversarial_max_joints.json`, `adversarial_single_joint.json`); see
   §4.2.

2. **"Subcommand registry exposes 19 subcommands"** (prior draft, §4.6).
   The registry exposes 20 — `VerifySelf` was missed. README and spec-v2.md's
   "20 subcommands" line is currently accurate.

3. **"`verify-package` CLI subcommand does not exist"** (implicit in prior
   draft §3.1/§3.2). It exists at
   [crates/invariant-cli/src/commands/verify_package.rs](../crates/invariant-cli/src/commands/verify_package.rs)
   and round-trips the `proof_package::assemble` API in unit tests
   ([:339-460](../crates/invariant-cli/src/commands/verify_package.rs#L339-L460)).
   The real gap is content (no Merkle, no signed manifest — §3.1) and the
   absence of a *campaign-level* `assemble` CLI subcommand (§3.2).

4. **"No RunPod fan-out script"** (prior draft §3.5).
   `scripts/run_15m_campaign.sh`, `scripts/runpod_setup.sh`, and
   `scripts/upload_results.py` all exist. The remaining gaps are
   preempt-recovery and a documented cost ceiling — narrowed in §3.5.

5. **"1 951 `#[test]` markers"** (prior draft §4.6). Re-counted: 1 881.

6. **"`invariant validate-profiles --strict` does not exist"** — confirmed
   true; carried forward into §4.2.
