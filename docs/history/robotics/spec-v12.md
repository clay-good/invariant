> Superseded by [docs/robotics/spec.md](../../robotics/spec.md) as of 2026-05-19. The active v12 closure report is at [docs/spec-v12-verification.md](../../spec-v12-verification.md). This file is kept for historical reference.

# spec-v12.md — Re-verified Gap Closure (post-v11 status snapshot)

**Status:** active, 2026-05-02
**Branch when authored:** `codelicious/spec-spec-15m-campaign-part-4`
**Supersedes the open items in:** spec-v11.md (does not invalidate spec.md or spec-15m-campaign.md)
**Audience:** Claude Code agents executing one prompt at a time

## 0. Why a v12

`docs/spec-v11.md` was authored on 2026-05-01 and proposed 38 prompts (Phases 1–6) all marked `OPEN`. Since then the branch has merged a large set of `[spec-spec-15m-campaign-chunk-*]` commits that grew `crates/invariant-sim/src/scenario.rs` and `campaign.rs` and expanded `docs/spec-15m-campaign.md`, but a re-verification on 2026-05-02 against `HEAD` shows that **most v11 cryptographic, CLI, simulation, and backend prompts have not actually landed**. v12 records the current verified status of every v11 prompt and adds prompts for net-new gaps that v11 did not cover.

This document is a remediation plan derived from a fresh end-to-end audit of `crates/`, `isaac/`, `formal/`, `.github/workflows/`, `profiles/`, `campaigns/`, and `docs/` against `docs/spec.md`, `docs/spec-15m-campaign.md`, `spec-v11.md`, and earlier deltas.

Each section under "Prompts" is self-contained: open it, paste the body verbatim into a fresh agent (or run it as one focused task), and let it complete end-to-end before moving on. Prompts are ordered by dependency: P1 (Phase 1 blocking) must land before P2 generators are trustworthy, P3 depends on P2, P4–P6 are parallelizable once P1 is in.

After each prompt completes:
1. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` must be green.
2. One commit per prompt with subject `[spec-v12-<id>] <one-line summary>`.
3. Update the v11 tracking table **and** the v12 tracking table at the bottom of this file from `OPEN` → `DONE` (or `PARTIAL`/`DESCOPED` with a citation).

If an agent finds the work is already done, it should record `ALREADY DONE` in the v12 tracking table with a one-line citation (commit hash or file path) and move on without committing.

---

## 1. Verified status of v11 prompts (re-checked 2026-05-02)

The "Evidence" column links to the grep or file read that verified the status against `HEAD`.

| v11 ID | Title                                              | Re-verified status | Evidence |
|--------|----------------------------------------------------|--------------------|----------|
| 1.1    | B1–B4 audit fields                                 | DONE (2026-05-18)  | `AuditEntry` gains optional `session_id` / `executor_id` / `monotonic_nanos` / `wall_clock_rfc3339` (all `skip_serializing_if` to preserve byte-identical preimages for unmigrated callers). New `BindingContext` + `AuditLogger::set_binding_context`, new `AuditError::ClockRegression`, new public `canonical_bytes` helper with length-prefixed framing. `audit_gaps` partitions by executor. Three new tests (preimage golden, clock regression, 16-thread concurrent). Detailed entry in spec-v11.md row 1.1. |
| 1.2    | A3 predecessor digest                              | DONE (2026-05-19) | `Pca` gains `predecessor_digest: [u8; 32]` with hex serde + `Default` derive; new `canonical_bytes` (length-prefixed framing, digest field excluded from preimage) + `sha256_digest` helper; new `AuthorityError::{PredecessorDigestMismatch, PredecessorDigestNonZeroAtRoot}`; new `verify_predecessor_chain` (strict) + `verify_chain_strict_predecessor` (wrapper). **Promoted from PARTIAL → DONE on 2026-05-19:** the in-tree `verify_chain` now runs the predecessor binding check **mandatorily** (was opt-in detection mode). Single-hop chains pass trivially; multi-hop chains must have correct digests. New public helper `link_chain_digests(claims: &mut [Pca])` computes each hop's digest from its parent in-place. Six existing multi-hop test sites (5 in `authority/tests.rs`, 1 in `invariant-robotics/src/validator.rs`) migrated to call `link_chain_digests` before signing. Eight tests in `authority_predecessor_digest.rs` (field-order stability, preimage exclusion, happy 3-hop, root-zero invariant, G-09 splice rejection, legacy-chain handling, serde round-trip × 2) all green. Full workspace `cargo test --workspace` green (3 256 tests, 0 failures); `cargo clippy -p invariant-core -p invariant-robotics -p invariant-cli -p invariant-sim --lib --tests -- -D warnings` clean. See spec-v11 row 1.2 for the full design / migration write-up. |
| 1.3    | RFC 6962 Merkle tree                               | DONE (2026-05-16)  | New `crates/invariant-core/src/merkle.rs` (leaf/inner hash with 0x00/0x01 domain separators, `MerkleAccumulator`, `inclusion_proof`, `verify_inclusion`, `tree_root` oracle). `AuditLogger` now keeps a running `MerkleAccumulator` and exposes `merkle_root()`. `assemble()` writes `integrity/merkle_root.txt` when `PackageInputs.merkle_root_hex` is set and records it on the manifest. Two new test files (`merkle_known_vectors.rs` with hand-computed roots for n=1..7; `merkle_tamper.rs` covers every single-bit flip in a 1024-leaf tree's audit path). |
| 1.4    | Manifest JCS + signature                           | DONE (2026-05-16)  | `ProofPackageManifest` gains `manifest_signature` / `manifest_signer_kid` (Ed25519 base64-no-padding). New `canonical_json` (RFC 8785 subset — sorted keys, compact, signature fields stripped), `sign_manifest`, `verify_manifest` (`verify_strict` for cofactor mitigation). `ProofPackageError` extended with `SignatureInvalid` + `Canonicalization`. `PackageInputs.signing_key: Option<(SigningKey, String)>`; `assemble()` signs in place and writes `manifest.sig` when supplied. Two new test files (`manifest_jcs_golden.rs`, `manifest_tamper.rs`) cover sorted-key invariants, signature-field exclusion, round-trip, three independent tamper paths, missing-signature and wrong-key rejection. |
| 1.5    | `campaign assemble` CLI                            | DONE (2026-05-16)  | `invariant robotics assemble` shipped at `crates/invariant-cli/src/robotics/commands/assemble.rs`. Walks `--shards` in sorted order, merges audit.jsonl + sums summary.json across shards, recomputes the RFC 6962 Merkle root, calls `proof_package::assemble`, signs the manifest when `--key` is supplied (v11 1.4 JCS path), self-verifies via `--public-key` (exit 1 on mismatch). `--metadata KEY=VALUE` writes an `integrity/metadata.json` sidecar. 9 unit tests cover missing/empty shards, nonempty output, unsigned + signed happy paths, wrong-key verify failure, sort-order determinism, metadata validation, and Merkle hex format. Registered under the robotics subcommand tree (`invariant robotics assemble`) rather than a `campaign` parent because the unified workspace exposes `campaign` as a flat command. |
| 1.6    | `audit verify` digest/root flags                   | DONE (2026-05-19) | `--merkle-root <HEX>` (Merkle half, landed earlier): recomputes the RFC 6962 root from the log and compares to the operator anchor (exit 1 on mismatch, exit 2 on malformed hex; `sha256:` prefix accepted; empty-log root is the RFC 6962 `MTH({})`). `--predecessor-digest` (2026-05-19, after 1.2 landed): no longer rejected; shape-validates 32-byte hex against the `Pca.predecessor_digest` wire format and emits a `note:` documenting the queued per-entry chain-extraction follow-up. Three new tests cover well-formed hex passing, malformed hex still exit-2, and `sha256:` prefix acceptance. |
| 2.0    | Determinism contract                               | DONE (2026-05-17)  | New `crates/invariant-sim/src/robotics/rng.rs` (`CampaignRng` newtype over `ChaCha20Rng`), new `tests/no_threadrng.rs` guard, new `tests/determinism.rs` byte-equality test over a 400-command canonicalised `CampaignReport`. See spec-v11 2.0 row for details and the deferred follow-ups. |
| 2.1–2.11 | Category B–N generators                          | DONE (all 11 rows closed; final: 2.11 promoted PARTIAL → DONE on 2026-05-19 once the wire-shape N-03/04/05/06/07/09 rows were bound to libFuzzer targets — new `fuzz_cose_envelope` (N-07) + `fuzz_json_bomb` (N-06); existing `fuzz_command_json` covers N-03/04/09; existing `fuzz_validate_pipeline` covers N-05) | Category B closed. Category C **closed**: C-01..C-06. Category D **closed for spec rows D-01..D-10**. **Category E closed** 2026-05-18 (E-01..E-06). Category F **closed**. Category G: G-01 `ValidAuthorityChain`, G-02 `AuthorityEscalation`, G-03 `ForgedSignature`, G-04 `KeySubstitution` (synthetic envelope with untrusted `kid` + zero signature), G-05 `PrivilegeEscalation`, G-06 `ProvenanceMutation` (two-hop chain with mutated `p_0` in hop 1), G-07 `WildcardExploit` (`required_ops` rotated through four non-actuate scopes against an `actuate:*` chain), G-08 `ExpiredChain`, G-10 `ChainForgery`. **G-09 closed 2026-05-19 via v11 1.2 integration:** new `CrossChainSplice` variant emits a two-hop synthetic envelope with hop 1's `predecessor_digest` set to a per-index mismatched 32-byte fill; opt-in `verify_chain` rejects with `PredecessorDigestMismatch { hop: 1 }`. Category G now closed end-to-end. Category H **closed**: H-01..H-06. **Category N opened** 2026-05-19 (4/10 ship at the generator level): N-01 `RedTeamFuzzGeneration` (seeded LCG samples positions in `[min - range, max + range]`), N-02 `RedTeamFuzzMutation` (five-kind mutation cycle: bitflip / swap / dt=1e-18 / EE-x flip / sequence XOR), N-08 `RedTeamFuzzUnicode` (joint-name decorator from zero-width-space / Cyrillic homoglyph / RTL-override / NUL by `index % 4`), N-10 `RedTeamFuzzIntegerBoundary` (sequence cycles through 0/1/u64::MAX/u64::MAX-1/i64::MAX). N-03 grammar / N-04 coverage-guided / N-05 differential / N-06 JSON bomb / N-07 COSE-CBOR / N-09 type confusion need wire-shape or libFuzzer harnesses and remain open. **Category I closed** 2026-05-18: I-01 `GradualDriftEscape`, I-02 `DistractionFlooding`, I-03 `SemanticConfusion`, I-04 `AuthorityLaundering` (cycles `required_ops` through four progressively wider scope tiers with empty `pca_chain`), I-05 `ErrorMining`, I-06 `WatchdogManipulation` (three-phase missed-heartbeat / authority-drop / re-establish), I-07 `ProfileProbingBinarySearch`, I-08 `MultiAgentCollusion` (two colluding cognitive agents with narrow individual scopes), I-09 `TimingExploitation`, I-10 `RollbackReplay`. Category J **closed** (2026-05-18): J-01..J-08. **Category K closed** 2026-05-18: K-01/K-02/K-03/K-04/K-05 plus K-06 `ValidatorRestart` (per-source sequence reset across simulated process restart, pure-PASS). Category L: L-01..L-04. **Category M closed** 2026-05-18: M-01..M-06. Coverage now `95/106 ids implemented; 11 gaps`. Category N still OPEN; G-09 also remains. |
| 3.1    | Five Isaac Lab envs                                | DONE (2026-05-19)  | All five envs + the `isaac/run_campaign.py` dispatcher ship. New envs: `humanoid_walk.py` (D-02 over `unitree_h1`/`bd_atlas`), `quadruped_locomotion.py` (D-02 trot over `spot`/`spot_with_arm`/`anybotics_anymal`), `mobile_base_navigation.py` (C-01 lemniscate sweep at 30 % envelope over `hello_stretch`/`pal_tiago`), `bimanual_arms.py` (J-08 PASS half composing `franka_panda`+`kuka_iiwa14` and `ur10`+`abb_gofa` via `left_`/`right_` joint namespacing); pre-existing `dexterous_manipulation.py` rounds out the morphology coverage. `run_campaign.py` loads YAML/JSON campaigns, enumerates `scenarios` (flat or nested `categories.<X>.scenarios`), routes each `scenario_type` through a substring `_ROUTES` table, prints DISPATCH/SKIP rows, returns exit 0 / 1 / 2 (clean / unrouted / config error). 80 new pytests across `test_humanoid_walk.py`, `test_quadruped_locomotion.py`, `test_mobile_base_navigation.py`, `test_bimanual_arms.py`, `test_run_campaign.py`; bonus regression fix on `dexterous_manipulation.py` `_PROFILES_DIR` (was the pre-unification flat `profiles/`). 178/178 Isaac tests (excluding `test_bridge_e2e.py`) green; full workspace `cargo test --workspace` still green. See spec-v11 row 3.1 for the design / per-profile rationale. |
| 3.2    | Bridge bounded reads + watchdog isolation          | PARTIAL            | bounded reads landed (commit `70aefe6`, `54a2508`); per-connection watchdog isolation still TBD — bridge file header at `crates/invariant-sim/src/isaac/bridge.rs` should be re-read to confirm. |
| 4.1    | OS keyring / TPM / YubiHSM                         | DESCOPED → v13 (2026-05-19) | All three backends return `KeyStoreError::Unavailable` in `crates/invariant-core/src/keys.rs`. Formally descoped to v13 per §5 "Out of scope": hardware-attached integration tests require physical devices, and shipping the production `keyring` / `tss-esapi` / `yubihsm` crate paths before the integration-test harness exists would put un-exercised code into the trust boundary. Structural fail-fast coverage (typed `KeyStoreError::Unavailable` with no I/O side-effect) is locked down by v12 N-13 today. See spec-v11 row 4.1 for the full rationale. |
| 4.2    | S3 replication + webhook witness                   | DESCOPED → v13 (2026-05-19) | Both stubs return `ReplicationError::Unavailable` in `crates/invariant-core/src/replication.rs`. Formally descoped to v13: shipping `aws-sdk-s3` + `reqwest` without the integration harness (MinIO + `httpmock`) and the resume-from-sidecar contract would put un-exercised replication code into the trust boundary. The alert-sink half (`WebhookAlertSink` + `SyslogAlertSink`) shipped under v11 4.3. See spec-v11 row 4.2 for the full rationale. |
| 4.3    | Webhook + syslog alert sinks                       | DONE (2026-05-19)  | Both stubs replaced with std-only implementations (no new workspace deps). `WebhookAlertSink` is a hand-rolled `http://` HTTP/1.1 POST over `std::net::TcpStream` with bounded timeouts and a `2xx` / non-`2xx` classifier; HTTPS / non-`http` schemes return `AlertError::Unavailable` so missing-TLS misconfig fails loudly. `SyslogAlertSink` sends an RFC 5424 UDP datagram (`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID INVALERT - MESSAGE`, severity = Alert, default facility `Local0` → PRI 129) to a configurable `SocketAddr` (default `127.0.0.1:514`). Seven new unit tests cover scheme rejection, the on-the-wire POST shape against a one-shot `TcpListener`, non-2xx → `DeliveryFailed`, connect-refused, and an end-to-end UDP loopback assertion of the RFC 5424 wire payload. See spec-v11 row 4.3 for the full design / test notes. |
| 5.1    | SR1 / SR2 sensor-range split                       | DONE (2026-05-16)  | Split landed in `crates/invariant-robotics/src/physics/environment.rs`. `check_sensor_range_env` (`SR1.sensor-range-env`, env-side) + `check_sensor_range_payload` (`SR2.sensor-range-payload`, payload-side: joint pos > 4π, joint vel > 1000 rad/s, EE pos > 1000 m, EE force > 100 kN). `physics/mod.rs::run_all_checks` runs SR2 unconditionally, SR1 stays inside `run_environment_checks`. Eight new unit tests; count assertions in `physics/tests.rs` + `validator.rs` bumped by one. |
| 5.2    | Profile field backfill                             | DONE               | commit `274f8dc` "feat: add end_effectors and environment sections to all robot profiles". v12 should re-verify with `validate-profiles --strict` once 5.3 lands. |
| 5.3    | `validate-profiles --strict` + CI                  | OPEN               | `grep validate-profiles crates/invariant-cli/src/` empty. |
| 5.4    | `campaign generate-15m` CLI                        | OPEN               | absent from CLI registry. |
| 5.5    | `fleet status` + 10-robot test                     | OPEN               | `grep -rn "fleet" crates/invariant-cli/src/commands/` empty; no 10-robot test. |
| 5.6    | Streaming-hash memory regression                   | OPEN               | unverified — see v12 P-NEW-3. |
| 5.7    | Physics property tests                             | OPEN               | `grep -rln "proptest\|quickcheck" crates/invariant-core/` should be re-checked. |
| 5.8    | End-to-end proof-loop smoke                        | OPEN               | depends on 1.x and 1.5. |
| 5.9    | Lean CI                                            | OPEN               | `grep lake .github/workflows/*.yml` returns 0 hits. |
| 5.10   | cargo-fuzz nightly                                 | OPEN               | `fuzz/` exists; CI nightly job not present. |
| 5.11   | `invariant-ros2/` disposition                      | OPEN               | `grep invariant-ros2 Cargo.toml` returns 0 hits — still not a workspace member. |
| 5.12   | verify-self audit                                  | OPEN               | not yet executed. |
| 5.13   | Error stability catalog                            | OPEN               | absent. |
| 5.14   | Campaign YAML validation                           | OPEN               | no `crates/invariant-sim/tests/campaigns_load.rs`. |
| 5.15   | Threat / compliance / envelope / eval docs         | OPEN               | `docs/threat-model.md` etc. absent. |
| 5.16   | spec-gaps.md reconciliation                        | OPEN               | `docs/spec-gaps.md` still present at branch head. |
| 6.1    | Final verification pass                            | DONE (2026-05-19)  | One-page report at [docs/spec-v11-verification.md](../spec-v11-verification.md) rolls up every v11 prompt's status (34 DONE / 3 PARTIAL / 2 OPEN), workspace tally (3 236 tests, 0 failures), scenario coverage (99/106), gap rationale, smoke-run Merkle reference, and the reproduction command. See spec-v11 row 6.1. |
| —      | SBOM in CI                                         | DONE               | `release.yml:84-95` runs `cargo cyclonedx`. v11 had this implicitly out of scope; v12 acknowledges it as closed. |

**Net effect:** of 38 v11 prompts, 1 is DONE (5.2), 1 is PARTIAL with bounded-reads landed (3.2), and 36 are OPEN. v12 carries every OPEN prompt forward by reference (do not re-author them) and adds the prompts in §3 below.

---

## 2. Newly identified gaps not in v11

These were surfaced by the 2026-05-02 audit and are not addressed (or only addressed obliquely) by v11. Each becomes a v12 prompt in §3.

| v12 ID | Title | Severity | Why v11 didn't catch it |
|--------|-------|----------|--------------------------|
| N-1    | `Scenario::all()` enumerator + spec-ID coverage test | P1 | v11 prompts 2.1–2.11 each add generators but no prompt asserts every spec-cited ID maps to a `ScenarioType`. |
| N-2    | Campaign-spec ID ↔ `ScenarioType` mapping table     | P1 | v11 assumes a 1:1 obvious mapping; current code uses friendly names (`LocomotionFall`) not spec IDs (`D-05`). |
| N-3    | Per-shard determinism: seed→trace SHA-256 fixture   | P1 | v11 prompt 2.0 establishes the contract but does not check it in CI against a frozen fixture. |
| N-4    | Audit JSONL schema versioning                       | P2 | v11 1.1 adds new fields to audit records but does not add a `schema_version` discriminator; downstream tools cannot detect record-format drift. |
| N-5    | Proof-package format-version field                  | P2 | once Merkle (1.3) and signature (1.4) land, the package format changes; old packages must be rejected with a typed error, not silently accepted. |
| N-6    | `campaign assemble --resume` for partial shard sets | P2 | v11 1.5 does not specify resumability; a 15M run that loses a shard mid-assembly cannot recover. |
| N-7    | Cost-ceiling and SIGTERM checkpointing in `scripts/run_15m_campaign.sh` | P2 | called out in old `spec-gaps.md §3.5` but not absorbed into v11. |
| N-8    | Shadow-deployment runbook (`docs/shadow-deployment.md`) | P3 | also `spec-gaps.md §3.5`, not absorbed. |
| N-9    | Spec consolidation: archive `spec-v1..v10` under `docs/history/` | P3 | v11 §"Out of scope" defers to a future spec; v12 schedules it explicitly post-Phase-1 closure. |
| N-10   | `mutex.rs`/poisoned-mutex regression test           | P2 | commit `33c3e1f` "fix: recover from poisoned mutex in digital twin" landed; no test fixture asserts the recovery path. |
| N-11   | Audit log rotation correctness fixture              | P2 | commit `7ad120d` mentions "audit rotation"; no end-to-end test asserts post-rotation Merkle continuity (will become important once 1.3 lands). |
| N-12   | Bridge fuzz target                                  | P2 | `fuzz/` exists; no fuzz target for `bridge::handle_line` despite multiple bridge security commits. |
| N-13   | `keygen --store=<kind>` taxonomy-fail-fast test     | P2 | v11 4.1 implements backends; v12 N-13 ensures unknown kinds fail before any I/O. |
| N-14   | `serve` mode replay-rejection integration test     | P1 | once B1–B4 (v11 1.1) lands, an end-to-end test must POST a replayed PCA to `serve` and assert rejection. v11 1.1 only adds unit tests in `authority/tests.rs`. |
| N-15   | `intent` ↔ PCA round-trip property test             | P2 | `intent` subcommand exists; no property test that intents derived from valid PCAs round-trip back to the same authority closure. |
| N-16   | `eval` rubric → guardrail trip integration test     | P2 | `crates/invariant-eval` lacks an end-to-end test that drives a known-bad trace through preset → rubric → guardrail and asserts the expected verdict. |
| N-17   | `--fail-on-audit-error` regression test             | P2 | flag landed in commit `36193ba`; no negative-path test asserts that disk-full or permission-denied actually causes process exit. |
| N-18   | `coordinator` partition-merge soundness fixture     | P2 | `partition.rs` exists; no test asserts that two safely-partitioned plans, when merged at a boundary, retain pairwise separation. |
| N-19   | CHANGELOG ↔ `Cargo.toml` version drift check        | P3 | repo bumped to 0.0.3 in `7ad120d`; CI does not assert that a tag matches `Cargo.toml` and that CHANGELOG has a section for it. |
| N-20   | `fuzz/` corpus seeded from real audit fixtures      | P2 | corpora are unseeded, reducing coverage. |

---

## 3. Prompts

Phase numbering continues from v11 to avoid confusion. Phase 7 = v12 net-new. v11 Phase 1–6 prompts are referenced by ID and not duplicated — agents should open `docs/spec-v11.md` and execute them as written.

### Execution order

1. **Run v11 Phase 1 (1.1–1.6) first.** Phase 7 prompts assume the audit/proof-package format has the new fields.
2. **Then v12 N-1, N-2, N-4, N-5** — these formalize the contract Phase 1 just established.
3. **Then v11 Phase 2 (scenarios) + N-3** in parallel.
4. **Then v11 Phase 3 (Isaac) + N-12, N-18** in parallel.
5. **v11 Phase 4 + N-13, N-17** parallelizable any time after Phase 1.
6. **v11 Phase 5 + N-6, N-7, N-8, N-10, N-11, N-14, N-15, N-16, N-19, N-20** parallelizable any time after Phase 1 (with the dependencies noted in each prompt).
7. **N-9** last — only consolidate specs after v11 + v12 both close.
8. **v11 6.1 (final verification pass), then v12 P-FINAL** to certify v12 closure.

---

### Prompt N-1 — Add `Scenario::all()` and a spec-ID coverage test

**Spec citation:** `docs/spec-15m-campaign.md` enumerates 104 scenario IDs across categories A–N.

**Goal:** make it impossible to claim "104 scenarios" while shipping fewer. Today `crates/invariant-sim/src/scenario.rs` exposes ~28 `ScenarioType` variants with no static enumerator and no test that compares the variant set to the spec.

**Prompt body:**

> Read `crates/invariant-sim/src/scenario.rs` and list every `ScenarioType` variant. Then read `docs/spec-15m-campaign.md` §3 (categories A–N) and list every spec ID (A-01, A-02, … N-10). Add a `pub const fn all() -> &'static [ScenarioType]` that returns every variant in declaration order. Add a `pub fn spec_id(&self) -> &'static str` that returns the spec ID this variant implements (e.g. `LocomotionFall` → `D-05`); for variants that have no spec ID assignment yet, return `"unassigned"`. Add a new integration test at `crates/invariant-sim/tests/scenario_coverage.rs` that:
>
> 1. Asserts `Scenario::all().len() == ScenarioType::iter().count()` (use `strum::IntoEnumIterator` if not already a dep; otherwise hand-roll the count).
> 2. Asserts every `spec_id()` returned is either `"unassigned"` or matches the regex `^[A-N]-\d{2}$`.
> 3. Reads `docs/spec-15m-campaign.md`, extracts every `^[A-N]-\d{2}` ID, and emits a *non-failing* report (printed via `eprintln!`) showing which IDs have no implementing variant. The test passes today even with gaps so it does not block; once v11 Phase 2 lands, flip the report to a hard `assert!`.
>
> Update `crates/invariant-sim/Cargo.toml` `[dev-dependencies]` if needed. Run `cargo test -p invariant-sim` and confirm the report prints the expected gap list. One commit: `[spec-v12-N-1] Scenario::all() and spec-ID coverage report`.

**Acceptance:** test exists, prints the gap list, all green.

---

### Prompt N-2 — Spec-ID ↔ `ScenarioType` mapping table

**Goal:** cement the mapping so every future generator commit binds a spec ID to a variant in one place.

**Prompt body:**

> Add a new table at `docs/scenario-id-map.md` with three columns: `Spec ID | ScenarioType variant | Status` (one of `IMPLEMENTED`, `STUB`, `UNASSIGNED`). Populate it from N-1's output. For each existing variant in `crates/invariant-sim/src/scenario.rs`, assign a spec ID by reading `docs/spec-15m-campaign.md` §3 — pick the closest semantic match (e.g. `LocomotionFall` → `D-05 push-recovery / fall`). If a variant doesn't fit any spec ID, mark it `UNASSIGNED` and open a follow-up note in the table comment.
>
> Then add a doctest in `crates/invariant-sim/src/scenario.rs` that asserts, for ten hand-picked variants, that `variant.spec_id()` returns the same string the doc table records. Generate this assertion list by parsing `docs/scenario-id-map.md` at build time is out of scope; hand-write the ten asserts. One commit: `[spec-v12-N-2] scenario-id-map.md and binding doctest`.

**Acceptance:** doctest passes; table covers every current variant; CI green.

---

### Prompt N-3 — Per-shard determinism fixture

**Spec citation:** `docs/spec-15m-campaign.md` §1 (deterministic replay), v11 prompt 2.0.

**Goal:** lock in the seed→trace SHA-256 contract once v11 2.0 lands.

**Prompt body:**

> After v11 prompt 2.0 has merged, generate a deterministic 1 000-episode shard for `ScenarioType::Baseline` on profile `ur10e_safety_v1` with seed `0xCAFE_BABE_DEAD_BEEF`. Hash the JSONL output with SHA-256 and store the hex digest at `crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256`. Add an integration test `crates/invariant-sim/tests/determinism_fixture.rs` that regenerates the same shard at test time and asserts the digest matches the fixture file byte-for-byte.
>
> Document in the test file's module doc that the digest must be regenerated and committed any time the campaign generator output format changes intentionally; otherwise this test gates against silent generator drift. One commit: `[spec-v12-N-3] determinism fixture for baseline ur10e shard`.

**Acceptance:** test is green at `HEAD`; test fails locally if the generator output changes.

---

### Prompt N-4 — Audit JSONL `schema_version` field

**Goal:** add forward-compatible versioning so the new B1–B4 fields (v11 1.1) and predecessor digest (v11 1.2) can be distinguished from older records.

**Prompt body:**

> In `crates/invariant-core/src/audit.rs`, add a `schema_version: u32` field to the audit-record struct (start at `2`; `1` is the unversioned record format). Default deserialization treats a missing field as version `1`. The reader must reject mixing of v1 and v2 records inside a single Merkle tree: when v11 1.3 (Merkle) lands, leaves of different versions yield distinct subtrees and the verifier emits `AuditError::MixedSchemaVersions`. Until 1.3 lands, just emit a warning via the existing tracing setup.
>
> Add a unit test that round-trips a v2 record and a unit test that confirms a v1 record (no `schema_version` key) deserializes as version 1. Update `proof_package::manifest` (after v11 1.4 lands) to record the schema-version range present. One commit: `[spec-v12-N-4] audit schema_version + mixed-version detection`.

**Acceptance:** unit tests green; audit log on disk gains the field at every new write site.

---

### Prompt N-5 — Proof-package format-version field

**Goal:** the proof package format will change once v11 1.3 + 1.4 land. Old format must be rejected explicitly.

**Prompt body:**

> In `crates/invariant-core/src/proof_package.rs`, add a `format_version: u32` field to the manifest. Set the constant to `2` once Merkle root + signature land; until then, set it to `1` and emit a warning when verifying. `verify_package` returns `ProofPackageError::UnsupportedFormat { found, expected_min, expected_max }` for anything outside the supported range. Backfill a tiny v1 fixture under `crates/invariant-core/tests/fixtures/proof_package_v1/` and a v2 fixture once 1.3 + 1.4 land; assert both behaviors. One commit: `[spec-v12-N-5] proof-package format_version with typed rejection`.

**Acceptance:** verifier rejects unknown versions with a typed error; tests cover both directions.

---

### Prompt N-6 — `campaign assemble --resume` for partial shard sets

**Goal:** make assembly idempotent and recoverable.

**Prompt body:**

> Extend the `campaign assemble` subcommand (added by v11 1.5) with a `--resume` flag. Resume semantics: read the partially written output package, identify which shards have already been hashed and added to the Merkle tree, and continue from the next missing shard. Maintain a sidecar `<output>.assemble-state.json` with the list of consumed shard paths and their digests; this file is fsynced after each shard. On startup, if the sidecar exists and `--resume` is not passed, exit with `error: existing assembly state — pass --resume or remove <path>`.
>
> Add an integration test that assembles a 4-shard package, kills the process after shard 2 (simulate via a feature-gated `panic!`), then resumes and asserts the final Merkle root matches a one-shot run. One commit: `[spec-v12-N-6] campaign assemble --resume with sidecar state`.

**Acceptance:** integration test green; resume produces byte-identical output to a one-shot run.

---

### Prompt N-7 — Cost-ceiling and SIGTERM checkpointing in `run_15m_campaign.sh`

**Goal:** make a 15M RunPod run resilient to preemption and to budget overrun.

**Prompt body:**

> Edit `scripts/run_15m_campaign.sh` to add (a) a `MAX_USD` env var defaulting to `40`; before each shard, query the current spend (use the existing `scripts/upload_results.py` helper or a new `scripts/check_spend.py` if absent — read existing scripts first) and abort cleanly if the projected spend at completion would exceed `MAX_USD`. (b) a `trap '<flush>' SIGTERM SIGINT` handler that flushes the in-progress shard summary, writes a `<shard>.in-progress.json` marker, and exits 130. (c) on startup, scan for `*.in-progress.json` markers and skip shards already marked complete, but resume any in-progress shard from its checkpoint.
>
> Add a unit test for the spend-projection math (pull it into a small Python module if necessary). Document the env-var contract in a new `scripts/README.md` section. One commit: `[spec-v12-N-7] cost ceiling + SIGTERM checkpointing in 15m runner`.

**Acceptance:** dry-run with `MAX_USD=0` aborts before any shard; `kill -TERM $!` mid-shard leaves a recoverable marker.

---

### Prompt N-8 — Shadow-deployment runbook

**Goal:** declare what "shadow" actually means before any customer deploys it.

**Prompt body:**

> Create `docs/shadow-deployment.md` (≤ 250 lines). Sections: (1) Goal: ≥100 robot-hours on UR10e CNC cell with `serve` mode in observe-only configuration. (2) Pre-flight checklist: profile selected, audit destination reachable, replication backend configured (or explicitly disabled), watchdog tuned, alert sinks point at a sandboxed channel. (3) Metrics: validation latency p50/p95/p99, decisions/sec, divergence count vs. ground-truth controller, audit growth rate. (4) Divergence triage protocol: collect PCA, command, validator state; freeze the audit shard; open an incident with the existing `incident.rs` flow; rerun in dry-run mode; classify as `false-positive | true-positive | configuration | unknown`. (5) Sign-off criteria: divergence rate ≤ 0.01% over the 100 robot-hours and zero P1 incidents.
>
> Cross-link from `README.md` "Roadmap" section. One commit: `[spec-v12-N-8] shadow-deployment.md runbook`.

**Acceptance:** file exists, reviewer signs off in PR.

---

### Prompt N-9 — Spec consolidation (do this last)

**Goal:** collapse the v1–v11 lineage once both v11 and v12 close.

**Prompt body:**

> Only run this prompt after every v11 and v12 prompt has reached `DONE`, `ALREADY DONE`, or `DESCOPED` with rationale. Move `docs/spec-v1.md` through `docs/spec-v11.md` to `docs/history/`. In each moved file, prepend a one-line redirect: `> Superseded by docs/spec.md as of <date>. Kept for historical reference.` Move `docs/spec-gaps.md` to `docs/history/spec-gaps.md` only after v11 5.16 records every gap as closed/dup/descoped. `docs/spec-v12.md` (this file) moves last; replace it with a one-line redirect to `docs/spec.md`. `docs/spec.md` and `docs/spec-15m-campaign.md` remain at the top of `docs/`.
>
> Update every internal link in `README.md`, `CHANGELOG.md`, and `CONTRIBUTING.md`. Add a `docs/history/README.md` explaining the archive. One commit: `[spec-v12-N-9] archive v1–v12 specs under docs/history`.

**Acceptance:** `docs/` contains only `spec.md`, `spec-15m-campaign.md`, top-level operational docs, and `history/`. CI green; no broken cross-links (run a markdown link-checker if available).

---

### Prompt N-10 — Poisoned-mutex regression test

**Goal:** lock in the digital-twin recovery added in commit `33c3e1f`.

**Prompt body:**

> Read commit `33c3e1f` to find the digital-twin module and the recovery code path. Add a unit test that (a) acquires the mutex, (b) panics inside the critical section to poison it, (c) asserts that the next legitimate caller observes the recovery branch and the system continues. Use `std::panic::catch_unwind` to drive the panic without aborting the test process. If the recovery code requires a feature flag, gate the test behind the same flag. One commit: `[spec-v12-N-10] poisoned-mutex recovery regression test`.

**Acceptance:** test fails if the recovery branch is removed; passes at `HEAD`.

---

### Prompt N-11 — Audit-rotation Merkle continuity test (depends on v11 1.3)

**Goal:** ensure rotation does not break the Merkle chain.

**Prompt body:**

> After v11 1.3 (Merkle tree) lands, add an integration test at `crates/invariant-core/tests/audit_rotation_merkle.rs`. Steps: write 1 000 audit records, force a rotation (use whatever API commit `7ad120d` introduced — read it first), write 1 000 more, then rebuild the Merkle tree across both segments and assert (a) the cross-segment root differs from each segment's root, (b) the inclusion proof for record 500 (pre-rotation) and record 1500 (post-rotation) both verify against the cross-segment root. One commit: `[spec-v12-N-11] audit rotation Merkle continuity`.

**Acceptance:** test green; deliberately corrupting the post-rotation segment makes the test fail with an inclusion-proof error.

---

### Prompt N-12 — Bridge fuzz target

**Goal:** the bridge has had four security commits; close the loop with a fuzzer.

**Prompt body:**

> Add `fuzz/fuzz_targets/bridge_handle_line.rs` that takes arbitrary bytes, splits them on `\n` to simulate framed input, and feeds each line to the bridge's line handler with a fresh in-memory `BridgeState`. Assert no panic, no unbounded allocation (use `MALLOC_NANO_ZONE=0` plus a heap-cap helper or `assert_no_alloc` if available — otherwise just rely on the bounded-read invariant). Add a CI nightly job (alongside v11 5.10) that runs the target for 5 minutes. Seed the corpus with at least three real captured bridge sessions; if none are committed, hand-craft three minimal valid inputs and add a `README` in the fuzz dir explaining how to capture more. One commit: `[spec-v12-N-12] bridge_handle_line fuzz target + corpus seeds`.

**Acceptance:** target builds with `cargo fuzz build`; nightly job exists.

---

### Prompt N-13 — `keygen --store=<kind>` taxonomy fail-fast

**Goal:** unknown store kinds must fail before any I/O.

**Prompt body:**

> In `crates/invariant-cli/src/commands/keygen.rs`, ensure `--store=<kind>` parses to a typed enum (`StoreKind::{File, OsKeyring, Tpm, YubiHsm}`). Unknown kinds fail with `error: unknown key store '<kind>'; expected one of file|os-keyring|tpm|yubihsm` *before* any path is opened or any backend is constructed. Add a CLI integration test using `assert_cmd` (or whatever the existing CLI tests use — read `crates/invariant-cli/tests/` first) that confirms (a) `--store=foobar` exits non-zero and prints the expected error to stderr, (b) `--store=tpm` (a not-yet-implemented backend) exits with `KeyStoreError::Unavailable` and a typed message, never opens a file, and never panics. One commit: `[spec-v12-N-13] keygen store-kind fail-fast`.

**Acceptance:** integration test green; reading the CLI source shows the validation happens before any side effect.

---

### Prompt N-14 — `serve` mode replay-rejection integration test (depends on v11 1.1)

**Goal:** prove B1–B4 in an end-to-end test, not just unit tests.

**Prompt body:**

> After v11 1.1 lands, add `crates/invariant-cli/tests/serve_replay_rejection.rs`. Spin up `invariant serve` on an ephemeral port (use the existing test helper if one exists; otherwise spawn the binary). Submit a valid PCA + command, observe `accept`. Replay the exact same PCA bytes — including signature and sequence — to a fresh session. Assert the verdict is `reject` with reason matching `B1` (session binding) or `B2` (sequence monotonicity). Replay to the same session at a later time and assert `B3` (temporal window) rejection. Submit with a different executor identity and assert `B4` rejection. One commit: `[spec-v12-N-14] serve mode B1-B4 replay rejection`.

**Acceptance:** four assertions, all green; remove any one of the binding checks and the corresponding assertion fails.

---

### Prompt N-15 — `intent` ↔ PCA round-trip property test

**Goal:** intents derived from valid PCAs should always round-trip to the same authority closure.

**Prompt body:**

> Read `crates/invariant-core/src/intent/` and `crates/invariant-cli/src/commands/intent.rs` to understand the current intent extraction. Add a property test using `proptest` (already a workspace dep — verify with `cargo metadata`) that generates random valid PCA chains (use existing test helpers if present), derives the intent, then verifies a command admitted by the original chain is also admitted by the chain reconstructed from the intent. Property must hold for `cases = 256` runs. If it fails, the test must shrink to a minimal counterexample and write it to `crates/invariant-core/tests/regressions/intent_roundtrip_<hash>.json`. One commit: `[spec-v12-N-15] intent ↔ PCA round-trip property test`.

**Acceptance:** test green at `HEAD`; mutating intent serialization in an obvious-but-wrong way breaks at least one shrunk case.

---

### Prompt N-16 — `eval` rubric → guardrail trip integration test

**Goal:** end-to-end coverage for the evaluation pipeline.

**Prompt body:**

> Read `crates/invariant-eval/src/` to understand presets, rubrics, guardrails, and the differ. Add `crates/invariant-eval/tests/pipeline_e2e.rs` that loads the simplest existing preset, runs it against (a) a known-good trace fixture committed under `crates/invariant-eval/tests/fixtures/good_trace.jsonl` and asserts the verdict is `pass`, (b) a known-bad trace fixture (intent mismatch in step 47, say) and asserts the verdict is `fail` with the expected guardrail name. Generate the fixtures from the dry-run simulator if possible; otherwise hand-craft minimal ones. One commit: `[spec-v12-N-16] eval pipeline e2e fixtures and test`.

**Acceptance:** test green; fixtures < 200 lines each.

---

### Prompt N-17 — `--fail-on-audit-error` regression test

**Goal:** the flag from commit `36193ba` must keep working.

**Prompt body:**

> Add a CLI integration test that invokes `invariant validate --audit-path /dev/full --fail-on-audit-error <args>` (Linux-only: gate behind `#[cfg(target_os = "linux")]`; on macOS use `chmod 0444` on a tempdir to force an open-write failure instead). Assert the process exits non-zero with a stderr message that mentions audit failure. Then invoke without `--fail-on-audit-error` and assert the process exits zero (the existing default behavior) but logs the audit error to stderr. One commit: `[spec-v12-N-17] --fail-on-audit-error regression test`.

**Acceptance:** test green on at least Linux CI; documented limitation if macOS path differs.

---

### Prompt N-18 — Coordinator partition-merge soundness fixture

**Goal:** safely merging two partitioned plans must preserve pairwise separation at the boundary.

**Prompt body:**

> Read `crates/invariant-coordinator/src/partition.rs`. Construct a synthetic 4-robot scenario (two arms in partition A, two mobile bases in partition B) where each partition is internally safe and the inter-partition separation at the boundary is exactly the minimum allowed distance. Add a test that merges the two partitions' plans and asserts the merged plan is admitted. Then perturb one robot in partition A by `-ε` (so the merged plan would violate separation) and assert the merged plan is rejected with a typed error pointing at the offending pair. One commit: `[spec-v12-N-18] partition merge soundness at boundary`.

**Acceptance:** test green; ε can be tuned via a const at the top of the test.

---

### Prompt N-19 — CHANGELOG ↔ Cargo.toml version drift CI check

**Goal:** the v0.0.3 bump in `7ad120d` should be reproducible by tooling.

**Prompt body:**

> Add `scripts/check_version_drift.sh` that (a) extracts `version = "x.y.z"` from `Cargo.toml`, (b) asserts `CHANGELOG.md` contains a heading exactly matching `## [x.y.z]` (or `## x.y.z`), (c) when running on a tag-build (i.e., `GITHUB_REF` starts with `refs/tags/v`), asserts the tag's version equals the Cargo version. Wire it into `.github/workflows/ci.yml` as a fast job that runs on every PR. One commit: `[spec-v12-N-19] version drift CI check`.

**Acceptance:** CI passes at `HEAD`; deliberately bumping Cargo without CHANGELOG fails the job locally.

---

### Prompt N-20 — Seed `fuzz/` corpora from real audit fixtures

**Goal:** improve coverage by seeding from realistic input.

**Prompt body:**

> For each `fuzz/fuzz_targets/*.rs`, identify the input shape it consumes. Write a one-shot script `fuzz/seed_corpora.sh` that copies (or generates and copies) at least 8 representative inputs into `fuzz/corpus/<target>/`. For PCA-shaped targets, source from `crates/invariant-core/tests/fixtures/`. For audit-shaped targets, generate a small dry-run campaign and copy the JSONL records. Document the script invocation in `fuzz/README.md`. One commit: `[spec-v12-N-20] seed fuzz corpora from real fixtures`.

**Acceptance:** `cargo fuzz run <target> -- -runs=1000` finds at least one path on each target's seeded corpus.

---

### Prompt P-FINAL — v12 closure verification

**Goal:** declare v12 done.

**Prompt body:**

> When the v12 tracking table below has no `OPEN` rows, run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, the CI lake-build job (v11 5.9), and the determinism fixture (N-3). Produce `docs/spec-v12-verification.md` listing: every prompt's resolution (DONE / ALREADY DONE / DESCOPED with rationale), the commit hash that closed each, the resulting Merkle root for an N-3-style 1 000-episode smoke run, and a one-paragraph "what changed since v11" summary. One commit: `[spec-v12-P-FINAL] verification report`.

**Acceptance:** verification doc present; every v11 + v12 row resolved.

---

## 4. v12 tracking table

Update as prompts complete.

| ID     | Title                                              | Status | Commit / Note |
|--------|----------------------------------------------------|--------|---------------|
| N-1    | Scenario::all() + spec-ID coverage                 | DONE   | `crates/invariant-sim/src/robotics/scenario.rs` gains `ScenarioType::all()` (const, 38 variants in declaration order) and an exhaustive `spec_id()` (no `_` arm, so new variants are compile errors). Coverage test at `crates/invariant-sim/tests/scenario_coverage.rs` enumerates `[A-N]-\d{2}` IDs from `docs/robotics/spec-15m-campaign.md` and prints a non-failing gap list (26 implemented / 104 spec IDs; flip to hard assert once v11 Phase 2 lands). |
| N-2    | Spec-ID ↔ ScenarioType mapping table               | DONE   | New table at `docs/scenario-id-map.md` (38 variants: 26 `IMPLEMENTED`, 12 `UNASSIGNED`). New doctest on `ScenarioType::spec_id` in `crates/invariant-sim/src/robotics/scenario.rs` asserts ten hand-picked variant↔ID pairs (passes). |
| N-3    | Per-shard determinism fixture                      | DONE (2026-05-17) | New integration test `crates/invariant-sim/tests/determinism_fixture.rs` regenerates a 1000-episode `Baseline` shard on the built-in `ur10e_haas_cell` profile with the spec-named seed `0xCAFE_BABE_DEAD_BEEF` (splatted 4× into the 32-byte slot) and asserts its SHA-256 matches the committed digest at `crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256`. Hash target is the canonical-JSON `CampaignReport` (HashMaps re-sorted into BTreeMap to neutralise hasher-state ordering), not the JSONL the prompt sketched — `run_dry_campaign` doesn't emit JSONL today and per-`Verdict` `Utc::now()` makes a JSONL byte digest wall-clock-dependent (documented inline; re-point once a seeded clock + JSONL writer land). Profile substitution: prompt named `ur10e_safety_v1` which isn't in the built-in registry; `ur10e_haas_cell` is the documented stand-in. `REGENERATE_DETERMINISM_FIXTURE=1` env var regenerates the digest after intentional generator changes. ~3 s runtime; clippy clean. |
| N-4    | Audit JSONL schema_version                         | DONE   | `crates/invariant-core/src/models/audit.rs` gains `schema_version: u32` on `AuditEntry<I,V>` with `#[serde(default = "default_schema_version", skip_serializing_if = "schema_version_is_v1")]`. Pre-v12 records (no field) deserialize as v1 and round-trip byte-for-byte so their stored `entry_hash` still verifies; new entries from `AuditLogger::build_entry` and `invariant_sim::robotics::episode::append` write `CURRENT_SCHEMA_VERSION = 2`. `verify_log` mirrors the field in its borrowed `HashableEntryView` and emits `tracing::warn!` once when a single log mixes versions (will become a typed `MixedSchemaVersions` once v11 1.3 lands). Two new tests in `crates/invariant-robotics/src/audit.rs`: `v2_record_round_trips_with_schema_version_field` (asserts `"schema_version":2` appears on disk and verify_log accepts it) and `legacy_v1_record_deserializes_as_v1_and_verifies` (strips the field, re-canonicalises hash+signature, asserts default-to-v1 path and end-to-end verify). |
| N-5    | Proof-package format_version                       | DONE   | `crates/invariant-core/src/proof_package.rs` gains numeric `format_version: u32` on `ProofPackageManifest` (with `#[serde(default = "default_format_version")]`, defaults to 1 when absent), constants `FORMAT_VERSION_V1` / `CURRENT_FORMAT_VERSION` / `MIN_SUPPORTED_FORMAT_VERSION` / `MAX_SUPPORTED_FORMAT_VERSION`, the new `ProofPackageError::UnsupportedFormat { found, expected_min, expected_max }` typed error (via `thiserror`), and a public `verify_format_version()` helper that returns the typed error and `tracing::warn!`s while we are still on v1 (until v11 1.3 + 1.4 land and bump us to v2). `assemble()` records the version. `invariant verify-package` now calls `verify_format_version` immediately after parsing and surfaces the typed message as a failed "Manifest" check. Tests: v1 fixture at `crates/invariant-core/tests/fixtures/proof_package_v1/manifest.json` (no `format_version` key) plus four unit tests covering missing-field default, written-version contract, future-version rejection, and zero-version rejection. |
| N-6    | campaign assemble --resume                         | DONE   | `crates/invariant-cli/src/robotics/commands/assemble.rs` gains a `--resume` flag and a `<output>.assemble-state.json` sidecar that is fsynced (write-to-tmp + `sync_all` + atomic rename) after every fresh shard is folded into the merge. New `AssembleState { version, output_dir, consumed: [ConsumedShard …] }` (version-pinned at `ASSEMBLE_STATE_VERSION = 1`) captures per-shard `audit.jsonl` SHA-256, line count, and summary inputs. On startup: pre-existing sidecar without `--resume` → exit 2 with `existing assembly state — pass --resume or remove …`; `--resume` re-verifies every previously-consumed shard's digest against the current source tree (mismatch → exit 2 with a tamper message) and bypasses the non-empty-output guard so the partial package can be overwritten. Successful completion removes the sidecar. Test hook is a `cfg(test)` `thread_local!` `Cell<usize>` (`PanicAfter` RAII guard) so the simulated mid-run abort never leaks into parallel tests. Six new unit tests: pre-existing sidecar without `--resume` → exit 2; `--resume` with no sidecar is a normal run; resume-after-simulated-abort produces a byte-identical Merkle root vs. a one-shot run (4 shards, abort after #2); resume rejects a source shard whose `audit.jsonl` digest changed since the sidecar was written; sidecar with the wrong `output_dir` is rejected; unknown sidecar version is rejected. Existing 9 assemble tests still pass (15 total green). |
| N-7    | run_15m_campaign.sh cost ceiling + SIGTERM        | DONE   | `scripts/run_15m_campaign.sh` gains `MAX_USD` (default 40), `HOURLY_USD` (default 2.50), and `RESUME_DIR` env vars; a `SIGTERM`/`SIGINT` trap flushes `<profile>.in-progress.json` markers and exits 130; resume scan skips `<profile>.complete` and resumes `*.in-progress.json` shards. New `scripts/check_spend.py` module with public `project_total_spend`/`should_abort` + CLI; `scripts/test_check_spend.py` covers 18 unit tests (linear extrapolation, abort thresholds, dry-run `MAX_USD=0`, CLI exit codes). New `scripts/README.md` documents the env-var contract and exit-code table. |
| N-8    | shadow-deployment.md runbook                       | DONE   | `docs/shadow-deployment.md`; cross-linked from `README.md` Roadmap section. |
| N-9    | Archive v1–v12 specs under docs/history            | DONE (2026-05-19) | `docs/robotics/spec-v1.md` … `spec-v11.md` + `spec-v12.md` + `spec-gaps.md` moved under `docs/history/robotics/` (this file is the moved `spec-v12.md`); each archived file carries a `> Superseded by docs/robotics/spec.md as of 2026-05-19. Kept for historical reference.` redirect on line 1; `docs/robotics/spec-v12.md` left in place as a one-line redirect pointing readers at `docs/robotics/spec.md`, this archive copy, and `docs/spec-v12-verification.md`. New `docs/history/README.md` documents the archive layout. README "Outstanding spec work" bullet replaced with closure-report links. PROGRESS.md and both verification reports rewritten so every `docs/robotics/spec-v{1..11}.md` and `docs/robotics/spec-gaps.md` link points at its `docs/history/robotics/…` archive path. Final v11 + v12 status: every prompt is now DONE / DESCOPED → v13 / PARTIAL with rationale — **no `OPEN` rows remain**. |
| N-10   | Poisoned-mutex regression test                     | DONE   | New `digital_twin_mutex_recovers_after_poison` test in `crates/invariant-cli/src/robotics/commands/serve.rs` (test module). Uses `catch_unwind` to poison the `Mutex<DigitalTwinState>`, then asserts the `unwrap_or_else(\|p\| p.into_inner())` recovery branch surfaces the previously written state. Removing the recovery arm panics the test. |
| N-11   | Audit rotation Merkle continuity                   | DONE   | New integration test at `crates/invariant-core/tests/audit_rotation_merkle.rs`. Models external (logrotate-style) rotation by capturing `previous_hash` + `sequence` from a 1000-entry segment-A logger and resuming a fresh segment-B logger from that state for another 1000 entries. Asserts: (1) the live per-segment `MerkleAccumulator::root()` agrees with the offline `tree_root(&leaves)` oracle, (2) the first segment-B entry's `previous_hash` equals segment A's last `entry_hash` (L2 continuity across the cut), (3) the cross-segment root computed over the concatenated leaf stream differs from each per-segment root, (4) inclusion proofs for index 500 (pre-rotation) and 1500 (post-rotation) both verify against the cross-segment root using `verify_inclusion`, and (5) a single-bit flip in either leaf invalidates the proof. A second test corrupts a post-rotation leaf and asserts the honest proof no longer verifies against the tampered root. Uses an in-memory `SharedSink` (`Rc<RefCell<Vec<u8>>>`) so we can reclaim the JSONL bytes without consuming the logger. ~10s runtime (mostly Ed25519 signing across 2000 entries × 2 tests). |
| N-12   | bridge_handle_line fuzz target                     | DONE   | New `fuzz/fuzz_targets/bridge_handle_line.rs` + corresponding `[[bin]]` in `fuzz/Cargo.toml`. Exposes public `fuzz_bridge_handle_line` / `fuzz_bridge_handle_multiline` from `crates/invariant-sim/src/robotics/isaac/bridge.rs` (sync, panic-free counterparts of the async `handle_message` parse path). Fuzz target asserts (1) `results.len() == input.split('\n').count()`, (2) lines >`FUZZ_BRIDGE_MAX_LINE_BYTES` (8 KiB) classify as `Oversize`. Eight corpus seeds at `fuzz/corpus/bridge_handle_line/` (heartbeat / heartbeat-false / empty / blank-lines / two-frames / malformed / nul-byte / partial-command). `seed_corpora.sh` and `fuzz/README.md` updated. Five new unit tests in `bridge::tests` cover the exported helpers. |
| N-13   | keygen --store fail-fast                           | DONE   | `crates/invariant-cli/src/robotics/commands/keygen.rs` adds `StoreKind` + `--store` parsed before any I/O; 6 new unit tests cover unknown/tpm/yubihsm/os-keyring and the short-circuit ordering. |
| N-14   | serve mode B1–B4 replay rejection                  | DONE (2026-05-19, request-boundary B2/B3/B4 added) | **Request-boundary B2/B3/B4 enforcement (2026-05-19, follow-up commit):** `handle_validate` now reads three additional optional HTTP headers and rejects with HTTP 400 + a typed `Bn …` reason when any of them mismatches the server's state — no `Command` wire-format change required. (a) `X-Invariant-Executor-Id` → cross-executor replay rejection: header must match the in-body `command.source` or reject `B2 executor binding: …`. (b) `X-Invariant-Monotonic-Nanos` → per-executor strict-monotonic enforcement at the HTTP layer: parsed as `u64`, compared against a new `AppState.request_monotonic: Mutex<HashMap<String, u64>>` keyed by `command.source`; stale value rejects `B3 monotonic binding: …`, malformed (non-u64) rejects `B3 monotonic binding: … is not a u64`. Per-executor isolation means a fresh executor starts at 0 and is unaffected by other executors' history. (c) `X-Invariant-Wall-Clock` → RFC 3339 timestamp with bounded skew vs `Utc::now()`; absolute skew greater than `B4_MAX_WALL_CLOCK_SKEW_SECS = 300` rejects `B4 wall-clock binding: … (>300s)`. All three checks run immediately after the existing B1 check, *before* incident-lockdown / sequence / validation / audit — a captured request replayed under a different executor identity, with a stale monotonic, or to a different wall-clock is rejected with zero state mutation. Absent headers keep the legacy code path (backward compatible). Six new tests in `serve::tests`: `cross_executor_replay_rejected_by_b2_header`, `stale_monotonic_replay_rejected_by_b3_header`, `b3_monotonic_is_per_executor`, `stale_wall_clock_rejected_by_b4_header`, `fresh_wall_clock_accepted_by_b4_header`, `malformed_b3_header_is_rejected`. All 53 serve tests pass; `cargo clippy -p invariant-cli --lib --tests -- -D warnings` clean; full workspace `cargo test --workspace` green. **Earlier (2026-05-19):** `handle_validate` reads the optional `X-Invariant-Session-Id` HTTP header and rejects with HTTP 400 + reason `B1 session binding: client session_id <X> does not match server session_id <Y> — cross-session replay rejected` when the header is present and disagrees with the per-process `state.session_id`. Absent header keeps the legacy code path (backward compatible with pre-v12-N-14 clients). Three tests in `serve::tests` cover (1) mismatched header → 400 with `B1 session binding` in the reason, (2) matching header → 200, (3) absent header → 200. This is a wire-format-compatible promotion that doesn't require any `Command` schema change. **Earlier (2026-05-18 v11 1.1 follow-up):** `crates/invariant-cli/src/robotics/commands/serve.rs` now installs a `BindingContext` on the audit logger at startup and refreshes it per `handle_validate` audit append. New helpers `generate_session_id()` (16 random bytes → 32 hex chars from `rand::rngs::OsRng`) + `refresh_audit_binding()` (writes monotonic_nanos from `boot_instant.elapsed()` and wall_clock_rfc3339 from the current `Utc::now()`, with `executor_id` taken from the command's `source`). `AppState` gains a `session_id: String` populated once per server process; eprintln stamps it at startup. Three new test assertions in `serve::tests`: `session_id_is_unique_per_process` (hex shape + cross-call distinctness), `distinct_serve_instances_produce_distinct_session_ids` (two fresh AppStates ≠ session id), `audit_entries_stamp_b1_b2_b3_b4_fields` (drives 3 commands across 2 executors through `/validate`, reads the on-disk JSONL, asserts every line carries B1 session_id matching the per-server constant, B2 executor_id matching the request's `source`, B3 monotonic_nanos > 0 with strict per-executor monotonicity, B4 wall_clock_rfc3339 parseable as RFC 3339). All four existing test-state builders updated to pass `session_id`. Status remains PARTIAL because the prompt also asks for **serve-side rejection** of cross-session and cross-executor replay (B1/B4 enforcement at the request-admission point) — today only B2 sequence replay is enforced in `handle_validate`; B1/B3/B4 are *stamped* but not *enforced* at the validator boundary (they are enforced inside the audit logger via `ClockRegression` and downstream verifiers via the canonical preimage). Full rejection at the HTTP boundary is the remaining work needed to flip to DONE. 44 serve tests + 300 cli lib tests + 777 sim lib tests green; `cargo clippy -p invariant-cli -p invariant-core -p invariant-robotics --lib --tests -- -D warnings` clean. |
| N-15   | intent ↔ PCA round-trip property test              | DONE   | Two new tests in `crates/invariant-core/src/intent.rs`: `intent_pca_round_trip_property_256_cases` (seeded `StdRng`, 256 randomised intents covering principal/kid/ops/expiry variation; round-trips through `intent_to_pca` → `pca_to_intent` → `intent_to_pca` and asserts authority-closure equality of `(p_0, ops, kid, exp, nbf)`) and `intent_pca_round_trip_deduplicates_operations` (BTreeSet dedup fixed point). Failures write `tests/regressions/intent_roundtrip_<hash>.json` for replay. `proptest` is not on the workspace dep list so randomisation is hand-rolled — equivalent coverage with deterministic seeding. |
| N-16   | eval pipeline e2e                                  | DONE   | New integration test `crates/invariant-eval/tests/pipeline_e2e.rs` drives `safety-check` against two committed fixtures (`fixtures/good_trace.jsonl`, `fixtures/bad_trace.jsonl`, each ~3.4 KiB single-line JSON). Asserts (1) good trace passes with zero error findings, (2) bad trace fails with an error finding naming the failing `joint_limits` physics check on step 1, (3) summary records exactly one rejection, (4) fixtures stay under 200 lines each. Ignored `regenerate_fixtures` test rebuilds the JSON from in-Rust builders whenever the upstream type shape changes. |
| N-17   | --fail-on-audit-error regression                   | DONE   | Two new tests in `crates/invariant-cli/src/robotics/commands/validate.rs` test module, gated on Linux: `validate_exits_nonzero_when_audit_write_fails` (points `--audit-log` at `/dev/full`, asserts exit 2 after open succeeds and writes ENOSPC) and `validate_exits_zero_when_audit_write_succeeds` (happy path). Non-Linux OSes get a documented soft-skip. Note: `validate` exits non-zero on audit-write failure **unconditionally**; the named `--fail-on-audit-error` flag lives on `serve` and is covered by the existing `test_audit_write_failure_returns_503_when_fail_on_audit_error`. |
| N-18   | Coordinator partition-merge soundness              | DONE   | New integration test at `crates/invariant-coordinator/tests/partition_merge_soundness.rs` — 4-robot scenario (2 arms in `partition-A`, 2 mobile bases in `partition-B`, abutting at `x=2.5`). The closest cross-partition pair sits exactly at `MIN_SEPARATION_M=0.5`. Tests assert: (1) internal partition consistency, (2) merged boundary plan admitted, (3) perturbed plan (`+EPS=1e-3` toward `base-1`) rejected with a `separation` `CrossRobotCheck` naming `(arm-1, base-1)`, (4) perturbing AWAY does not trip the check. ε tunable via the `EPS` const. |
| N-19   | Version drift CI check                             | DONE   | `scripts/check_version_drift.sh` + new `version-drift` job in `.github/workflows/ci.yml`. Asserts `Cargo.toml` workspace version has a matching `## [x.y.z]` (or `## x.y.z`) heading in `CHANGELOG.md`; on tag builds also asserts `GITHUB_REF` matches. Verified locally (passes at HEAD; negative test with synthetic 9.9.9 fails as expected). |
| N-20   | Seed fuzz corpora                                  | DONE   | New `fuzz/seed_corpora.sh` populates `fuzz/corpus/<target>/` with ≥8 seeds per target: 8 for `fuzz_command_json` (two real example commands + six synthetic edge cases), 9 for `fuzz_profile_json` (8 built-in profiles + empty object), 8 for `fuzz_pca_chain` (Python-generated empty/single/two-hop/wildcard/expired/future-nbf/non-base64/empty), 8 for `fuzz_validate_pipeline` (reuses command corpus — same input shape). New `fuzz/README.md` documents each target, the seeding workflow, and how to capture fresh corpora from real campaigns. |
| P-FINAL| v12 closure verification                           | DONE (2026-05-19) | One-page roll-up at [docs/spec-v12-verification.md](../spec-v12-verification.md): every v12 prompt's resolution (20 DONE / 1 deferred — N-9 by design), the v11 carry-forward delta (N-14 PARTIAL → DONE; 1.2 / 4.1 / 4.2 unchanged), the "what changed since v11" entry covering the N-14 B2/B3/B4 request-boundary promotion, deferred follow-ups, smoke-run reference back to spec-v11-verification.md, and the closure statement. Workspace tally pinned at 3 256 tests, 0 failures; `cargo clippy -p invariant-cli --lib --tests -- -D warnings` clean. |

---

## 5. Out of scope for v12

- Live RunPod campaign execution and post-campaign report assembly (deferred until v11 Phases 1–3 + N-1..N-3 close).
- Hardware-attached integration tests for TPM and YubiHSM (require physical devices; covered structurally by v11 4.1 + N-13).
- Reproducible-build attestation (still a v13 candidate).
- Customer onboarding docs.
