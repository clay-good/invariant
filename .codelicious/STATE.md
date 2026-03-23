# Invariant — Build State

## Current Status
Phase 1, Step 3 complete. **Quality review identified 12 P1, 18 P2, and 14 P3 findings.** The most critical: all 10 physics checks silently pass NaN inputs (IEEE 754 bypass). These must be fixed before Step 4.

## Completed Tasks

### Phase 1: Core
- [x] **Step 1 — Workspace init**: Cargo workspace, 4 crates (`invariant-core`, `invariant-cli`, `invariant-sim`, `invariant-eval`), all module stubs, 4 robot profile JSON files.
- [x] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety. Fixed all 6 P1 and all 15 P2 findings from Step 2 review.
- [x] **Step 3 — Physics checks (10)**: All 10 pure functions (P1-P10) implemented in `physics/` with `run_all_checks()` orchestrator and 64 passing tests.

---

## Review Findings — Step 3 Quality Review (2026-03-23)

Reviewed: all physics modules, all model types, CLI/sim/eval crates, workspace config, 4 robot profiles, test suite (64 tests), clippy, build.

Build: PASS. Tests: 64/64 PASS. Clippy: FAIL (1 lint error).

### P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| R1-01 | `physics/joint_limits.rs:27` | **NaN bypass**: `NaN < def.min` and `NaN > def.max` both return `false` (IEEE 754). A NaN joint position silently passes P1. Same pattern in P2-P8, P10 |
| R1-02 | `physics/velocity.rs:30` | NaN velocity: `NaN.abs()` is NaN, `NaN > limit` is `false` — silently passes P2 |
| R1-03 | `physics/torque.rs:27` | NaN effort silently passes P3 (same IEEE 754 pattern) |
| R1-04 | `physics/acceleration.rs:39,68` | NaN delta_time passes the `<= 0.0` guard; NaN velocities produce NaN accel; `NaN > max_accel` is `false` — P4 silently passes |
| R1-05 | `physics/workspace.rs:32-34` | NaN end-effector position passes all 6 AABB comparisons — silently passes P5 |
| R1-06 | `physics/exclusion_zones.rs:73-79,85-90` | NaN coordinates: `point_in_aabb` and `point_in_sphere` both return `false` for NaN — end-effector treated as "outside" every zone, silently passes P6 |
| R1-07 | `physics/self_collision.rs:72-76` | `euclidean_distance` returns NaN for NaN input; `NaN < MIN_DIST` is `false` — collision check silently passes P7 |
| R1-08 | `physics/delta_time.rs:11` | NaN delta_time: `NaN <= 0.0` false, `NaN > max` false — P8 silently passes. This also poisons P4 (acceleration depends on dt) |
| R1-09 | `physics/proximity.rs:130` | NaN position in `point_in_sphere` treated as "outside" all zones — proximity velocity scaling skipped entirely, P10 passes |
| R1-10 | `models/profile.rs:32` | **Clippy error**: manual `impl Default for SafeStopStrategy` triggers `derivable_impls` lint — `cargo clippy -D warnings` fails, blocks CI |
| R1-11 | `models/profile.rs:73-93,276` | Unbounded `Vec`/`HashMap` in `RobotProfile` (joints, zones, collision_pairs) and `SafeStopProfile` — no length caps in `validate()`, enables memory exhaustion DoS |
| R1-12 | `Cargo.toml:33` | `reqwest = "0.12"` still declared in workspace `[dependencies]` — P2-13 only partially fixed (removed from sim but not workspace). Any future crate can silently adopt it |

### P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| R2-01 | `physics/self_collision.rs:37-42` | Missing link in `end_effectors` causes pair to be **silently skipped** — misconfigured profile gets zero collision checking with no error |
| R2-02 | `physics/acceleration.rs:64-66` | Joint absent from `previous_joints` is silently skipped — new joint name in command bypasses acceleration check |
| R2-03 | `physics/proximity.rs:52-55` | Unknown joints (no definition) silently skipped with `continue` — inconsistent with P1/P2/P3 which flag unknown joints as violations |
| R2-04 | `physics/self_collision.rs:9` | `MIN_SELF_COLLISION_DIST` hardcoded to 0.01m — not configurable per-profile or per-pair; different robots need different clearances |
| R2-05 | `profiles/humanoid_28dof.json:71` | Collision pairs reference `"left_hand"`/`"right_hand"` — names absent from joint defs. P7 silently no-ops for all 5 pairs in this profile |
| R2-06 | `profiles/quadruped_12dof.json:41` | Collision pairs reference `"fl_foot"` etc. — absent from joint defs. All pairs silently skipped |
| R2-07 | `profiles/franka_panda.json:43`, `profiles/ur10.json:49` | Collision pairs use URDF link names not joint names — P7 would silently no-op unless end-effector positions match link names |
| R2-08 | `models/command.rs:15,25` | `Command.joint_states` unbounded Vec, `metadata` unbounded HashMap — no size cap against profile joint count |
| R2-09 | `models/trace.rs:16,31` | `Trace.metadata` is `HashMap<String, serde_json::Value>`, `TraceStep.simulation_state` is `Option<serde_json::Value>` — arbitrary nesting depth, stack-overflow DoS risk |
| R2-10 | `models/authority.rs:91-102,121-128` | `Pca.ops` unbounded `BTreeSet`, `AuthorityChain.hops` unbounded Vec — no max ops/hops cap |
| R2-11 | `models/verdict.rs:22-24` | `CheckResult.category` is raw String — should be enum to prevent unknown categories in audit |
| R2-12 | `models/verdict.rs:29-33` | `AuthoritySummary.operations_granted/required` are `Vec<String>` not `Vec<Operation>` — newtypes lost at verdict boundary |
| R2-13 | `models/profile.rs:258-263` | `StabilityConfig.support_polygon` accepts fewer than 3 points — degenerate polygon not validated |
| R2-14 | `models/profile.rs:103-127` | `ExclusionZone` variants never validated — sphere radius can be 0 or negative |
| R2-15 | `models/profile.rs:73,86-87` | `name`/`version` accept empty strings; `watchdog_timeout_ms` has no min (0 disables watchdog); `max_delta_time` no positive check |
| R2-16 | `commands/validate.rs:18-23` | Neither `--command` nor `--batch` is `required_unless_present` — bare invocation silently accepted |
| R2-17 | `invariant-cli/main.rs:40-48` | All stubs return exit code 2 (POSIX "usage error") — should be 1 for "not implemented" |
| R2-18 | `models/profile.rs:186` | `WorkspaceBounds::Aabb` min/max not checked for finiteness — `Infinity`/`NaN` in bounds passes validation |

### P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| R3-01 | `physics/tests.rs` | **Zero NaN/Inf tests** across all 10 checks — the most safety-critical input class has no coverage |
| R3-02 | `physics/tests.rs` | No `-0.0` tests for position/velocity/effort |
| R3-03 | `physics/tests.rs:686` | `run_all_checks` integration tests never trigger P4 or P10 failures |
| R3-04 | `physics/tests.rs:542` | No test for 0-vertex or 1-vertex support polygon in P9 |
| R3-05 | `exclusion_zones.rs:85-90`, `proximity.rs:126-131` | `point_in_sphere` copy-pasted in two modules — future fix won't propagate |
| R3-06 | `stability.rs:18` | Parameter named `center_of_mass` but docs say ZMP — CoM and ZMP are different physical quantities for moving robots |
| R3-07 | `physics/joint_limits.rs:11-12` | Empty `joints` + empty `end_effectors` trivially passes all 10 checks — a completely empty command passes the entire firewall |
| R3-08 | `Cargo.toml:31` | `tokio` workspace declaration has no features — maintenance trap for new crates |
| R3-09 | `Cargo.toml:25` | `rand = "0.8"` in crypto-adjacent code; 0.9 series has CSPRNG improvements |
| R3-10 | `commands/keygen.rs:6` | `--kid` accepts arbitrary string — path separators or shell chars could cause injection |
| R3-11 | `invariant-core/src/lib.rs:1` | `#![allow(dead_code)]` crate-wide suppresses all dead-code warnings — hides legitimate issues |
| R3-12 | `models/authority.rs:36` | `Pca`, `SignedPca`, `AuthorityChain` have fully `pub` fields — construction bypasses future chain-invariant checks |
| R3-13 | `crates/invariant-sim/`, `crates/invariant-eval/` | Stub crates declare `serde_yaml`, `regex`, `reqwest` deps but use none — dead compile-time and supply-chain weight |
| R3-14 | `Cargo.toml:19` | `coset = "0.3"` declared at workspace level but only used by `invariant-core` — should be crate-local |

---

## Prior Step 2 Review Findings — Status

| Prior ID | Status | Notes |
|----------|--------|-------|
| P1-1 through P1-6 | FIXED | All 6 P1 items resolved in Step 2 |
| P2-1 through P2-7 | FIXED | All 7 P2 items resolved in Step 2 |
| P2-8 | FIXED | `Cli::parse()` result now used for dispatch |
| P2-9 | FIXED | `try_init()` used |
| P2-10 | PARTIAL | `conflicts_with` added but `required_unless_present` missing (see R2-16) |
| P2-11 | FIXED | `ValidationMode` is a `ValueEnum` |
| P2-12 | Not verified | Low priority |
| P2-13 | PARTIAL | Removed from sim but `reqwest` remains in workspace manifest (see R1-12) |
| P2-14 | FIXED | Tokio features minimized per-crate |
| P2-15 | FIXED | `diff.rs` and `DiffArgs` present |
| P3-1 through P3-7 | FIXED | All resolved in Step 2 |
| P3-8 | FIXED | All file-path args use `PathBuf` |
| P3-9 through P3-18 | Various | Most remain; some are deferred to Steps 9/20 |

---

## Pending Tasks

### Phase 1: Core
- [x] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety. Fixed all 6 P1 and all 15 P2 findings.
- [x] **Step 3 — Physics checks (10)**: Pure functions, zero allocation, extensively tested.
- [ ] **Step 3a — Fix P1 review findings**: NaN/Inf guards in all physics checks, clippy fix, unbounded collection caps. **Must fix all R1-* and R2-01 through R2-07 before Step 4.**
- [ ] **Step 4 — Authority validation**: Ed25519 COSE_Sign1 chain verification, monotonicity, provenance.
- [ ] **Step 5 — Validator orchestrator**: Authority + physics -> signed verdict + optional signed actuation.
- [ ] **Step 6 — Signed audit logger**: Append-only, hash-chained, Ed25519-signed JSONL.
- [ ] **Step 7 — Watchdog**: Heartbeat monitor, safe-stop command generation.
- [ ] **Step 8 — Profile library**: 4 validated profiles (humanoid 28-DOF, Franka, quadruped, UR10).

### Phase 2: CLI
- [ ] **Step 9 — CLI**: clap-based, all subcommands. **Fix R2-16, R2-17, R3-10.**
- [ ] **Step 10 — Embedded Trust Plane**: `invariant serve` mode using axum.
- [ ] **Step 11 — Key management**: `invariant keygen`, key file format.

### Phase 3: Eval
- [ ] **Step 12 — Eval presets**: safety-check, completeness-check, regression-check.
- [ ] **Step 13 — Custom rubrics**: YAML/JSON loader with pattern matching. **Apply P3-13 YAML-bomb mitigations.**
- [ ] **Step 14 — Guardrail engine**: Policy-based pattern matching with actions. **Apply P3-14 regex size limits.**
- [ ] **Step 15 — Trace differ**: Step-by-step comparison with divergence detection.

### Phase 4: Simulation
- [ ] **Step 16 — Campaign config**: YAML parser, validation. **Apply P3-13 YAML-bomb mitigations.**
- [ ] **Step 17 — Scenarios**: 7 built-in scenarios.
- [ ] **Step 18 — Fault injector**: Velocity overshoot, position violation, authority escalation, chain forgery, metadata attack.
- [ ] **Step 19 — Orchestrator**: Isaac Lab bridge + DryRunOrchestrator + campaign reporter. **Remove reqwest (R1-12).**

### Phase 5: Hardening and Proof
- [ ] **Step 20 — Security hardening**: Input validation, numeric safety, file safety, identifier validation. **Fix remaining R2-* and R3-*.**
- [ ] **Step 21 — Property-based tests**: proptest for all invariants.
- [ ] **Step 22 — Adversarial integration tests**: All 12 attacks as test cases.
- [ ] **Step 23 — Documentation**: README, architecture, authority model, simulation guide, etc.
