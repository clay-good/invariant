# Invariant — Build State

## Current Status
Phase 1, Step 1 complete. Code review complete with 6 P1, 15 P2, 18 P3 findings recorded below.

## Completed Tasks

### Phase 1: Core
- [x] **Step 1 — Workspace init**: Cargo workspace, 4 crates (`invariant-core`, `invariant-cli`, `invariant-sim`, `invariant-eval`), all module stubs, 4 robot profile JSON files.

## Review Findings (Step 2 must address all P1 and P2 items)

Reviewed: `invariant-core` models, `invariant-cli`, `invariant-sim`, `invariant-eval`, workspace config, robot profiles.

### P1 — Blocking / Security

| ID | File | Line | Issue |
|----|------|------|-------|
| P1-1 | `models/command.rs` | 17 | `metadata: HashMap<String, serde_json::Value>` — unbounded recursive JSON causes stack-overflow DoS on deeply nested input; firewall can be silenced |
| P1-2 | `models/authority.rs` | 34 | `Operation` is a raw `String` type alias — any `String` is assignment-compatible; spec requires newtype with validation to make malformed ops non-representable |
| P1-3 | `command.rs:6`, `verdict.rs:8`, `authority.rs:13-15`, `actuation.rs:12` | multiple | All timestamp fields are unconstrained `String`; replay-prevention (`exp`/`nbf`) requires typed `chrono::DateTime<Utc>`; string comparison mis-orders non-zero-padded dates |
| P1-4 | `models/authority.rs:19`, `models/verdict.rs:32` | 19, 32 | `SignedPca` and `AuthorityChain` derive no serde; `AuditEntry` stores bare `Verdict` not `SignedVerdict` — audit log cannot prove which signed verdict corresponds to which entry (breaks L3) |
| P1-5 | `lib.rs:3,6` / `models/mod.rs:4,5` | multiple | Module name collision: `invariant_core::authority` (chain-validation logic) vs `invariant_core::models::authority` (data types) — `use invariant_core::authority::Pca` is a compile error |
| P1-6 | `models/profile.rs:96` | 96 | `SafeStopProfile.strategy` is free `String` — unknown strategy string loads silently; watchdog fails to issue safe-stop at runtime instead of at profile-load time (safety-critical) |

### P2 — Important / Correctness

| ID | File | Line | Issue |
|----|------|------|-------|
| P2-1 | `models/profile.rs` | 49 | `WorkspaceBounds.bounds_type` is free `String`; wrong case or unknown type silently skips workspace check |
| P2-2 | `models/profile.rs` | 38 | `JointDefinition.joint_type` is free `String`; `"Revolute"` vs `"revolute"` produces silent wrong dispatch |
| P2-3 | `models/profile.rs` | 73 | `ProximityZone.zone_type` is free `String`; `ExclusionZone` correctly uses tagged enum — inconsistency |
| P2-4 | `models/profile.rs` | 35-44 | No validation that `min < max`, `max_velocity > 0`, `max_torque > 0`, `max_acceleration > 0` on `JointDefinition` |
| P2-5 | `models/profile.rs` | 19 | `global_velocity_scale` unconstrained — value `> 1.0` silently raises velocity limits above hardware spec; negative inverts comparison |
| P2-6 | `models/profile.rs` | 76 | `ProximityZone.velocity_scale` unconstrained — value `> 1.0` allows higher-than-max velocities near humans; defeats P10 / ISO 15066 |
| P2-7 | `models/trace.rs` | 20-21 | `TraceStep.command` and `.verdict` are untyped `serde_json::Value` — malformed trace deserializes without error; double-deserialization in eval engine |
| P2-8 | `invariant-cli/src/main.rs` | 34 | `let _cli = Cli::parse()` discards result; dispatch permanently unreachable; underscore suppresses warning that would catch the error when Step 9 is implemented |
| P2-9 | `invariant-cli/src/main.rs` | 33 | `tracing_subscriber::fmt::init()` panics on double-install in tests; use `try_init()` |
| P2-10 | `commands/validate.rs` | 7-11 | `--command` / `--batch` have no `conflicts_with` or `required_unless_present` — both can be supplied simultaneously or neither supplied |
| P2-11 | `commands/validate.rs` | 13-14 | `--mode` is unconstrained `String`; spec allows only `guardian` / `shadow`; use `clap::ValueEnum` |
| P2-12 | `commands/eval.rs` | 5 | `trace` positional arg has no `#[arg(value_name = "TRACE_FILE")]`; inconsistent with all other file-path args |
| P2-13 | `invariant-sim/Cargo.toml` | 14 | `reqwest` declared with no corresponding code; bridge stub says "Unix socket" — HTTP client is unjustified and adds TLS stack attack surface |
| P2-14 | `Cargo.toml` | 31 | `tokio = "full"` workspace-wide enables every runtime subsystem; use minimal feature set per crate |
| P2-15 | `invariant-cli/src/main.rs` | — | `invariant diff trace_a.json trace_b.json` required by spec line 669 is absent — no `Commands::Diff` variant, no `diff.rs` command file |

### P3 — Quality / Future-Proofing

| ID | File | Line | Issue |
|----|------|------|-------|
| P3-1 | all model files | — | No `PartialEq` on any model type — test assertions in Steps 3/4/22 require manual field comparison |
| P3-2 | `models/verdict.rs` | 15, 23 | No `Eq, Hash` on `CheckResult` / `AuthoritySummary` — unusable as `HashMap` keys or in `HashSet` |
| P3-3 | `models/authority.rs` | 9 | `Pca.ops` is `Vec<String>` — duplicates pass monotonicity subset check; use `BTreeSet` |
| P3-4 | `models/authority.rs` | 28 | `AuthorityChain.hops` has no minimum-length check — empty-hop chain passes provenance and monotonicity vacuously |
| P3-5 | `models/profile.rs` | 56 | `ExclusionZone` enum not `#[non_exhaustive]` — adding `Cylinder` later silently ignored by downstream `_ => {}` arms in eval |
| P3-6 | `models/profile.rs` | 14 | `collision_pairs: Vec<[String; 2]>` — positional access (`pair[0]`) vs named struct `CollisionPair { link_a, link_b }` |
| P3-7 | `models/command.rs` | 35 | `CommandAuthority.required_ops` is `Vec<String>` not `Vec<Operation>` — will diverge when `Operation` becomes newtype |
| P3-8 | `invariant-cli/src/commands/*.rs` | — | All file-path args use `String` not `std::path::PathBuf` — no OS-level path validation |
| P3-9 | `commands/keygen.rs` | 7-8 | `--output` path unconstrained — future path-traversal risk when writing private key material |
| P3-10 | `commands/serve.rs` | 9-10 | `port: u16` allows privileged ports 0-1023 without guard |
| P3-11 | `invariant-core/src/lib.rs` | 2-7 | `pub mod validator` / `pub mod actuator` export modules with zero public items — broken public API surface |
| P3-12 | `models/authority.rs:9` | — | `Pca.ops` / `AuthorityChain.final_ops` should be `BTreeSet<Operation>` once P1-2 resolved |
| P3-13 | `Cargo.toml` | 34 | `serde_yaml = "0.9"` uses `libyaml-sys` with known anchor-expansion (YAML bomb) risk for future campaign/rubric YAML parsers |
| P3-14 | `invariant-eval/Cargo.toml` | 13 | `regex` dependency — future user-supplied patterns need `RegexBuilder::size_limit` + `dfa_size_limit` to prevent ReDoS |
| P3-15 | all sim/eval stub files | — | Stub files have no commented-out type scaffold — intended public API undiscoverable without reading spec |
| P3-16 | `invariant-core` stubs | — | No `#[allow(dead_code)]` at crate root — may fail CI with `-D warnings` once dependencies are imported in Step 2 |
| P3-17 | `invariant-cli/src/main.rs` | — | No `#[allow(dead_code)]` guard on command arg structs — will trigger warnings before Step 9 dispatch is wired |
| P3-18 | `models/command.rs:35` / `models/authority.rs` | — | `CommandAuthority.pca_chain` decode path to `Pca` is undocumented — Step 4 implementer must infer the base64 → COSE → Pca pipeline from context |

---

## Pending Tasks

### Phase 1: Core
- [ ] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety. **Must fix all P1 and P2 findings above.**
- [ ] **Step 3 — Physics checks (10)**: Pure functions, zero allocation, extensively tested.
- [ ] **Step 4 — Authority validation**: Ed25519 COSE_Sign1 chain verification, monotonicity, provenance.
- [ ] **Step 5 — Validator orchestrator**: Authority + physics -> signed verdict + optional signed actuation.
- [ ] **Step 6 — Signed audit logger**: Append-only, hash-chained, Ed25519-signed JSONL.
- [ ] **Step 7 — Watchdog**: Heartbeat monitor, safe-stop command generation.
- [ ] **Step 8 — Profile library**: 4 validated profiles (humanoid 28-DOF, Franka, quadruped, UR10).

### Phase 2: CLI
- [ ] **Step 9 — CLI**: clap-based, all subcommands. **Fix P2-8 through P2-15, P3-8 through P3-10.**
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
- [ ] **Step 19 — Orchestrator**: Isaac Lab bridge + DryRunOrchestrator + campaign reporter. **Remove reqwest (P2-13) unless HTTP confirmed.**

### Phase 5: Hardening and Proof
- [ ] **Step 20 — Security hardening**: Input validation, numeric safety, file safety, identifier validation.
- [ ] **Step 21 — Property-based tests**: proptest for all invariants.
- [ ] **Step 22 — Adversarial integration tests**: All 12 attacks as test cases.
- [ ] **Step 23 — Documentation**: README, architecture, authority model, simulation guide, etc.
