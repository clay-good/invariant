# Invariant — Build State

## Current Status
Phase 1, Step 1 complete: Cargo workspace initialized with 4 crates and 4 robot profiles.

## Completed Tasks

### Phase 1: Core
- [x] **Step 1 — Workspace init**: Cargo workspace, 4 crates (`invariant-core`, `invariant-cli`, `invariant-sim`, `invariant-eval`), all module stubs, 4 robot profile JSON files.

## Pending Tasks

### Phase 1: Core
- [ ] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety.
- [ ] **Step 3 — Physics checks (10)**: Pure functions, zero allocation, extensively tested.
- [ ] **Step 4 — Authority validation**: Ed25519 COSE_Sign1 chain verification, monotonicity, provenance.
- [ ] **Step 5 — Validator orchestrator**: Authority + physics -> signed verdict + optional signed actuation.
- [ ] **Step 6 — Signed audit logger**: Append-only, hash-chained, Ed25519-signed JSONL.
- [ ] **Step 7 — Watchdog**: Heartbeat monitor, safe-stop command generation.
- [ ] **Step 8 — Profile library**: 4 validated profiles (humanoid 28-DOF, Franka, quadruped, UR10).

### Phase 2: CLI
- [ ] **Step 9 — CLI**: clap-based, all subcommands.
- [ ] **Step 10 — Embedded Trust Plane**: `invariant serve` mode using axum.
- [ ] **Step 11 — Key management**: `invariant keygen`, key file format.

### Phase 3: Eval
- [ ] **Step 12 — Eval presets**: safety-check, completeness-check, regression-check.
- [ ] **Step 13 — Custom rubrics**: YAML/JSON loader with pattern matching.
- [ ] **Step 14 — Guardrail engine**: Policy-based pattern matching with actions.
- [ ] **Step 15 — Trace differ**: Step-by-step comparison with divergence detection.

### Phase 4: Simulation
- [ ] **Step 16 — Campaign config**: YAML parser, validation.
- [ ] **Step 17 — Scenarios**: 7 built-in scenarios.
- [ ] **Step 18 — Fault injector**: Velocity overshoot, position violation, authority escalation, chain forgery, metadata attack.
- [ ] **Step 19 — Orchestrator**: Isaac Lab bridge + DryRunOrchestrator + campaign reporter.

### Phase 5: Hardening and Proof
- [ ] **Step 20 — Security hardening**: Input validation, numeric safety, file safety, identifier validation.
- [ ] **Step 21 — Property-based tests**: proptest for all invariants.
- [ ] **Step 22 — Adversarial integration tests**: All 12 attacks as test cases.
- [ ] **Step 23 — Documentation**: README, architecture, authority model, simulation guide, etc.
