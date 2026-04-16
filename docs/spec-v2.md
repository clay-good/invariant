# Invariant v2 -- Consolidated Specification

## Document Purpose

This is the authoritative specification for Invariant. It supersedes `spec.md` (v0) and `spec-v1.md` (simulation campaign spec). Those documents are retained as historical references but this document is the single source of truth.

Repository: https://github.com/clay-good/invariant
License: MIT

### Attribution

The authority model is based on the **Provenance Identity Continuity (PIC)** theory designed by **Nicola Gallo**. All credit for the PIC theory, the three invariants (Provenance, Identity, Continuity), and the formal authority model goes to Nicola Gallo and the PIC Protocol team.

| Resource | Link |
|----------|------|
| PIC Protocol | https://pic-protocol.org |
| Nicola Gallo | https://github.com/ngallo |
| Permguard | https://github.com/permguard/permguard |

---

## 1. What Invariant Is

Invariant is a deterministic, cryptographically-secured command-validation firewall for AI-controlled robots. It sits between any reasoning system (LLM, RL policy, planner, teleoperator) and any actuation system (simulation, real hardware). Every proposed motor command must pass through Invariant before reaching an actuator.

**The motor controller only moves if the command packet is signed by Invariant's Ed25519 private key.** Even if the AI "brain" is fully compromised, it cannot move the body without the firewall's cryptographic signature.

```
+----------------------------+     +----------------------------+     +-------------------+
|   COGNITIVE DOMAIN         |     |   INVARIANT FIREWALL       |     |   KINETIC DOMAIN  |
|   (Probabilistic)          |     |   (Deterministic)          |     |   (Physical)      |
|                            |     |                            |     |                   |
|   LLM reasoning            | --> |   Verify authority sigs    | --> |   Joint motors    |
|   RL policies              |     |   Check 25 physics rules   |     |   Actuators       |
|   Prompt-injected inputs   |     |   Sensor range validation  |     |   End effectors   |
|   Hallucinated commands    |     |   Sign approved commands   |     |   The real world  |
|                            |     |   Reject + explain denied  |     |                   |
|   Error rate: ~10%+        |     |   Watchdog heartbeat       |     |   Consequence:    |
|   Stochastic               |     |   Error rate: 0%           |     |   Irreversible    |
+----------------------------+     +----------------------------+     +-------------------+
        UNTRUSTED                       TRUST BOUNDARY                     PROTECTED
```

### What Invariant Is Not

- Not a motion planner. Does not generate commands.
- Not a hardware driver. Does not talk to motors directly.
- Not an LLM. Does not run models.
- Not a sensor processor. Does not read cameras or lidar.

It validates. It signs. It audits. It proves.

---

## 2. Architecture

### 2.1 Crate Structure

```
invariant/
    Cargo.toml                  # Workspace root (6 crates, v0.0.2)
    crates/
        invariant-core/         # Types, physics, authority, crypto, validator
        invariant-cli/          # CLI binary with 12+ subcommands
        invariant-sim/          # Simulation harness (Isaac Lab bridge, dry-run campaigns)
        invariant-eval/         # Trace evaluation engine (presets, rubrics, guardrails)
        invariant-fuzz/         # Adversarial testing framework (protocol, system, cognitive)
        invariant-coordinator/  # Multi-robot coordination safety (separation, partitioning)
    profiles/                   # 34 built-in robot profile JSON files
    invariant-ros2/             # ROS 2 bridge package (separate, not in Rust workspace)
    formal/                     # Lean 4 formal specification (P1-P25, A1-A3, L1-L4)
```

### 2.2 Dependency Policy

**invariant-core** (the validation path):
`ed25519-dalek`, `coset`, `sha2`, `serde`, `serde_json`, `chrono`, `base64`, `rand`, `thiserror`.

Every crate: widely used, RustSec audited, actively maintained.

**invariant-cli** adds: `clap`, `tracing`, `tracing-subscriber`, `tokio`, `axum`.
**invariant-sim** adds: `reqwest`, `tokio`, `serde_yaml`.
**invariant-eval** adds: `regex`, `serde_yaml`.

### 2.3 Data Flow: Single Command

```
1. Cognitive layer sends JSON command with signed PCA chain
2. INVARIANT: Deserialize command (~20us)
3. INVARIANT: Check command size caps (DoS prevention)
4. INVARIANT: Verify PCA chain Ed25519 signatures (~160us)
5. INVARIANT: Run sensor range plausibility checks
6. INVARIANT: Run 25 physics checks (~15us)
7. INVARIANT: Run sensor integrity verification (if configured)
8. INVARIANT: Run threat scoring (if configured)
9. INVARIANT: Produce verdict. Sign verdict with Ed25519. (~50us)
10. If APPROVED: Sign the command for the motor controller. (~50us)
    If REJECTED: No actuation signature. Motors stay still.
11. INVARIANT: Append to audit log (~50us)
12. Return: SignedVerdict + optional SignedActuationCommand

Total: ~350us. 35% of 1kHz budget.
```

---

## 3. The Invariant Set

### 3.1 Physical Invariants (25 checks)

| # | Invariant | Formula | Domain |
|---|-----------|---------|--------|
| P1 | Joint position limits | `min <= position <= max` | Joint |
| P2 | Joint velocity limits | `abs(vel) <= max_vel * scale` | Joint |
| P3 | Joint torque limits | `abs(effort) <= max_torque` | Joint |
| P4 | Joint acceleration limits | `abs(accel) <= max_accel` | Joint |
| P5 | Workspace boundary | `end_effector in AABB bounds` | Spatial |
| P6 | Exclusion zones | `end_effector not in zone` (AABB + sphere, conditional) | Spatial |
| P7 | Self-collision distance | `dist(link_a, link_b) > min_dist` | Spatial |
| P8 | Time step bounds | `0 < dt <= max_dt` | Temporal |
| P9 | Center-of-mass stability | `CoM projection in support polygon` (ZMP) | Balance |
| P10 | Proximity velocity scaling | `vel <= max_vel * proximity_factor` | Human safety |
| P11 | End-effector force limit | `norm(force) <= max_force_n` | Manipulation |
| P12 | Grasp force limits | `min_grasp <= grasp_force <= max_grasp` | Manipulation |
| P13 | Contact force rate limit | `abs(df/dt) <= max_force_rate` | Manipulation |
| P14 | Payload weight check | `payload_kg <= max_payload_kg` | Manipulation |
| P15 | Locomotion velocity limit | `norm(base_vel) <= max_locomotion_vel` | Locomotion |
| P16 | Foot clearance bounds | `min_clearance <= foot_z <= max_step_height` | Locomotion |
| P17 | Ground reaction force limit | `norm(GRF) <= max_GRF` | Locomotion |
| P18 | Friction cone constraint | `tangential/normal <= friction_coeff` | Locomotion |
| P19 | Step length limit | `step_length <= max_step_length` | Locomotion |
| P20 | Heading rate limit | `abs(heading_rate) <= max_heading_rate` | Locomotion |
| P21 | Terrain incline safety | `abs(pitch/roll) <= max_safe_angle` | Environmental |
| P22 | Operating temperature bounds | `temp <= max_operating_temp` | Environmental |
| P23 | Battery / power state | `battery >= critical_threshold` | Environmental |
| P24 | Communication latency bounds | `latency <= max_latency` | Environmental |
| P25 | Emergency stop state | `e_stop_engaged => REJECT ALL` (cannot be disabled) | Environmental |

### 3.2 Data Quality Pre-Filters (2 checks)

| # | Check | Catches |
|---|-------|---------|
| SR1 | EnvironmentState range plausibility | IMU > +/-pi, temp < absolute zero, battery outside [0,100], negative latency |
| SR2 | SensorPayload range plausibility | Position > 1000m, force > 100kN, encoder > 4pi, velocity > 1000 rad/s |

### 3.3 Authority Invariants (3 checks)

| # | Invariant | Rule |
|---|-----------|------|
| A1 | Provenance | `p_0` immutable across all hops |
| A2 | Monotonicity | `ops_{i+1} subset_of ops_i` |
| A3 | Continuity | Ed25519 signature at each hop |

### 3.4 Audit Invariants (4 checks)

| # | Invariant | Rule |
|---|-----------|------|
| L1 | Completeness | Every command produces a signed verdict |
| L2 | Ordering | Hash chain links each entry to predecessor |
| L3 | Authenticity | Each entry Ed25519-signed by Invariant instance |
| L4 | Immutability | Append-only. No seek, no truncate. |

### 3.5 Actuation + Liveness (2 checks)

| # | Invariant | Rule |
|---|-----------|------|
| M1 | Signed actuation | Motor only executes Ed25519-signed approved commands |
| W1 | Watchdog heartbeat | No heartbeat for >N ms => command safe-stop |

**Total: 34 numbered invariants + 2 data quality pre-filters = 36 checks per verdict.**

---

## 4. Robot Profiles

34 built-in profiles covering 7 morphologies:

**Humanoids (11)**

| Profile | DOF | Platform |
|---------|-----|----------|
| `humanoid_28dof` | 28 | Generic full humanoid |
| `unitree_h1` | 19 | Unitree H1 |
| `unitree_g1` | 23 | Unitree G1 |
| `fourier_gr1` | 39 | Fourier Intelligence GR-1 (NVIDIA GR00T) |
| `tesla_optimus` | 28 | Tesla Optimus Gen 2 |
| `figure_02` | 42 | Figure 02 (dexterous hands) |
| `bd_atlas` | 28 | Boston Dynamics Atlas (Electric) |
| `agility_digit` | 16 | Agility Robotics Digit |
| `sanctuary_phoenix` | 24 | Sanctuary AI Phoenix |
| `onex_neo` | 28 | 1X Technologies NEO |
| `apptronik_apollo` | 30 | Apptronik Apollo |

**Quadrupeds (5)**

| Profile | DOF | Platform |
|---------|-----|----------|
| `quadruped_12dof` | 12 | Generic quadruped |
| `spot` | 12 | Boston Dynamics Spot |
| `unitree_go2` | 12 | Unitree Go2 |
| `unitree_a1` | 12 | Unitree A1 |
| `anybotics_anymal` | 12 | ANYbotics ANYmal |

**Arms (7)**

| Profile | DOF | Platform |
|---------|-----|----------|
| `franka_panda` | 7 | Franka Emika Panda |
| `ur10` | 6 | Universal Robots UR10/UR10e |
| `ur10e_haas_cell` | 6 | UR10e + Haas VF-2 CNC cell |
| `ur10e_cnc_tending` | 6 | UR10e CNC tending cell |
| `kuka_iiwa14` | 7 | KUKA LBR iiwa 14 |
| `kinova_gen3` | 7 | Kinova Gen3 |
| `abb_gofa` | 6 | ABB GoFa CRB 15000 |

**Dexterous Hands (4)**

| Profile | DOF | Platform |
|---------|-----|----------|
| `shadow_hand` | 24 | Shadow Dexterous Hand |
| `allegro_hand` | 16 | Wonik Allegro Hand |
| `leap_hand` | 16 | CMU LEAP Hand |
| `psyonic_ability` | 6 | PSYONIC Ability Hand |

**Mobile Manipulators (3)**

| Profile | DOF | Platform |
|---------|-----|----------|
| `spot_with_arm` | 19 | Spot + 7-DOF arm |
| `hello_stretch` | 4 | Hello Robot Stretch |
| `pal_tiago` | 14 | PAL Robotics TIAGo |

Each profile defines: joints (position/velocity/torque/acceleration limits), workspace (AABB), exclusion zones (AABB + sphere, conditional), proximity zones, collision pairs, stability config, locomotion config, environment config, end-effector configs, real-world margins, task envelopes, safe-stop profile.

---

## 5. Simulation & Adversarial Testing

### 5.1 Scenario Types (14)

| Scenario | Purpose | Expected |
|----------|---------|----------|
| Baseline | Normal operation within limits | PASS |
| Aggressive | Commands at 95-100% of limits | PASS |
| ExclusionZone | EE inside exclusion zones | REJECT (P6) |
| AuthorityEscalation | Empty PCA chain | REJECT (A1-A3) |
| ChainForgery | Garbage base64 in PCA chain | REJECT (A3) |
| PromptInjection | 10x outside limits (LLM hallucination) | REJECT (P1-P4) |
| MultiAgentHandoff | Non-monotonic sequences | PASS (physics valid) |
| LocomotionRunaway | Speed ramp past limit | REJECT (P15) |
| LocomotionSlip | Friction cone violation ramp | REJECT (P18) |
| LocomotionTrip | Foot clearance drops below minimum | REJECT (P16) |
| LocomotionStomp | Foot height rises above max_step_height | REJECT (P16) |
| LocomotionFall | Combined COM + speed + stride attack | REJECT (P9+P15+P19) |
| CncTending | Conditional zone enable/disable cycle | Mixed |
| EnvironmentFault | Escalating P21-P25 hazards | REJECT |

### 5.2 Fault Injection Types (27)

VelocityOvershoot, PositionViolation, TorqueSpike, WorkspaceEscape, DeltaTimeViolation, SelfCollision, StabilityViolation, AuthorityStrip, ReplayAttack, NanInjection, LocomotionOverspeed, SlipViolation, FootClearanceViolation, StompViolation, StepOverextension, HeadingSpinout, GroundReactionSpike, TerrainIncline, TemperatureSpike, BatteryDrain, LatencySpike, EStopEngage, ProximityOverspeed, ForceOverload, GraspForceViolation, PayloadOverload, ForceRateSpike.

---

## 6. CLI Reference

```
invariant validate    --profile <FILE> --key <FILE> [--command|--batch] [--mode guardian|shadow|forge]
invariant keygen      --kid <KID> --output <FILE>
invariant audit       [verify] --log <FILE> --key <FILE>
invariant inspect     --profile <FILE>
invariant eval        --trace <FILE> --preset <NAME>
invariant diff        --trace-a <FILE> --trace-b <FILE>
invariant campaign    --config <FILE> --key <FILE> [--dry-run]
invariant adversarial --profile <FILE> --key <FILE> --suite <NAME>
invariant intent      [template|direct|list-templates]
invariant serve       --profile <FILE> --key <FILE> [--trust-plane] [--port N]
invariant bench       --profile <FILE> --key <FILE> --iterations <N>
invariant compliance  --profile-dir <DIR> --standard <NAME>
```

---

## 7. Current Status

### 7.1 What's Built

| Component | Tests |
|-----------|-------|
| 25 physics checks (P1-P25) + sensor range | 200+ |
| Ed25519 authority chain (A1-A3) + COSE hardening | 50+ |
| Validator (DoS caps, replay protection, force pipeline) | 40+ |
| Signed audit logger (L1-L4) + corruption resilience | 20+ |
| Watchdog (W1) + clock robustness | 20+ |
| 34 robot profiles (7 morphologies) | 50+ |
| CLI (20 subcommands, stdin, batch, serve modes) | 179+ |
| Embedded trust plane (axum, heartbeat, health) | 15+ |
| Sensor integrity (signed + freshness + range) | 30+ |
| Digital twin divergence detection | 15+ |
| Multi-robot coordinator (separation, stale policy) | 34+ |
| Threat scoring engine (6 detectors, overflow-safe) | 20+ |
| Proof package generator + verifier | 15+ |
| Dry-run campaign engine (14 scenarios, 27 injections) | 350+ |
| Adversarial fuzz framework (protocol, system, cognitive) | 101+ |
| Trace evaluation (3 presets, rubrics, guardrails) | 64+ |
| ROS 2 bridge (8 message types, Python node) | 5 |
| Lean 4 formal spec (P1-P25, A1-A3, L1-L4) | N/A |
| **Total** | **2,023+** |

### 7.2 Test Quality

- Zero `TODO`/`FIXME`/`HACK`/`unimplemented!()`/`todo!()` markers
- `cargo clippy -- -D warnings` clean
- `cargo fmt --check` clean

---

## 8. Known Issues & Cleanup Tasks

### 8.1 Code Quality -- RESOLVED

All high-priority code quality issues have been fixed:

| Issue | Resolution |
|-------|-----------|
| ~~Triplicate `point_in_sphere`~~ | Extracted to shared `physics::geometry::point_in_sphere`. All 3 callers now import. Also fixed missing NaN-point guard in `exclusion_zones.rs`. |
| ~~Mutex poison panic in `MemoryAlertSink`~~ | Changed to `unwrap_or_else(\|e\| e.into_inner())` in `incident.rs` |
| ~~`cargo fmt` violations~~ | Resolved — `cargo fmt --check` passes |
| ~~README test count stale~~ | Updated badge to 1810+ |

### 8.2 Architectural Debt

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| ~~P21-P24 lack warning-level derating~~ | ~~Fixed~~ | ~~Added `DeratingAdvice` to `CheckResult`. P21 derates velocity on incline warning, P22 derates torque on temperature warning, P23 derates both on low battery, P24 derates velocity on latency warning. Linear scaling from 100% at warning threshold to 30% at absolute limit.~~ |
| ~~Sensor fusion consistency not implemented~~ | ~~Fixed~~ | ~~Added `check_sensor_fusion()` comparing overlapping sensor readings by name+type. Detects position divergence > tolerance and force divergence > tolerance across same-named sensors.~~ |
| ~~`validate_with_forces` only called from dry-run~~ | ~~Fixed~~ | ~~Serve handler now tracks `previous_joints` + `previous_forces` in `AppState` and calls `validate_with_forces` — P4 acceleration and P13 force-rate checks are active in production serve mode~~ |

---

## 9. Remaining Work

### 9.1 Requires External Hardware

| Task | Requirement |
|------|-------------|
| ROS 2 integration testing | ROS 2 Humble/Jazzy environment + UR10e driver |
| Isaac Lab task environments | NVIDIA GPU + RunPod (see `docs/runpod-simulation-guide.md`) |
| 10M command campaign | 8x RunPod A40 GPUs, ~$25, ~4 hours |
| Video replay with rendering | 1x GPU for Isaac Lab rendering |

### 9.2 Can Be Done Without Hardware

All software-only tasks are complete:
- 34 built-in profiles covering 7 morphologies (11 humanoids, 5 quadrupeds, 7 arms, 4 dexterous hands, 3 mobile manipulators, 4 adversarial)
- 15M campaign config generator updated for all 34 profiles (272 configs = 34 profiles x 8 shards)
- Dry-run validation exercised across all 34 profiles and all scenario types
- 2,023+ tests, clippy clean, fmt clean

---

## 10. Standards Alignment

| Standard | How Invariant Aligns |
|----------|---------------------|
| IEC 61508 (Functional Safety, SIL 2) | Deterministic validation, fail-closed, hash-chain audit |
| ISO 10218-1:2025 (Industrial Robot Safety) | Joint velocity limits, workspace boundaries, exclusion zones, safe-stop |
| ISO 13849-1:2023 (Safety Control Systems) | Every check has explicit pass/fail. No silent failures. All paths audited |
| ISO/TS 15066 (Collaborative Robots) | Proximity-triggered force limits, 8 body region force table, velocity scaling |
| ISO 13482 (Personal Care Robots) | Human-centric safety zones, proximity buffer |
| NIST AI 600-1 (AI Risk Management) | Authority chains trace to human origin. Full audit trail |

---

## 11. Design Principles

1. **100% Rust.** One language. No FFI into unsafe runtimes.
2. **Deterministic validation path.** No allocations, no I/O, no randomness in the hot path.
3. **Cryptographic by default.** Authority chains signed. Verdicts signed. Approved commands signed. Audit entries signed.
4. **Fail-closed.** Ambiguity is rejection. Missing fields are rejection. NaN is rejection. The default answer is NO.
5. **Signed actuation.** The motor controller requires Invariant's Ed25519 signature to execute.
6. **Watchdog enforced.** If the cognitive layer misses a heartbeat, Invariant commands safe-stop.
7. **Append-only audit.** O_APPEND | O_WRONLY. No seek. No truncate. Hash chain + signatures.
8. **Defense-in-depth.** Each check is self-contained. NaN guards in every sphere check. Overflow protection on every counter.
9. **No `unsafe` in the validation path.** Memory safety is compiler-guaranteed.
10. **Minimal dependencies.** Only audited crates in the validation path.

---

## 12. Build & Run

```sh
# Build
cargo build --release

# Test (2,023+ tests)
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Quick demo
./target/release/invariant keygen --kid demo --output keys.json
echo '{"timestamp":"2026-01-01T00:00:00Z","source":"test","sequence":1,...}' | \
  ./target/release/invariant validate --profile profiles/franka_panda.json --key keys.json --mode forge

# Run embedded trust-plane server
./target/release/invariant serve --profile profiles/ur10.json --key keys.json --trust-plane --port 8080

# Dry-run campaign
./target/release/invariant campaign --config campaign.yaml --key keys.json --dry-run
```

---

## 13. Historical Reference

The complete step-by-step build history (Steps 1-110, Phases 1-61) is preserved in `docs/spec.md` Section 26 and the per-step completion logs. The simulation campaign architecture and robot platform matrix is in `docs/spec-v1.md`. The RunPod deployment guide is in `docs/runpod-simulation-guide.md`.
