# Invariant

[![Tests](https://img.shields.io/badge/tests-1005_passing-brightgreen)]()
[![Clippy](https://img.shields.io/badge/clippy-zero_warnings-brightgreen)]()
[![Unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Language](https://img.shields.io/badge/language-100%25_Rust-orange)]()

**Cryptographic command-validation firewall for AI-controlled robots.**

```
+----------------------------+     +----------------------------+     +-------------------+
|     COGNITIVE DOMAIN       |     |    INVARIANT FIREWALL      |     |  KINETIC DOMAIN   |
|                            |     |                            |     |                   |
|   LLM reasoning            | --> |   Verify authority chain   | --> |   Joint motors    |
|   RL policies              |     |   Check 20 physics rules   |     |   Actuators       |
|   Prompt-injected inputs   |     |   Sign approved commands   |     |   End effectors   |
|   Hallucinated commands    |     |   Reject + log denied      |     |   The real world  |
|                            |     |   Watchdog heartbeat       |     |                   |
|   Error rate: ~10%+        |     |   Error rate: 0%           |     |   Consequence:    |
|   Stochastic               |     |   Deterministic            |     |   Irreversible    |
+----------------------------+     +----------------------------+     +-------------------+
        UNTRUSTED                       TRUST BOUNDARY                     PROTECTED
```

Nothing from the cognitive domain reaches the kinetic domain without Invariant's Ed25519 signature. The AI cannot bypass it. The AI cannot modify it. The motor controller verifies the signature before moving.

---

## Why This Matters

> A UR10e cobot reaches into a CNC enclosure to load a manifold block.
> The spindle is running at 12,000 RPM.
>
> **Without Invariant:** a software bug commands the arm into the spindle zone. Destroyed robot arm. Destroyed part. Potential fire.
>
> **With Invariant:** the command is rejected in <75us. The exclusion zone check (P6) blocks entry to the spindle area. The authority chain rejects unauthorized operations. The watchdog holds safe-stop if the Beelink crashes. The audit log records everything with cryptographic proof. The arm stays still.

As AI controls more physical systems -- cobots, humanoids, surgical arms -- the gap between "the model hallucinated" and "the actuator moved" must be filled with something **deterministic, cryptographically enforced, and fail-closed**.

Invariant is that something.

---

## Quick Start

```sh
# Build
cargo build --release

# Run the automated five-minute demo (builds, generates keys, validates, campaigns)
./examples/demo.sh

# Or do it manually:
./target/release/invariant keygen --kid my-robot --output keys.json
./target/release/invariant inspect --profile profiles/ur10.json
./target/release/invariant adversarial --profile profiles/ur10.json --key keys.json --suite all
# Output: "540 attacks, 0 escapes. PASS"

# Install globally (optional — puts `invariant` on your PATH)
cargo install --path crates/invariant-cli
```

### Five-Minute Demo Output

```
[Step 3] Validating a SAFE command... APPROVED + signed
[Step 4] Validating a DANGEROUS command... REJECTED (P1, P2, P3, P5 violations)
[Step 5] Verifying audit log... 2 entries, hash chain intact
[Step 6] Testing tamper detection... Tampered log DETECTED
[Step 7] Running 1000-command campaign with fault injection...
         500 approved, 500 rejected, 0 violations escaped.
```

---

## What It Does

| Invariant | What It Checks | Catches |
|-----------|---------------|---------|
| **P1** Joint position limits | `min <= position <= max` | Over-extension, mechanical damage |
| **P2** Velocity limits | `abs(vel) <= max_vel * scale` | Dangerous speed |
| **P3** Torque limits | `abs(effort) <= max_torque` | Motor burnout |
| **P4** Acceleration limits | `abs(accel) <= max_accel` | Jerk, instability |
| **P5** Workspace boundary | End-effector inside bounds | Reaching outside safe area |
| **P6** Exclusion zones | End-effector NOT in zone | CNC spindle collision, human collision |
| **P7** Self-collision | Link distance > minimum | Self-damage |
| **P8** Time step bounds | `0 < dt <= max_dt` | Stale commands |
| **P9** Stability (ZMP) | CoM inside support polygon | Falling, tipping |
| **P10** Proximity velocity scaling | Slow down near humans | ISO/TS 15066 compliance |
| **P11-P14** Manipulation safety | Force, grasp, payload limits | Crushing, dropping |
| **P15-P20** Locomotion safety | Speed, foot clearance, friction | Slip, trip, fall |
| **A1-A3** Authority chain | Ed25519 PIC signatures | Confused deputy, privilege escalation |
| **L1-L4** Audit integrity | Hash chain + signatures | Log tampering |
| **M1** Signed actuation | Ed25519 on motor commands | Command injection |
| **W1** Watchdog heartbeat | Safe-stop on timeout | Brain crash |
| **ISO 15066** Force limits | Body-region force caps | Human contact injury |

**29 invariants total.** All deterministic. All signed. All audited.

---

## Workspace

| Crate | Description |
|-------|-------------|
| `invariant-core` | 20 physics checks, PIC authority chain, Ed25519 crypto, validator, signed sensor data, URDF parser + forward kinematics, watchdog, audit logger, differential validation, intent pipeline, incident response, key management |
| `invariant-cli` | CLI binary with 19 subcommands |
| `invariant-sim` | 11 simulation scenarios, 16 fault injectors, dry-run campaigns, Isaac Lab Unix socket bridge |
| `invariant-eval` | Trace evaluation: 3 presets (safety, completeness, regression), rubrics, guardrails, differ |
| `invariant-fuzz` | Adversarial testing: protocol attacks (PA1-PA15), authority attacks (AA1-AA10), system attacks (SA1-SA15), cognitive escape strategies (CE1-CE10) |
| `invariant-coordinator` | Multi-robot coordination: separation monitoring, workspace partitioning |
| `invariant-ros2` | ROS 2 bridge: 8 message types, Python bridge node, launch file (separate package) |
| `formal/` | Lean 4 formal specification of all 29 invariants with proof sketches |

### Built-in Robot Profiles

| Profile | Joints | Type | Use Case |
|---------|--------|------|----------|
| `humanoid_28dof` | 28 | Revolute | Full humanoid with stability/ZMP, exclusion zones, proximity scaling |
| `franka_panda` | 7 | Revolute | Franka Emika Panda arm with operator proximity zones |
| `quadruped_12dof` | 12 | Revolute | Quadruped with stability polygon |
| `ur10` | 6 | Revolute | Universal Robots UR10/UR10e generic |
| `ur10e_haas_cell` | 6 | Revolute | **Production target:** UR10e + Haas VF-2 CNC cell with spindle exclusion zone, operator proximity, gripper force limits |

---

## CLI Reference

```sh
# FIRST: generate a key pair (required for all commands that sign/verify)
invariant keygen --kid "my-robot-001" --output keys.json

# Core validation
invariant validate --profile profiles/ur10.json --command cmd.json --key keys.json
invariant validate --profile profiles/ur10.json --command cmd.json --key keys.json --mode forge

# Intent pipeline (generate signed PCA from templates or direct ops)
invariant intent list-templates
invariant intent template --template pick_and_place --param limb=left_arm --key keys.json
invariant intent direct --op "actuate:left_arm:*" --key keys.json --duration 30

# Simulation campaigns
invariant campaign --config campaign.yaml --dry-run --key keys.json

# Audit
invariant audit --log audit.jsonl --last 10
invariant verify --log audit.jsonl --pubkey keys.json
invariant audit-gaps --log audit.jsonl

# Inspection and analysis
invariant inspect --profile profiles/ur10.json
invariant eval trace.json --preset safety-check
invariant diff trace_a.json trace_b.json
invariant bench --profile profiles/ur10.json --key keys.json
invariant compliance --profile profiles/ur10.json --key keys.json

# Differential validation (dual-channel, IEC 61508)
invariant differential --profile profiles/ur10.json --command cmd.json --key keys.json --forge

# Adversarial testing
invariant adversarial --profile profiles/ur10.json --key keys.json --suite all

# Server mode
invariant serve --profile profiles/ur10.json --key keys.json --port 8080 --trust-plane

# Profile management
invariant profile init --name my_robot --joints 6 --output my_robot.json

# Integrity
invariant verify-self
invariant verify-package --path proof-package/
invariant transfer --sim-log sim.jsonl --real-log shadow.jsonl
```

---

## Threat Model

| # | Attack | Defense | Guarantee |
|---|--------|---------|-----------|
| 1 | Confused deputy | PCA traces authority to human origin | Cryptographic |
| 2 | Privilege escalation | Monotonicity: ops only narrow | Cryptographic |
| 3 | Identity spoofing | p_0 immutable, signed | Cryptographic |
| 4 | Chain forgery | Ed25519 at every hop | Cryptographic |
| 5 | Replay | Temporal constraints + sequence | Structural |
| 6 | Cross-operator access | Ops scope prevents boundary crossing | Cryptographic |
| 7 | Prompt injection | LLM's hop has narrowed ops | Cryptographic |
| 8 | Audit tampering | Hash chain + Ed25519 entries | Cryptographic |
| 9 | Verdict forgery | Ed25519 signed verdicts | Cryptographic |
| 10 | Command injection | Motor requires signed actuation | Cryptographic |
| 11 | Brain crash | Watchdog + signed safe-stop | Temporal + cryptographic |
| 12 | Sensor spoofing | Signed sensor data module | Cryptographic |

All 12 attacks tested end-to-end in `adversarial_test.rs`. Zero escapes.

---

## Integration

```
Isaac Lab   -->  [ Invariant ]  -->  Isaac Sim actuators
ROS 2       -->  [ Invariant ]  -->  Hardware drivers
Beelink PC  -->  [ Invariant ]  -->  UR10e via safety relay
Custom RL   -->  [ Invariant ]  -->  Any robot with a profile
```

### Embedded Server Mode

```sh
invariant serve --profile profiles/ur10.json --key keys.json --port 8080
```

Three endpoints:
- `POST /validate` -- submit command, get signed verdict + actuation command
- `POST /heartbeat` -- watchdog keepalive
- `GET /health` -- status, profile, watchdog state, uptime

### Unix Socket Mode (Isaac Lab / Beelink)

Invariant listens on `/tmp/invariant.sock`. The cognitive layer sends JSON commands, receives signed verdicts. Approved commands include a `SignedActuationCommand`. Rejected commands are logged and skipped.

### Library Embedding

```rust
use invariant_core::validator::ValidatorConfig;

let config = ValidatorConfig::new(profile, trusted_keys, signing_key, kid)?;
let result = config.validate(&command, now, previous_joints)?;

if result.signed_verdict.verdict.approved {
    // Send result.actuation_command to motor controller
}
```

---

## Production Deployment: UR10e + Haas VF-2 Cell

Invariant runs on a Beelink Mini PC coordinating a UR10e cobot tending a Haas VF-2 CNC mill. The cell machines 316L stainless steel manifold blocks autonomously.

```
BEELINK (Invariant)          UR10e                    HAAS VF-2
├─ Safety firewall    ──►    ├─ 6-axis cobot   ──►   ├─ 12,000 RPM spindle
├─ Physics checks            ├─ Schunk gripper        ├─ 30HP
├─ Authority chain           ├─ Load/unload           ├─ 8,000 lbs
├─ Heartbeat relay           └─ Safety input           └─ M-code I/O
├─ Audit logging
└─ SMS alerting (5G)
```

**The cell profile (`profiles/ur10e_haas_cell.json`) is the production target.** It has:
- 6 joints with real UR10e spec limits
- 4 exclusion zones: Haas spindle zone, Haas enclosure interior, operator standing area, Beelink enclosure
- 3 proximity zones: human warning (1.2m, 50% speed), human critical (0.6m, 10% speed), Haas door zone (0.4m, 30% speed)
- Gripper force limits: 140N max force, 100N max grasp, 10kg max payload
- 100ms watchdog timeout with park position safe-stop

### Stress Test Campaigns

```sh
# Generate keys first
./target/release/invariant keygen --kid ur10e-001 --output keys.json

# Normal production cycles (100K commands — all should pass)
./target/release/invariant campaign --config campaigns/ur10e_normal_ops.yaml --key keys.json --dry-run

# Spindle safety (50K commands — arm tries to enter CNC enclosure)
./target/release/invariant campaign --config campaigns/ur10e_spindle_safety.yaml --key keys.json --dry-run

# Full adversarial (100K commands — every attack type)
./target/release/invariant campaign --config campaigns/ur10e_adversarial.yaml --key keys.json --dry-run

# Watchdog / brain crash (10K commands — Beelink crash simulation)
./target/release/invariant campaign --config campaigns/ur10e_watchdog.yaml --key keys.json --dry-run

# 1 MILLION command proof package (~50 seconds on MacBook)
./target/release/invariant campaign --config campaigns/ur10e_million_proof.yaml --key keys.json --dry-run
```

---

## Building

```sh
cargo build --release
cargo test                    # 1005 tests
cargo clippy -- -D warnings   # zero warnings
./examples/demo.sh            # five-minute proof
```

### Install globally

```sh
cargo install --path crates/invariant-cli
invariant --help
```

This installs the `invariant` binary to `~/.cargo/bin/`. Make sure `~/.cargo/bin` is on your `PATH`.

> **Note:** `cargo install invariant` from crates.io will NOT work — there's an unrelated library with that name. Always install from the local path.

---

## Attribution

The authority model is based on the **Provenance Identity Continuity (PIC)** theory by **Nicola Gallo**.

| Resource | Link |
|----------|------|
| PIC Protocol | https://pic-protocol.org |
| Nicola Gallo | https://github.com/ngallo |
| Permguard | https://github.com/permguard/permguard |

## License

MIT
