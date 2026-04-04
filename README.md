# Invariant

[![Tests](https://img.shields.io/badge/tests-1210_passing-brightgreen)]()
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
|   RL policies              |     |   Check 25 physics rules   |     |   Actuators       |
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

> A UR10e cobot reaches into a CNC enclosure to load a workpiece.
> The spindle is running at 12,000 RPM.
>
> **Without Invariant:** a software bug commands the arm into the spindle zone. Destroyed robot arm. Destroyed part. Potential fire.
>
> **With Invariant:** the command is rejected in <75us. The exclusion zone check (P6) blocks entry to the spindle area. The authority chain rejects unauthorized operations. The watchdog holds safe-stop if the edge PC crashes. The audit log records everything with cryptographic proof. The arm stays still.

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

# Install from crates.io (puts `invariant` on your PATH)
cargo install invariant-robotics
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
| **P21** Terrain incline | IMU pitch/roll vs limits | Walking on unsafe slopes |
| **P22** Actuator temperature | Per-joint temp vs max | Motor overheating |
| **P23** Battery state | Charge % vs critical threshold | Power loss mid-task |
| **P24** Communication latency | RTT vs max acceptable | Stale commands from lag |
| **P25** Emergency stop | Hardware e-stop engaged | Always reject, cannot disable |
| **A1-A3** Authority chain | Ed25519 PIC signatures | Confused deputy, privilege escalation |
| **L1-L4** Audit integrity | Hash chain + signatures | Log tampering |
| **M1** Signed actuation | Ed25519 on motor commands | Command injection |
| **W1** Watchdog heartbeat | Safe-stop on timeout | Brain crash |
| **ISO 15066** Force limits | Body-region force caps | Human contact injury |

**34 invariants total.** All deterministic. All signed. All audited.

---

## Workspace

| Crate | Description |
|-------|-------------|
| `invariant-core` | 25 physics checks (P1-P25), PIC authority chain, Ed25519 crypto, validator, signed sensor data, URDF parser + forward kinematics, watchdog, audit logger, differential validation, intent pipeline, incident response, key management |
| `invariant-cli` | CLI binary with 19 subcommands |
| `invariant-sim` | 13 simulation scenarios, 21 fault injectors, dry-run campaigns, Isaac Lab Unix socket bridge |
| `invariant-eval` | Trace evaluation: 3 presets (safety, completeness, regression), rubrics, guardrails, differ |
| `invariant-fuzz` | Adversarial testing: protocol attacks (PA1-PA15), authority attacks (AA1-AA10), system attacks (SA1-SA15), cognitive escape strategies (CE1-CE10) |
| `invariant-coordinator` | Multi-robot coordination: separation monitoring, workspace partitioning |
| `invariant-ros2` | ROS 2 bridge: 8 message types, Python bridge node, launch file (separate package) |
| `formal/` | Lean 4 formal specification of invariants with proof sketches |

### Built-in Robot Profiles

| Profile | Joints | Type | Use Case |
|---------|--------|------|----------|
| `humanoid_28dof` | 28 | Revolute | Full humanoid with stability/ZMP, exclusion zones, proximity scaling |
| `franka_panda` | 7 | Revolute | Franka Emika Panda arm with operator proximity zones |
| `quadruped_12dof` | 12 | Revolute | Quadruped with stability polygon |
| `ur10` | 6 | Revolute | Universal Robots UR10/UR10e generic |
| `ur10e_haas_cell` | 6 | Revolute | UR10e + Haas VF-2 dev cell with spindle exclusion, operator proximity, gripper force limits |
| `ur10e_cnc_tending` | 6 | Revolute | UR10e CNC tending cell with tighter workspace, floor zone, conditional spindle area, real-world Guardian margins |

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
invariant audit show --log audit.jsonl --last 10
invariant audit verify --log audit.jsonl --pubkey keys.json
invariant verify --log audit.jsonl --pubkey keys.json  # alias for audit verify
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

# Server mode (embedded Trust Plane)
invariant serve --profile profiles/ur10.json --key keys.json --port 8080 --trust-plane

# Full production Guardian mode
invariant serve --profile profiles/ur10e_cnc_tending.json --key keys.json \
  --threat-scoring --monitors --bridge --audit-log audit.jsonl --digital-twin

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
Edge PC     -->  [ Invariant ]  -->  Cobot via safety relay
Custom RL   -->  [ Invariant ]  -->  Any robot with a profile
```

### Embedded Server Mode

```sh
invariant serve --profile profiles/ur10.json --key keys.json --port 8080
```

Three endpoints:
- `POST /validate` -- submit command, get signed verdict + actuation command
- `POST /heartbeat` -- watchdog keepalive
- `GET /health` -- status, profile, watchdog state, uptime, threat scoring, monitors, digital twin divergence, incident lockdown

### Unix Socket Mode (Isaac Lab / Edge Deployment)

```sh
invariant serve --profile profiles/ur10e_cnc_tending.json --key keys.json --bridge
```

Invariant listens on `/tmp/invariant.sock`. The cognitive layer sends JSON commands, receives signed verdicts. Approved commands include a `SignedActuationCommand`. Rejected commands are logged and skipped.

Python client (`crates/invariant-sim/invariant_isaac_bridge.py`):

```python
from invariant_isaac_bridge import InvariantBridge

with InvariantBridge("/tmp/invariant.sock") as bridge:
    verdict = bridge.validate(command_dict)
    if verdict["approved"]:
        env.apply_action(verdict["signed_verdict"])
    bridge.heartbeat()
```

Isaac Lab CNC tending environment (`isaac/envs/`):

```python
from isaac.envs import CncTendingEnv

env = CncTendingEnv(num_billets=15, connect_bridge=True)
obs = env.reset()
while not env.is_done:
    obs, info = env.cycle_step()
```

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

## Example Deployment: UR10e + Haas VF-2 CNC Tending Cell

Invariant ships with a complete example deployment for a UR10e cobot tending a Haas VF-2 CNC mill -- including profiles, campaigns, Isaac Lab environment, and stress tests.

```
EDGE PC (Invariant)          UR10e                    HAAS VF-2
├─ Safety firewall    ──►    ├─ 6-axis cobot   ──►   ├─ 12,000 RPM spindle
├─ 25 physics checks         ├─ Schunk gripper        ├─ 30HP
├─ Authority chain           ├─ Load/unload           ├─ M-code I/O
├─ Heartbeat relay           └─ Safety input           └─ Cycle coordination
├─ Audit logging
└─ Incident response
```

**The CNC tending profile (`profiles/ur10e_cnc_tending.json`) defines:**
- 6 joints with real UR10e hardware limits
- Tighter workspace [-1.2, -0.8, 0.0] to [0.8, 0.8, 1.8] matching cell footprint
- 4 exclusion zones: conditional spindle area, enclosure rear, floor zone, edge PC enclosure
- Door approach proximity zone (50% velocity scaling near humans)
- Gripper force limits: 140N max force, 100N max grasp, 10kg max payload
- Real-world Guardian margins: 5% position, 15% velocity, 10% torque, 10% acceleration
- Environmental awareness: 5° tilt limit, 75°C actuator temp, 50ms latency bound, e-stop always active
- 100ms watchdog timeout with controlled_crouch safe-stop

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

# Watchdog / brain crash (10K commands — edge PC crash simulation)
./target/release/invariant campaign --config campaigns/ur10e_watchdog.yaml --key keys.json --dry-run

# 1 MILLION command proof package (~50 seconds on MacBook)
./target/release/invariant campaign --config campaigns/ur10e_million_proof.yaml --key keys.json --dry-run

# 1.06M episode CNC tending campaign
./target/release/invariant campaign --config campaigns/cnc_tending_1m.yaml --key keys.json --dry-run
```

---

## Building

```sh
cargo build --release
cargo test                    # 1210 Rust tests
python3 -m pytest isaac/tests # 42 Python tests (unit + e2e bridge)
cargo clippy -- -D warnings   # zero warnings
./examples/demo.sh            # five-minute proof
```

### Install from crates.io

```sh
cargo install invariant-robotics
invariant --help
```

Or from source:

```sh
cargo install --path crates/invariant-cli
```
