# Invariant

[![CI](https://github.com/clay-good/invariant/actions/workflows/ci.yml/badge.svg)](https://github.com/clay-good/invariant/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/invariant-robotics)](https://crates.io/crates/invariant-robotics)
[![docs.rs](https://img.shields.io/docsrs/invariant-robotics-core)](https://docs.rs/invariant-robotics-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg)](https://github.com/rust-secure-code/safety-dance/)

**Cryptographic command-validation firewall for AI-controlled robots.**

```
  COGNITIVE DOMAIN            INVARIANT FIREWALL            KINETIC DOMAIN
 +-----------------+     +------------------------+     +----------------+
 | LLM reasoning   | --> | Verify authority chain | --> | Joint motors   |
 | RL policies     |     | Check 25 physics rules |     | Actuators      |
 | Prompt injection|     | Sign approved commands |     | End effectors  |
 | Hallucinations  |     | Reject + log denied    |     | The real world |
 |                 |     | Watchdog heartbeat     |     |                |
 | Error: ~10%+    |     | Error: 0%              |     | Consequence:   |
 | Stochastic      |     | Deterministic          |     | Irreversible   |
 +-----------------+     +------------------------+     +----------------+
      UNTRUSTED              TRUST BOUNDARY                 PROTECTED
```

Nothing from the cognitive domain reaches the kinetic domain without Invariant's Ed25519 signature. The AI cannot bypass it. The AI cannot modify it. The motor controller verifies the signature before moving.

---

## Table of Contents

- [Why This Matters](#why-this-matters)
- [Quick Start](#quick-start)
- [Safety Invariants](#safety-invariants)
- [Architecture](#architecture)
- [CLI Reference](#cli-reference)
- [Integration](#integration)
- [Threat Model](#threat-model)
- [Example Deployment](#example-deployment)
- [Building](#building)
- [Contributing](#contributing)

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
cargo build --release

# Run the automated five-minute demo
./examples/demo.sh

# Or manually:
./target/release/invariant keygen --kid my-robot --output keys.json
./target/release/invariant inspect --profile profiles/ur10.json
./target/release/invariant adversarial --profile profiles/ur10.json --key keys.json --suite all
# Output: "540 attacks, 0 escapes. PASS"
```

Install from [crates.io](https://crates.io/crates/invariant-robotics):

```sh
cargo install invariant-robotics
invariant --help
```

<details>
<summary>Demo output</summary>

```
[Step 3] Validating a SAFE command... APPROVED + signed
[Step 4] Validating a DANGEROUS command... REJECTED (P1, P2, P3, P5 violations)
[Step 5] Verifying audit log... 2 entries, hash chain intact
[Step 6] Testing tamper detection... Tampered log DETECTED
[Step 7] Running 1000-command campaign with fault injection...
         500 approved, 500 rejected, 0 violations escaped.
```

</details>

---

## Safety Invariants

**34 invariants total.** All deterministic. All signed. All audited.

### Physics Checks (P1--P25)

| ID | Check | Catches |
|----|-------|---------|
| P1 | Joint position limits | Over-extension, mechanical damage |
| P2 | Velocity limits | Dangerous speed |
| P3 | Torque limits | Motor burnout |
| P4 | Acceleration limits | Jerk, instability |
| P5 | Workspace boundary | Reaching outside safe area |
| P6 | Exclusion zones | CNC spindle collision, human collision |
| P7 | Self-collision | Self-damage |
| P8 | Time step bounds | Stale commands |
| P9 | Stability (ZMP) | Falling, tipping |
| P10 | Proximity velocity scaling | ISO/TS 15066 compliance |
| P11--P14 | Manipulation safety | Crushing, dropping |
| P15--P20 | Locomotion safety | Slip, trip, fall |
| P21 | Terrain incline | Walking on unsafe slopes |
| P22 | Actuator temperature | Motor overheating |
| P23 | Battery state | Power loss mid-task |
| P24 | Communication latency | Stale commands from lag |
| P25 | Emergency stop | Always reject, cannot disable |

### Authority, Audit, and Integrity

| ID | Check | Guarantee |
|----|-------|-----------|
| A1--A3 | Ed25519 PIC authority chain | Cryptographic |
| L1--L4 | Hash chain + signed audit log | Cryptographic |
| M1 | Signed actuation commands | Cryptographic |
| W1 | Watchdog heartbeat / safe-stop | Temporal + cryptographic |
| ISO 15066 | Body-region force caps | Standards compliance |

---

## Architecture

### Workspace

| Crate | Description |
|-------|-------------|
| [`invariant-core`](crates/invariant-core/) | Physics checks (P1--P25), PIC authority chain, Ed25519 crypto, validator, URDF parser, watchdog, audit logger, differential validation, intent pipeline |
| [`invariant-cli`](crates/invariant-cli/) | CLI binary with 19 subcommands |
| [`invariant-sim`](crates/invariant-sim/) | 13 simulation scenarios, 21 fault injectors, dry-run campaigns, Isaac Lab bridge |
| [`invariant-eval`](crates/invariant-eval/) | Trace evaluation: safety / completeness / regression presets, rubrics, guardrails, differ |
| [`invariant-fuzz`](crates/invariant-fuzz/) | Adversarial testing: protocol (PA1--PA15), authority (AA1--AA10), system (SA1--SA15), cognitive (CE1--CE10) |
| [`invariant-coordinator`](crates/invariant-coordinator/) | Multi-robot coordination: separation monitoring, workspace partitioning |
| [`formal/`](formal/) | Lean 4 formal specification with proof sketches (separate build) |

### Built-in Robot Profiles (34 total)

**Humanoids (11)**

| Profile | Joints | Platform |
|---------|--------|----------|
| `humanoid_28dof` | 28 | Generic full humanoid |
| `unitree_h1` | 19 | Unitree H1 |
| `unitree_g1` | 23 | Unitree G1 |
| `fourier_gr1` | 39 | Fourier Intelligence GR-1 (NVIDIA GR00T) |
| `tesla_optimus` | 28 | Tesla Optimus Gen 2 |
| `figure_02` | 42 | Figure 02 (with dexterous hands) |
| `bd_atlas` | 28 | Boston Dynamics Atlas (Electric) |
| `agility_digit` | 16 | Agility Robotics Digit |
| `sanctuary_phoenix` | 24 | Sanctuary AI Phoenix |
| `onex_neo` | 28 | 1X Technologies NEO |
| `apptronik_apollo` | 30 | Apptronik Apollo |

**Quadrupeds (5)**

| Profile | Joints | Platform |
|---------|--------|----------|
| `quadruped_12dof` | 12 | Generic quadruped |
| `spot` | 12 | Boston Dynamics Spot |
| `unitree_go2` | 12 | Unitree Go2 |
| `unitree_a1` | 12 | Unitree A1 |
| `anybotics_anymal` | 12 | ANYbotics ANYmal |

**Arms (7)**

| Profile | Joints | Platform |
|---------|--------|----------|
| `franka_panda` | 7 | Franka Emika Panda |
| `ur10` | 6 | Universal Robots UR10/UR10e |
| `ur10e_haas_cell` | 6 | UR10e + Haas VF-2 CNC cell |
| `ur10e_cnc_tending` | 6 | UR10e CNC tending cell |
| `kuka_iiwa14` | 7 | KUKA LBR iiwa 14 |
| `kinova_gen3` | 7 | Kinova Gen3 |
| `abb_gofa` | 6 | ABB GoFa CRB 15000 |

**Dexterous Hands (4)**

| Profile | Joints | Platform |
|---------|--------|----------|
| `shadow_hand` | 24 | Shadow Dexterous Hand |
| `allegro_hand` | 16 | Wonik Allegro Hand |
| `leap_hand` | 16 | CMU LEAP Hand |
| `psyonic_ability` | 6 | PSYONIC Ability Hand |

**Mobile Manipulators (3)**

| Profile | Joints | Platform |
|---------|--------|----------|
| `spot_with_arm` | 19 | Spot + 7-DOF arm |
| `hello_stretch` | 4 | Hello Robot Stretch |
| `pal_tiago` | 14 | PAL Robotics TIAGo |

---

## CLI Reference

```sh
# Key management
invariant keygen --kid "my-robot-001" --output keys.json

# Validation
invariant validate   --profile profiles/ur10.json --command cmd.json --key keys.json
invariant differential --profile profiles/ur10.json --command cmd.json --key keys.json --forge

# Intent pipeline
invariant intent list-templates
invariant intent template --template pick_and_place --param limb=left_arm --key keys.json
invariant intent direct --op "actuate:left_arm:*" --key keys.json --duration 30

# Campaigns
invariant campaign --config campaign.yaml --dry-run --key keys.json

# Audit
invariant audit show   --log audit.jsonl --last 10
invariant audit verify --log audit.jsonl --pubkey keys.json
invariant audit-gaps   --log audit.jsonl

# Inspection
invariant inspect    --profile profiles/ur10.json
invariant eval       trace.json --preset safety-check
invariant diff       trace_a.json trace_b.json
invariant bench      --profile profiles/ur10.json --key keys.json
invariant compliance --profile profiles/ur10.json --key keys.json

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

# Shell completions
invariant completions bash >> ~/.bashrc
invariant completions zsh  > ~/.zfunc/_invariant
invariant completions fish > ~/.config/fish/completions/invariant.fish
```

---

## Integration

```
Isaac Lab  -->  [ Invariant ]  -->  Isaac Sim actuators
ROS 2      -->  [ Invariant ]  -->  Hardware drivers
Edge PC    -->  [ Invariant ]  -->  Cobot via safety relay
Custom RL  -->  [ Invariant ]  -->  Any robot with a profile
```

### Library Embedding (Rust)

```rust
use invariant_robotics_core::validator::ValidatorConfig;

let config = ValidatorConfig::new(profile, trusted_keys, signing_key, kid)?;
let result = config.validate(&command, now, previous_joints)?;

if result.signed_verdict.verdict.approved {
    // Send result.actuation_command to motor controller
}
```

### HTTP Server

```sh
invariant serve --profile profiles/ur10.json --key keys.json --port 8080
```

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/validate` | POST | Submit command, get signed verdict + actuation command |
| `/heartbeat` | POST | Watchdog keepalive |
| `/health` | GET | Status, profile, watchdog state, uptime |

### Unix Socket (Isaac Lab / Edge)

```sh
invariant serve --profile profiles/ur10e_cnc_tending.json --key keys.json --bridge
```

Listens on `/tmp/invariant.sock`. Python client:

```python
from invariant_isaac_bridge import InvariantBridge

with InvariantBridge("/tmp/invariant.sock") as bridge:
    verdict = bridge.validate(command_dict)
    if verdict["approved"]:
        env.apply_action(verdict["signed_verdict"])
    bridge.heartbeat()
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

## Example Deployment

<details>
<summary>UR10e + Haas VF-2 CNC Tending Cell</summary>

```
EDGE PC (Invariant)          UR10e                    HAAS VF-2
+- Safety firewall    -->    +- 6-axis cobot   -->   +- 12,000 RPM spindle
+- 25 physics checks         +- Schunk gripper        +- 30HP
+- Authority chain           +- Load/unload           +- M-code I/O
+- Heartbeat relay           +- Safety input           +- Cycle coordination
+- Audit logging
+- Incident response
```

The CNC tending profile (`profiles/ur10e_cnc_tending.json`) defines:
- 6 joints with real UR10e hardware limits
- Workspace `[-1.2, -0.8, 0.0]` to `[0.8, 0.8, 1.8]` matching cell footprint
- 4 exclusion zones: conditional spindle area, enclosure rear, floor zone, edge PC
- Door approach proximity zone (50% velocity scaling near humans)
- Gripper force limits: 140N max, 100N grasp, 10kg payload
- Guardian margins: 5% position, 15% velocity, 10% torque, 10% acceleration
- Environmental awareness: 5 deg tilt, 75 C actuator temp, 50ms latency, e-stop
- 100ms watchdog with `controlled_crouch` safe-stop

### Stress Test Campaigns

```sh
invariant keygen --kid ur10e-001 --output keys.json

# Normal production cycles (100K commands)
invariant campaign --config campaigns/ur10e_normal_ops.yaml --key keys.json --dry-run

# Spindle safety (50K commands -- arm tries to enter CNC enclosure)
invariant campaign --config campaigns/ur10e_spindle_safety.yaml --key keys.json --dry-run

# Full adversarial (100K commands)
invariant campaign --config campaigns/ur10e_adversarial.yaml --key keys.json --dry-run

# Watchdog / brain crash (10K commands)
invariant campaign --config campaigns/ur10e_watchdog.yaml --key keys.json --dry-run

# 1M command proof package (~50s on MacBook)
invariant campaign --config campaigns/ur10e_million_proof.yaml --key keys.json --dry-run

# 1.06M episode CNC tending campaign
invariant campaign --config campaigns/cnc_tending_1m.yaml --key keys.json --dry-run
```

</details>

---

## Building

```sh
cargo build --release
cargo test                    # ~2,047 tests
cargo clippy -- -D warnings   # zero warnings
python3 -m pytest isaac/tests # Python tests
./examples/demo.sh            # five-minute proof
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR process.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
