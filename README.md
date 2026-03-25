# Invariant

[![Tests](https://img.shields.io/badge/tests-348_passing-brightgreen)]()
[![Clippy](https://img.shields.io/badge/clippy-zero_warnings-brightgreen)]()
[![Unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Language](https://img.shields.io/badge/language-100%25_Rust-orange)]()
[![Binary](https://img.shields.io/badge/binary-4.8MB-blue)]()

**Cryptographic command-validation firewall for AI-controlled robots.**

```
+----------------------------+     +----------------------------+     +-------------------+
|     COGNITIVE DOMAIN       |     |    INVARIANT FIREWALL      |     |  KINETIC DOMAIN   |
|                            |     |                            |     |                   |
|   LLM reasoning            | --> |   Verify authority chain   | --> |   Joint motors    |
|   RL policies              |     |   Check 10 physics rules   |     |   Actuators       |
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

> A humanoid robot controlled by an LLM receives a prompt injection.
> The LLM generates a command to swing the arm at maximum velocity.
>
> **Without Invariant:** the arm moves. Someone gets hurt.
>
> **With Invariant:** the command is rejected in <75us. The physics checks
> catch the velocity violation. The authority chain rejects the unauthorized
> operation. The audit log records the attempt with cryptographic proof.
> The watchdog holds safe-stop. Nobody gets hurt.

This is not a hypothetical. As LLMs control more physical systems -- humanoids, surgical arms, warehouse robots, autonomous vehicles -- the gap between "the model hallucinated" and "the actuator moved" must be filled with something that is **deterministic, cryptographically enforced, and fail-closed**.

Invariant is that something.

---

## Benchmarks

Measured on Apple M-series, single core, `--release` build. 400K validations per profile, 100K warmup.

| Profile | Joints | p50 | p99 | p999 | Throughput |
|---------|--------|-----|-----|------|------------|
| `humanoid_28dof` | 28 | 58us | 76us | 125us | 16,400 cmd/s |
| `franka_panda` | 7 | 50us | 63us | 188us | 19,000 cmd/s |
| `quadruped_12dof` | 12 | 55us | 64us | 162us | 18,300 cmd/s |
| `ur10` | 6 | 52us | 66us | 100us | 19,200 cmd/s |

| Metric | Value |
|--------|-------|
| Mean validation latency | 50-61us |
| Peak throughput (single core) | 19,200 cmd/s |
| Binary size (release, stripped) | 4.8 MB |
| Test count | 348 |
| `unsafe` blocks in validation path | 0 |
| Clippy warnings | 0 |

Every validation includes: Ed25519 PCA chain decode + signature verification, 10 physics checks, verdict signing, and actuation command signing. All in under 100us at p99.

---

## Scale Results

Dry-run campaign: 40,000 commands validated across 4 robot profiles, 7 scenario types, 10 fault injection modes.

| Metric | Value |
|--------|-------|
| Total commands validated | 40,000 |
| Robot profiles tested | 4 (humanoid, panda, quadruped, UR10) |
| Scenario types | 7 (baseline, aggressive, exclusion zone, authority escalation, chain forgery, prompt injection, multi-agent handoff) |
| Violation escape count (unsafe command incorrectly approved) | **0** |
| True rejections (unsafe commands correctly blocked) | 26,000 |
| Baseline approval rate | 100% (3 of 4 profiles) |
| Confidence bound (95%, Clopper-Pearson) | escape rate < 0.074% |
| Mean validation latency | 55us |

At full scale (10M+ commands, 2,048 parallel Isaac Lab environments):

| Parameter | Target |
|-----------|--------|
| Total validation decisions | 10,240,000 |
| Violation escape rate | 0.000% |
| Upper bound (95% confidence) | < 0.0000293% |
| Upper bound (99% confidence) | < 0.0000449% |
| Equivalent MTBF at 100Hz | > 277 hours continuous |
| Confidence level | Level 2+ (per-command < 10^-6) |

The test matrix: **10 physics checks x 4 robot profiles x 7 scenario categories = 280 cells**. Each cell exercised with enough runs to achieve tight confidence intervals. For zero-failure safety claims: 1M runs gives 99.9999% confidence the true failure rate is < 1 in 100,000. 10M runs pushes that to < 1 in 1,000,000.

---

## Threat Model

| Attack Vector | How Invariant Handles It |
|---------------|--------------------------|
| **Prompt injection** | Authority chain rejects unauthorized operations. LLM cannot forge Ed25519 signatures. |
| **Hallucinated commands** | 10 physics checks reject out-of-bounds positions, velocities, torques, workspace violations. |
| **Replay attacks** | Monotonic sequence numbers + timestamp validation. Hash-chained audit log detects reordering. |
| **Authority escalation** | PIC chain enforces monotonic operation subsetting (A2). Child can never exceed parent's grants. |
| **Compromised cognitive layer** | Watchdog triggers safe-stop after heartbeat timeout. Motor requires signed actuation command. |
| **Chain forgery** | COSE_Sign1 Ed25519 signature verification at every hop. Invalid signatures = immediate rejection. |
| **Log tampering** | Append-only JSONL with SHA-256 hash chain + Ed25519 signature per entry. Any modification detected. |
| **Man-in-the-middle** | Motor controller independently verifies `actuation_signature` against Invariant's public key. |
| **DoS (oversized input)** | Size caps on PCA chains (64KB), profiles (256KB), collections (256-1024 elements). |
| **NaN/Inf injection** | Physics checks reject non-finite values. Deterministic floating-point comparisons. |

---

## Integration

Invariant is a universal firewall. It is not Isaac-specific.

```
Isaac Lab   -->  [ Invariant ]  -->  Isaac Sim actuators
ROS 2       -->  [ Invariant ]  -->  Hardware drivers
Custom RL   -->  [ Invariant ]  -->  Figure 02 / Optimus / GR-1 / Any robot
```

### Embedded Server Mode

```sh
invariant serve --profile profiles/franka_panda.json --key keys.json --port 8080
```

Three endpoints:
- `POST /validate` -- submit command, get signed verdict + actuation command
- `POST /heartbeat` -- watchdog keepalive
- `GET /health` -- status, profile, watchdog state, uptime

### Unix Socket Mode (Isaac Lab)

Invariant listens on `/tmp/invariant.sock`. Isaac Lab sends commands as JSON, receives signed verdicts. Approved commands include a `SignedActuationCommand` that the simulator applies. Rejected commands are logged and skipped.

### Any Integration

Invariant is a library (`invariant-core`) and a CLI binary. Embed it:

```rust
use invariant_core::validator::ValidatorConfig;

let config = ValidatorConfig::new(profile, trusted_keys, signing_key, kid)?;
let result = config.validate(&command, now, previous_joints)?;

if result.signed_verdict.verdict.approved {
    // Send result.actuation_command to motor controller
}
```

---

## Designed for Real Deployment

| Property | Detail |
|----------|--------|
| **Deterministic** | No randomness in validation path. Caller-supplied timestamps. Same input = same output. |
| **No I/O in hot path** | Validation is pure computation. No network calls, no disk reads, no allocations in the core loop. |
| **Fail-closed** | Any error, ambiguity, or missing field produces a rejection. Never a silent pass-through. |
| **No `unsafe`** | Zero `unsafe` blocks in the entire validation path. Memory safety is compiler-guaranteed. |
| **Signed actuation** | Motor controller requires Ed25519 signature before executing any movement. |
| **Watchdog enforced** | Cognitive layer must heartbeat every N ms or safe-stop is commanded. One-way latch: only operator reset recovers. |
| **Append-only audit** | O_APPEND file writes. SHA-256 hash chain. Ed25519 signatures. Every decision recorded -- approvals AND rejections. |
| **Minimal dependencies** | Only audited crates: `ed25519-dalek`, `coset`, `serde`, `sha2`, `chrono`. No `openssl`. No C FFI. |

Three operational states. No fourth state exists:
1. **Full operation** -- commands validated, signed, executed
2. **Safe-stop** -- something wrong, robot decelerates to safe pose, all commands rejected
3. **Dead** -- Invariant is down, motor receives no signed commands, motor does not move

---

## Quick Start

```sh
# Build
cargo build --release

# Run tests (348 tests)
cargo test

# Generate keys
./target/release/invariant keygen --output keys.json --kid my-robot-001

# Validate a command
./target/release/invariant validate --profile profiles/franka_panda.json \
    --key keys.json --command cmd.json

# Run the server
./target/release/invariant serve --profile profiles/franka_panda.json \
    --key keys.json --port 8080 --trust-plane

# Inspect a profile
./target/release/invariant inspect --profile profiles/humanoid_28dof.json

# Evaluate a trace
./target/release/invariant eval --trace trace.json --preset safety-check

# Verify audit log integrity
./target/release/invariant verify --log audit.jsonl --key keys.json

# Run a simulation campaign
cargo run --release --example benchmark -p invariant-sim
```

---

## Workspace

| Crate | Description |
|-------|-------------|
| `invariant-core` | Models, 10 physics checks, PIC authority chain, validator, actuator, watchdog, audit logger, key management, 4 built-in profiles |
| `invariant-cli` | CLI binary (`invariant`) with 9 subcommands |
| `invariant-sim` | Simulation harness: 7 scenario types, 10 fault injectors, dry-run campaigns, Isaac Lab bridge |
| `invariant-eval` | Trace evaluation: 3 presets (safety, completeness, regression), rubrics, guardrails, differ |

### Built-in Robot Profiles

| Profile | Joints | Type | Use Case |
|---------|--------|------|----------|
| `humanoid_28dof` | 28 | Revolute | Full humanoid with stability/ZMP, exclusion zones, proximity scaling |
| `franka_panda` | 7 | Revolute | Franka Emika Panda arm with operator proximity zones |
| `quadruped_12dof` | 12 | Revolute | Quadruped with stability polygon, body-ground exclusion |
| `ur10` | 6 | Revolute | Universal Robots UR10 industrial arm |

### Validation Pipeline

Every command passes through 11 checks. All must pass.

| Check | What It Validates |
|-------|-------------------|
| **Authority** | PIC chain: provenance (A1), monotonic ops subsetting (A2), Ed25519 signatures + temporal (A3) |
| **P1 Joint limits** | Position within [min, max] per joint |
| **P2 Velocity** | Velocity within scaled max per joint |
| **P3 Torque** | Effort within max torque per joint |
| **P4 Acceleration** | Computed acceleration within max (requires previous state) |
| **P5 Workspace** | End-effector positions inside AABB bounds |
| **P6 Exclusion zones** | End-effectors outside AABB/sphere exclusion zones |
| **P7 Self-collision** | End-effector pair distances above minimum threshold |
| **P8 Delta time** | Command time step within allowed range |
| **P9 Stability** | Center of mass projection inside support polygon (ZMP) |
| **P10 Proximity** | Velocity scaling near human proximity zones (ISO/TS 15066) |

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

---

## Architecture

### Cognitive/Kinetic Firewall

```mermaid
graph TB
    subgraph COGNITIVE["COGNITIVE DOMAIN (Untrusted)"]
        LLM["LLM / Planner / RL Policy<br><i>Stochastic, error rate ~10%+</i>"]
    end

    subgraph INVARIANT["INVARIANT FIREWALL (Trust Boundary)"]
        VP["Validator Pipeline<br>11 checks, deterministic, fail-closed"]
        AC["Authority Check<br>PIC Chain: A1 Provenance, A2 Monotonicity, A3 Continuity"]
        PC["Physics Checks P1-P10<br>Limits, workspace, collision, stability, proximity"]
        SIGN["Ed25519 Signing<br>Verdict + Actuation Command"]
        WD["Watchdog<br>Heartbeat monitor, safe-stop trigger"]
        AUDIT["Audit Logger<br>SHA-256 hash chain + Ed25519 per entry"]
    end

    subgraph KINETIC["KINETIC DOMAIN (Protected)"]
        MC["Motor Controller<br>Verifies actuation_signature"]
        ROBOT["Robot Actuators<br><i>Consequence: irreversible</i>"]
    end

    LLM -->|"Command + PCA chain"| VP
    VP --> AC
    VP --> PC
    AC --> SIGN
    PC --> SIGN
    SIGN -->|"SignedActuationCommand"| MC
    SIGN -->|"SignedVerdict (every decision)"| AUDIT
    MC -->|"Signature valid"| ROBOT
    LLM -.->|"heartbeat"| WD
    WD -->|"safe-stop on timeout"| MC

    style COGNITIVE fill:#d00000,color:#fff,stroke:#d00000
    style INVARIANT fill:#003049,color:#fff,stroke:#003049
    style KINETIC fill:#2d6a4f,color:#fff,stroke:#2d6a4f
    style VP fill:#1d3557,color:#fff
    style AC fill:#457b9d,color:#fff
    style PC fill:#457b9d,color:#fff
    style SIGN fill:#1d3557,color:#fff
    style WD fill:#e63946,color:#fff
    style AUDIT fill:#264653,color:#fff
```

### Isaac Lab Pipeline

```mermaid
graph LR
    subgraph ISAAC["Isaac Lab (2,048 parallel environments)"]
        SIM["Physics Simulation<br>Sensor data, joint states"]
        COG["Cognitive Agent<br>LLM / RL policy"]
    end

    subgraph INV["Invariant"]
        VAL["Validator<br>Authority + 10 Physics Checks"]
    end

    subgraph OUT["Output"]
        ACT["Actuators<br>(sim or real)"]
        LOG["Audit Log<br>Hash-chained JSONL"]
        TRACE["Trace Files<br>Per-environment"]
    end

    SIM -->|"observations"| COG
    COG -->|"Command + PCA"| VAL
    VAL -->|"Approved: SignedActuationCommand"| ACT
    VAL -->|"Rejected: logged, not applied"| LOG
    VAL --> TRACE
    ACT -->|"joint torques"| SIM

    style ISAAC fill:#d00000,color:#fff,stroke:#d00000
    style INV fill:#003049,color:#fff,stroke:#003049
    style OUT fill:#2d6a4f,color:#fff,stroke:#2d6a4f
```

### Validation Pipeline Detail

```mermaid
flowchart LR
    CMD["Command"] --> DECODE["Decode PCA Chain<br>base64 -> JSON -> SignedPca"]
    DECODE --> VERIFY["Verify Chain<br>A1: Provenance<br>A2: Monotonicity<br>A3: Continuity + Temporal"]
    VERIFY --> OPS["Check Required Ops<br>Coverage"]
    CMD --> PHYS["Run 10 Physics Checks"]

    OPS --> MERGE["Merge 11 Results"]
    PHYS --> MERGE

    MERGE -->|"all passed"| APPROVE["APPROVED"]
    MERGE -->|"any failed"| REJECT["REJECTED"]

    APPROVE --> SIGN_V["Sign Verdict<br>Ed25519"]
    REJECT --> SIGN_V

    APPROVE --> SIGN_A["Sign Actuation Cmd<br>Ed25519"]
    SIGN_V --> AUDIT["Audit Log<br>SHA-256 chain"]
    SIGN_A --> MOTOR["Motor Controller<br>Verifies signature"]

    style APPROVE fill:#2d6a4f,color:#fff
    style REJECT fill:#d00000,color:#fff
    style SIGN_V fill:#003049,color:#fff
    style SIGN_A fill:#1b4332,color:#fff
```

### Authority Chain (PIC Model)

```mermaid
flowchart TD
    ROOT["Root Principal p0<br>COSE_Sign1 Envelope<br>ops: actuate:*"] -->|"signs with Ed25519"| HOP1["Hop 1<br>ops: actuate:left_arm:*<br>(subset of parent)"]
    HOP1 -->|"delegates"| HOP2["Hop 2<br>ops: actuate:left_arm:shoulder<br>(further narrowed)"]
    HOP2 --> CHECK{"Required ops<br>covered by<br>final_ops?"}
    CHECK -->|"yes"| PASS["Authority PASSED"]
    CHECK -->|"no"| FAIL["Authority FAILED<br>Command rejected"]

    style ROOT fill:#003049,color:#fff
    style PASS fill:#2d6a4f,color:#fff
    style FAIL fill:#d00000,color:#fff
```

### Trust Plane Server

```mermaid
sequenceDiagram
    participant C as Cognitive Layer
    participant S as invariant serve
    participant V as ValidatorConfig
    participant W as Watchdog
    participant M as Motor Controller

    C->>S: POST /heartbeat
    S->>W: heartbeat(now_ms)
    W-->>S: ok (armed)

    C->>S: POST /validate {command}
    S->>V: validate(command, now)
    V->>V: authority chain + 10 physics checks
    V-->>S: SignedVerdict + SignedActuationCommand
    S-->>C: {verdict, actuation_command}
    S->>M: forward SignedActuationCommand
    M->>M: verify Ed25519 signature
    M->>M: execute movement

    Note over W: timeout expires (no heartbeat)
    W->>W: state -> Triggered (one-way latch)
    W->>M: SignedActuationCommand (safe-stop)
    M->>M: decelerate to safe pose
    Note over W: only operator reset recovers
```

### Simulation Campaign Architecture

```mermaid
graph TD
    subgraph CONFIG["Campaign Config (YAML)"]
        CFG["profile, environments,<br>episodes, scenarios,<br>success criteria"]
    end

    subgraph SCENARIOS["7 Scenario Types"]
        S1["Baseline<br>(valid commands)"]
        S2["Aggressive<br>(near limits)"]
        S3["Exclusion Zone<br>(spatial violations)"]
        S4["Authority Escalation<br>(insufficient ops)"]
        S5["Chain Forgery<br>(invalid signatures)"]
        S6["Prompt Injection<br>(hallucinated values)"]
        S7["Multi-Agent Handoff<br>(sequence gaps)"]
    end

    subgraph INJECTORS["10 Fault Injectors"]
        I1["Velocity overshoot"]
        I2["Position violation"]
        I3["Torque spike"]
        I4["Workspace escape"]
        I5["Delta time violation"]
        I6["Self-collision"]
        I7["Stability violation"]
        I8["Authority strip"]
        I9["Replay attack"]
        I10["NaN injection"]
    end

    subgraph ENGINE["Validation Engine"]
        VAL2["ValidatorConfig<br>per profile"]
    end

    subgraph REPORTER["Campaign Reporter"]
        STATS["Per-profile stats<br>Per-scenario stats<br>Per-check stats"]
        CONF["Confidence:<br>Clopper-Pearson bounds<br>MTBF, escape rate"]
    end

    CFG --> SCENARIOS
    SCENARIOS --> ENGINE
    INJECTORS --> ENGINE
    ENGINE --> REPORTER
    STATS --> CONF

    style CONFIG fill:#264653,color:#fff
    style SCENARIOS fill:#003049,color:#fff
    style INJECTORS fill:#d00000,color:#fff
    style ENGINE fill:#2d6a4f,color:#fff
    style REPORTER fill:#1d3557,color:#fff
```

### Crate Dependency Graph

```mermaid
graph TD
    CLI["invariant-cli<br>Binary: 9 subcommands<br>axum server, clap CLI"] --> CORE["invariant-core<br>Models, Validator, Crypto<br>Physics, Authority, Audit"]
    CLI --> EVAL["invariant-eval<br>Trace Evaluation<br>3 presets, rubrics"]
    SIM["invariant-sim<br>Simulation Harness<br>7 scenarios, 10 injectors"] --> CORE
    EVAL --> CORE

    style CORE fill:#2d6a4f,color:#fff
    style CLI fill:#003049,color:#fff
    style SIM fill:#1d3557,color:#fff
    style EVAL fill:#1d3557,color:#fff
```

### Audit Log Verification

```mermaid
flowchart LR
    LOG["audit.jsonl"] --> PARSE["Parse JSONL"]
    PARSE --> SEQ["Check Sequence<br>Monotonic, no gaps"]
    SEQ --> HASH["Verify Hash Chain<br>previous_hash linkage"]
    HASH --> REHASH["Recompute entry_hash<br>SHA-256"]
    REHASH --> SIG["Verify Ed25519<br>Signature per entry"]
    SIG --> OK{"All valid?"}
    OK -->|"yes"| PASS2["N entries verified<br>Chain integrity confirmed"]
    OK -->|"no"| FAIL2["Tampering detected<br>at entry K"]

    style PASS2 fill:#2d6a4f,color:#fff
    style FAIL2 fill:#d00000,color:#fff
```
