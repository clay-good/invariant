# Invariant — Build Specification

## Document Purpose

This is the single, exhaustive build specification for Invariant. It supersedes all prior specifications (spec-v1.md, spec-v2.md, spec-v3.md, Invariant.txt). Invariant is written entirely in Rust. One language, one binary, maximum security.

```
cargo install invariant
```

Repository: https://github.com/clay-good/invariant
License: MIT

### Attribution

The authority model is based on the **Provenance Identity Continuity (PIC)** theory designed by **Nicola Gallo**. All credit for the PIC theory, the three invariants (Provenance, Identity, Continuity), the formal authority ontology, and the concepts of Causal Authority Transition (CAT), Proof of Continuity (PoC), and Provenance Causal Authority (PCA) goes to Nicola Gallo and the PIC Protocol team.

The kinetic execution firewall concept — the deterministic enforcement layer between probabilistic cognition and irreversible physical actuation — was developed by Clay Good as a domain-specific application of the PIC authority model to robotics.

| Resource | Link |
|----------|------|
| PIC Protocol | https://pic-protocol.org |
| PIC Specification | https://github.com/pic-protocol/pic-spec |
| PIC Rust Implementation | https://github.com/pic-protocol/pic-rust |
| Nicola Gallo | https://github.com/ngallo |
| Permguard | https://github.com/permguard/permguard |

### Architectural Relationship: PIC and Invariant

PIC and Invariant are complementary but operate at different layers of the safety stack.

**PIC answers:** "Is this authority chain valid? Does a complete, cryptographically proven lineage exist from the immutable human origin through every delegation hop to this executor, with authority monotonically restricted at each step?"

**Invariant answers:** "Is this concrete input/output transition — this specific motor command, at this moment, with these physics — still bound to the same active execution context and physically safe to execute?"

PIC protects **lineage validity across execution boundaries**. Invariant protects **execution safety within a boundary**. Together they form two halves of a complete safety model:

```
┌─────────────────────────────────────────────────────────────────┐
│                     PIC AUTHORITY LAYER                         │
│                                                                 │
│   Proves: this authority chain is valid                         │
│                                                                 │
│   p_0 (immutable origin) → PCA_1 → PCA_2 → ... → PCA_n        │
│   ∀i: p_i = p_0              (origin immutability)              │
│   ∀i: ops_{i+1} ⊆ ops_i     (monotonic restriction)            │
│   ∀i: PoC_i is non-forgeable (causal continuity)                │
│                                                                 │
│   Confused deputy: structurally inexpressible                   │
│   Authority expansion: structurally impossible                  │
│   Lineage forgery: cryptographically impossible                 │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                  INVARIANT EXECUTION LAYER                      │
│                                                                 │
│   Proves: this transition is safe and bound                     │
│                                                                 │
│   Physics invariants (P1–P25): command is physically safe       │
│   Execution binding: command is tied to current active context   │
│   Signed actuation: motor only moves on firewall signature      │
│   Audit chain: every decision is hash-chained and signed        │
│   Watchdog: cognitive layer liveness is continuously verified    │
│                                                                 │
│   Unsafe commands: deterministically rejected                   │
│   Unbound commands: deterministically rejected                  │
│   Unsigned commands: physically ignored by motor controller     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Neither layer is sufficient alone. A signed PCA chain with valid lineage does not prove the commanded motion is physically safe. A physics-validated command with no authority lineage does not prove the executor has the right to issue it. Both proofs are required before a motor moves.

### Relationship to Prior Work

Invariant is a standalone project. It takes concepts from three MIT-licensed projects but depends on none of them:

| Source | What We Take | What We Leave |
|--------|-------------|---------------|
| **PIC Protocol** | PIC invariants, authority chain model, Ed25519 COSE_Sign1 crypto, monotonicity algorithm, operation wildcards, confused deputy taxonomy, CAT/PoC/PCA architecture | The standalone Trust Plane server, Keycloak SPI, TypeScript SDK, federation bridges |
| **agent-replay** | Trace data model, step types, eval presets, guardrail pattern matching, diff/fork concepts, golden dataset export | Node.js/TypeScript code, SQLite database, blessed TUI dashboard |
| **ZTAuth*** | Zero-trust delegation model, identity-based access concepts | The ZTAuth* protocol spec, Hugo site content |

### End Goal

Prove that an LLM-controlled humanoid robot is safe by running 2,000+ parallel simulation environments in NVIDIA Isaac Lab, generating 10 million+ cryptographically signed validation decisions, and producing a tamper-proof audit trail that constitutes statistical proof of safety. Then deploy to real hardware.

---

## 1. Product Definition

### 1.1 The Problem

When AI controls a physical robot, five failures can occur:

**1. Physical safety failure.** The AI hallucinates a motor command that exceeds joint limits, violates velocity constraints, or moves an end-effector into a zone where a human is standing. The gearbox shatters. The arm strikes a person. A $50,000 repair. Or worse.

**2. Authority continuity failure.** The AI exceeds its granted authority. A prompt injection causes it to command joints the operator never authorized. Traditional authorization checks the *service's* permissions, not the *request's* authority traced to its human origin — the confused deputy problem. But even a correctly scoped authority check is not enough: there must be a cryptographic proof that the current execution step is a **valid successor in the same authority lineage** under immutable origin and monotonic restriction. Without authority continuity, a signed command with scope checks is just a snapshot — it cannot prove that the delegation chain from human to motor was never broken, replayed, or re-rooted.

**3. Intent enforcement failure.** The operator says "pick up the dishes." The AI interprets this as permission to pick up anything, including a knife. There is no cryptographic link between the operator's stated intent and the motor commands the AI generates. The AI's operations should be scoped to exactly what the human authorized — no more.

**4. Audit trail failure.** After an incident, the logs can be modified. There is no cryptographic proof of what commands were issued, who authorized them, or whether the safety system approved or rejected them. Liability is unknowable.

**5. Provability gap.** No one has run 10 million validated commands through a humanoid robot simulation with cryptographic audit trails and published the results. The evidence that these systems work at scale does not exist.

### 1.2 The Solution

Invariant is a deterministic, cryptographically-secured command-validation firewall that embeds PIC authority continuity. It sits between any reasoning system (LLM, RL policy, planner, teleoperator) and any actuation system (simulation, real hardware). Every proposed motor command must pass through Invariant before reaching an actuator.

**The motor controller will only move if the command packet is signed by Invariant's private key.** This is the hard boundary. Even if the AI "brain" is fully compromised, it cannot move the body without the firewall's cryptographic signature. The AI may suggest movement; Invariant allows movement.

Invariant enforces two complementary proof requirements:

**Authority continuity (PIC layer):**

1. **Provenance (A1):** Complete, unbroken, auditable causal chain from human origin (p_0) through every delegation hop to the current executor.
2. **Monotonicity (A2):** Authority can only decrease at each hop: `ops_{i+1} ⊆ ops_i`. Expansion is structurally impossible.
3. **Continuity (A3):** Each hop carries a non-forgeable Proof of Continuity (PoC) demonstrating that it is a valid causal successor — not merely signed, but cryptographically bound to the predecessor PCA.

**Execution safety (Invariant layer):**

4. **Physical invariants:** 25 deterministic checks against a declarative robot profile.
5. **Execution binding:** The validated PCA is bound to the current execution context — same session, same executor, same temporal window.
6. **Signed actuation:** Approved commands are Ed25519-signed for the motor controller.
7. **Signed audit:** Every decision is hash-chained and Ed25519-signed. Non-repudiable.
8. **Watchdog:** If the cognitive layer stops sending heartbeats, Invariant commands safe-stop.

One Rust binary. Zero `unsafe` in the validation path. Sub-millisecond latency.

### 1.3 The Cognitive/Kinetic Firewall

```
+----------------------------+     +----------------------------+     +-------------------+
|                            |     |                            |     |                   |
|   COGNITIVE DOMAIN         |     |   INVARIANT FIREWALL       |     |   KINETIC DOMAIN  |
|   (Probabilistic)          |     |   (Deterministic)          |     |   (Physical)      |
|                            |     |                            |     |                   |
|   LLM reasoning            | --> |   Verify PIC lineage       | --> |   Joint motors    |
|   RL policies              |     |   Bind to execution ctx    |     |   Actuators       |
|   Prompt-injected inputs   |     |   Check 25 physics rules   |     |   End effectors   |
|   Hallucinated commands    |     |   Sign approved commands   |     |   The real world  |
|                            |     |   Reject + explain denied  |     |                   |
|   Error rate: ~10%+        |     |   Watchdog heartbeat       |     |   Consequence:    |
|   Stochastic               |     |   Error rate: 0%           |     |   Irreversible    |
|                            |     |   Deterministic            |     |                   |
+----------------------------+     +----------------------------+     +-------------------+
        UNTRUSTED                       TRUST BOUNDARY                     PROTECTED
```

**The rule:** Nothing from the cognitive domain reaches the kinetic domain without both (a) a valid PIC authority chain proving lineage from the human origin, and (b) Invariant's Ed25519 execution signature proving the command is physically safe and contextually bound. The AI cannot bypass it. The AI cannot modify it. A compromised process between Invariant and the motor is detected by signature verification on the motor controller side.

### 1.4 What Invariant Is Not

- Not a motion planner. Does not generate commands.
- Not a hardware driver. Does not talk to motors directly.
- Not an LLM. Does not run models.
- Not a sensor processor. Does not read cameras or lidar.
- Not a full Trust Plane server (but can run in embedded Trust Plane mode).
- Not a PIC implementation. Does not implement CAT, PoC construction, or federation bridges. It **consumes** PIC authority chains and verifies their invariants.

It validates. It signs. It audits. It proves. Nothing more.

### 1.5 Design Principles

1. **100% Rust.** One language. No FFI into unsafe runtimes.
2. **Deterministic validation path.** No allocations, no I/O, no randomness in the hot path.
3. **Cryptographic by default.** Authority chains signed. Verdicts signed. Approved commands signed. Audit entries signed.
4. **Fail-closed.** Ambiguity is rejection. Missing fields are rejection. Malformed authority is rejection. The default answer is NO.
5. **Signed actuation.** The motor controller requires Invariant's Ed25519 signature to execute. Unsigned commands are physically ignored.
6. **Watchdog enforced.** If the cognitive layer misses a heartbeat, Invariant commands safe-stop.
7. **Append-only audit.** O_APPEND | O_WRONLY. No seek. No truncate. Hash chain + signatures.
8. **Type-safe authority.** Invalid authority states are non-representable in Rust's type system.
9. **No `unsafe` in the validation path.** Memory safety is compiler-guaranteed.
10. **Minimal dependencies.** Only audited crates: ed25519-dalek, coset, serde, sha2.
11. **Authority is continuity, not possession.** Following PIC: authority is proven by causal relationship to the origin, not by possessing a token or credential.

### 1.6 Operational Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Forge** | Simulation-only. Isaac Lab. Dry-run campaigns. | Development, testing, proof generation |
| **Guardian** | Full firewall active. All commands validated and signed. | Production deployment on real hardware |
| **Shadow** | Commands validated and logged but not blocked. Motor receives unsigned pass-through. | Gradual rollout, A/B safety testing |

### 1.7 Standards Alignment

| Standard | How Invariant Aligns |
|----------|---------------------|
| **IEC 61508** (Functional Safety, SIL 2) | Deterministic validation, fail-closed, hash-chain audit, comprehensive test suite |
| **ISO 10218-1:2025** (Industrial Robot Safety) | Joint velocity limits, workspace boundaries, exclusion zones, safe-stop integration |
| **ISO 13849-1:2023** (Safety Control Systems) | Every check has explicit pass/fail. No silent failures. All paths audited |
| **ISO/TS 15066** (Collaborative Robots) | Torque limits, velocity limits, exclusion zones for human proximity, velocity scaling by proximity |
| **ISO 13482** (Personal Care Robots) | Human-centric safety zones, "ghost shield" proximity buffer |
| **NIST AI 600-1** (AI Risk Management) | Authority chains trace to human origin. Verdicts include explanations. Full audit trail |

---

## 2. Authority Model — PIC Integration

This section defines how Invariant implements the PIC authority model. Invariant is not a PIC Protocol implementation — it does not implement CAT services, federation bridges, or PoC construction. It is a **PIC-native verifier**: it consumes PIC authority chains and enforces their invariants as a precondition for physical actuation.

### 2.1 PIC Foundations

The PIC Model (Nicola Gallo, 2025) establishes that authority is a continuous system proven by causal relationship, not by possession of tokens or credentials. Three invariants are enforced at every execution hop:

| Invariant | Formal Property | Meaning |
|-----------|----------------|---------|
| **Provenance** | ∀i: p_i = p_0 | The origin principal is immutable. Every hop traces to the same human who initiated the transaction. |
| **Identity** | p_0 generates all authority; cannot be changed, spoofed, or re-rooted | The human origin is the sole source of authority. No executor can claim authority from a different origin. |
| **Continuity** | ∀i: ops_{i+1} ⊆ ops_i, proven by non-forgeable PoC | Authority can only shrink. Each step must cryptographically prove it is a valid causal successor of the previous step — not just signed, but causally derived. |

Under these invariants, the confused deputy problem is **structurally inexpressible**: an executor cannot exercise authority beyond what was causally derived from the origin, regardless of the executor's own privileges.

### 2.2 PIC Data Structures

**Provenance Causal Authority (PCA):**

The PCA at hop *i* represents the causally derived authority available to an executor at that point in the chain. It is a COSE_Sign1 envelope containing:

| Field | Type | Constraint |
|-------|------|-----------|
| `alg` | Protected header | Signature algorithm (EdDSA) |
| `kid` | Protected header | Key identifier of signing entity |
| `hop` | Integer | Position in causal chain (0-indexed) |
| `p_0` | String | Immutable origin principal — MUST equal p_0 of all predecessors |
| `ops` | Set<Operation> | Permitted operations — MUST satisfy ops_i ⊆ ops_{i-1} |
| `executor` | Binding | Cryptographic binding to the executing entity |
| `provenance` | Reference | Causal chain reference linking to predecessor PCA |
| `constraints` | Optional | Temporal, environmental, or contextual bounds |

**Proof of Continuity (PoC):**

The PoC is the non-forgeable proof that an executor constructs to demonstrate valid causal continuation. It is bound to the predecessor PCA and cannot be replayed, transferred, or forged. In Invariant's embedded mode, PoC construction is simplified to Ed25519 signature chains; full PoC with attestation types (SPIFFE, VP, TEE quotes) is expected from external PIC implementations.

**Causal Authority Transition (CAT):**

The CAT is the enforcement mechanism that validates PIC invariants, issues challenges, verifies continuity proofs, and derives successor PCA states. Invariant's authority verifier acts as an embedded CAT for the robotics domain — it validates the chain but does not issue challenges or construct PoC on behalf of executors.

### 2.3 Authority Continuity vs. Execution Binding

This is the critical distinction identified by Nicola Gallo:

**Authority continuity (PIC's domain):** Proves that the current step is a valid successor in the same authority lineage under immutable origin and monotonic restriction. This is a property of the delegation chain itself, independent of any specific execution context.

**Execution binding (Invariant's domain):** Proves that a concrete input/output transition — a specific motor command at a specific time with specific physics — is still bound to the same active execution context. This is a property of the runtime, not the authority chain.

A valid PCA chain proves lineage. Execution binding proves the command carrying that lineage is contextually appropriate *right now*. Both are required:

```
Authority Continuity (PIC)              Execution Binding (Invariant)
─────────────────────────              ────────────────────────────────
Is this chain valid?                    Is this command bound?
  p_0 immutable?              ✓          Same session?                ✓
  ops monotonically shrink?   ✓          Same executor identity?      ✓
  Each hop causally derived?  ✓          Within temporal window?      ✓
  PoC non-forgeable?          ✓          Sequence monotonic?          ✓
                                         Physics constraints met?     ✓
                                         Watchdog alive?              ✓

        LINEAGE IS VALID                    TRANSITION IS SAFE
              ↓                                    ↓
              └──────────── BOTH REQUIRED ─────────┘
                                 ↓
                        MOTOR MAY MOVE
```

### 2.4 Authority Flow: Human to Motor

```
HUMAN OPERATOR (p_0 — immutable origin identity)
    │
    │  Signs PCA_0 with operator's Ed25519 key
    │  ops_0 = full authorized operation set for this task
    │
    ▼
TASK PLANNER / SUPERVISOR (Executor E_1)
    │
    │  Constructs PoC_1 proving causal continuation from PCA_0
    │  CAT validates: p_0 preserved, ops_1 ⊆ ops_0
    │  PCA_1 issued with narrowed scope
    │
    ▼
AI EXECUTOR / COGNITIVE LAYER (Executor E_2)
    │
    │  Constructs PoC_2 proving causal continuation from PCA_1
    │  CAT validates: p_0 preserved, ops_2 ⊆ ops_1
    │  PCA_2 issued with further narrowed scope
    │
    ▼
INVARIANT FIREWALL (embedded CAT + execution layer)
    │
    │  1. Verify PIC chain: A1 provenance, A2 monotonicity, A3 continuity
    │  2. Verify execution binding: session, sequence, temporal window
    │  3. Verify physics: P1–P25 against robot profile
    │  4. If ALL pass: sign command for motor controller
    │  5. Append to hash-chained audit log
    │
    ▼
MOTOR CONTROLLER (verifies Invariant's Ed25519 signature)
    │
    │  Key baked into firmware at manufacturing
    │  No valid signature → motor does not move
    │
    ▼
PHYSICAL ACTUATION
```

At no point in this chain can authority expand. At no point can lineage be forged. At no point can an unsafe command reach a motor. The PIC layer guarantees the first two properties; the Invariant layer guarantees the third.

### 2.5 Confused Deputy Elimination

The confused deputy problem occurs when a service uses its own elevated credentials on behalf of a less-privileged client. In robotics, this manifests as an AI executor that has broad motor access but receives commands from a narrowly-scoped operator.

**Token-based systems (vulnerable):** The motor controller checks whether the AI executor's credentials permit the action. The executor's credentials are broad. The attack succeeds.

**PIC-native systems (immune):** Authority is scoped to the transaction origin (p_0) and monotonically restricted through the chain. The executor cannot exercise authority beyond ops_i, which was derived from the operator's ops_0. The executor's own credentials are irrelevant — only the causally derived authority matters.

This is not a policy check that can be misconfigured. It is a structural property of the authority model. The confused deputy is not mitigated; it is **inexpressible**.

### 2.6 Operations and Monotonicity

Operations define what an executor is authorized to do. They follow the PIC monotonicity invariant: `ops_{i+1} ⊆ ops_i`.

```
ops_0 (operator):     move:arm:*, move:gripper:*, move:base:*
ops_1 (supervisor):   move:arm:*, move:gripper:open
ops_2 (AI executor):  move:arm:joint1, move:arm:joint2, move:gripper:open

Invariant verifies: ops_2 ⊆ ops_1 ⊆ ops_0  ✓
```

Wildcard matching: `move:arm:*` covers `move:arm:joint1`. Subset checking accounts for wildcards at each level.

If the AI executor attempts `move:base:forward`, rejection is immediate — `move:base:*` was narrowed out at hop 1 and cannot be re-introduced at any subsequent hop.

---

## 3. Invariants

### 3.1 Physical Invariants (P1–P25)

**Core checks (P1–P10):**

| # | Invariant | Formula | Catches |
|---|-----------|---------|---------|
| P1 | Joint position limits | `min <= position <= max` | Over-extension, mechanical damage |
| P2 | Joint velocity limits | `abs(vel) <= max_vel * scale` | Dangerous speed, whiplash |
| P3 | Joint torque limits | `abs(effort) <= max_torque` | Motor burnout, structural failure |
| P4 | Joint acceleration limits | `abs(accel) <= max_accel` | Jerk, instability, vibration |
| P5 | Workspace boundary | `end_effector in bounds` | Reaching outside safe area |
| P6 | Exclusion zones (AABB + sphere) | `end_effector not in zone` | Human collision, obstacle collision |
| P7 | Self-collision distance | `dist(link_a, link_b) > min_dist` | Self-damage |
| P8 | Time step bounds | `0 < dt <= max_dt` | Stale commands, control loop failure |
| P9 | Center-of-mass stability (ZMP) | `CoM projection in support polygon` | Falling, tipping |
| P10 | Proximity velocity scaling | `vel <= max_vel * proximity_factor` | Human collision at speed |

**Manipulation checks (P11–P14):**

| # | Invariant | Catches |
|---|-----------|---------|
| P11 | Payload capacity | Exceeding rated load |
| P12 | Grasp force limits | Crushing objects, gripper damage |
| P13 | Tool center point velocity | Tool tip moving too fast near humans |
| P14 | Handoff zone validation | Unsafe robot-to-robot or robot-to-human transfers |

**Locomotion checks (P15–P20):**

| # | Invariant | Catches |
|---|-----------|---------|
| P15 | Gait phase validation | Foot placement during wrong phase |
| P16 | Ground contact force | Excessive or insufficient ground reaction force |
| P17 | Terrain slope limits | Walking on unsafe inclines |
| P18 | Step height limits | Excessive step-up or step-down |
| P19 | Heading rate limits | Turning too fast, loss of stability |
| P20 | IMU-based fall detection | Active falling — trigger safe collapse |

**Environmental checks (P21–P25):**

| # | Invariant | Catches |
|---|-----------|---------|
| P21 | Ambient temperature range | Operation outside thermal limits |
| P22 | Battery/power threshold | Operation with insufficient power for safe-stop |
| P23 | Communication latency | Control loop running with stale data |
| P24 | Sensor range pre-filter | Out-of-range sensor values indicating hardware fault |
| P25 | ISO/TS 15066 force limits | Exceeding biomechanical contact limits (65N face, 140N chest) |

### 3.2 Authority Invariants (A1–A3)

| # | Invariant | Formal Property | Catches |
|---|-----------|----------------|---------|
| A1 | Provenance | ∀i: p_i = p_0 | Identity spoofing, chain re-rooting |
| A2 | Monotonicity | ∀i: ops_{i+1} ⊆ ops_i | Privilege escalation, authority expansion |
| A3 | Continuity | ∀i: PoC_i is valid causal successor of PCA_{i-1} | Chain forgery, replay, substitution |

### 3.3 Execution Binding Invariants (B1–B4)

These are Invariant's contribution — the properties that keep a validated authority chain bound to a concrete execution context:

| # | Invariant | Rule | Catches |
|---|-----------|------|---------|
| B1 | Session binding | Command's session ID matches active execution session | Cross-session replay |
| B2 | Sequence monotonicity | Command sequence number > last accepted sequence | Within-session replay |
| B3 | Temporal window | Command timestamp within acceptable window of wall clock | Stale commands, time-warp attacks |
| B4 | Executor identity | Command's executor binding matches the PCA's executor field | Executor impersonation |

### 3.4 Audit Invariants (L1–L4)

| # | Invariant | Rule | Catches |
|---|-----------|------|---------|
| L1 | Completeness | Every command produces a signed verdict | Silent drops |
| L2 | Ordering | Hash chain links each entry to predecessor | Reordering, insertion |
| L3 | Authenticity | Each entry Ed25519-signed by Invariant instance | Log forgery |
| L4 | Immutability | Append-only. No seek, no truncate. | After-the-fact tampering |

### 3.5 Actuation Invariant (M1)

| # | Invariant | Rule | Catches |
|---|-----------|------|---------|
| M1 | Signed actuation | Motor only executes Ed25519-signed approved commands | Bypass, injection between firewall and motor |

### 3.6 Liveness Invariant (W1)

| # | Invariant | Rule | Catches |
|---|-----------|------|---------|
| W1 | Watchdog heartbeat | If no heartbeat from cognitive layer for >N ms, command safe-stop | Brain crash, hang, network partition |

### 3.7 Invariant Completeness Summary

| Layer | Invariants | Count | Domain |
|-------|-----------|-------|--------|
| Physics | P1–P25 | 25 | Execution safety |
| Authority (PIC) | A1–A3 | 3 | Lineage validity |
| Execution binding | B1–B4 | 4 | Context binding |
| Audit | L1–L4 | 4 | Forensic integrity |
| Actuation | M1 | 1 | Motor gate |
| Liveness | W1 | 1 | Cognitive health |
| **Total** | | **38** | |

---

## 4. Architecture

### 4.1 Crate Structure

```
invariant/
    Cargo.toml                  # Workspace root
    crates/
        invariant-core/         # Types, physics, authority, crypto. Zero unsafe.
            src/
                lib.rs
                models/
                    mod.rs
                    profile.rs      # RobotProfile, JointDefinition, ExclusionZone, ProximityZone
                    command.rs       # Command, JointState, EndEffectorPosition
                    verdict.rs       # Verdict, CheckResult, SignedVerdict
                    authority.rs     # AuthorityChain, SignedPca, Operation, ExecutionBinding
                    audit.rs         # AuditEntry, SignedAuditEntry
                    trace.rs         # Trace, TraceStep (agent-replay compatible)
                    actuation.rs     # SignedActuationCommand (for motor controller)
                physics/
                    mod.rs
                    joint_limits.rs
                    velocity.rs
                    torque.rs
                    acceleration.rs
                    workspace.rs
                    exclusion_zones.rs
                    self_collision.rs
                    delta_time.rs
                    stability.rs     # Center-of-mass / ZMP check
                    proximity.rs     # Proximity-based velocity scaling
                    iso15066.rs      # ISO/TS 15066 proximity-triggered force limits
                authority/
                    mod.rs
                    chain.rs         # PIC chain verification (A1–A3)
                    operations.rs    # Wildcard matching + monotonicity
                    crypto.rs        # Ed25519 + COSE_Sign1
                    binding.rs       # Execution binding checks (B1–B4)
                validator.rs        # Orchestrator: PIC + binding + physics -> signed verdict
                differential.rs     # Dual-instance verdict comparison
                intent.rs           # Intent-to-operations pipeline
                sensor.rs           # Signed sensor data for zero-trust integrity
                urdf.rs             # URDF parser + forward kinematics
                actuator.rs         # Signed actuation command generator
                audit.rs            # Append-only signed JSONL logger
                watchdog.rs         # Heartbeat monitor + safe-stop trigger
            Cargo.toml

        invariant-cli/          # CLI binary
            src/
                main.rs
                commands/
                    mod.rs
                    validate.rs
                    audit.rs
                    verify.rs
                    inspect.rs
                    eval.rs
                    campaign.rs
                    differential.rs
                    intent.rs
                    keygen.rs
                    serve.rs        # Embedded Trust Plane mode

        invariant-sim/          # Simulation harness (Isaac Lab integration)
            src/
                lib.rs
                orchestrator.rs
                scenario.rs
                injector.rs
                campaign.rs
                collector.rs
                reporter.rs
                isaac/
                    mod.rs
                    bridge.rs       # Isaac Sim IPC (Unix socket)
                    dry_run.rs      # No-Isaac mock for testing

        invariant-eval/         # Trace evaluation engine
            src/
                lib.rs
                presets.rs
                rubric.rs
                differ.rs
                guardrails.rs

        invariant-fuzz/         # Adversarial testing framework
            src/
                lib.rs
                protocol.rs     # Protocol-level attacks
                system.rs       # System-level attacks
                cognitive.rs    # Cognitive/injection attacks

        invariant-coordinator/  # Multi-robot coordination safety
            src/
                lib.rs
                monitor.rs
                partition.rs

    profiles/                   # Built-in robot profile JSON files
        humanoid_28dof.json
        franka_panda.json
        quadruped_12dof.json
        ur10.json
        ...

    formal/                     # Lean 4 formal specification
        lakefile.lean
        lean-toolchain
        Invariant.lean
        Invariant/
            Types.lean
            Physics.lean
            Authority.lean      # A1–A3 + B1–B4 + monotonicity theorem
            Audit.lean
```

### 4.2 Dependency Policy

**invariant-core** (the validation path — complete list):

```toml
[dependencies]
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
coset = "0.3"
sha2 = "0.10"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
base64 = "0.22"
rand = "0.8"
thiserror = "2.0"
```

Every crate: widely used, RustSec audited, actively maintained.

**invariant-cli** adds: `clap`, `tracing`, `tracing-subscriber`, `tokio` (for serve mode).
**invariant-sim** adds: `reqwest`, `tokio`, `serde_yaml`.
**invariant-eval** adds: `regex`, `serde_yaml`.

### 4.3 Data Flow: Single Command (Full Cryptographic Chain)

```
1. Cognitive layer sends JSON command with signed PCA chain
                    |
                    v
2. INVARIANT: Deserialize command (~20us)
                    |
                    v
3. INVARIANT: Verify PIC authority chain (~160us)
   - A3: Ed25519 signature at each hop verified against trusted keys
   - A1: p_0 immutable across all hops
   - A2: ops monotonically narrowing at each hop
   - Required ops covered by final PCA's ops
   - Temporal constraints valid (not expired, not too early)
                    |
                    v
4. INVARIANT: Verify execution binding (~5us)
   - B1: Session ID matches active session
   - B2: Sequence number > last accepted (monotonic)
   - B3: Timestamp within acceptable window
   - B4: Executor binding matches PCA executor field
                    |
                    v
5. INVARIANT: Run 25 physics checks (~15us)
   - Delta time, joint limits, velocity, torque, acceleration
   - Workspace bounds, exclusion zones, self-collision
   - Center-of-mass stability, proximity velocity scaling
   - ISO/TS 15066 force limits, manipulation, locomotion, environment
                    |
                    v
6. INVARIANT: Produce verdict. Sign verdict with Ed25519. (~50us)
                    |
                    v
7. If APPROVED: Sign the command for the motor controller. (~50us)
   - SignedActuationCommand = Ed25519(approved_command)
   - Motor controller verifies this signature before executing
   If REJECTED: No actuation signature produced. Motors stay still.
                    |
                    v
8. INVARIANT: Append to audit log (~50us)
   - Hash chain link to previous entry
   - Ed25519 sign the audit entry
   - Write JSONL line (O_APPEND)
                    |
                    v
9. Return: SignedVerdict + optional SignedActuationCommand

Total: ~350us. 35% of 1kHz budget. 3.5% of 100Hz budget.
```

### 4.4 Data Flow: Watchdog

```
Cognitive layer sends heartbeat every N ms (configurable, default 50ms)
         |
         v
    INVARIANT: Reset watchdog timer
         |
         |--- If timer expires (no heartbeat for >N ms):
         |        |
         |        v
         |    INVARIANT: Sign safe-stop command
         |    Motor controller receives signed safe-stop
         |    Robot decelerates to zero velocity
         |    Audit log records: W1 violation, watchdog-initiated safe-stop
```

### 4.5 Process Isolation Model (On-Board Humanoids)

For humanoids running all compute locally:

- LLM runs in separate process with own container/VM
- Invariant firewall runs isolated process with own memory space
- Signing key lives in secure enclave (TPM chip or ARM TrustZone)
- LLM cannot access firewall memory or signing key
- Communication via Unix socket with defined message formats only
- Separate watchdogs: LLM watchdog and firewall watchdog cannot interfere
- If LLM crashes, firewall detects missing heartbeat and initiates safe-stop
- If firewall crashes, motor controller's hardware key verification fails → motors stop

### 4.6 Defense-in-Depth Stack

Five independent safety layers, each addressing different failure modes:

| Layer | Component | Type | Failure Mode Addressed |
|-------|-----------|------|----------------------|
| 1 | Invariant firewall | Smart, updatable | Authority violation, physics violation, execution binding |
| 2 | E-Stop relay | Dumb, unfallible | Total system failure — hardware circuit breaker (piece of copper) |
| 3 | OEM safety controller | Certified | UR, ABB, FANUC built-in safety systems |
| 4 | Remote monitoring | Slow, smart | Human oversight with anomaly detection |
| 5 | Environmental controls | Passive | Physical enclosures, barriers, impact-absorbing design |

Layer 2 is the most reliable because it requires no software.

---

## 5. Attack Resistance

### 5.1 PIC + Invariant Combined Defense

| Attack | Example | PIC Defense | Invariant Defense |
|--------|---------|-------------|-------------------|
| Environmental injection | QR code with fake commands | Scope check fails (ops not in PCA) | — |
| Voice/label injection | Written instructions on object | Identity check fails (not p_0) | — |
| Compromised LLM | Hallucinated destination | Scope check fails (ops outside granted) | Physics check fails (workspace bounds) |
| Rogue API calls | External service injection | Signature verification fails (no valid PoC) | — |
| Replay attacks | Old commands reused | PoC freshness binding fails | B2: sequence monotonicity fails |
| Self-expansion | LLM grants itself authority | Cannot construct valid PoC for expanded ops | — |
| Cross-session replay | Command from expired session | — | B1: session binding fails |
| Stale command injection | Old command with valid chain | — | B3: temporal window fails |
| Executor impersonation | Different process uses same PCA | Executor binding in PCA mismatches | B4: executor identity check fails |
| Unsafe physics | Valid authority, dangerous motion | — | P1–P25: physics invariants reject |
| Cognitive layer crash | Brain stops responding | — | W1: watchdog triggers safe-stop |
| Audit tampering | Post-incident log modification | — | L1–L4: hash chain + signatures detect |
| Motor bypass | Command injected after firewall | — | M1: motor requires Invariant signature |

### 5.2 Why Both Layers Are Necessary

**PIC alone is insufficient for robotics:** A perfectly valid authority chain can authorize a physically dangerous command. Authority says "you may move the arm" — physics determines whether moving the arm at this velocity, to this position, at this time, is safe.

**Invariant alone is insufficient for authority:** A physics-safe command issued by an unauthorized executor, or by an executor whose authority was forged, replayed, or expanded, must be rejected even if it would not cause physical harm. The question "may this executor do this?" is logically prior to "is this action safe?"

Together:
- PIC proves the authority chain is valid (lineage)
- Invariant proves the transition is safe and bound (execution)
- Both proofs required before motor moves (composition)

---

## 6. PIC Protocol Interoperability

### 6.1 Deployment Models

Invariant supports multiple PIC deployment configurations:

| Model | CAT Location | Use Case |
|-------|-------------|----------|
| **Embedded** | CAT logic within Invariant process | Single-robot, on-board compute, lowest latency |
| **Sidecar** | CAT as adjacent service, validated via API | Multi-robot fleet with centralized authority management |
| **Federated** | Cross-domain CAT with federation bridges | Multi-organization deployments (hospital + robot vendor) |
| **External** | Full PIC Trust Plane (pic-rust) | Enterprise deployments with existing PIC infrastructure |

In all models, Invariant verifies the PCA chain independently. The CAT's role is to *construct* valid chains; Invariant's role is to *verify* them and gate physical actuation.

### 6.2 Federation and Cross-Domain Authority

When robots operate across organizational boundaries (e.g., a robot vendor's AI executor operating in a hospital), PIC's federation model applies:

**Bridge invariants (from PIC Spec):**
- `p_0(PCA_T₂) = p_0(PCA_T₁)` — origin preservation across domains
- `ops(PCA_T₂) ⊆ ops(PCA_T₁)` — monotonicity across domains
- No expansion: bridges cannot fabricate authority
- Provenance continuity: chain remains verifiable across the bridge

Invariant verifies these bridge invariants identically to intra-domain hops. A cross-domain PCA chain is validated the same way as a single-domain chain — the invariants are structural, not topological.

### 6.3 AI Agent Authority Model

Following the PIC AI Agents Specification: agents are executors, tools are executors. No new authority concepts are introduced. An LLM-based motion planner is an executor at some hop *i* in the PCA chain, and its authority is `ops_i ⊆ ops_{i-1}`.

The cognitive layer cannot:
- Construct PCA extensions (it lacks the signing keys)
- Expand its own authority (monotonicity is structural)
- Forge PoC for unauthorized operations (requires predecessor PCA binding)
- Bypass execution binding checks (Invariant verifies independently)

Human and AI executors receive identical authority semantics governed by causal continuity.

### 6.4 Identity Mapping at Federation Boundaries

When external identity systems feed into PIC chains:

| Source | p_0 Derivation | ops_0 Derivation |
|--------|---------------|------------------|
| OAuth/OIDC | `sub` claim | `scope` claim → operation set mapping |
| SPIFFE | SPIFFE ID | Trust domain policy |
| X.509 | Subject DN | Certificate extensions |
| DID/VC | DID URI | VC claims |

Invariant's embedded mode uses Ed25519 key pairs directly. Federation bridges translate external identity into PCA_0 at the domain entry point.

---

## 7. Statistical Validation

### 7.1 Four-Stage Safety Evidence Process

Demonstrating adequate safety requires sequential evidence accumulation:

**Stage 1: Dry-Run Simulation (Forge mode)**
Millions of simulated episodes in NVIDIA Isaac Lab. Measure false positive rates (safe commands rejected) and false negatives (unsafe commands accepted). Physics invariants must have zero false negatives in simulation. Authority invariant violations tested with adversarial injection campaigns.

**Stage 2: Hardware-in-the-Loop Testing**
Real robot, real firewall hardware, real motor controllers in controlled environments without humans. Exercise complete invariant set including execution binding. Test timing, hardware-software discrepancies, communication failures.

**Stage 3: Shadow Mode**
Real robot in real environment; firewall checks all commands but does not block them. Separate safety layer provides actual protection. Accumulate thousands of operating hours.

Statistical requirement using Clopper-Pearson confidence intervals: for 1-per-million false negative rate at 95% confidence, approximately 3 million shadow-mode commands needed.

**Stage 4: Guardian Mode**
Firewall actively blocks unsafe commands. Existing OEM safety systems remain as independent backstop. Human supervisors monitor initial operations. Transition to routine operation after defined period with zero safety incidents.

### 7.2 Adversarial Testing (invariant-fuzz)

The adversarial testing framework exercises attacks at three levels:

| Level | Attack Type | Examples |
|-------|------------|---------|
| Protocol | PIC chain forgery | Replayed PoC, expanded ops, re-rooted p_0, missing hops |
| System | Execution binding bypass | Cross-session replay, stale commands, sequence manipulation |
| Cognitive | Prompt injection | Environmental injection, context contamination, hallucinated authority |

Every attack must be rejected by the appropriate invariant. Zero false negatives in adversarial testing is a release gate.

---

## 8. Formal Specification (Lean 4)

The Lean 4 formalization proves that the invariant composition is sound:

```lean
-- Master safety theorem
theorem safety_guarantee :
  ∀ (cmd : Command) (profile : RobotProfile) (chain : PcaChain) (ctx : ExecutionContext),
    pic_chain_valid chain →           -- A1, A2, A3 hold
    execution_bound cmd ctx chain →   -- B1, B2, B3, B4 hold
    physics_safe cmd profile →        -- P1–P25 hold
    watchdog_alive ctx →              -- W1 holds
    → CommandIsApproved cmd
```

The authority formalization specifically encodes the PIC properties:

```lean
-- PIC authority continuity
def pic_chain_valid (chain : PcaChain) : Prop :=
  origin_immutable chain ∧           -- ∀i: p_i = p_0
  authority_monotonic chain ∧         -- ∀i: ops_{i+1} ⊆ ops_i
  continuity_proven chain             -- ∀i: PoC_i valid for PCA_{i-1}

-- Confused deputy impossibility (derived theorem)
theorem confused_deputy_impossible :
  ∀ (chain : PcaChain) (executor : Executor) (op : Operation),
    pic_chain_valid chain →
    executor_at_hop chain executor →
    executes executor op →
    op ∈ ops_at_hop chain executor    -- Can only exercise derived authority
```

---

## 9. Limitations and Unsolved Problems

1. **Model validity.** The physics model in the firewall must be accurate. Sufficiently wrong models cause false rejections (nuisance) or, critically, allow dangerous commands through (safety failure). Model validation against real hardware is essential.

2. **Root key security.** The architecture assumes the root authority key (p_0's signing key) is secure. Key management in the field — rotation, revocation, compromise recovery — remains a hard operational problem.

3. **Invariant completeness.** The 25 physics checks and 4 execution binding checks cover known configurations. Novel robotics situations may require updates to the invariant set.

4. **Update mechanism.** The process for securely updating invariants, profiles, and firmware must itself be secure and auditable. A malicious update that weakens an invariant is equivalent to removing the firewall.

5. **PIC PoC construction.** Invariant verifies PCA chains but does not implement full PoC construction with attestation types (SPIFFE SVID, Verifiable Presentations, TEE quotes). Deployments requiring these must use an external PIC implementation (pic-rust) to construct chains.

6. **Latency under federation.** Cross-domain PCA chain verification adds network round-trips for bridge validation. Embedded CAT eliminates this for single-domain deployments, but federated deployments must account for verification latency in the servo loop budget.

7. **Governance integration.** PIC distinguishes between structural invariants (always enforced) and governance policies (conditionally applied). Invariant does not yet implement a governance policy engine — it enforces the structural invariants only.

---

## 10. Adoption Timeline

**Phase 1 (2025–2026)**
Open-source reference implementation. Physics library. Dry-run simulation in Isaac Lab. First manufacturing cell pilots. Embedded PIC chain verification (A1–A3). Execution binding (B1–B4).

**Phase 2 (2026–2027)**
Hardware-in-the-loop testing. Shadow mode data collection. IEC 61508 pre-assessment. Quadruped deployments. PIC sidecar mode for fleet management.

**Phase 3 (2027–2028)**
Guardian mode manufacturing. PCA tooling for fleet operators. Humanoid pilots in controlled settings. Federation bridge integration for multi-organization deployments.

**Phase 4 (2028–2030)**
Full certification path (PLd/SIL 2). Humanoid semi-structured deployments. Surgical assist applications. Full PIC Protocol interoperability including governance policies.
