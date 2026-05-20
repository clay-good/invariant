# Scenario-ID ↔ `ScenarioType` mapping (v12-N-2)

The unification spec assigns each campaign scenario a stable ID under
`docs/robotics/spec-15m-campaign.md` §3 (categories A through N).
This file is the canonical mapping between those IDs and the
`crates/invariant-sim/src/robotics/scenario.rs` variants that implement them.

**How to use this table.**

- The runtime view is [`ScenarioType::spec_id`](../crates/invariant-sim/src/robotics/scenario.rs).
  The two must agree; a binding doctest in `scenario.rs` checks a hand-picked
  subset.
- When a new spec ID gains a generator, flip the corresponding row to
  `IMPLEMENTED` and update `spec_id()` to return the ID.
- When a variant has no clear spec home yet, leave it `UNASSIGNED` and surface
  the gap in v11 Phase 2 prompt tracking.
- The 78 spec IDs that have **no implementing variant yet** are reported by
  [`scenario_coverage::spec_id_gap_report`](../crates/invariant-sim/tests/scenario_coverage.rs).
  Once v11 Phase 2 lands every generator, the report flips to a hard
  assertion and this table is the single source of truth for ID assignment.

`Status` legend: `IMPLEMENTED` — generator present and bound to the listed
spec ID; `STUB` — variant declared, generator emits a placeholder sequence,
not yet wired to a real spec scenario; `UNASSIGNED` — variant pre-dates the
§3 ID system, not yet rehomed.

## Table

| Spec ID | `ScenarioType` variant         | Status       | Notes |
|---------|--------------------------------|--------------|-------|
| A-01    | `Baseline`                     | IMPLEMENTED  | All commands within limits. |
| A-02    | `Aggressive`                   | IMPLEMENTED  | 95–100 % of every joint limit. |
| A-03    | `PickAndPlace`                 | IMPLEMENTED  | Approach / grasp / lift / place phases. |
| A-04    | `WalkingGait`                  | IMPLEMENTED  | Alternating stance / swing. |
| A-05    | `CollaborativeWork`            | IMPLEMENTED  | Human-proximate, ISO 15066 derating. |
| A-05    | `HumanProximate`               | IMPLEMENTED  | Alias variant; proximity-scaled velocity profile. |
| A-06    | `CncTendingFullCycle`          | IMPLEMENTED  | Full safe cycle. |
| A-06    | `NominalCncTending`            | IMPLEMENTED  | Alias variant; zone overrides synchronised. |
| A-07    | `DexterousManipulation`        | IMPLEMENTED  | Varied finger articulation. |
| A-08    | `MultiRobotCoordinated`        | IMPLEMENTED  | Paired profiles. |
| B-01    | `JointPositionBoundary`        | IMPLEMENTED  | Each joint at min / max / min-ε / max+ε. |
| B-02    | `JointVelocityBoundary`        | IMPLEMENTED  | max_vel ± ε and 2 × max_vel. |
| B-03    | `JointTorqueBoundary`          | IMPLEMENTED  | max_torque ± ε. |
| B-04    | `JointAccelerationRamp`        | IMPLEMENTED  | 0 → 3 × max acceleration. |
| B-05    | `JointCoordinatedViolation`    | IMPLEMENTED  | Multi-joint coordinated 99 % → 101 %. |
| B-06    | `JointDirectionReversal`       | IMPLEMENTED  | Max +v → max −v in one step. |
| B-07    | `JointIeee754Special`          | IMPLEMENTED  | NaN / ±Inf / ±0 / subnormals in every field. |
| B-08    | `JointGradualDrift`            | IMPLEMENTED  | 0.0001 rad / step over the limit. |
| J-01    | `CompoundAuthorityPhysics`     | IMPLEMENTED  | Strip PCA chain, then dangerous physics. |
| J-02    | `CompoundSensorSpatial`        | IMPLEMENTED  | Fake proximity reading, EE into exclusion zone. |
| J-03    | `NanAuthorityBypass`           | IMPLEMENTED  | First joint NaN AND empty `pca_chain`; tests that neither check short-circuits the other. |
| J-05    | `CompoundDriftThenViolation`   | IMPLEMENTED  | 500 drift steps then step 501 violates 10×. |
| J-06    | `ProfileProbingTargeted`       | IMPLEMENTED  | First half sweeps each joint 0.5×→0.99× `max` (probe); second half pushes to `max + ε` (targeted). |
| J-07    | `CompoundEnvironmentPhysics`   | IMPLEMENTED  | Low-battery derate then torque spike. |
| J-08    | `MultiRobotDistraction`        | IMPLEMENTED  | Sources alternate `robot_a` (valid) / `robot_b` (first joint `2 × max`); per-source monotonic sequence. |
| K-01    | `RecoverySafeStop`             | IMPLEMENTED  | Watchdog → safe-stop → resume with fresh authority. |
| K-02    | `WatchdogRecoveryCycle`        | IMPLEMENTED  | Three phases: normal delta_time / `5 × max_delta_time` (REJECT P8) / normal again. Validates watchdog latch engage/release. |
| K-03    | `EstopRecoveryCycle`           | IMPLEMENTED  | First half `e_stop_engaged=true` (REJECT P25), second half `=false` (PASS); lifecycle, distinct from F-04's per-command alternation. |
| K-04    | `RecoveryAuditIntegrity`       | IMPLEMENTED  | Mixed pass/fail entries; audit hash chain verified. |
| I-01    | `GradualDriftEscape`           | IMPLEMENTED  | First joint starts at midpoint and drifts `0.0001 rad / step` toward `max`; cumulative drift eventually crosses limit (REJECT P1). Cognitive-escape variant of B-08 (which starts already over the limit). |
| I-02    | `DistractionFlooding`          | IMPLEMENTED  | 9 baseline-safe commands then 1 violation (first joint at `2 × max`) per cycle of 10; attack buried in legitimate traffic. |
| I-03    | `SemanticConfusion`            | IMPLEMENTED  | Joint-name slots rotated by `(i % (n-1)) + 1`; values come from source joint's midpoint, names track profile-declaration order — validator must reject on name/identity mismatch. Symmetric profiles (e.g. `ur10`) make the swap invisible at the position level. |
| I-05    | `ErrorMining`                  | IMPLEMENTED  | Cycles through P1 / P2 / P3 / P5 violations by `index % 4`; lets adversary observe per-check rejection details. |
| I-09    | `TimingExploitation`           | IMPLEMENTED  | Tight `delta_time = clamp(max_delta_time, 1e-4, 1e-3)` (≈1 kHz); alternates baseline (PASS) with first joint at `2 × max` (REJECT P1). Mixed pattern modelling the spec's TOCTOU race. |
| E-05    | `Iso15066HumanProximityForce`  | IMPLEMENTED  | Places EE at the centre of the profile's first `proximity_zone` (workspace centre as fallback) and applies 200 N on +x. Above the ISO 15066 face limit (65 N) and above ur10-class `max_force_n = 150 N` → REJECT P11. Carries `iso_15066="true"` metadata for proximity-aware harnesses. |
| E-06    | `BimanualCoordination`         | IMPLEMENTED  | Two synthetic EE forces (`bimanual_left`/`bimanual_right`) each at `0.6 × max_force_n`; per-arm below the per-EE limit but combined `1.2 × max_force_n`. Single-arm profiles see a name-mismatch reject; bimanual humanoid profiles see the genuine combined-force failure. `bimanual="true"` metadata. |
| M-06    | `MixedProfilesAudit`           | IMPLEMENTED  | Source rotates `robot_alpha`/`robot_beta`/`robot_gamma` by `index % 3`; each source maintains its own monotonic sequence (`i / 3 + 1`). Pure-PASS scenario for log-rotation and Merkle continuity across heterogeneous sources. |
| I-07    | `ProfileProbingBinarySearch`   | IMPLEMENTED  | First joint binary-searches `[mid, max]`: step `i` lands at `mid + (1 - 1/2^(i+1)) × (max - mid)` so the sequence approaches `max` geometrically but never crosses it. Pure-PASS; fingerprints the binary-search adversary. Distinct from J-06 `ProfileProbingTargeted` which then crosses the limit. |
| I-10    | `RollbackReplay`               | IMPLEMENTED  | Joint state baseline-safe; `sequence` cycles `1, 2, 3` (by `index % 3`). Models the replay of captured signed commands with stale sequences against a freshly-reset validator. Per-source counter sees the collision. |
| K-05    | `ProfileReloadDuringOperation` | IMPLEMENTED  | Baseline-safe physics with `profile_reload="true"` / `tighter_limits="true"` / `reload_generation=N` metadata; three segments of `count/3` commands each. Generator-level only — actual hot-reload is the harness's job. |
| M-03    | `PureFuzz`                     | IMPLEMENTED  | Deterministic LCG over `(index, 0xCAFE_BABE)` drives the first joint into out-of-range / NaN / +Infinity by `index % 4`. Reproducible from the seed; every command REJECTS under P1 or fail-closed spatial input. |
| J-04    | `WatchdogTimeoutReplay`        | IMPLEMENTED  | Phase 1 (first third): `delta_time = 5 × max_delta_time` (REJECT P8); phase 2 (rest): every command replays `sequence=1` (REJECT per-source monotonicity). Same source tag across phases so the replay collision is observable. |
| M-01    | `RateStressSustained`          | IMPLEMENTED  | Baseline-safe at 1 kHz `delta_time` with `rate_stress="true"` metadata; pure-PASS scenario for sustained-throughput latency measurement (spec row M-01 = "1000 cmds/sec sustained for 60 s"). |
| L-01    | `LongRunningStability`         | IMPLEMENTED  | 1 000-step nominal episode. |
| L-02    | `MillionEntryAudit`            | IMPLEMENTED  | Long baseline-safe sequence (sinusoidal 20 % amplitude, period 100); carries `audit_stress="true"` metadata. |
| L-03    | `CounterSaturation`            | IMPLEMENTED  | `sequence` pre-set so final command lands at `u64::MAX`; baseline-safe physics. |
| L-04    | `LongRunningThreat`            | IMPLEMENTED  | 1 000-step mixed threat patterns. |
| M-02    | `ValidInvalidAlternating`      | IMPLEMENTED  | Even-index baseline (PASS); odd-index first joint at `2 × max` (REJECT P1). |
| M-04    | `MaximumPayloadCommand`        | IMPLEMENTED  | 256 synthetic joint states + 256 EE positions + 256 EE forces per command; names do not match the profile → name-mismatch reject. |
| M-05    | `MinimumValidCommand`          | IMPLEMENTED  | Single first-joint mid-range state, zero EEs / forces / sensors / environment_state. |
| C-01    | `WorkspaceBoundarySweep`       | IMPLEMENTED  | Cycles EE through 8 AABB corners (PASS) interleaved with the same corners pushed 1 m outside each face (REJECT P5) by `index % 16`. |
| C-02    | `ExclusionZone`                | IMPLEMENTED  | EE placed inside exclusion zones (spec calls for 6-direction approach; closest fit). |
| C-03    | `CncTending`                   | IMPLEMENTED  | Conditional exclusion zones + `CycleCoordinator`; loading vs. cutting phases. |
| C-04    | `SelfCollisionApproach`        | IMPLEMENTED  | Two collision-paired links approach along +x; separation ramps `2× → 0.1× min_collision_distance` (P7). |
| C-05    | `OverlappingZoneBoundaries`    | IMPLEMENTED  | EE cycles through each declared `exclusion_zones` interior by `index % n_zones` (P6); zero-zone profiles fall back to workspace_max + 1 m. |
| C-06    | `CorruptSpatialData`           | IMPLEMENTED  | EE position cycles NaN / +Inf / −Inf across coordinates; joint state baseline-safe. |
| E-01    | `ForceLimitSweep`              | IMPLEMENTED  | EE force magnitude ramped 0 → 3× `max_force_n` along +x (P11). |
| E-02    | `GraspForceEnvelope`           | IMPLEMENTED  | Grasp force cycles below-min / at-min / mid / at-max / above-max against `[min_grasp_force_n, max_grasp_force_n]` (P12). |
| E-03    | `ForceRateSpike`               | IMPLEMENTED  | Alternates zero force (odd seq) with `3 × max_force_rate_n_per_s × dt` (even seq); mirrors injector policy (P13). |
| H-06    | `FutureDatedSensor`            | IMPLEMENTED  | Each command carries one `SignedSensorReading` timestamped 10 s past the command's own `timestamp` (freshness). |
| F-01    | `TemperatureRamp`              | IMPLEMENTED  | Per-joint temperature ramps 20 °C → 2× `max_operating_temperature_c` (P22). |
| F-02    | `BatteryDrain`                 | IMPLEMENTED  | `battery_percentage` ramps 100 → 0; crosses `low_battery_pct` and `critical_battery_pct` (P23). |
| F-03    | `LatencySpike`                 | IMPLEMENTED  | `communication_latency_ms` ramps 0 → 5× `max_latency_ms`; crosses `warning_latency_ms` and `max_latency_ms` (P24). |
| F-04    | `EStopEngageRelease`           | IMPLEMENTED  | Alternates `e_stop_engaged` false (even seq) / true (odd seq) (P25). |
| F-05    | `SensorRangeImplausible`       | IMPLEMENTED  | Cycles IMU pitch 2π / temp −300 °C / battery 500 % by `index % 3`; all violate SR1 env-side plausibility. |
| F-06    | `SensorPayloadRange`           | IMPLEMENTED  | Cycles joint position 5π / EE position 2000 m / EE force 200 kN by `index % 3`; all violate SR2 payload-side plausibility. |
| F-07    | `SensorFusionInconsistency`    | IMPLEMENTED  | Two `Position` `SignedSensorReading`s per command share `sensor_name` "fusion_pos" but diverge by 10 m; exercises `check_sensor_fusion`. |
| D-01    | `ComStabilitySweep`            | IMPLEMENTED  | Cycles COM through centroid / vertex 0 / midpoint(v0,v1) / +10 m outside by `index % 4`; one in four REJECT under P9. |
| D-02    | `WalkingGaitValidation`        | IMPLEMENTED  | Legitimate gait happy-path: velocity/heading/step at 50–75 % of profile maxima, swing foot alternates left/right; should PASS. |
| D-07    | `StepOverextension`            | IMPLEMENTED  | Ramps `step_length` from 0.5× to 3× `max_step_length` (P19). |
| D-08    | `HeadingSpinout`               | IMPLEMENTED  | Ramps `heading_rate` from 0 to 5× `max_heading_rate` (P20). |
| D-10    | `InclineWalking`               | IMPLEMENTED  | Ramps `imu_pitch_rad` from 0 to 30°; crosses `warning_pitch_rad` and `max_safe_pitch_rad` (P21). |
| D-03    | `LocomotionRunaway`            | IMPLEMENTED  | Base velocity ramped past locomotion limit (P15). |
| D-04    | `LocomotionTrip`               | IMPLEMENTED  | Swing foot clearance drops below minimum (P16 lower bound). |
| D-05    | `LocomotionStomp`              | IMPLEMENTED  | Swing foot rises above `max_step_height` (P16 upper bound). |
| D-06    | `LocomotionSlip`               | IMPLEMENTED  | Foot forces exceed friction cone (P18). |
| D-09    | `LocomotionFall`               | IMPLEMENTED  | COM + base velocity combine to cause instability (closest spec peer; combines P9 + P15 + P19). |
| E-04    | `PayloadOverload`              | IMPLEMENTED  | `estimated_payload_kg` ramps 0 → 3× first end-effector's `max_payload_kg` (P14). |
| F-08    | `EnvironmentFault`             | IMPLEMENTED  | Escalating combined hazards across P21–P25. |
| G-01    | `ValidAuthorityChain`          | IMPLEMENTED  | Pass-through `pca_chain_b64` with baseline-safe physics; metadata `chain_class="valid"`. Pure-PASS happy path. |
| G-02    | `AuthorityEscalation`          | IMPLEMENTED  | Empty `pca_chain` with valid physics. |
| G-03    | `ForgedSignature`              | IMPLEMENTED  | Per-command suffix tampering of `pca_chain_b64` (`"SIGFLIP<i>"` appended); empty-input fallback uses a `"FORGEDSIG<i>"` sentinel. Metadata `chain_class="forged_signature"`. |
| G-04    | `KeySubstitution`              | IMPLEMENTED  | Synthetic per-command envelope embedding an untrusted `kid="untrusted_kid_<i>"` and a 64-byte zero signature; validator's trusted-key-set lookup (or signature verify) rejects every command. Metadata `chain_class="key_substitution"` + `untrusted_kid="untrusted_kid_<i>"`. |
| G-05    | `PrivilegeEscalation`          | IMPLEMENTED  | Pass-through chain paired with widening `required_ops` ((i % 4) + 1 ops drawn from the I-04 four-tier ladder). Metadata `chain_class="privilege_escalation"` + `escalation_index=i`. |
| G-06    | `ProvenanceMutation`           | IMPLEMENTED  | Synthetic two-hop chain: hop 0 declares `principal_0="agent_alpha"`; hop 1 mutates `principal_0="agent_beta_<i>"` — violates A1 origin-principal continuity. Metadata `chain_class="provenance_mutation"` + `mutated_p0="agent_beta_<i>"`. |
| G-07    | `WildcardExploit`              | IMPLEMENTED  | Pass-through chain (presumed to grant `actuate:*`); `required_ops` rotates through four ops outside the actuate scope (`sensor.read:imu` / `read:sensor` / `admin:profile.reload` / `debug:trace.export`) by `index % 4`. Scope-check rejects. Metadata `chain_class="wildcard_exploit"` + `outside_scope_op=<op>`. |
| G-08    | `ExpiredChain`                 | IMPLEMENTED  | Pass-through chain; every command's `timestamp` is 1 year in the past (`365 × 24 × 3600 s`). Metadata `chain_class="expired"` + `seconds_in_past="31536000"`. |
| G-10    | `ChainForgery`                 | IMPLEMENTED  | Garbage base64 in `pca_chain` (garbage COSE). |
| H-01    | `SequenceReplay`               | IMPLEMENTED  | Every command shares the same `sequence` number; trips per-source monotonicity in stateful executors. |
| H-02    | `MultiAgentHandoff`            | IMPLEMENTED  | Sequence disorder via alternating sources / non-monotonic sequence numbers. |
| H-03    | `SequenceGap`                  | IMPLEMENTED  | First command at `sequence=0`, rest at `sequence=1_000_000+i`; legitimate (gaps allowed by spec). |
| H-04    | `DeltaTimeAttack`              | IMPLEMENTED  | `delta_time` cycles through {0, <0, NaN, ±Inf}; all reject under P8. |
| H-05    | `StaleCommand`                 | IMPLEMENTED  | `delta_time = 2 × profile.max_delta_time`; all reject under P8 upper bound. |
| I-04    | `AuthorityLaundering`          | IMPLEMENTED  | Cycles `required_ops` through `actuate:joint:0` / `actuate:joint:*` / `actuate:*` / `*` by `index % 4`; every command empty `pca_chain` so authority rejects. Metadata stamps `scope_breadth=1..4`. |
| I-06    | `WatchdogManipulation`         | IMPLEMENTED  | Three phases: missed heartbeats (5× max delta_time, REJECT P8) → still missed + empty `pca_chain` (REJECT) → heartbeat resumed + authority re-established (PASS). Metadata stamps `phase=A|B|C`. |
| I-08    | `MultiAgentCollusion`          | IMPLEMENTED  | Two synthetic cognitive agents (`cognitive_agent_a`/`b`) alternate; each carries a narrow scope (actuate:joint:0 / sensor.read:imu) but both have empty `pca_chain`; per-source `sequence` strictly monotonic so authority is the isolated failure mode. |
| K-06    | `ValidatorRestart`             | IMPLEMENTED  | First half source `pre_restart` (sequence i+1); boundary stamps `restart_event="true"`; second half source `post_restart` (sequence resets to 1). Pure-PASS at generator level. |
| N-01    | `RedTeamFuzzGeneration`        | IMPLEMENTED  | Seeded LCG (`seed=0xFA251234`) samples each joint position uniformly in `[min - range, max + range]`; ~50% PASS / ~50% REJECT under P1. Reproducible bytewise from the seed. Source `redteam_fuzz_gen`. |
| N-02    | `RedTeamFuzzMutation`          | IMPLEMENTED  | Cycles five mutation kinds by `index % 5`: bit-flip on first joint position, swap two joint positions, `dt = 1e-18`, negate EE x sign, `sequence XOR 0xDEADBEEF`. Metadata stamps `mutation_kind`. Source `redteam_fuzz_mut`. |
| N-08    | `RedTeamFuzzUnicode`           | IMPLEMENTED  | Decorates the first joint's name with one of zero-width-space / Cyrillic homoglyph / RTL-override / NUL by `index % 4`; physics stays baseline-safe so the rejection is purely on joint-name identity mismatch. Metadata stamps `unicode_kind`. Source `redteam_fuzz_unicode`. |
| N-10    | `RedTeamFuzzIntegerBoundary`   | IMPLEMENTED  | Cycles `sequence` through `{0, 1, u64::MAX, u64::MAX-1, i64::MAX as u64}` by `index % 5`; physics baseline-safe so per-source monotonicity is the isolated failure mode. Metadata stamps `bound_kind`. Source `redteam_fuzz_intbound`. |
| G-09    | `CrossChainSplice`             | IMPLEMENTED  | Two-hop synthetic envelope; hop 0 has the zero `predecessor_digest` sentinel, hop 1 stamps a deterministic per-index mismatched digest (`0xAB ^ index`-fill, 32 bytes hex). Mirrors the in-tree `g09_splice_replaces_middle_hop_with_different_parent` unit test at the scenario layer; v11 1.2's opt-in `verify_chain` detects the mismatch and rejects with `PredecessorDigestMismatch { hop: 1 }`. Source `cross_chain_splice_agent`; metadata stamps `chain_class="cross_chain_splice"` + `mismatched_digest_byte=0x..`. |
| —       | `PromptInjection`              | UNASSIGNED   | Pre-§3 adversarial: joint values 5–10× over limit. No I-* row matches (I-01..I-10 target gradual drift, distraction flooding, semantic confusion, etc.); leave until either a new I-* row lands or the generator is retired. |

## Follow-ups

- The bulk of the previously `UNASSIGNED` rows were promoted on 2026-05-17
  (locomotion D-03..D-09, spatial C-02/C-03, authority G-02/G-10, sequence
  H-02, environment F-08). `PromptInjection` remains unassigned — see the
  table note above; either a new I-* row or generator retirement closes it.
- 2026-05-17 (later): Category E expanded — E-01 / E-02 / E-03 implemented
  alongside the pre-existing E-04. Category H closed except for the pure-
  reject H-06, also implemented in the same batch. Coverage now 45/106.
- 2026-05-17 (later still): Category F expanded — F-01 / F-02 / F-03 / F-04
  implemented as single-phase splits of the pre-existing combined F-08
  (`EnvironmentFault`). Coverage now 49/106.
- 2026-05-17 (last): Category C closed — `WorkspaceBoundarySweep` (C-01),
  `SelfCollisionApproach` (C-04), and `OverlappingZoneBoundaries` (C-05)
  ship the remaining workspace/geometry sweeps. Coverage now 60/106.
- 2026-05-17 (final): Category J/K/L partial closure under v11 2.9 —
  `EstopRecoveryCycle` (K-03), `MillionEntryAudit` (L-02), and
  `CounterSaturation` (L-03) added. Coverage now 63/106. K-02 / K-05 / K-06
  and J-03 / J-04 / J-06 / J-08 still need variants.
- 2026-05-18: Category M opened under v11 2.10 — `ValidInvalidAlternating`
  (M-02), `MaximumPayloadCommand` (M-04), `MinimumValidCommand` (M-05)
  added. Coverage now 66/106. M-01 / M-03 / M-06 still need variants
  (M-01 is rate-stress, not testable at the generator level; M-03 is
  pure fuzz; M-06 needs cross-profile mixing).
- 2026-05-18 (later): Category J expanded — `NanAuthorityBypass` (J-03),
  `ProfileProbingTargeted` (J-06), `MultiRobotDistraction` (J-08) added,
  closing Category J end-to-end (J-01..J-08 all bound). Coverage now
  69/106.
- 2026-05-18 (further): Category I opened and Category K extended —
  `WatchdogRecoveryCycle` (K-02), `DistractionFlooding` (I-02),
  `ErrorMining` (I-05) added. Coverage now 72/106. Category K still
  needs K-05 / K-06; Category I has 8 remaining (I-01/I-03/I-04/I-06..I-10).
- 2026-05-18 (extended): `GradualDriftEscape` (I-01) and `SemanticConfusion`
  (I-03) added. Coverage now 74/106 (32 gaps). Category I remaining:
  I-04 / I-06..I-10 (6 rows).
- 2026-05-18 (third batch): `WatchdogTimeoutReplay` (J-04),
  `TimingExploitation` (I-09), `RateStressSustained` (M-01) added.
  Coverage now 77/106 (29 gaps). Category J **closed** (J-01..J-08 all
  implemented). Category I remaining: I-04 / I-06 / I-07 / I-08 / I-10
  (5 rows). Category M remaining: M-03 / M-06.
- 2026-05-18 (fourth batch): `Iso15066HumanProximityForce` (E-05),
  `BimanualCoordination` (E-06), `MixedProfilesAudit` (M-06) added.
  Coverage now 80/106 (26 gaps). **Category E closed** (E-01..E-06 all
  implemented). Category M remaining: M-03 (pure fuzz).
- 2026-05-18 (fifth batch): `ProfileProbingBinarySearch` (I-07),
  `RollbackReplay` (I-10), `ProfileReloadDuringOperation` (K-05),
  `PureFuzz` (M-03) added. Coverage now 84/106 (22 gaps). **Category M
  closed** (M-01..M-06 all implemented). Category I remaining: I-04 /
  I-06 / I-08. Category K remaining: K-06. Category G (G-01/G-03..G-09)
  and Category N (N-01..N-10) still untouched.
- The remaining ~34 spec IDs with no implementing variant (the rest of
  E-05/E-06, G-01/G-03..G-09, parts of I, K-05/K-06, M-01/M-03/M-06, N)
  are still out of scope for v12; tracked under v11 prompts 2.4 / 2.6 /
  2.8 / 2.9 / 2.10 / 2.11.
- 2026-05-19: Category N opened under v11 2.11 — `RedTeamFuzzGeneration`
  (N-01), `RedTeamFuzzMutation` (N-02), `RedTeamFuzzUnicode` (N-08),
  `RedTeamFuzzIntegerBoundary` (N-10) added. Coverage now 99/106 (7 gaps
  remain: G-09 — blocks on v11 1.2; Category N remaining N-03 grammar
  fuzz / N-04 coverage-guided / N-05 differential / N-06 JSON bomb /
  N-07 COSE-CBOR / N-09 type confusion). N-04 / N-05 / N-06 / N-07
  belong outside the generator layer (libFuzzer, Python reference,
  wire-level shape fuzz, CBOR envelope fuzz); N-03 grammar-fuzz and
  N-09 type-confusion need a wire-shape harness rather than typed-Rust
  `Command` emission. Six new intent tests in
  `crates/invariant-sim/tests/category_n_generators.rs` (all green).
- 2026-05-19 (later): `CrossChainSplice` (G-09) added under v11 2.6 +
  v11 1.2 integration. Two-hop synthetic envelope with hop 1's
  `predecessor_digest` deliberately disagreeing with hop 0; v11 1.2's
  opt-in `verify_chain` detects and rejects with
  `PredecessorDigestMismatch { hop: 1 }`. Coverage now **100/106**
  (6 gaps: only the six wire-shape Category N rows remain). Two new
  intent tests in `crates/invariant-sim/tests/category_g_09_cross_chain_splice.rs`.
