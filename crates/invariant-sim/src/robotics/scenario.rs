// Built-in simulation scenarios.
//
// Each `ScenarioType` produces a deterministic sequence of `Command` values
// designed to exercise a specific failure mode (or the happy path) of the
// Invariant safety firewall.

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, Utc};
use invariant_robotics::models::authority::Operation;
use invariant_robotics::models::command::{
    Command, CommandAuthority, EndEffectorForce, EndEffectorPosition, FootState, JointState,
    LocomotionState,
};
use invariant_robotics::models::profile::{ExclusionZone, ProximityZone, RobotProfile, WorkspaceBounds};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ScenarioType
// ---------------------------------------------------------------------------

/// Built-in scenario classes for the 15M campaign.
///
/// # Examples
///
/// ```
/// use invariant_sim::robotics::scenario::ScenarioType;
///
/// // Each variant can be compared for equality.
/// assert_eq!(ScenarioType::Baseline, ScenarioType::Baseline);
/// assert_ne!(ScenarioType::Baseline, ScenarioType::Aggressive);
///
/// // Adversarial variants are distinct from the baseline.
/// let violation_scenarios = [
///     ScenarioType::ExclusionZone,
///     ScenarioType::AuthorityEscalation,
///     ScenarioType::ChainForgery,
///     ScenarioType::PromptInjection,
///     ScenarioType::LocomotionRunaway,
///     ScenarioType::LocomotionSlip,
///     ScenarioType::LocomotionTrip,
///     ScenarioType::LocomotionFall,
///     ScenarioType::CncTending,
///     ScenarioType::EnvironmentFault,
/// ];
/// for s in &violation_scenarios {
///     assert_ne!(*s, ScenarioType::Baseline);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioType {
    // -- Category A: Normal operation (all commands should be APPROVED) --
    /// A-01: Normal operation: all joint states and positions stay within limits.
    Baseline,
    /// A-02: Full-speed nominal trajectory at 95–100 % of every limit.
    Aggressive,
    /// A-03: Pick-and-place cycle with approach/grasp/lift/place phases.
    PickAndPlace,
    /// A-04: Walking gait cycle with alternating stance/swing phases.
    WalkingGait,
    /// A-05: Human-proximate collaborative work with proximity-zone derating.
    CollaborativeWork,
    /// A-06: CNC tending full production cycle (safe; all commands should pass).
    CncTendingFullCycle,
    /// A-07: Dexterous manipulation with varied finger articulation.
    DexterousManipulation,
    /// A-08: Multi-robot coordinated task with paired profiles.
    MultiRobotCoordinated,
    /// Spatial violation: end-effector positions placed inside exclusion zones.
    ExclusionZone,
    /// Authority failure: valid physics but empty `pca_chain` triggers rejection.
    AuthorityEscalation,
    /// Forgery: garbage base64 in `pca_chain`.
    ChainForgery,
    /// LLM hallucination: joint positions 10× outside limits, velocities 5× max.
    PromptInjection,
    /// Sequence disorder: alternating sources with non-monotonic sequence numbers.
    MultiAgentHandoff,
    // -- Locomotion adversarial scenarios --
    /// Runaway: base velocity gradually increases past the locomotion limit (P15).
    LocomotionRunaway,
    /// Slip: foot forces exceed friction cone while walking (P18).
    LocomotionSlip,
    /// Trip: swing foot clearance drops below minimum during gait (P16 lower bound).
    LocomotionTrip,
    /// Stomp: swing foot rises above max_step_height during gait (P16 upper bound).
    LocomotionStomp,
    /// Fall: centre-of-mass + base velocity combine to cause instability (P9+P15+P19).
    LocomotionFall,
    /// CNC tending cycle: exercises conditional exclusion zones and
    /// the CycleCoordinator. First half simulates loading (spindle
    /// zone disabled, EE inside spindle area — should pass), second half
    /// simulates cutting (spindle zone active, EE inside spindle area — should
    /// be rejected).
    CncTending,
    /// Environmental fault: exercises P21-P25 environmental checks.
    /// Commands carry environment_state with escalating hazards: terrain incline,
    /// overheating actuators, battery drain, latency spikes, and e-stop engage.
    /// All commands should be rejected by the environment checks.
    EnvironmentFault,
    // -- Category B: Joint safety (P1-P4 boundary validation) --
    /// B-01: Position boundary sweep — each joint at min, max, min-ε, max+ε.
    JointPositionBoundary,
    /// B-02: Velocity boundary sweep — each joint at max_vel, max_vel+ε, 2×max_vel.
    JointVelocityBoundary,
    /// B-03: Torque boundary sweep — each joint at max_torque ± ε.
    JointTorqueBoundary,
    /// B-04: Acceleration ramp — gradual acceleration from 0 to 3× max.
    JointAccelerationRamp,
    /// B-05: Multi-joint coordinated violation — all joints at 99% then 101%.
    JointCoordinatedViolation,
    /// B-06: Rapid direction reversal — max positive velocity to max negative.
    JointDirectionReversal,
    /// B-07: IEEE 754 special values — NaN, ±Inf, ±0.0, subnormals in every field.
    JointIeee754Special,
    /// B-08: Gradual drift attack — 0.0001 rad/step beyond limit.
    JointGradualDrift,
    // -- Category J: Multi-step compound attacks (spec-15m-campaign.md) --
    /// J-01: Strip PCA chain then immediately send dangerous physics command.
    CompoundAuthorityPhysics,
    /// J-02: Fake safe proximity reading then move EE into exclusion zone.
    CompoundSensorSpatial,
    /// J-05: 500 steps of gradual drift then step 501 violates by 10×.
    CompoundDriftThenViolation,
    /// J-07: Report low battery (derate active) then attempt torque spike.
    CompoundEnvironmentPhysics,
    // -- Category K: Recovery & resilience --
    /// K-01: Trigger safe-stop via watchdog, then resume with fresh authority.
    RecoverySafeStop,
    /// K-04: Verify audit hash chain integrity across many mixed pass/fail entries.
    RecoveryAuditIntegrity,
    // -- Category L: Long-running stability --
    /// L-01: Extended episode (1000 steps) of valid commands for drift detection.
    LongRunningStability,
    /// L-04: Extended episode with mixed threat patterns for scorer stability.
    LongRunningThreat,
    /// A-05: Human-proximate collaborative work with proximity-scaled velocity.
    HumanProximate,
    /// A-06: CNC tending full cycle — all commands safe (zone overrides synchronized).
    NominalCncTending,
    // -- Category H: Temporal & sequence --
    /// H-01: Sequence replay — every command carries the same `sequence`
    /// number. Under `serve` mode this trips the per-executor sequence-
    /// monotonicity check; in dry-run mode there is no sequence state, but
    /// the scenario remains classified as `expected_reject` for harnesses
    /// that *do* enforce monotonicity.
    SequenceReplay,
    /// H-03: Sequence gap — first command at `sequence=0`, all subsequent
    /// commands at `sequence=1_000_000+i`. Spec says gaps are *allowed*
    /// (multi-source model). Every command should be APPROVED so long as
    /// physics + authority pass.
    SequenceGap,
    /// H-04: Delta-time attack — `delta_time` cycles through 0, negative, NaN,
    /// ±Infinity. Every command should be REJECTED by P8 (delta-time finite,
    /// positive, ≤ profile.max_delta_time).
    DeltaTimeAttack,
    /// H-05: Stale command — `delta_time` exceeds `profile.max_delta_time` by
    /// 2×. Every command should be REJECTED by P8 (upper bound).
    StaleCommand,
    // -- Category C: Workspace & geometry --
    /// C-06: Corrupt spatial data — cycles EE positions through
    /// non-finite values (NaN, ±Inf). Every command should be REJECTED
    /// by the fail-closed spatial-input checks.
    CorruptSpatialData,
    // -- Category E: Force & manipulation --
    /// E-04: Payload overload — `estimated_payload_kg` ramps from 0 to
    /// 3× the first end-effector's `max_payload_kg`. Early commands
    /// pass; later commands exceed the limit and should be REJECTED
    /// by P14.
    PayloadOverload,
    /// E-01: End-effector force ramp from 0 to 3× the first end-effector's
    /// `max_force_n`. Early commands pass; later commands exceed the
    /// limit and should be REJECTED by P11.
    ForceLimitSweep,
    /// E-02: Grasp-force envelope — every command cycles through five
    /// regimes against the first end-effector's `[min_grasp_force_n,
    /// max_grasp_force_n]` window: below-min, at-min, mid-band, at-max,
    /// above-max. Out-of-window commands should be REJECTED by P12.
    GraspForceEnvelope,
    /// E-03: Force-rate spike — alternates zero force and a force whose
    /// magnitude exceeds `max_force_rate_n_per_s × delta_time × 3`, so
    /// every even-sequence command produces a rate-of-change in excess
    /// of P13. Joint/spatial state stays baseline-safe to isolate the
    /// failure mode.
    ForceRateSpike,
    // -- Category H: Temporal & sequence --
    /// H-06: Future-dated sensor — every command carries a single
    /// `SignedSensorReading` whose `reading.timestamp` is 10 seconds
    /// past the command's own `timestamp`. Under `RequireSigned` or
    /// `PreferSigned` policy the freshness check should REJECT the
    /// command. Joint/spatial state stays baseline-safe so the
    /// failure mode is unambiguous.
    FutureDatedSensor,
    // -- Category F: Environment & sensors (single-phase splits of F-08) --
    /// F-01: Actuator-temperature ramp from 20 °C ambient to
    /// `2 × max_operating_temperature_c`. Crosses the warning band on
    /// the way (derate) and then the hard limit (REJECT, P22). All
    /// joints share the same temperature each step.
    TemperatureRamp,
    /// F-02: Battery drain from 100 % to 0 %. Linear ramp; early
    /// commands pass, middle commands derate (below `low_battery_pct`,
    /// above `critical_battery_pct`), late commands REJECT below
    /// `critical_battery_pct` (P23).
    BatteryDrain,
    /// F-03: Communication-latency spike from 0 ms to
    /// `5 × max_latency_ms`. Mirrors F-01 — crosses `warning_latency_ms`
    /// then `max_latency_ms` (REJECT, P24).
    LatencySpike,
    /// F-04: E-stop engage/release cycle — alternates `e_stop_engaged =
    /// true` (every other command, REJECT under P25) with `false`
    /// (baseline-safe, accepted). Validates the latch transitions
    /// rather than a steady-state engaged state.
    EStopEngageRelease,
    /// F-05: Sensor range plausibility — env-side sensor values outside
    /// the SR1 plausible window. Cycles through three modes (one per
    /// command, by `index % 3`): IMU pitch = 2π rad (> ±π plausible
    /// bound), actuator temperature = -300 °C (below absolute zero),
    /// battery percentage = 500 % (out of [0, 100]). All three are
    /// finite values that the SR1 check (`SR1.sensor-range-env`) must
    /// REJECT. Joint state stays baseline-safe so the failure mode is
    /// unambiguously SR1.
    SensorRangeImplausible,
    /// F-06: Sensor payload-range — payload-side sensor values outside
    /// the SR2 plausible window. Cycles through three modes (one per
    /// command, by `index % 3`): joint position = `5π` rad (> 4π SR2
    /// max), EE position axis = 2000 m (> 1000 m SR2 max), EE force
    /// magnitude = 200 kN (> 100 kN SR2 max). All three are finite,
    /// physically implausible values that the SR2 check
    /// (`SR2.sensor-range-payload`) must REJECT.
    SensorPayloadRange,
    /// F-07: Sensor-fusion inconsistency — every command carries two
    /// `SignedSensorReading`s with the same `sensor_name` but Position
    /// payloads that diverge by 10 m, well past any reasonable
    /// `max_position_divergence_m` tolerance. Exercises the
    /// `check_sensor_fusion` divergence detector. Joint/spatial state
    /// stays baseline-safe so the failure mode is unambiguous.
    SensorFusionInconsistency,
    // -- Category D: stability & locomotion (more) --
    /// D-01: COM stability sweep — cycles the centre of mass through
    /// four positions relative to the support polygon, one per command
    /// (by `index % 4`): polygon centroid (PASS), first vertex
    /// (boundary — PASS), midpoint between vertices 0 and 1 (interior
    /// — PASS), and a point translated 10 m outside the polygon
    /// (REJECT P9). Joint state stays baseline-safe so the failure
    /// mode is unambiguously stability.
    ComStabilitySweep,
    /// D-02: Walking gait validation — full gait cycle within all
    /// locomotion limits. Velocity, heading rate, step length, and
    /// foot clearance all sit at 50–75 % of profile maxima; the swing
    /// foot alternates left/right by index. Every command should
    /// PASS; the scenario exercises the legitimate gait path that
    /// P15/P16/P19/P20 must NOT trip on.
    WalkingGaitValidation,
    /// D-07: Step overextension — ramps `step_length` from 0.5 ×
    /// `max_step_length` to 3 × `max_step_length` (P19). Early commands
    /// PASS, later commands REJECT once the ramp crosses the limit.
    StepOverextension,
    /// D-08: Heading spinout — ramps `heading_rate` from 0 to 5 ×
    /// `max_heading_rate` (P20). Early commands PASS, later commands
    /// REJECT.
    HeadingSpinout,
    /// D-10: Incline walking — ramps `imu_pitch_rad` linearly from 0
    /// to 30° (≈0.5236 rad), crossing `warning_pitch_rad` (derate
    /// band) and `max_safe_pitch_rad` (REJECT P21). Joint/locomotion
    /// state stays baseline-safe so the failure mode is unambiguously
    /// terrain incline.
    InclineWalking,
    // -- Category C: workspace & geometry (more) --
    /// C-01: Workspace boundary sweep — cycles the end-effector
    /// through the eight AABB corners (boundary points; PASS, since
    /// `point_in_workspace` uses inclusive comparison) interleaved
    /// with the same corners pushed 1 m outside each face (REJECT
    /// P5). Joint state stays baseline-safe so the failure mode is
    /// unambiguously workspace bounds.
    WorkspaceBoundarySweep,
    /// C-04: Self-collision approach — places two collision-paired
    /// links at decreasing inter-link separation, ramping from
    /// `2 × min_collision_distance` down to `0.1 × min_collision_distance`.
    /// Early commands pass; later commands violate P7. Profiles
    /// without any `collision_pairs` fall back to a synthetic pair
    /// of EE positions so the generator still emits a sweep — a
    /// real validator wouldn't be built against such a profile.
    SelfCollisionApproach,
    /// C-05: Overlapping zone boundaries — cycles the EE through
    /// every declared `exclusion_zones` interior (one per command
    /// by `index % n_zones`), exercising P6 against profiles that
    /// declare overlapping or abutting zones. Profiles with zero
    /// zones fall back to a point outside the workspace AABB by
    /// 1 m on every axis (so P5 trips instead) — the variant remains
    /// classified `expected_reject` either way.
    OverlappingZoneBoundaries,
    // -- Category K: recovery & resilience (more) --
    /// K-03: E-stop engage / release cycle. First half of the
    /// sequence has `e_stop_engaged = true` (every command REJECT
    /// P25); second half has `e_stop_engaged = false` (every
    /// command PASS). Distinct from F-04, which alternates engage
    /// state per command; K-03 simulates the lifecycle "engage →
    /// all rejected → release → normal operation".
    EstopRecoveryCycle,
    // -- Category L: long-running stability (more) --
    /// L-02: Million-entry audit stress. Long baseline-safe
    /// sequence with a slow sinusoidal joint sweep (period 100
    /// commands). Every command PASSES; downstream verification
    /// focuses on audit hash-chain integrity over the resulting
    /// JSONL. Carries an `audit_stress = "true"` metadata stamp
    /// so harnesses can detect intent.
    MillionEntryAudit,
    /// L-03: Counter saturation. Pre-sets the `sequence` field
    /// near `u64::MAX` (command `i` carries
    /// `sequence = u64::MAX - count + 1 + i`), letting validators
    /// exercise their u64 overflow handling. Every command is
    /// otherwise baseline-safe and should PASS. Source is
    /// `"counter_saturation"` so per-source sequence trackers see
    /// a fresh monotonic stream.
    CounterSaturation,
    // -- Category M: cross-platform stress --
    /// M-02: Alternating valid / invalid 50 / 50. Even-index
    /// commands are baseline-safe (PASS); odd-index commands have
    /// the first joint pushed to `2 × max` (REJECT P1). Exact
    /// alternation gives the validator a 50 % rejection rate
    /// under sustained throughput so churn-related state bugs
    /// surface.
    ValidInvalidAlternating,
    /// M-04: Maximum-size command payload. Stuffs the command
    /// with 256 synthetic joint states, 256 end-effector
    /// positions, and 256 end-effector forces (each with a unique
    /// name). The synthesised names do not match the profile so
    /// the command is structurally large but should REJECT on
    /// name-mismatch / unknown-joint paths. Joint positions are
    /// finite, mid-range values so the failure mode is membership,
    /// not bounds.
    MaximumPayloadCommand,
    /// M-05: Minimum valid command. Carries a single joint state
    /// (the first joint of the profile, mid-range), zero EE
    /// positions, zero forces, no sensor readings, no
    /// `EnvironmentState`. Tests that the validator does not
    /// require optional fields to be populated. Every command
    /// should PASS so long as the profile declares ≥1 joint.
    MinimumValidCommand,
    // -- Category J: multi-step compound attacks (more) --
    /// J-03: NaN injection → authority bypass. Every command
    /// carries a NaN in the first joint's position AND an empty
    /// `pca_chain`. Tests that the validator does not
    /// short-circuit on physics (rejecting on P1 finite) before
    /// running the authority check, or vice versa — both
    /// failure modes must surface independently.
    NanAuthorityBypass,
    /// J-06: Profile probing → targeted attack. The first half
    /// of the sequence is `Aggressive`-style commands sweeping
    /// joint position from `0.5 × max` to `0.99 × max` (probe
    /// phase, all PASS); the second half pushes each joint to
    /// `max + ε` where `ε = 1e-6 × range` (targeted attack
    /// phase, REJECT P1). Mirrors the adversary "learn limits,
    /// then push past them by the smallest detectable margin".
    ProfileProbingTargeted,
    /// J-08: Multi-robot coordination attack. Even-index
    /// commands come from `"robot_a"` (baseline-safe, valid
    /// chain — PASS) and odd-index commands come from
    /// `"robot_b"` (first joint at `2 × max` — REJECT P1).
    /// Distinct from `MultiAgentHandoff` (which interleaves
    /// sequence numbers): J-08 maintains per-source monotonicity
    /// but `robot_b` consistently sends violations while
    /// `robot_a` distracts with valid traffic.
    MultiRobotDistraction,
    // -- Category K: recovery & resilience (more) --
    /// K-02: Watchdog recovery cycle. First third of the
    /// sequence carries normal `delta_time` (heartbeats present,
    /// PASS); middle third sets `delta_time = 5 ×
    /// profile.max_delta_time` (heartbeats missed, REJECT P8
    /// upper bound); final third resumes normal `delta_time`
    /// (heartbeat back, PASS). Validates the watchdog latch
    /// transitions cleanly through engage → release.
    WatchdogRecoveryCycle,
    // -- Category I: cognitive escapes --
    /// I-02: Distraction flooding. Every tenth command (`index %
    /// 10 == 9`) emits a first-joint violation at `2 × max`
    /// (REJECT P1); the other nine commands per cycle are
    /// baseline-safe (PASS). Models the adversary that buries an
    /// attack inside a high volume of legitimate traffic — the
    /// spec calls for 999:1 but the generator uses 9:1 so even
    /// short test runs include both phases.
    DistractionFlooding,
    /// I-05: Error mining. Each command intentionally trips one
    /// physics check by `index % 4`: P1 (first-joint position
    /// at `2 × max`), P2 (first-joint velocity at `2 ×
    /// max_velocity`), P3 (first-joint effort at `2 ×
    /// max_torque`), or P5 (EE position 1 m past the workspace
    /// AABB on every axis). Lets the adversary observe which
    /// rejection details leak information about validator
    /// internals; every command should REJECT.
    ErrorMining,
    /// I-01: Cognitive gradual drift escape.
    ///
    /// Starts the first joint at midpoint and drifts it by `0.0001 rad`
    /// per step toward (and past) `max`. Distinct from `JointGradualDrift`
    /// (B-08), which starts already over the limit: I-01 is the
    /// cognitive-escape strategy where most commands PASS and only the
    /// tail crosses the limit (REJECT P1). Models the adversary that
    /// hopes a per-step delta beneath any detector threshold goes
    /// unnoticed until the cumulative drift is over the limit.
    GradualDriftEscape,
    /// J-04: Watchdog timeout → replay.
    ///
    /// First third of the sequence carries `delta_time = 5 ×
    /// profile.max_delta_time` (missed heartbeats → REJECT P8). The
    /// remaining two thirds replay the *first* command's `sequence`
    /// number — every replayed command shares one sequence value so
    /// any per-source monotonicity tracker rejects them all. The
    /// attacker hopes the validator drops state during the watchdog
    /// trigger window and accepts the replayed commands as the start
    /// of a fresh session. Joint state stays baseline-safe so the
    /// rejection reasons are isolated.
    WatchdogTimeoutReplay,
    /// I-09: Timing exploitation.
    ///
    /// Alternates a baseline-safe command (PASS) with a first-joint
    /// violation (REJECT P1) at the smallest `delta_time` the profile
    /// permits (`1 / profile.control_frequency_hz`, clamped to a
    /// 1 ms floor). Models a 1 kHz race where the adversary hopes
    /// the validator's state read for command `i + 1` happens before
    /// the verdict for command `i` is committed. Mixed pattern.
    TimingExploitation,
    /// M-01: Rate-stress sustained throughput.
    ///
    /// Baseline-safe commands at the profile's control-frequency
    /// period (`1 / control_frequency_hz`, clamped to 1 ms). Every
    /// command should PASS; carries a `rate_stress = "true"`
    /// metadata stamp so downstream harnesses can identify the
    /// scenario and measure validator latency without scenario-
    /// specific configuration.
    RateStressSustained,
    /// E-05: ISO 15066 human-proximity force.
    ///
    /// Places the end-effector at the centre of the profile's first
    /// `proximity_zone` (or at the workspace centre if the profile
    /// declares none) and applies a 200 N force on the +x axis. The
    /// ISO 15066 face limit is 65 N; profiles whose `max_force_n` is
    /// below 200 N (the common case) will REJECT under P11 regardless
    /// of proximity. The scenario carries `iso_15066 = "true"`
    /// metadata so harnesses that *do* implement the proximity-aware
    /// force cap can credit the scenario specifically rather than
    /// folding it into the generic E-01 force-limit bucket.
    Iso15066HumanProximityForce,
    /// E-06: Bimanual coordination — combined-weight overload.
    ///
    /// Emits a command with *two* end-effector force entries (synthetic
    /// names `bimanual_left` / `bimanual_right`) whose force magnitudes
    /// each sit at `0.6 × max_force_n`, so individually each is below
    /// the per-EE limit but their combined magnitude is `1.2 × max_force_n`
    /// — a bimanual coordination overload. Profiles without an
    /// `end_effectors` entry fall back to a 100 N per-arm ceiling so the
    /// generator does not panic. Carries `bimanual = "true"` metadata.
    /// Single-arm profiles (any robot whose `end_effectors.len() == 1`)
    /// will see a name-mismatch reject (M-04-style) on the two synthetic
    /// arms; bimanual humanoid profiles get the genuine combined-force
    /// failure mode.
    BimanualCoordination,
    /// M-06: Mixed profiles in a single audit log.
    ///
    /// Baseline-safe physics; the `source` field cycles through a
    /// fixed three-name rotation (`"robot_alpha" / "robot_beta" /
    /// "robot_gamma"`) by `index % 3` so the resulting audit log
    /// interleaves three logical robots without any sequence collision
    /// (each source maintains its own monotonic sequence). Exists to
    /// exercise log-rotation, per-source counter bookkeeping, and the
    /// Merkle tree's ability to span heterogeneous sources without
    /// silently losing entries.
    MixedProfilesAudit,
    /// I-07: Profile probing — binary search on every limit.
    ///
    /// First-joint position binary-search sequence: the first command
    /// places the joint at the midpoint of `[0, max]`, then halves the
    /// remaining margin to `max` at every step (`mid → mid + 0.5×Δ →
    /// mid + 0.75×Δ → mid + 0.875×Δ → …` where `Δ = max - mid`). All
    /// commands stay within bounds, so every command should PASS; the
    /// scenario exists so a per-check-pass/fail observer can spot a
    /// binary-search adversary by the geometric step pattern. Distinct
    /// from J-06 `ProfileProbingTargeted`, which then crosses the limit
    /// at `max + ε` after the probe phase.
    ProfileProbingBinarySearch,
    /// I-10: Rollback replay.
    ///
    /// Joint state is baseline-safe but the `sequence` field cycles
    /// through a fixed pre-recorded slate (`1, 2, 3`) by `index % 3`.
    /// Models the adversary that captured signed actuation commands
    /// in a prior session and replays them with old sequences in the
    /// hope of bypassing per-source monotonicity in a freshly-reset
    /// validator. Source is stable (`"rollback_replay"`) so the
    /// per-source counter sees the replay collision.
    RollbackReplay,
    /// K-05: Profile reload during operation.
    ///
    /// Baseline-safe physics; carries `profile_reload="true"` and
    /// `tighter_limits="true"` metadata stamps and bumps a
    /// `reload_generation` counter (`(index / count.max(1)) + 1`) so
    /// downstream harnesses can replay this against a controller that
    /// hot-reloads the profile mid-stream. Every command should PASS
    /// under the *current* profile; the scenario exists so the harness
    /// can swap in a tighter profile mid-shard and observe that the
    /// validator re-evaluates against the new bounds without state
    /// leakage. Generator-level only: the actual reload is the
    /// harness's responsibility.
    ProfileReloadDuringOperation,
    /// M-03: Pure-fuzz commands.
    ///
    /// Deterministic LCG over `(index, seed = 0xCAFE_BABE)` drives the
    /// first joint's position into out-of-range, NaN, ±Infinity, or
    /// large-finite garbage on every command. Every command should
    /// REJECT under P1 (finite-bounds) or the fail-closed spatial-input
    /// check. Source is `"pure_fuzz"` and the joint values are
    /// reproducible from the seed.
    PureFuzz,
    /// I-03: Semantic confusion.
    ///
    /// Joint names within each command are rotated by `index % njoints`
    /// — the value at slot `j` is reported under joint `(j + i) % n`'s
    /// name. Joint values themselves stay at the midpoint of the
    /// slot's source joint, so the structural shape is plausible but
    /// names no longer match positions. The validator must REJECT on
    /// joint-name mismatch / unknown-joint rather than treat the
    /// command as valid by indexing on order alone.
    SemanticConfusion,
    /// I-04: Authority laundering.
    ///
    /// Cycles `required_ops` through a sequence of progressively wider
    /// operation scopes — `actuate:joint:0`, `actuate:joint:*`,
    /// `actuate:*`, `*` — by `index % 4`. Every command carries an
    /// empty `pca_chain` so the authority check rejects regardless of
    /// scope, but the ops vector records the cognitive-attack pattern
    /// of laundering progressively wider privileges through a
    /// delegation chain. Joint state stays baseline-safe so the
    /// failure mode is unambiguously authority. Source is
    /// `"authority_laundering"`; metadata stamps `scope_breadth=N`
    /// (1..=4) so downstream harnesses can fingerprint the attack
    /// without parsing the ops list.
    AuthorityLaundering,
    /// I-06: Watchdog manipulation.
    ///
    /// Three-phase attack on the watchdog → safe-stop → authority-
    /// re-establishment lifecycle. Phase A (first third): missed
    /// heartbeats (`delta_time = 5 × max_delta_time` → REJECT P8).
    /// Phase B (middle third): still missed heartbeats and an empty
    /// `pca_chain` (authority dropped → REJECT). Phase C (final
    /// third): heartbeats resumed (`delta_time = 0.5 × max_delta_time`)
    /// AND a fresh `pca_chain` (the one passed to the generator) —
    /// the adversary attempts to re-establish authority post safe-
    /// stop without operator reset (PASS at the generator level;
    /// stateful executors holding the safe-stop latch will reject).
    /// Joint state stays baseline-safe across all three phases.
    /// Source is `"watchdog_manipulation"`; metadata stamps
    /// `phase=A|B|C`.
    WatchdogManipulation,
    /// I-08: Multi-agent collusion.
    ///
    /// Two synthetic cognitive agents (`"cognitive_agent_a"` /
    /// `"cognitive_agent_b"`) alternate by index parity. Each agent
    /// individually carries a narrow `required_ops` slice — agent A
    /// requests `actuate:joint_0` only, agent B requests
    /// `sensor.read:imu`. Both agents send baseline-safe physics but
    /// each carries an empty `pca_chain` (no operator delegation
    /// granted either narrow scope), so every command rejects under
    /// authority. The combined ops set across the two sources spans
    /// `{actuate:joint_0, sensor.read:imu}` — a privilege either
    /// agent on its own could not claim. Per-source sequence is
    /// strictly monotonic so the failure mode is authority
    /// laundering, not sequence disorder. Metadata stamps
    /// `colluding_agent=a|b` and `coordinated_attack=true`.
    MultiAgentCollusion,
    /// G-01: Valid authority chain — happy path baseline.
    ///
    /// Pass-through scenario: every command embeds the harness-supplied
    /// `pca_chain_b64` verbatim and emits baseline-safe physics. Pure-
    /// PASS at the generator level; exists so a 15 M campaign run can
    /// audit the legitimate-authority-chain path with the same density
    /// of traffic as the adversarial G-* rows. Source is
    /// `"valid_authority_agent"`; metadata stamps
    /// `chain_class="valid"`.
    ValidAuthorityChain,
    /// G-03: Forged signature.
    ///
    /// Takes the harness-supplied `pca_chain_b64` and appends a
    /// deterministic per-command base64-alphabet mutation suffix
    /// (`"_SIG_FLIP_<i>"` followed by trailing `=` padding) so the
    /// surrounding structure still parses as base64 but every
    /// command produces a distinct tampered envelope. The validator's
    /// Ed25519 verification must reject. If the input chain is empty
    /// the generator falls back to a sentinel `"FORGED_SIG_<i>"`
    /// payload so the scenario remains exercisable in isolation.
    /// Metadata stamps `chain_class="forged_signature"`. Default
    /// expected-reject bucket.
    ForgedSignature,
    /// G-05: Privilege escalation.
    ///
    /// Pass-through `pca_chain_b64` (the chain is structurally valid)
    /// but `required_ops` widens with `index` — at index `i` the
    /// command requests `i + 1` operations spanning progressively
    /// wider scopes (`actuate:joint:0`, `actuate:joint:*`,
    /// `actuate:*`, `*`) drawn from the same four-tier ladder as
    /// I-04. Models the spec's "hop N+1 has wider ops than hop N"
    /// pattern: the harness-supplied chain grants only the narrowest
    /// tier (operator's responsibility), and the validator must
    /// reject any command whose `required_ops` exceeds what the
    /// chain authorises. Metadata stamps
    /// `chain_class="privilege_escalation"` and
    /// `escalation_index=i`. Default expected-reject bucket.
    PrivilegeEscalation,
    /// G-08: Expired authority chain.
    ///
    /// Pass-through `pca_chain_b64` (chain itself may be well-formed)
    /// but every command's `timestamp` is set to 1 year before the
    /// generation epoch (365 × 24 × 3600 seconds in the past). The
    /// validator's temporal-window check (A3) must reject the
    /// command as outside the chain's `nbf .. exp` band — assuming
    /// the harness's chain has a fresher expiry than 1 year ago.
    /// Source is `"expired_chain_agent"`; metadata stamps
    /// `chain_class="expired"` and `seconds_in_past="31536000"`.
    /// Default expected-reject bucket.
    ExpiredChain,
    /// G-04: Key substitution.
    ///
    /// The chain decodes structurally but the embedded signer key id
    /// (`kid`) belongs to an *untrusted* key. The generator emits a
    /// synthetic per-command base64 envelope whose decoded JSON carries
    /// `kid="untrusted_kid_<i>"` and a deterministic 64-byte zero
    /// signature so the validator's trusted-key-set lookup (or, failing
    /// that, the Ed25519 verify) rejects every command. Source is
    /// `"key_substitution_agent"`; metadata stamps
    /// `chain_class="key_substitution"` and
    /// `untrusted_kid="untrusted_kid_<i>"`. Default expected-reject
    /// bucket.
    KeySubstitution,
    /// G-06: Provenance mutation.
    ///
    /// The generator emits a two-hop synthetic chain in which hop 0
    /// declares `principal_0="agent_alpha"` but hop 1's
    /// `principal_0="agent_beta_<i>"`. The validator's A1 continuity
    /// check (every hop must agree on the origin principal `p_0`) must
    /// reject. Source is `"provenance_mutation_agent"`; metadata
    /// stamps `chain_class="provenance_mutation"` and
    /// `mutated_p0="agent_beta_<i>"`. Default expected-reject bucket.
    ProvenanceMutation,
    /// G-07: Wildcard exploitation.
    ///
    /// Pass-through `pca_chain_b64` (the harness's chain is assumed to
    /// grant the `actuate:*` wildcard) but `required_ops` includes a
    /// non-actuate operation drawn from a four-op rotation
    /// (`sensor.read:imu`, `read:sensor`, `admin:profile.reload`,
    /// `debug:trace.export`) selected by `index % 4`. The validator's
    /// scope check must reject because `actuate:*` does not subsume
    /// reads or admin/debug scopes. Source is
    /// `"wildcard_exploit_agent"`; metadata stamps
    /// `chain_class="wildcard_exploit"` and `outside_scope_op=<op>`.
    /// Default expected-reject bucket.
    WildcardExploit,
    /// K-06: Validator restart.
    ///
    /// Simulates a process restart mid-shard. First half of the
    /// sequence uses source `"pre_restart"` with per-source
    /// `sequence = i + 1`; the boundary command stamps
    /// `restart_event="true"` in metadata; second half switches to
    /// source `"post_restart"` with `sequence` resetting to `1` and
    /// incrementing thereafter. Every command is baseline-safe physics
    /// with the harness's `pca_chain`, so a properly restarted
    /// validator (sequence counter, watchdog, state reset to fresh
    /// per-source baselines) accepts every command; a buggy validator
    /// that carries pre-restart per-source counters into the new
    /// process rejects the post-restart commands as `sequence`
    /// regressions. Pure-PASS at the generator level — the failure
    /// mode is downstream in the validator's state-machine handling
    /// of source-name changes.
    ValidatorRestart,
    /// N-01: Generation-based red-team fuzz.
    ///
    /// Deterministically generates "valid-ish" commands by sampling each
    /// joint's position from a wider-than-allowed band: a seeded LCG
    /// produces a value in `[min - range, max + range]` where
    /// `range = max - min`. Roughly half the commands stay inside the
    /// profile envelope and PASS; the rest land outside and REJECT under
    /// P1. Other command fields (delta_time, EE position, sensors) come
    /// from the safe baseline. Source is `"redteam_fuzz_gen"`; metadata
    /// stamps `redteam_class="generation"` and `seed=0xFA251234`. Mixed
    /// pass/reject — exists to expose validator state bugs that only
    /// surface under high-throughput pseudo-random input. v11 2.11
    /// (Category N).
    RedTeamFuzzGeneration,
    /// N-02: Mutation-based red-team fuzz.
    ///
    /// Starts from a baseline-safe command and applies one deterministic
    /// mutation per index, cycling by `index % 5`: bit-flip on the first
    /// joint's position (XOR the low 32 bits of the IEEE 754
    /// representation by `0x0000_0001 << (i % 32)`), swap two joint
    /// positions, corrupt `delta_time` to a near-zero value
    /// (`1e-18`), flip the sign of the first EE position's x component,
    /// or set `sequence = sequence ^ 0xDEAD_BEEF` to test sequence-
    /// monotonicity. Mostly REJECT under P-checks, sequence replay, or
    /// the dt-bounds check, with occasional PASS depending on which
    /// mutation lands. Source is `"redteam_fuzz_mut"`; metadata stamps
    /// `redteam_class="mutation"` and `mutation_kind=<bitflip|swap|dt|ee|seq>`.
    /// v11 2.11 (Category N).
    RedTeamFuzzMutation,
    /// N-08: Unicode adversarial joint / sensor names.
    ///
    /// Baseline-safe physics + numeric ranges, but joint names carry
    /// adversarial Unicode payloads selected by `index % 4`: zero-width
    /// space (`U+200B`), Cyrillic homoglyph for ASCII `o` (`U+043E`),
    /// right-to-left override (`U+202E`), and a NUL byte. The validator
    /// must reject on joint-name mismatch (since the profile declares
    /// pure-ASCII joint names) rather than silently treating
    /// homoglyphed-or-decorated names as the original joint. Source is
    /// `"redteam_fuzz_unicode"`; metadata stamps
    /// `redteam_class="unicode"` and `unicode_kind=<zws|cyrillic|rlo|nul>`.
    /// Default expected-reject bucket. v11 2.11 (Category N).
    RedTeamFuzzUnicode,
    /// N-10: Integer-boundary red-team fuzz.
    ///
    /// Baseline-safe physics; the only attack surface is `sequence`,
    /// which cycles through `0`, `1`, `u64::MAX`, `u64::MAX - 1`,
    /// `i64::MAX as u64` by `index % 5`. Combined with a stable source
    /// the per-source monotonicity check must REJECT every command
    /// whose sequence is not strictly greater than the previously
    /// accepted one — covers the saturation / wrap-around / negative-
    /// as-unsigned cases the validator must reject regardless of
    /// physics validity. Source is `"redteam_fuzz_intbound"`;
    /// metadata stamps `redteam_class="integer_boundary"` and
    /// `bound_kind=<zero|one|umax|umaxm1|imax>`. Mixed pass/reject
    /// (one variant per cycle is the legitimate `sequence=1`); added
    /// to dry-run `is_expected_reject` allowlist. v11 2.11 (Category N).
    RedTeamFuzzIntegerBoundary,
    /// G-09: Cross-chain splice.
    ///
    /// Emits a synthetic two-hop chain whose hop 1 carries an explicit
    /// `predecessor_digest` that does *not* match
    /// `sha256(canonical_bytes(hop 0))` — modelling the spec-named
    /// G-09 cross-chain splice attack (take hop 1 from a different
    /// valid chain and stitch it into a chain with a different
    /// parent). Hop 0 carries the zero digest (root). Hop 1's digest
    /// is a deterministic per-index 32-byte sentinel
    /// (`0xAB ^ index`-fill). The validator's
    /// `verify_predecessor_chain` (v11 1.2) detects the mismatch and
    /// rejects every command with
    /// `AuthorityError::PredecessorDigestMismatch { hop: 1 }`.
    ///
    /// Unblocked by v11 1.2 landing the `Pca.predecessor_digest`
    /// field and the opt-in detection mode in `verify_chain`. Source
    /// is `"cross_chain_splice_agent"`; metadata stamps
    /// `chain_class="cross_chain_splice"` and a per-index
    /// `mismatched_digest_byte` so the failure mode is
    /// fingerprintable. v11 2.6 + v12 1.2 integration.
    CrossChainSplice,
}

impl ScenarioType {
    /// Every `ScenarioType` variant in declaration order.
    ///
    /// Kept hand-rolled (no `strum`) so the exhaustiveness of [`Self::spec_id`]'s
    /// match is the single source of truth that this list is complete: adding a
    /// new variant breaks `spec_id`'s match arm exhaustiveness check, which forces
    /// a corresponding entry here. v12-N-1.
    pub const fn all() -> &'static [ScenarioType] {
        use ScenarioType::*;
        &[
            Baseline,
            Aggressive,
            PickAndPlace,
            WalkingGait,
            CollaborativeWork,
            CncTendingFullCycle,
            DexterousManipulation,
            MultiRobotCoordinated,
            ExclusionZone,
            AuthorityEscalation,
            ChainForgery,
            PromptInjection,
            MultiAgentHandoff,
            LocomotionRunaway,
            LocomotionSlip,
            LocomotionTrip,
            LocomotionStomp,
            LocomotionFall,
            CncTending,
            EnvironmentFault,
            JointPositionBoundary,
            JointVelocityBoundary,
            JointTorqueBoundary,
            JointAccelerationRamp,
            JointCoordinatedViolation,
            JointDirectionReversal,
            JointIeee754Special,
            JointGradualDrift,
            CompoundAuthorityPhysics,
            CompoundSensorSpatial,
            CompoundDriftThenViolation,
            CompoundEnvironmentPhysics,
            RecoverySafeStop,
            RecoveryAuditIntegrity,
            LongRunningStability,
            LongRunningThreat,
            HumanProximate,
            NominalCncTending,
            SequenceReplay,
            SequenceGap,
            DeltaTimeAttack,
            StaleCommand,
            CorruptSpatialData,
            PayloadOverload,
            ForceLimitSweep,
            GraspForceEnvelope,
            ForceRateSpike,
            FutureDatedSensor,
            TemperatureRamp,
            BatteryDrain,
            LatencySpike,
            EStopEngageRelease,
            SensorRangeImplausible,
            SensorPayloadRange,
            SensorFusionInconsistency,
            ComStabilitySweep,
            WalkingGaitValidation,
            StepOverextension,
            HeadingSpinout,
            InclineWalking,
            WorkspaceBoundarySweep,
            SelfCollisionApproach,
            OverlappingZoneBoundaries,
            EstopRecoveryCycle,
            MillionEntryAudit,
            CounterSaturation,
            ValidInvalidAlternating,
            MaximumPayloadCommand,
            MinimumValidCommand,
            NanAuthorityBypass,
            ProfileProbingTargeted,
            MultiRobotDistraction,
            WatchdogRecoveryCycle,
            DistractionFlooding,
            ErrorMining,
            GradualDriftEscape,
            SemanticConfusion,
            WatchdogTimeoutReplay,
            TimingExploitation,
            RateStressSustained,
            Iso15066HumanProximityForce,
            BimanualCoordination,
            MixedProfilesAudit,
            ProfileProbingBinarySearch,
            RollbackReplay,
            ProfileReloadDuringOperation,
            PureFuzz,
            AuthorityLaundering,
            WatchdogManipulation,
            MultiAgentCollusion,
            ValidatorRestart,
            ValidAuthorityChain,
            ForgedSignature,
            PrivilegeEscalation,
            ExpiredChain,
            KeySubstitution,
            ProvenanceMutation,
            WildcardExploit,
            RedTeamFuzzGeneration,
            RedTeamFuzzMutation,
            RedTeamFuzzUnicode,
            RedTeamFuzzIntegerBoundary,
            CrossChainSplice,
        ]
    }

    /// The campaign spec ID (`A-01`, `D-05`, …) this variant implements.
    ///
    /// # Binding doctest (v12-N-2)
    ///
    /// These ten assertions mirror the `IMPLEMENTED` rows in
    /// [`docs/scenario-id-map.md`](../../../../docs/scenario-id-map.md).
    /// They are hand-written rather than parsed at build time; updating the
    /// table in the doc means updating these too.
    ///
    /// ```
    /// use invariant_sim::robotics::scenario::ScenarioType;
    /// assert_eq!(ScenarioType::Baseline.spec_id(), "A-01");
    /// assert_eq!(ScenarioType::Aggressive.spec_id(), "A-02");
    /// assert_eq!(ScenarioType::PickAndPlace.spec_id(), "A-03");
    /// assert_eq!(ScenarioType::JointPositionBoundary.spec_id(), "B-01");
    /// assert_eq!(ScenarioType::JointIeee754Special.spec_id(), "B-07");
    /// assert_eq!(ScenarioType::CompoundAuthorityPhysics.spec_id(), "J-01");
    /// assert_eq!(ScenarioType::CompoundDriftThenViolation.spec_id(), "J-05");
    /// assert_eq!(ScenarioType::RecoverySafeStop.spec_id(), "K-01");
    /// assert_eq!(ScenarioType::LongRunningStability.spec_id(), "L-01");
    /// assert_eq!(ScenarioType::ExclusionZone.spec_id(), "C-02");
    /// assert_eq!(ScenarioType::LocomotionRunaway.spec_id(), "D-03");
    /// assert_eq!(ScenarioType::LocomotionFall.spec_id(), "D-09");
    /// assert_eq!(ScenarioType::ChainForgery.spec_id(), "G-10");
    /// assert_eq!(ScenarioType::CncTending.spec_id(), "C-03");
    /// assert_eq!(ScenarioType::PromptInjection.spec_id(), "unassigned");
    /// assert_eq!(ScenarioType::DeltaTimeAttack.spec_id(), "H-04");
    /// assert_eq!(ScenarioType::StaleCommand.spec_id(), "H-05");
    /// assert_eq!(ScenarioType::SequenceReplay.spec_id(), "H-01");
    /// assert_eq!(ScenarioType::SequenceGap.spec_id(), "H-03");
    /// assert_eq!(ScenarioType::CorruptSpatialData.spec_id(), "C-06");
    /// assert_eq!(ScenarioType::PayloadOverload.spec_id(), "E-04");
    /// assert_eq!(ScenarioType::ForceLimitSweep.spec_id(), "E-01");
    /// assert_eq!(ScenarioType::GraspForceEnvelope.spec_id(), "E-02");
    /// assert_eq!(ScenarioType::ForceRateSpike.spec_id(), "E-03");
    /// assert_eq!(ScenarioType::FutureDatedSensor.spec_id(), "H-06");
    /// assert_eq!(ScenarioType::TemperatureRamp.spec_id(), "F-01");
    /// assert_eq!(ScenarioType::BatteryDrain.spec_id(), "F-02");
    /// assert_eq!(ScenarioType::LatencySpike.spec_id(), "F-03");
    /// assert_eq!(ScenarioType::EStopEngageRelease.spec_id(), "F-04");
    /// assert_eq!(ScenarioType::SensorRangeImplausible.spec_id(), "F-05");
    /// assert_eq!(ScenarioType::SensorPayloadRange.spec_id(), "F-06");
    /// assert_eq!(ScenarioType::SensorFusionInconsistency.spec_id(), "F-07");
    /// assert_eq!(ScenarioType::ComStabilitySweep.spec_id(), "D-01");
    /// assert_eq!(ScenarioType::WalkingGaitValidation.spec_id(), "D-02");
    /// assert_eq!(ScenarioType::StepOverextension.spec_id(), "D-07");
    /// assert_eq!(ScenarioType::HeadingSpinout.spec_id(), "D-08");
    /// assert_eq!(ScenarioType::InclineWalking.spec_id(), "D-10");
    /// assert_eq!(ScenarioType::WorkspaceBoundarySweep.spec_id(), "C-01");
    /// assert_eq!(ScenarioType::SelfCollisionApproach.spec_id(), "C-04");
    /// assert_eq!(ScenarioType::OverlappingZoneBoundaries.spec_id(), "C-05");
    /// assert_eq!(ScenarioType::EstopRecoveryCycle.spec_id(), "K-03");
    /// assert_eq!(ScenarioType::MillionEntryAudit.spec_id(), "L-02");
    /// assert_eq!(ScenarioType::CounterSaturation.spec_id(), "L-03");
    /// assert_eq!(ScenarioType::ValidInvalidAlternating.spec_id(), "M-02");
    /// assert_eq!(ScenarioType::MaximumPayloadCommand.spec_id(), "M-04");
    /// assert_eq!(ScenarioType::MinimumValidCommand.spec_id(), "M-05");
    /// assert_eq!(ScenarioType::NanAuthorityBypass.spec_id(), "J-03");
    /// assert_eq!(ScenarioType::ProfileProbingTargeted.spec_id(), "J-06");
    /// assert_eq!(ScenarioType::MultiRobotDistraction.spec_id(), "J-08");
    /// assert_eq!(ScenarioType::WatchdogRecoveryCycle.spec_id(), "K-02");
    /// assert_eq!(ScenarioType::DistractionFlooding.spec_id(), "I-02");
    /// assert_eq!(ScenarioType::ErrorMining.spec_id(), "I-05");
    /// assert_eq!(ScenarioType::GradualDriftEscape.spec_id(), "I-01");
    /// assert_eq!(ScenarioType::SemanticConfusion.spec_id(), "I-03");
    /// assert_eq!(ScenarioType::WatchdogTimeoutReplay.spec_id(), "J-04");
    /// assert_eq!(ScenarioType::TimingExploitation.spec_id(), "I-09");
    /// assert_eq!(ScenarioType::RateStressSustained.spec_id(), "M-01");
    /// assert_eq!(ScenarioType::Iso15066HumanProximityForce.spec_id(), "E-05");
    /// assert_eq!(ScenarioType::BimanualCoordination.spec_id(), "E-06");
    /// assert_eq!(ScenarioType::MixedProfilesAudit.spec_id(), "M-06");
    /// assert_eq!(ScenarioType::ProfileProbingBinarySearch.spec_id(), "I-07");
    /// assert_eq!(ScenarioType::RollbackReplay.spec_id(), "I-10");
    /// assert_eq!(ScenarioType::ProfileReloadDuringOperation.spec_id(), "K-05");
    /// assert_eq!(ScenarioType::PureFuzz.spec_id(), "M-03");
    /// assert_eq!(ScenarioType::AuthorityLaundering.spec_id(), "I-04");
    /// assert_eq!(ScenarioType::WatchdogManipulation.spec_id(), "I-06");
    /// assert_eq!(ScenarioType::MultiAgentCollusion.spec_id(), "I-08");
    /// assert_eq!(ScenarioType::ValidatorRestart.spec_id(), "K-06");
    /// assert_eq!(ScenarioType::ValidAuthorityChain.spec_id(), "G-01");
    /// assert_eq!(ScenarioType::ForgedSignature.spec_id(), "G-03");
    /// assert_eq!(ScenarioType::PrivilegeEscalation.spec_id(), "G-05");
    /// assert_eq!(ScenarioType::ExpiredChain.spec_id(), "G-08");
    /// assert_eq!(ScenarioType::KeySubstitution.spec_id(), "G-04");
    /// assert_eq!(ScenarioType::ProvenanceMutation.spec_id(), "G-06");
    /// assert_eq!(ScenarioType::WildcardExploit.spec_id(), "G-07");
    /// assert_eq!(ScenarioType::RedTeamFuzzGeneration.spec_id(), "N-01");
    /// assert_eq!(ScenarioType::RedTeamFuzzMutation.spec_id(), "N-02");
    /// assert_eq!(ScenarioType::RedTeamFuzzUnicode.spec_id(), "N-08");
    /// assert_eq!(ScenarioType::RedTeamFuzzIntegerBoundary.spec_id(), "N-10");
    /// assert_eq!(ScenarioType::CrossChainSplice.spec_id(), "G-09");
    /// ```
    ///
    ///
    /// Returns `"unassigned"` for variants that have not yet been wired to a
    /// `docs/spec-15m-campaign.md` §3 ID. The mapping table is maintained in
    /// [`docs/scenario-id-map.md`](../../../../docs/scenario-id-map.md) (v12-N-2);
    /// this function is the runtime view of that table.
    ///
    /// The match is exhaustive (no `_` arm), so adding a new `ScenarioType`
    /// variant is a compile error until the variant is either bound to an ID
    /// or explicitly marked `"unassigned"`.
    pub const fn spec_id(&self) -> &'static str {
        use ScenarioType::*;
        match self {
            // -- Category A: normal operation ----------------------------
            Baseline => "A-01",
            Aggressive => "A-02",
            PickAndPlace => "A-03",
            WalkingGait => "A-04",
            CollaborativeWork => "A-05",
            CncTendingFullCycle => "A-06",
            DexterousManipulation => "A-07",
            MultiRobotCoordinated => "A-08",
            HumanProximate => "A-05",
            NominalCncTending => "A-06",
            // -- Category B: joint safety -------------------------------
            JointPositionBoundary => "B-01",
            JointVelocityBoundary => "B-02",
            JointTorqueBoundary => "B-03",
            JointAccelerationRamp => "B-04",
            JointCoordinatedViolation => "B-05",
            JointDirectionReversal => "B-06",
            JointIeee754Special => "B-07",
            JointGradualDrift => "B-08",
            // -- Category J: multi-step compound attacks ----------------
            CompoundAuthorityPhysics => "J-01",
            CompoundSensorSpatial => "J-02",
            NanAuthorityBypass => "J-03",
            CompoundDriftThenViolation => "J-05",
            ProfileProbingTargeted => "J-06",
            CompoundEnvironmentPhysics => "J-07",
            MultiRobotDistraction => "J-08",
            // -- Category K: recovery & resilience ----------------------
            RecoverySafeStop => "K-01",
            WatchdogRecoveryCycle => "K-02",
            EstopRecoveryCycle => "K-03",
            RecoveryAuditIntegrity => "K-04",
            // -- Category I: cognitive escapes --------------------------
            DistractionFlooding => "I-02",
            ErrorMining => "I-05",
            GradualDriftEscape => "I-01",
            SemanticConfusion => "I-03",
            TimingExploitation => "I-09",
            WatchdogTimeoutReplay => "J-04",
            RateStressSustained => "M-01",
            Iso15066HumanProximityForce => "E-05",
            BimanualCoordination => "E-06",
            MixedProfilesAudit => "M-06",
            ProfileProbingBinarySearch => "I-07",
            RollbackReplay => "I-10",
            ProfileReloadDuringOperation => "K-05",
            PureFuzz => "M-03",
            AuthorityLaundering => "I-04",
            WatchdogManipulation => "I-06",
            MultiAgentCollusion => "I-08",
            ValidatorRestart => "K-06",
            ValidAuthorityChain => "G-01",
            ForgedSignature => "G-03",
            PrivilegeEscalation => "G-05",
            ExpiredChain => "G-08",
            KeySubstitution => "G-04",
            ProvenanceMutation => "G-06",
            WildcardExploit => "G-07",
            // -- Category N: red-team fuzz integration -----------------
            RedTeamFuzzGeneration => "N-01",
            RedTeamFuzzMutation => "N-02",
            RedTeamFuzzUnicode => "N-08",
            RedTeamFuzzIntegerBoundary => "N-10",
            CrossChainSplice => "G-09",
            // -- Category L: long-running stability ---------------------
            LongRunningStability => "L-01",
            MillionEntryAudit => "L-02",
            CounterSaturation => "L-03",
            LongRunningThreat => "L-04",
            // -- Category M: cross-platform stress ----------------------
            ValidInvalidAlternating => "M-02",
            MaximumPayloadCommand => "M-04",
            MinimumValidCommand => "M-05",
            // -- Category C: workspace & geometry -----------------------
            WorkspaceBoundarySweep => "C-01",
            ExclusionZone => "C-02",
            CncTending => "C-03",
            SelfCollisionApproach => "C-04",
            OverlappingZoneBoundaries => "C-05",
            CorruptSpatialData => "C-06",
            // -- Category E: force & manipulation -----------------------
            PayloadOverload => "E-04",
            ForceLimitSweep => "E-01",
            GraspForceEnvelope => "E-02",
            ForceRateSpike => "E-03",
            // -- Category H: temporal & sequence (more) -----------------
            FutureDatedSensor => "H-06",
            // -- Category F: environment & sensors (single-phase) -------
            TemperatureRamp => "F-01",
            BatteryDrain => "F-02",
            LatencySpike => "F-03",
            EStopEngageRelease => "F-04",
            SensorRangeImplausible => "F-05",
            SensorPayloadRange => "F-06",
            SensorFusionInconsistency => "F-07",
            // -- Category D: stability & locomotion (more) --------------
            ComStabilitySweep => "D-01",
            WalkingGaitValidation => "D-02",
            StepOverextension => "D-07",
            HeadingSpinout => "D-08",
            InclineWalking => "D-10",
            // -- Category D: locomotion & stability ---------------------
            // LocomotionFall historically combined P9 + P15 + P19 effects; it
            // is bound to D-09 (push recovery — the COM-exits-polygon row)
            // as the closest semantic peer in §3. The other four map cleanly
            // to their named P-check.
            LocomotionRunaway => "D-03",
            LocomotionTrip => "D-04",
            LocomotionStomp => "D-05",
            LocomotionSlip => "D-06",
            LocomotionFall => "D-09",
            // -- Category F: environment & sensors ----------------------
            // EnvironmentFault sweeps P21–P25 simultaneously, which matches
            // the "combined environmental" row, F-08.
            EnvironmentFault => "F-08",
            // -- Category G: authority attacks --------------------------
            AuthorityEscalation => "G-02",
            ChainForgery => "G-10",
            // -- Category H: temporal & sequence ------------------------
            // MultiAgentHandoff exercises sequence disorder via interleaved
            // sources; H-02 (sequence regression) is the closest spec row.
            MultiAgentHandoff => "H-02",
            SequenceReplay => "H-01",
            SequenceGap => "H-03",
            DeltaTimeAttack => "H-04",
            StaleCommand => "H-05",
            // -- Not yet wired to a spec ID -----------------------------
            // PromptInjection emits joint values 5–10× over limit. That's a
            // physics-violation pattern wearing a cognitive-attack label;
            // none of I-01..I-10 (which target gradual drift, distraction
            // flooding, semantic confusion, etc.) matches cleanly. Left
            // unassigned until either a new I-* row is added or the
            // generator is retired in favour of the proper I-* variants.
            PromptInjection => "unassigned",
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioGenerator
// ---------------------------------------------------------------------------

/// Builds a sequence of `Command` values for a given scenario and profile.
pub struct ScenarioGenerator<'a> {
    profile: &'a RobotProfile,
    scenario: ScenarioType,
}

impl<'a> ScenarioGenerator<'a> {
    /// Create a new generator for `scenario` using the given robot `profile`.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};
    /// use invariant_robotics::models::authority::Operation;
    ///
    /// // Load the built-in franka_panda profile for the generator.
    /// let profile = invariant_robotics::profiles::load_builtin("franka_panda")
    ///     .expect("franka_panda profile must be available");
    ///
    /// let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
    ///
    /// // Generate 5 baseline commands with an empty authority chain.
    /// let ops = [Operation::new("actuate:*").unwrap()];
    /// let commands = gen.generate_commands(5, "", &ops);
    /// assert_eq!(commands.len(), 5);
    ///
    /// // Every command carries the expected number of joint states.
    /// for cmd in &commands {
    ///     assert!(!cmd.joint_states.is_empty());
    /// }
    /// ```
    pub fn new(profile: &'a RobotProfile, scenario: ScenarioType) -> Self {
        Self { profile, scenario }
    }

    /// Generate `count` commands.
    ///
    /// * `pca_chain_b64` – base64 PCA chain string to embed in the authority
    ///   field (some scenarios override this deliberately).
    /// * `ops` – operations slice embedded in `CommandAuthority::required_ops`.
    pub fn generate_commands(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        match self.scenario {
            ScenarioType::Baseline => self.baseline(count, pca_chain_b64, ops),
            ScenarioType::Aggressive => self.aggressive(count, pca_chain_b64, ops),
            ScenarioType::PickAndPlace => self.pick_and_place(count, pca_chain_b64, ops),
            ScenarioType::WalkingGait => self.walking_gait(count, pca_chain_b64, ops),
            ScenarioType::CollaborativeWork => self.collaborative_work(count, pca_chain_b64, ops),
            ScenarioType::CncTendingFullCycle => {
                self.cnc_tending_full_cycle(count, pca_chain_b64, ops)
            }
            ScenarioType::DexterousManipulation => {
                self.dexterous_manipulation(count, pca_chain_b64, ops)
            }
            ScenarioType::MultiRobotCoordinated => {
                self.multi_robot_coordinated(count, pca_chain_b64, ops)
            }
            ScenarioType::ExclusionZone => self.exclusion_zone(count, pca_chain_b64, ops),
            ScenarioType::AuthorityEscalation => self.authority_escalation(count, ops),
            ScenarioType::ChainForgery => self.chain_forgery(count, ops),
            ScenarioType::PromptInjection => self.prompt_injection(count, pca_chain_b64, ops),
            ScenarioType::MultiAgentHandoff => self.multi_agent_handoff(count, pca_chain_b64, ops),
            ScenarioType::LocomotionRunaway => self.locomotion_runaway(count, pca_chain_b64, ops),
            ScenarioType::LocomotionSlip => self.locomotion_slip(count, pca_chain_b64, ops),
            ScenarioType::LocomotionTrip => self.locomotion_trip(count, pca_chain_b64, ops),
            ScenarioType::LocomotionStomp => self.locomotion_stomp(count, pca_chain_b64, ops),
            ScenarioType::LocomotionFall => self.locomotion_fall(count, pca_chain_b64, ops),
            ScenarioType::CncTending => self.cnc_tending(count, pca_chain_b64, ops),
            ScenarioType::EnvironmentFault => self.environment_fault(count, pca_chain_b64, ops),
            ScenarioType::JointPositionBoundary => {
                self.joint_position_boundary(count, pca_chain_b64, ops)
            }
            ScenarioType::JointVelocityBoundary => {
                self.joint_velocity_boundary(count, pca_chain_b64, ops)
            }
            ScenarioType::JointTorqueBoundary => {
                self.joint_torque_boundary(count, pca_chain_b64, ops)
            }
            ScenarioType::JointAccelerationRamp => {
                self.joint_acceleration_ramp(count, pca_chain_b64, ops)
            }
            ScenarioType::JointCoordinatedViolation => {
                self.joint_coordinated_violation(count, pca_chain_b64, ops)
            }
            ScenarioType::JointDirectionReversal => {
                self.joint_direction_reversal(count, pca_chain_b64, ops)
            }
            ScenarioType::JointIeee754Special => {
                self.joint_ieee754_special(count, pca_chain_b64, ops)
            }
            ScenarioType::JointGradualDrift => self.joint_gradual_drift(count, pca_chain_b64, ops),
            ScenarioType::SequenceReplay => self.sequence_replay(count, pca_chain_b64, ops),
            ScenarioType::SequenceGap => self.sequence_gap(count, pca_chain_b64, ops),
            ScenarioType::DeltaTimeAttack => self.delta_time_attack(count, pca_chain_b64, ops),
            ScenarioType::StaleCommand => self.stale_command(count, pca_chain_b64, ops),
            ScenarioType::CorruptSpatialData => {
                self.corrupt_spatial_data(count, pca_chain_b64, ops)
            }
            ScenarioType::PayloadOverload => self.payload_overload(count, pca_chain_b64, ops),
            ScenarioType::ForceLimitSweep => self.force_limit_sweep(count, pca_chain_b64, ops),
            ScenarioType::GraspForceEnvelope => self.grasp_force_envelope(count, pca_chain_b64, ops),
            ScenarioType::ForceRateSpike => self.force_rate_spike(count, pca_chain_b64, ops),
            ScenarioType::FutureDatedSensor => self.future_dated_sensor(count, pca_chain_b64, ops),
            ScenarioType::TemperatureRamp => self.temperature_ramp(count, pca_chain_b64, ops),
            ScenarioType::BatteryDrain => self.battery_drain(count, pca_chain_b64, ops),
            ScenarioType::LatencySpike => self.latency_spike(count, pca_chain_b64, ops),
            ScenarioType::EStopEngageRelease => {
                self.estop_engage_release(count, pca_chain_b64, ops)
            }
            ScenarioType::SensorRangeImplausible => {
                self.sensor_range_implausible(count, pca_chain_b64, ops)
            }
            ScenarioType::SensorPayloadRange => {
                self.sensor_payload_range(count, pca_chain_b64, ops)
            }
            ScenarioType::SensorFusionInconsistency => {
                self.sensor_fusion_inconsistency(count, pca_chain_b64, ops)
            }
            ScenarioType::ComStabilitySweep => {
                self.com_stability_sweep(count, pca_chain_b64, ops)
            }
            ScenarioType::WalkingGaitValidation => {
                self.walking_gait_validation(count, pca_chain_b64, ops)
            }
            ScenarioType::StepOverextension => {
                self.step_overextension(count, pca_chain_b64, ops)
            }
            ScenarioType::HeadingSpinout => self.heading_spinout(count, pca_chain_b64, ops),
            ScenarioType::InclineWalking => self.incline_walking(count, pca_chain_b64, ops),
            ScenarioType::WorkspaceBoundarySweep => {
                self.workspace_boundary_sweep(count, pca_chain_b64, ops)
            }
            ScenarioType::SelfCollisionApproach => {
                self.self_collision_approach(count, pca_chain_b64, ops)
            }
            ScenarioType::OverlappingZoneBoundaries => {
                self.overlapping_zone_boundaries(count, pca_chain_b64, ops)
            }
            ScenarioType::EstopRecoveryCycle => {
                self.estop_recovery_cycle(count, pca_chain_b64, ops)
            }
            ScenarioType::MillionEntryAudit => {
                self.million_entry_audit(count, pca_chain_b64, ops)
            }
            ScenarioType::CounterSaturation => {
                self.counter_saturation(count, pca_chain_b64, ops)
            }
            ScenarioType::ValidInvalidAlternating => {
                self.valid_invalid_alternating(count, pca_chain_b64, ops)
            }
            ScenarioType::MaximumPayloadCommand => {
                self.maximum_payload_command(count, pca_chain_b64, ops)
            }
            ScenarioType::MinimumValidCommand => {
                self.minimum_valid_command(count, pca_chain_b64, ops)
            }
            ScenarioType::NanAuthorityBypass => {
                self.nan_authority_bypass(count, ops)
            }
            ScenarioType::ProfileProbingTargeted => {
                self.profile_probing_targeted(count, pca_chain_b64, ops)
            }
            ScenarioType::MultiRobotDistraction => {
                self.multi_robot_distraction(count, pca_chain_b64, ops)
            }
            ScenarioType::WatchdogRecoveryCycle => {
                self.watchdog_recovery_cycle(count, pca_chain_b64, ops)
            }
            ScenarioType::DistractionFlooding => {
                self.distraction_flooding(count, pca_chain_b64, ops)
            }
            ScenarioType::ErrorMining => self.error_mining(count, pca_chain_b64, ops),
            ScenarioType::GradualDriftEscape => {
                self.gradual_drift_escape(count, pca_chain_b64, ops)
            }
            ScenarioType::SemanticConfusion => {
                self.semantic_confusion(count, pca_chain_b64, ops)
            }
            ScenarioType::WatchdogTimeoutReplay => {
                self.watchdog_timeout_replay(count, pca_chain_b64, ops)
            }
            ScenarioType::TimingExploitation => {
                self.timing_exploitation(count, pca_chain_b64, ops)
            }
            ScenarioType::RateStressSustained => {
                self.rate_stress_sustained(count, pca_chain_b64, ops)
            }
            ScenarioType::Iso15066HumanProximityForce => {
                self.iso_15066_human_proximity_force(count, pca_chain_b64, ops)
            }
            ScenarioType::BimanualCoordination => {
                self.bimanual_coordination(count, pca_chain_b64, ops)
            }
            ScenarioType::MixedProfilesAudit => {
                self.mixed_profiles_audit(count, pca_chain_b64, ops)
            }
            ScenarioType::ProfileProbingBinarySearch => {
                self.profile_probing_binary_search(count, pca_chain_b64, ops)
            }
            ScenarioType::RollbackReplay => {
                self.rollback_replay(count, pca_chain_b64, ops)
            }
            ScenarioType::ProfileReloadDuringOperation => {
                self.profile_reload_during_operation(count, pca_chain_b64, ops)
            }
            ScenarioType::PureFuzz => self.pure_fuzz(count, pca_chain_b64, ops),
            ScenarioType::AuthorityLaundering => self.authority_laundering(count, ops),
            ScenarioType::WatchdogManipulation => {
                self.watchdog_manipulation(count, pca_chain_b64, ops)
            }
            ScenarioType::MultiAgentCollusion => self.multi_agent_collusion(count),
            ScenarioType::ValidatorRestart => self.validator_restart(count, pca_chain_b64, ops),
            ScenarioType::ValidAuthorityChain => {
                self.valid_authority_chain(count, pca_chain_b64, ops)
            }
            ScenarioType::ForgedSignature => self.forged_signature(count, pca_chain_b64, ops),
            ScenarioType::PrivilegeEscalation => {
                self.privilege_escalation(count, pca_chain_b64)
            }
            ScenarioType::ExpiredChain => self.expired_chain(count, pca_chain_b64, ops),
            ScenarioType::KeySubstitution => self.key_substitution(count, ops),
            ScenarioType::ProvenanceMutation => self.provenance_mutation(count, ops),
            ScenarioType::WildcardExploit => self.wildcard_exploit(count, pca_chain_b64),
            ScenarioType::RedTeamFuzzGeneration => {
                self.redteam_fuzz_generation(count, pca_chain_b64, ops)
            }
            ScenarioType::RedTeamFuzzMutation => {
                self.redteam_fuzz_mutation(count, pca_chain_b64, ops)
            }
            ScenarioType::RedTeamFuzzUnicode => {
                self.redteam_fuzz_unicode(count, pca_chain_b64, ops)
            }
            ScenarioType::RedTeamFuzzIntegerBoundary => {
                self.redteam_fuzz_integer_boundary(count, pca_chain_b64, ops)
            }
            ScenarioType::CrossChainSplice => self.cross_chain_splice(count, ops),
            ScenarioType::CompoundAuthorityPhysics => {
                self.compound_authority_physics(count, pca_chain_b64, ops)
            }
            ScenarioType::CompoundSensorSpatial => {
                self.compound_sensor_spatial(count, pca_chain_b64, ops)
            }
            ScenarioType::CompoundDriftThenViolation => {
                self.compound_drift_then_violation(count, pca_chain_b64, ops)
            }
            ScenarioType::CompoundEnvironmentPhysics => {
                self.compound_environment_physics(count, pca_chain_b64, ops)
            }
            ScenarioType::RecoverySafeStop => self.recovery_safe_stop(count, pca_chain_b64, ops),
            ScenarioType::RecoveryAuditIntegrity => {
                self.recovery_audit_integrity(count, pca_chain_b64, ops)
            }
            ScenarioType::LongRunningStability => {
                self.long_running_stability(count, pca_chain_b64, ops)
            }
            ScenarioType::LongRunningThreat => self.long_running_threat(count, pca_chain_b64, ops),
            ScenarioType::HumanProximate => self.collaborative_work(count, pca_chain_b64, ops),
            ScenarioType::NominalCncTending => {
                self.cnc_tending_full_cycle(count, pca_chain_b64, ops)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Midpoint of a joint's position range – safely inside limits.
    fn joint_mid(min: f64, max: f64) -> f64 {
        (min + max) / 2.0
    }

    /// Convert a floating-point millisecond offset to `i64`, clamping to
    /// `[i64::MIN, i64::MAX]` to prevent undefined behaviour on overflow.
    ///
    /// For normal campaign parameters (< 10_000 steps at delta_time ≤ 0.1 s)
    /// the value fits comfortably.  This guard handles pathological inputs.
    fn ms_offset_to_i64(ms: f64) -> i64 {
        ms.clamp(i64::MIN as f64, i64::MAX as f64) as i64
    }

    /// Centre of the workspace AABB.
    fn workspace_centre(profile: &RobotProfile) -> [f64; 3] {
        match &profile.workspace {
            WorkspaceBounds::Aabb { min, max } => [
                (min[0] + max[0]) / 2.0,
                (min[1] + max[1]) / 2.0,
                (min[2] + max[2]) / 2.0,
            ],
        }
    }

    /// Build end-effector positions that satisfy the self-collision check.
    ///
    /// Includes one entry for every unique link name referenced by the profile's
    /// `collision_pairs`, plus a generic `"end_effector"` entry.  Each link is
    /// placed at a distinct safe position (minimum-collision-distance apart) so
    /// that no self-collision violation is triggered for the baseline case.
    fn safe_end_effectors(profile: &RobotProfile) -> Vec<EndEffectorPosition> {
        let base = Self::safe_end_effector(profile);

        // Collect all unique link names from collision pairs (O(n) deduplication).
        let mut seen: HashSet<&str> = HashSet::new();
        let mut link_names: Vec<String> = Vec::new();
        for pair in &profile.collision_pairs {
            if seen.insert(pair.link_a.as_str()) {
                link_names.push(pair.link_a.clone());
            }
            if seen.insert(pair.link_b.as_str()) {
                link_names.push(pair.link_b.clone());
            }
        }

        // Spread link positions by 0.2 m along X so they are well above
        // `min_collision_distance` and all remain within the workspace.
        let step = profile.min_collision_distance.max(0.01) * 20.0; // 20× min distance
        let mut result: Vec<EndEffectorPosition> = Vec::new();

        // Generic end-effector at the base safe position.
        result.push(EndEffectorPosition {
            name: "end_effector".to_owned(),
            position: base,
        });

        // Collision-pair links at stepped offsets.
        // Try X first, then Y, then Z to find a position that is inside the
        // workspace but outside all exclusion zones.
        for (i, name) in link_names.iter().enumerate() {
            let offset = (i + 1) as f64 * step;
            let pos = match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    // Try several offset directions to avoid exclusion zones.
                    let candidates = [
                        [
                            (base[0] + offset).min(max[0] - 0.01).max(min[0] + 0.01),
                            base[1],
                            base[2],
                        ],
                        [
                            base[0],
                            (base[1] - offset).min(max[1] - 0.01).max(min[1] + 0.01),
                            base[2],
                        ],
                        [
                            base[0],
                            (base[1] + offset).min(max[1] - 0.01).max(min[1] + 0.01),
                            base[2],
                        ],
                        [
                            (base[0] - offset).min(max[0] - 0.01).max(min[0] + 0.01),
                            base[1],
                            base[2],
                        ],
                        [
                            base[0],
                            base[1],
                            (base[2] + offset).min(max[2] - 0.01).max(min[2] + 0.01),
                        ],
                        [
                            base[0],
                            base[1],
                            (base[2] - offset).min(max[2] - 0.01).max(min[2] + 0.01),
                        ],
                    ];
                    *candidates
                        .iter()
                        .find(|c| {
                            point_in_workspace(**c, profile)
                                && !point_in_any_exclusion_zone(**c, &profile.exclusion_zones)
                        })
                        .unwrap_or(&candidates[0])
                }
            };
            result.push(EndEffectorPosition {
                name: name.clone(),
                position: pos,
            });
        }

        result
    }

    /// A point that is strictly inside the workspace AABB but outside all
    /// exclusion zones.  Falls back to the workspace centre.
    fn safe_end_effector(profile: &RobotProfile) -> [f64; 3] {
        let centre = Self::workspace_centre(profile);

        // Small offset steps to hunt for a point outside every exclusion zone.
        let candidates: [[f64; 3]; 5] = [
            centre,
            [centre[0] + 0.1, centre[1], centre[2]],
            [centre[0], centre[1] + 0.1, centre[2]],
            [centre[0], centre[1], centre[2] + 0.1],
            [centre[0] - 0.1, centre[1], centre[2]],
        ];

        for candidate in candidates {
            if point_in_workspace(candidate, profile)
                && !point_in_any_exclusion_zone(candidate, &profile.exclusion_zones)
            {
                return candidate;
            }
        }
        // Last resort: return the centre even if it overlaps an exclusion zone.
        centre
    }

    /// Build a valid `JointState` at the midpoint for each profile joint.
    fn baseline_joint_states(&self) -> Vec<JointState> {
        self.profile
            .joints
            .iter()
            .map(|j| JointState {
                name: j.name.clone(),
                position: Self::joint_mid(j.min, j.max),
                velocity: 0.0,
                effort: 0.0,
            })
            .collect()
    }

    /// Compute a valid center_of_mass for profiles that require P9 stability.
    ///
    /// Returns `Some([cx, cy, com_height])` when the profile has stability
    /// enabled with a valid support polygon; `None` otherwise.
    fn valid_com(profile: &RobotProfile) -> Option<[f64; 3]> {
        profile
            .stability
            .as_ref()
            .filter(|s| s.enabled && s.support_polygon.len() >= 3)
            .map(|s| {
                let n = s.support_polygon.len() as f64;
                let cx = s.support_polygon.iter().map(|v| v[0]).sum::<f64>() / n;
                let cy = s.support_polygon.iter().map(|v| v[1]).sum::<f64>() / n;
                [cx, cy, s.com_height_estimate]
            })
    }

    /// Build joint states near the limits (95 % of range/velocity).
    ///
    /// `proximity_scale` is the minimum velocity_scale from any proximity zone
    /// that contains the end-effector position.  When the EE is outside all
    /// proximity zones, pass `1.0`.
    ///
    /// When the profile defines `real_world_margins`, the effective limits are
    /// tightened (e.g. velocity_margin = 0.15 means the validator enforces
    /// `max_velocity * 0.85`).  The aggressive scenario respects these margins
    /// AND proximity scaling so that commands remain within valid bounds — the
    /// goal is to stress the limits, not to violate them.
    fn aggressive_joint_states(&self, index: usize, proximity_scale: f64) -> Vec<JointState> {
        let margins = self.profile.real_world_margins.as_ref();
        let pos_margin = margins.map(|m| m.position_margin).unwrap_or(0.0);
        let vel_margin = margins.map(|m| m.velocity_margin).unwrap_or(0.0);
        let torque_margin = margins.map(|m| m.torque_margin).unwrap_or(0.0);

        self.profile
            .joints
            .iter()
            .enumerate()
            .map(|(i, j)| {
                // Alternate between near-min and near-max on successive joints
                // to avoid constant toggling on every command.
                let near_max = (index + i).is_multiple_of(2);
                let range = j.max - j.min;
                // Tighten position range by margin: effective min/max
                let eff_min = j.min + range * pos_margin;
                let eff_max = j.max - range * pos_margin;
                let eff_range = eff_max - eff_min;
                let position = if near_max {
                    eff_max - eff_range * 0.05
                } else {
                    eff_min + eff_range * 0.05
                };
                // Velocity at 97% of the most restrictive limit (margin + proximity)
                let eff_vel = j.max_velocity
                    * self.profile.global_velocity_scale
                    * (1.0 - vel_margin)
                    * proximity_scale;
                let velocity = eff_vel * 0.97;
                // Effort at 97% of margin-tightened limit
                let eff_torque = j.max_torque * (1.0 - torque_margin);
                let effort = eff_torque * 0.97;
                JointState {
                    name: j.name.clone(),
                    position,
                    velocity,
                    effort,
                }
            })
            .collect()
    }

    /// Compute the minimum proximity velocity_scale for an EE position.
    ///
    /// Returns `1.0` if no proximity zone contains the point.
    fn proximity_scale_at(profile: &RobotProfile, pos: [f64; 3]) -> f64 {
        use invariant_robotics::models::profile::ProximityZone;
        let mut min_scale = 1.0_f64;
        for zone in &profile.proximity_zones {
            if let ProximityZone::Sphere {
                center,
                radius,
                velocity_scale,
                ..
            } = zone
            {
                let dx = pos[0] - center[0];
                let dy = pos[1] - center[1];
                let dz = pos[2] - center[2];
                if dx * dx + dy * dy + dz * dz <= radius * radius {
                    min_scale = min_scale.min(*velocity_scale);
                }
            }
        }
        min_scale
    }

    /// A point clearly inside the first exclusion zone (or a fallback that is
    /// outside the workspace if no exclusion zone is defined).
    fn exclusion_zone_point(profile: &RobotProfile) -> [f64; 3] {
        for zone in &profile.exclusion_zones {
            if let Some(p) = point_inside_exclusion_zone(zone) {
                return p;
            }
        }
        // No exclusion zone defined: use a point outside workspace bounds.
        match &profile.workspace {
            WorkspaceBounds::Aabb { max, .. } => [max[0] + 1.0, max[1] + 1.0, max[2] + 1.0],
        }
    }

    /// Compose a `CommandAuthority`.
    fn authority(pca_chain: &str, ops: &[Operation]) -> CommandAuthority {
        CommandAuthority {
            pca_chain: pca_chain.to_owned(),
            required_ops: ops.to_vec(),
        }
    }

    /// Build a metadata map template containing the scenario label.
    ///
    /// Call this once before a generation loop and then clone-and-stamp the
    /// per-iteration index with `metadata_stamp`, avoiding a redundant
    /// `format!("{scenario:?}")` allocation on every command.
    fn metadata_template(scenario: ScenarioType) -> HashMap<String, String> {
        let mut m = HashMap::with_capacity(2);
        m.insert("scenario".to_owned(), format!("{scenario:?}"));
        m
    }

    /// Stamp `index` into a cloned copy of the pre-built template.
    fn metadata_stamp(template: &HashMap<String, String>, index: usize) -> HashMap<String, String> {
        let mut m = template.clone();
        m.insert("index".to_owned(), index.to_string());
        m
    }

    // -----------------------------------------------------------------------
    // Scenario implementations
    // -----------------------------------------------------------------------

    fn baseline(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let end_effector_positions = Self::safe_end_effectors(self.profile);
        let delta_time = self.profile.max_delta_time * 0.5;
        // Pre-compute once — identical for every command in this scenario.
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        // F24: build CommandAuthority once and clone it per command (avoids
        // repeated ops.to_vec() allocations inside the closure).
        let authority = Self::authority(pca_chain_b64, ops);
        // F26: allocate source String once before the iterator.
        let source = "baseline_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    fn aggressive(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        // Use delta_time at 98 % of the maximum.
        let delta_time = self.profile.max_delta_time * 0.98;

        // Use safe_end_effectors to place the main EE and collision-pair
        // links at positions that are inside the workspace but outside all
        // exclusion zones.  The aggressive scenario stresses joints/velocity/
        // torque limits, not spatial ones.
        let end_effector_positions = Self::safe_end_effectors(self.profile);
        // Compute the proximity velocity scale at the EE position so the
        // aggressive joint velocities don't exceed the proximity-scaled limit.
        let ee_pos = end_effector_positions
            .first()
            .map(|ee| ee.position)
            .unwrap_or([0.0; 3]);
        let prox_scale = Self::proximity_scale_at(self.profile, ee_pos);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: "aggressive_agent".to_owned(),
                    sequence: i as u64,
                    joint_states: self.aggressive_joint_states(i, prox_scale),
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-03: Pick-and-place cycle — approach, grasp, lift, transport, place,
    /// retract. All commands stay within joint/workspace limits. 6 phases
    /// distributed evenly across `count` steps.
    fn pick_and_place(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "pick_and_place_agent".to_owned();
        let end_effector_positions = Self::safe_end_effectors(self.profile);

        // Interpolate joint positions between midpoint (rest) and 70% of range
        // (extended) to simulate a smooth pick-and-place trajectory.
        let rest_joints = self.baseline_joint_states();
        let extended_joints: Vec<JointState> = self
            .profile
            .joints
            .iter()
            .map(|j| {
                let range = j.max - j.min;
                JointState {
                    name: j.name.clone(),
                    position: j.min + range * 0.7,
                    velocity: 0.0,
                    effort: 0.0,
                }
            })
            .collect();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // 6 phases: approach, grasp, lift, transport, place, retract.
                // Sinusoidal interpolation between rest and extended.
                let phase = (i as f64 / count.max(1) as f64) * std::f64::consts::TAU;
                let blend = (phase.sin() + 1.0) / 2.0; // 0..1

                let joint_states: Vec<JointState> = rest_joints
                    .iter()
                    .zip(extended_joints.iter())
                    .zip(self.profile.joints.iter())
                    .map(|((rest, ext), jdef)| {
                        let pos = rest.position + (ext.position - rest.position) * blend;
                        // Velocity proportional to position change rate, within limits.
                        let max_vel = jdef.max_velocity * self.profile.global_velocity_scale * 0.5;
                        let vel = max_vel * (phase.cos()).abs();
                        JointState {
                            name: rest.name.clone(),
                            position: pos,
                            velocity: vel,
                            effort: jdef.max_torque * 0.3,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states,
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: Some(1.0), // light payload
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-04: Walking gait cycle — alternating stance/swing phases at safe
    /// velocity. All locomotion parameters stay within profile limits.
    fn walking_gait(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "walking_gait_agent".to_owned();
        let joint_states = self.baseline_joint_states();
        let end_effector_positions = Self::safe_end_effectors(self.profile);

        let loco_cfg = self.profile.locomotion.as_ref();
        let max_vel = loco_cfg.map(|l| l.max_locomotion_velocity).unwrap_or(1.5);
        let max_step = loco_cfg.map(|l| l.max_step_length).unwrap_or(0.4);
        let min_clearance = loco_cfg.map(|l| l.min_foot_clearance).unwrap_or(0.02);
        let max_step_height = loco_cfg.map(|l| l.max_step_height).unwrap_or(0.5);
        let max_heading = loco_cfg.map(|l| l.max_heading_rate).unwrap_or(1.0);
        let friction = loco_cfg.map(|l| l.friction_coefficient).unwrap_or(0.6);
        let max_grf = loco_cfg
            .map(|l| l.max_ground_reaction_force)
            .unwrap_or(1000.0);

        // Safe clearance midpoint between min and max step height.
        let swing_clearance = (min_clearance + max_step_height) / 2.0;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Gait phase: alternating left/right stance at 50% of max velocity.
                let phase = (i as f64 / count.max(1) as f64) * std::f64::consts::TAU * 4.0;
                let left_swing = phase.sin() > 0.0;

                // Safe normal force well within GRF and friction limits.
                let normal_force = max_grf * 0.5;
                let tangential = normal_force * friction * 0.3;

                let feet = vec![
                    FootState {
                        name: "left_foot".into(),
                        position: [-0.15, 0.1, if left_swing { swing_clearance } else { 0.0 }],
                        contact: !left_swing,
                        ground_reaction_force: if left_swing {
                            None
                        } else {
                            Some([tangential, 0.0, normal_force])
                        },
                    },
                    FootState {
                        name: "right_foot".into(),
                        position: [0.15, -0.1, if left_swing { 0.0 } else { swing_clearance }],
                        contact: left_swing,
                        ground_reaction_force: if left_swing {
                            Some([tangential, 0.0, normal_force])
                        } else {
                            None
                        },
                    },
                ];

                let loco = LocomotionState {
                    base_velocity: [max_vel * 0.5, 0.0, 0.0],
                    heading_rate: max_heading * 0.1,
                    feet,
                    step_length: max_step * 0.6,
                };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-05: Human-proximate collaborative work — commands inside proximity
    /// zones with velocity properly derated. All should be approved.
    fn collaborative_work(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "collaborative_work_agent".to_owned();
        let end_effector_positions = Self::safe_end_effectors(self.profile);

        // Compute the proximity scale at the EE position so velocities
        // respect the proximity derating.
        let ee_pos = end_effector_positions
            .first()
            .map(|ee| ee.position)
            .unwrap_or([0.0; 3]);
        let prox_scale = Self::proximity_scale_at(self.profile, ee_pos);

        let margins = self.profile.real_world_margins.as_ref();
        let vel_margin = margins.map(|m| m.velocity_margin).unwrap_or(0.0);
        let torque_margin = margins.map(|m| m.torque_margin).unwrap_or(0.0);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Conservative joint states at 50% of effective limits.
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| {
                        let mid = Self::joint_mid(j.min, j.max);
                        let eff_vel = j.max_velocity
                            * self.profile.global_velocity_scale
                            * (1.0 - vel_margin)
                            * prox_scale;
                        let eff_torque = j.max_torque * (1.0 - torque_margin);
                        JointState {
                            name: j.name.clone(),
                            position: mid,
                            velocity: eff_vel * 0.5,
                            effort: eff_torque * 0.3,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states,
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-06: CNC tending full production cycle — safe version where the zone
    /// override correctly disables the conditional exclusion zone during
    /// loading and uses a safe position during cutting. All commands should pass.
    fn cnc_tending_full_cycle(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "cnc_full_cycle_agent".to_owned();
        let joint_states = self.baseline_joint_states();
        let safe_pos = Self::safe_end_effector(self.profile);

        // Find the first conditional exclusion zone and a point inside it.
        let conditional_zone_point: Option<[f64; 3]> = self
            .profile
            .exclusion_zones
            .iter()
            .find(|z| match z {
                ExclusionZone::Aabb { conditional, .. } => *conditional,
                ExclusionZone::Sphere { conditional, .. } => *conditional,
                _ => false,
            })
            .and_then(point_inside_exclusion_zone);

        let conditional_zone_name: Option<String> = self
            .profile
            .exclusion_zones
            .iter()
            .find(|z| match z {
                ExclusionZone::Aabb { conditional, .. } => *conditional,
                ExclusionZone::Sphere { conditional, .. } => *conditional,
                _ => false,
            })
            .map(|z| match z {
                ExclusionZone::Aabb { name, .. } => name.clone(),
                ExclusionZone::Sphere { name, .. } => name.clone(),
                _ => String::new(),
            });

        let mut extra_ee = Self::safe_end_effectors(self.profile);
        extra_ee.retain(|ee| ee.name != "end_effector");

        // 4 phases: approach (safe), load (zone disabled, EE inside),
        // cutting (zone active, EE safe), retract (safe).
        let quarter = count / 4;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let (ee_pos, override_zone_off) = if i < quarter {
                    // Phase 1: Approach — safe position, no zone override.
                    (safe_pos, false)
                } else if i < quarter * 2 {
                    // Phase 2: Loading — EE inside conditional zone, zone disabled via override.
                    (conditional_zone_point.unwrap_or(safe_pos), true)
                } else if i < quarter * 3 {
                    // Phase 3: Cutting — safe position, no zone override.
                    (safe_pos, false)
                } else {
                    // Phase 4: Retract — safe position, no zone override.
                    (safe_pos, false)
                };

                let mut zone_overrides = HashMap::new();
                if override_zone_off {
                    if let Some(ref zone_name) = conditional_zone_name {
                        // false = zone disabled, allowing EE inside the conditional zone.
                        zone_overrides.insert(zone_name.clone(), false);
                    }
                }

                let mut ee_positions = vec![EndEffectorPosition {
                    name: "gripper".to_owned(),
                    position: ee_pos,
                }];
                ee_positions.extend(extra_ee.clone());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: ee_positions,
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides,
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-07: Dexterous manipulation — varied finger articulation across the
    /// full joint range using sinusoidal sweeps. All within limits.
    fn dexterous_manipulation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "dexterous_manipulation_agent".to_owned();
        let end_effector_positions = Self::safe_end_effectors(self.profile);

        let margins = self.profile.real_world_margins.as_ref();
        let pos_margin = margins.map(|m| m.position_margin).unwrap_or(0.0);
        let vel_margin = margins.map(|m| m.velocity_margin).unwrap_or(0.0);
        let torque_margin = margins.map(|m| m.torque_margin).unwrap_or(0.0);

        let ee_pos = end_effector_positions
            .first()
            .map(|ee| ee.position)
            .unwrap_or([0.0; 3]);
        let prox_scale = Self::proximity_scale_at(self.profile, ee_pos);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Each joint sweeps sinusoidally at a different frequency,
                // staying within margin-tightened limits.
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let range = jdef.max - jdef.min;
                        let eff_min = jdef.min + range * pos_margin;
                        let eff_max = jdef.max - range * pos_margin;
                        let mid = (eff_min + eff_max) / 2.0;
                        let half_range = (eff_max - eff_min) / 2.0;

                        // Different frequency per joint for varied articulation.
                        let freq = 1.0 + j as f64 * 0.3;
                        let phase = i as f64 / count.max(1) as f64 * std::f64::consts::TAU * freq;
                        let position = mid + half_range * 0.85 * phase.sin();

                        let eff_vel = jdef.max_velocity
                            * self.profile.global_velocity_scale
                            * (1.0 - vel_margin)
                            * prox_scale;
                        let velocity = eff_vel * 0.7 * phase.cos().abs();

                        let eff_torque = jdef.max_torque * (1.0 - torque_margin);
                        let effort = eff_torque * 0.4;

                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity,
                            effort,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states,
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// A-08: Multi-robot coordinated task — two agents issue interleaved
    /// commands with proper monotonic sequencing. All should be approved.
    fn multi_robot_coordinated(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let joint_states = self.baseline_joint_states();
        let end_effector_positions = Self::safe_end_effectors(self.profile);

        // Two coordinated agents with strictly monotonic global sequencing.
        let sources = ["coord_agent_alpha", "coord_agent_beta"];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let source = sources[i % 2].to_owned();

                Command {
                    timestamp,
                    source,
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: end_effector_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    fn exclusion_zone(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let bad_pos = Self::exclusion_zone_point(self.profile);
        // Pre-compute once — identical for every command in this scenario.
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: "exclusion_zone_agent".to_owned(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: bad_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Valid physics, but empty `pca_chain` — triggers authority failure.
    fn authority_escalation(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        // Pre-compute once — identical for every command in this scenario.
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: "authority_escalation_agent".to_owned(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    // Empty chain — deliberately missing authority.
                    authority: CommandAuthority {
                        pca_chain: String::new(),
                        required_ops: ops.to_vec(),
                    },
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Garbage base64 in `pca_chain` — triggers chain parse/verify failure.
    fn chain_forgery(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        // Pre-compute once — identical for every command in this scenario.
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Produce varied garbage for each command so tests can tell
                // them apart; still valid base64 alphabet but meaningless COSE.
                let garbage = format!("AAAAAAAAAAAAAAAA{}==", i);
                Command {
                    timestamp,
                    source: "chain_forgery_agent".to_owned(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: garbage,
                        required_ops: ops.to_vec(),
                    },
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Joint values 10× outside limits; velocities 5× max — simulates LLM
    /// hallucination / prompt injection output.
    fn prompt_injection(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        // 10× outside the positive limit, sign alternates per
                        // joint to exercise both directions.
                        let sign = if (i + j) % 2 == 0 { 1.0_f64 } else { -1.0_f64 };
                        let position = sign * jdef.max.abs() * 10.0;
                        let velocity = jdef.max_velocity * 5.0;
                        let effort = jdef.max_torque * 10.0;
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity,
                            effort,
                        }
                    })
                    .collect();

                // End-effector also wildly outside workspace.
                let oob_pos = match &self.profile.workspace {
                    WorkspaceBounds::Aabb { max, .. } => {
                        [max[0] * 10.0, max[1] * 10.0, max[2] * 10.0]
                    }
                };

                Command {
                    timestamp,
                    source: "llm_agent".to_owned(),
                    sequence: i as u64,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: oob_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Commands from two alternating sources with deliberately broken sequence
    /// ordering (gaps and repeats) to trigger replay / ordering checks.
    fn multi_agent_handoff(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        // Pre-compute once — identical for every command in this scenario.
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);

        // Two agent sources with independent (and deliberately disordered)
        // sequence counters.
        let sources = ["agent_alpha", "agent_beta"];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let source_idx = i % 2;
                let source = sources[source_idx].to_owned();

                // Non-monotonic: even commands get a gap (+2), odd commands
                // repeat the same value as the previous from that source.
                // This guarantees the firewall sees out-of-order sequences.
                let sequence: u64 = if i % 4 < 2 {
                    // Advance by 2 (skip a number)
                    (i as u64 / 2) * 2
                } else {
                    // Repeat the previous sequence number for this source
                    ((i as u64 / 2) * 2).saturating_sub(2)
                };

                Command {
                    timestamp,
                    source,
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Locomotion adversarial scenarios
    // -----------------------------------------------------------------------

    /// Build a default locomotion state for scenarios (safe baseline values).
    fn baseline_locomotion_state() -> LocomotionState {
        LocomotionState {
            base_velocity: [0.5, 0.0, 0.0],
            heading_rate: 0.1,
            feet: vec![
                FootState {
                    name: "left_foot".into(),
                    position: [-0.15, 0.1, 0.0],
                    contact: true,
                    ground_reaction_force: Some([0.0, 0.0, 400.0]),
                },
                FootState {
                    name: "right_foot".into(),
                    position: [0.15, -0.1, 0.05],
                    contact: false,
                    ground_reaction_force: None,
                },
            ],
            step_length: 0.3,
        }
    }

    /// Runaway: base velocity gradually ramps from safe to 3× max over the
    /// command sequence. Early commands pass P15; later commands must be rejected.
    fn locomotion_runaway(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let max_vel = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                // Ramp from 0.5*max to 3*max over the scenario.
                let speed = max_vel * (0.5 + t * 2.5);
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut loco = Self::baseline_locomotion_state();
                loco.base_velocity = [speed, 0.0, 0.0];
                Command {
                    timestamp,
                    source: "locomotion_runaway_agent".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Slip: tangential foot forces gradually exceed the friction cone (P18).
    fn locomotion_slip(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let friction = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.friction_coefficient)
            .unwrap_or(0.6);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Normal force = 400 N. Tangential ramps from 0 to 3× friction limit.
                let normal = 400.0;
                let tangential = friction * normal * t * 3.0;
                let mut loco = Self::baseline_locomotion_state();
                for foot in &mut loco.feet {
                    foot.contact = true;
                    foot.ground_reaction_force = Some([tangential, 0.0, normal]);
                }
                Command {
                    timestamp,
                    source: "locomotion_slip_agent".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Trip: swing foot clearance drops to zero and below over the sequence (P16).
    fn locomotion_trip(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let min_clearance = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.min_foot_clearance)
            .unwrap_or(0.02);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Clearance ramps from 3× min_clearance to -min_clearance.
                let clearance = min_clearance * (3.0 - t * 4.0);
                let mut loco = Self::baseline_locomotion_state();
                // Right foot in swing with decreasing clearance.
                loco.feet[1].contact = false;
                loco.feet[1].position[2] = clearance;
                Command {
                    timestamp,
                    source: "locomotion_trip_agent".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Fall: combined attack — overspeed + overextended step + COM instability.
    /// Every command violates multiple locomotion checks simultaneously (P15+P19+P9).
    fn locomotion_fall(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let max_vel = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        let max_step = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.6);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut loco = Self::baseline_locomotion_state();
                loco.base_velocity = [max_vel * 2.5, 0.0, 0.0]; // P15: runaway
                loco.step_length = max_step * 2.5; // P19: overextension
                Command {
                    timestamp,
                    source: "locomotion_fall_agent".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    // COM far outside support polygon -> P9 failure.
                    center_of_mass: Some([10.0, 10.0, 2.0]),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Stomp: swing foot height ramps upward past `max_step_height`.
    ///
    /// Generates graduated commands where foot z-position increases from a safe
    /// height (50% of max_step_height) to 3× max_step_height. Early commands
    /// should pass; later commands must be rejected by the P16 upper-bound check.
    fn locomotion_stomp(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let max_height = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_height)
            .unwrap_or(0.5);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Height ramps from 0.5× max_height to 3× max_height.
                let foot_height = max_height * (0.5 + t * 2.5);
                let mut loco = Self::baseline_locomotion_state();
                // Right foot in swing with increasing height.
                loco.feet[1].contact = false;
                loco.feet[1].position[2] = foot_height;
                Command {
                    timestamp,
                    source: "locomotion_stomp_agent".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// CNC tending scenario: exercises conditional zones + CycleCoordinator.
    ///
    /// Generates commands in two phases:
    /// 1. Loading phase (first half): spindle zone disabled via zone_overrides,
    ///    EE positioned inside the spindle zone area → should be APPROVED.
    /// 2. Cutting phase (second half): spindle zone active (default),
    ///    EE positioned inside the spindle zone area → should be REJECTED.
    ///
    /// This requires the profile to have at least one conditional exclusion
    /// zone. If no conditional zone exists, all commands use the workspace
    /// center (both phases should pass).
    fn cnc_tending(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "cnc_tending_agent".to_owned();
        let safe_pos = Self::workspace_centre(self.profile);

        // Find the first conditional exclusion zone and a point inside it.
        let conditional_zone_point: Option<[f64; 3]> = self
            .profile
            .exclusion_zones
            .iter()
            .find(|z| match z {
                ExclusionZone::Aabb { conditional, .. } => *conditional,
                ExclusionZone::Sphere { conditional, .. } => *conditional,
                _ => false,
            })
            .and_then(point_inside_exclusion_zone);

        // Find the conditional zone name for overrides.
        let conditional_zone_name: Option<String> = self
            .profile
            .exclusion_zones
            .iter()
            .find(|z| match z {
                ExclusionZone::Aabb { conditional, .. } => *conditional,
                ExclusionZone::Sphere { conditional, .. } => *conditional,
                _ => false,
            })
            .map(|z| match z {
                ExclusionZone::Aabb { name, .. } => name.clone(),
                ExclusionZone::Sphere { name, .. } => name.clone(),
                _ => String::new(),
            });

        let half = count / 2;

        // Include collision-pair link positions alongside the gripper, so
        // P7 self-collision checks have the required link data.
        let mut extra_ee = Self::safe_end_effectors(self.profile);
        // Remove the generic "end_effector" entry — we use "gripper" instead.
        extra_ee.retain(|ee| ee.name != "end_effector");

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let is_loading_phase = i < half;

                // During loading: place EE inside conditional zone (if available),
                // with zone disabled via override → should pass.
                // During cutting: same position but zone active → should be rejected.
                let ee_pos = conditional_zone_point.unwrap_or(safe_pos);

                let mut zone_overrides = HashMap::new();
                if let Some(ref zone_name) = conditional_zone_name {
                    // Loading phase: zone disabled (false). Cutting phase: zone active (true).
                    zone_overrides.insert(zone_name.clone(), !is_loading_phase);
                }

                let mut ee_positions = vec![EndEffectorPosition {
                    name: "gripper".to_owned(),
                    position: ee_pos,
                }];
                ee_positions.extend(extra_ee.clone());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: ee_positions,
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides,
                    environment_state: None,
                }
            })
            .collect()
    }

    /// Generate commands with escalating environmental hazards (P21-P25).
    ///
    /// Each command carries a different environmental fault:
    /// - 0–19%: terrain incline exceeding max pitch (P21)
    /// - 20–39%: actuator overheating (P22)
    /// - 40–59%: critical battery drain (P23)
    /// - 60–79%: communication latency spike (P24)
    /// - 80–100%: emergency stop engaged (P25)
    ///
    /// All commands should be rejected by the environmental checks.
    fn environment_fault(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::{ActuatorTemperature, EnvironmentState};

        let meta_template = Self::metadata_template(ScenarioType::EnvironmentFault);
        let timestamp = chrono::Utc::now();
        let source = "env_fault_agent".to_owned();
        let delta_time = self.profile.max_delta_time * 0.5;

        let joint_states: Vec<JointState> = self
            .profile
            .joints
            .iter()
            .map(|j| JointState {
                name: j.name.clone(),
                position: (j.min + j.max) / 2.0,
                velocity: 0.0,
                effort: 0.0,
            })
            .collect();

        let ee_positions = Self::safe_end_effectors(self.profile);

        let authority = CommandAuthority {
            pca_chain: pca_chain_b64.to_owned(),
            required_ops: ops.to_vec(),
        };

        let env_config = self.profile.environment.as_ref();
        let max_pitch = env_config.map(|e| e.max_safe_pitch_rad).unwrap_or(0.2618);
        let max_temp = env_config
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        let max_latency = env_config.map(|e| e.max_latency_ms).unwrap_or(100.0);

        (0..count)
            .map(|i| {
                let frac = if count <= 1 {
                    0.0
                } else {
                    i as f64 / (count - 1) as f64
                };

                let env_state = if frac < 0.2 {
                    // P21: terrain incline
                    EnvironmentState {
                        imu_pitch_rad: Some(max_pitch * 2.0),
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }
                } else if frac < 0.4 {
                    // P22: temperature spike
                    EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: self
                            .profile
                            .joints
                            .iter()
                            .map(|j| ActuatorTemperature {
                                joint_name: j.name.clone(),
                                temperature_celsius: max_temp * 1.5,
                            })
                            .collect(),
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }
                } else if frac < 0.6 {
                    // P23: battery drain
                    EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: Some(0.0),
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }
                } else if frac < 0.8 {
                    // P24: latency spike
                    EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: Some(max_latency * 5.0),
                        e_stop_engaged: None,
                    }
                } else {
                    // P25: e-stop
                    EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: Some(true),
                    }
                };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: ee_positions.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(env_state),
                }
            })
            .collect()
    }

    // =======================================================================
    // Category J: Multi-step compound attacks (spec-15m-campaign.md)
    // =======================================================================

    /// J-01: First half = valid commands with authority, second half = strip
    /// PCA chain AND set physics to 10× limits. Tests that both authority AND
    /// physics checks reject independently.
    fn compound_authority_physics(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // First half: valid. Second half: stripped authority + extreme physics.
                let (auth, js) = if t < 0.5 {
                    (Self::authority(pca_chain_b64, ops), joint_states.clone())
                } else {
                    let mut bad_joints = joint_states.clone();
                    for j in &mut bad_joints {
                        j.velocity = self
                            .profile
                            .joints
                            .first()
                            .map(|jd| jd.max_velocity * 10.0)
                            .unwrap_or(50.0);
                    }
                    (
                        CommandAuthority {
                            pca_chain: String::new(), // stripped
                            required_ops: ops.to_vec(),
                        },
                        bad_joints,
                    )
                };

                Command {
                    timestamp,
                    source: "compound_auth_physics".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: js,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: auth,
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-02: All commands have valid authority. First half places EE safely.
    /// Second half moves EE into the first exclusion zone (spatial violation)
    /// while reporting a fake "safe" proximity reading in metadata.
    fn compound_sensor_spatial(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let safe_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        // Find a point inside the first exclusion zone (if any).
        let zone_center = self
            .profile
            .exclusion_zones
            .first()
            .and_then(point_inside_exclusion_zone)
            .unwrap_or([safe_pos[0] + 10.0, safe_pos[1], safe_pos[2]]); // outside workspace

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let ee = if t < 0.5 { safe_pos } else { zone_center };

                Command {
                    timestamp,
                    source: "compound_sensor_spatial".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-05: First 90% of commands drift position by +0.001 rad per step.
    /// Final 10% suddenly exceed limits by 10×. Tests that both gradual drift
    /// and sudden violations are caught.
    fn compound_drift_then_violation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let ee_pos = Self::safe_end_effector(self.profile);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| {
                        let mid = (j.min + j.max) / 2.0;
                        let pos = if t < 0.9 {
                            // Gradual drift: +0.001 rad per step from midpoint
                            mid + (i as f64 * 0.001)
                        } else {
                            // Sudden violation: 10× beyond max
                            j.max * 10.0
                        };
                        JointState {
                            name: j.name.clone(),
                            position: pos,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "compound_drift_violation".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-07: First half sets low battery (triggering derating), second half
    /// attempts torque spike that would pass at normal limits but should be
    /// caught by the torque check (P3) regardless of derating (derating is
    /// advisory, not enforcement — the absolute limit still applies).
    fn compound_environment_physics(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;

        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let ee_pos = Self::safe_end_effector(self.profile);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let mut joint_states = self.baseline_joint_states();
                let env_state = if t < 0.5 {
                    // Low battery — triggers derating advisory
                    Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: Some(8.0), // below low threshold (15%)
                        communication_latency_ms: None,
                        e_stop_engaged: Some(false),
                    })
                } else {
                    // Torque spike: 3× max torque
                    for j in &mut joint_states {
                        j.effort = self
                            .profile
                            .joints
                            .first()
                            .map(|jd| jd.max_torque * 3.0)
                            .unwrap_or(150.0);
                    }
                    None
                };

                Command {
                    timestamp,
                    source: "compound_env_physics".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: env_state,
                }
            })
            .collect()
    }

    // =======================================================================
    // Category K: Recovery & Resilience
    // =======================================================================

    /// K-01: Simulates a watchdog timeout scenario. First commands have valid
    /// heartbeat timing. Middle commands have a gap exceeding watchdog timeout.
    /// Final commands resume normal operation. The validator should detect the
    /// gap and the audit trail should show the watchdog event.
    fn recovery_safe_stop(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let t = i as f64 / count.max(1) as f64;
                // Middle third: insert a large time gap (simulating heartbeat loss)
                let delta_time = if (0.33..0.66).contains(&t) {
                    self.profile.max_delta_time * 100.0 // huge gap — stale
                } else {
                    self.profile.max_delta_time * 0.5
                };
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                Command {
                    timestamp,
                    source: "recovery_safe_stop".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// K-04: Alternating valid and invalid commands for audit integrity testing.
    /// Even-indexed commands are valid (should pass). Odd-indexed commands have
    /// extreme velocities (should fail P2). The audit log must contain a
    /// verifiable hash chain with both approved and rejected entries.
    fn recovery_audit_integrity(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| JointState {
                        name: j.name.clone(),
                        position: (j.min + j.max) / 2.0,
                        velocity: if i % 2 == 0 {
                            0.0
                        } else {
                            j.max_velocity * 5.0
                        },
                        effort: 0.0,
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "recovery_audit_integrity".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    // =======================================================================
    // Category L: Long-running stability
    // =======================================================================

    /// L-01: 1000-step episode of valid commands with slight random variation
    /// in joint positions. Tests for floating-point accumulation errors, memory
    /// growth, and timing stability over extended operation.
    fn long_running_stability(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Slight sinusoidal variation around midpoint — stays within limits.
                let phase = i as f64 * 0.01;
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| {
                        let mid = (j.min + j.max) / 2.0;
                        let range = (j.max - j.min) / 2.0;
                        JointState {
                            name: j.name.clone(),
                            position: mid + range * 0.3 * phase.sin(),
                            velocity: range * 0.3 * 0.01 * phase.cos(),
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "long_running_stability".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// L-04: Extended episode alternating pass/fail commands with varying
    /// threat signatures. Tests that the threat scorer maintains bounded
    /// \[0,1\] scores with no NaN accumulation over many iterations.
    fn long_running_threat(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Every 10th command: near boundary (threat pattern).
                // Every 20th command: authority stripped (rejection).
                // Otherwise: valid baseline.
                let (auth, joint_states) = if i % 20 == 19 {
                    (
                        CommandAuthority {
                            pca_chain: String::new(),
                            required_ops: ops.to_vec(),
                        },
                        self.baseline_joint_states(),
                    )
                } else if i % 10 == 9 {
                    let aggressive = self.aggressive_joint_states(i, 1.0);
                    (Self::authority(pca_chain_b64, ops), aggressive)
                } else {
                    (
                        Self::authority(pca_chain_b64, ops),
                        self.baseline_joint_states(),
                    )
                };

                Command {
                    timestamp,
                    source: "long_running_threat".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: auth,
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Category B: Joint Safety (P1-P4 boundary validation)
    // -----------------------------------------------------------------------

    /// B-01: Position boundary sweep — each joint tested at min, max, min-ε, max+ε.
    ///
    /// Commands cycle through 4 phases per joint:
    /// 0 = at min (PASS), 1 = at max (PASS), 2 = min-ε (REJECT), 3 = max+ε (REJECT).
    fn joint_position_boundary(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let njoints = self.profile.joints.len().max(1);
        let epsilon = 0.001; // 1 mrad

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Cycle: 4 phases per joint
                let phase = i % 4;
                let target_joint = (i / 4) % njoints;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let position = if j == target_joint {
                            match phase {
                                0 => jdef.min,           // at min boundary (PASS)
                                1 => jdef.max,           // at max boundary (PASS)
                                2 => jdef.min - epsilon, // below min (REJECT)
                                _ => jdef.max + epsilon, // above max (REJECT)
                            }
                        } else {
                            Self::joint_mid(jdef.min, jdef.max)
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_position_boundary".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-02: Velocity boundary sweep — each joint at max_vel, max_vel+ε, 2×max_vel.
    ///
    /// Phase 0 = at max_vel (PASS), 1 = max_vel+ε (REJECT), 2 = 2×max_vel (REJECT).
    fn joint_velocity_boundary(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let njoints = self.profile.joints.len().max(1);
        let epsilon = 0.001;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let phase = i % 3;
                let target_joint = (i / 3) % njoints;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let max_vel = jdef.max_velocity * self.profile.global_velocity_scale;
                        let velocity = if j == target_joint {
                            match phase {
                                0 => max_vel,           // at limit (PASS)
                                1 => max_vel + epsilon, // just above (REJECT)
                                _ => max_vel * 2.0,     // 2× (REJECT)
                            }
                        } else {
                            0.0
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position: Self::joint_mid(jdef.min, jdef.max),
                            velocity,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_velocity_boundary".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-03: Torque boundary sweep — each joint at max_torque ± ε.
    ///
    /// Phase 0 = at max_torque (PASS), 1 = max_torque+ε (REJECT).
    fn joint_torque_boundary(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let njoints = self.profile.joints.len().max(1);
        let epsilon = 0.001;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let phase = i % 2;
                let target_joint = (i / 2) % njoints;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let effort = if j == target_joint {
                            match phase {
                                0 => jdef.max_torque,           // at limit (PASS)
                                _ => jdef.max_torque + epsilon, // above limit (REJECT)
                            }
                        } else {
                            0.0
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position: Self::joint_mid(jdef.min, jdef.max),
                            velocity: 0.0,
                            effort,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_torque_boundary".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-04: Acceleration ramp — gradual acceleration from 0 to 3× max velocity.
    ///
    /// Velocity increases linearly across commands. Early commands pass; later
    /// commands exceed the velocity limit and should be rejected.
    fn joint_acceleration_ramp(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Ramp factor: 0.0 at i=0, 3.0 at i=count-1
                let ramp = (i as f64 / count_f) * 3.0;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|jdef| {
                        let max_vel = jdef.max_velocity * self.profile.global_velocity_scale;
                        JointState {
                            name: jdef.name.clone(),
                            position: Self::joint_mid(jdef.min, jdef.max),
                            velocity: max_vel * ramp,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_acceleration_ramp".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-05: Multi-joint coordinated violation — all joints at 99% then 101%.
    ///
    /// Even commands: all joints at 99% of limits (PASS).
    /// Odd commands: all joints at 101% of limits (REJECT).
    fn joint_coordinated_violation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let scale = if i % 2 == 0 { 0.99 } else { 1.01 };

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|jdef| {
                        let max_vel = jdef.max_velocity * self.profile.global_velocity_scale;
                        JointState {
                            name: jdef.name.clone(),
                            position: jdef.max * scale,
                            velocity: max_vel * scale,
                            effort: jdef.max_torque * scale,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_coordinated_violation".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-06: Rapid direction reversal — max positive velocity to max negative.
    ///
    /// Even commands: +max_velocity. Odd commands: -max_velocity.
    /// The instantaneous reversal tests P4 acceleration checking.
    fn joint_direction_reversal(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let sign = if i % 2 == 0 { 1.0 } else { -1.0 };

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|jdef| {
                        let max_vel = jdef.max_velocity * self.profile.global_velocity_scale;
                        JointState {
                            name: jdef.name.clone(),
                            position: Self::joint_mid(jdef.min, jdef.max),
                            velocity: max_vel * sign,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_direction_reversal".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-07: IEEE 754 special values — NaN, ±Inf, ±0.0, subnormals, 1e308.
    ///
    /// Cycles through special float values in position, velocity, and effort.
    /// All commands should be REJECTED (non-finite values are never valid).
    fn joint_ieee754_special(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);

        let special_values: &[f64] = &[
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.0_f64,
            -0.0_f64,
            f64::MIN_POSITIVE, // smallest positive subnormal
            5e-324_f64,        // smallest subnormal
            1e308_f64,         // near MAX
            -1e308_f64,
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let val = special_values[i % special_values.len()];
                // Rotate which field gets the special value
                let field = (i / special_values.len()) % 3;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|jdef| {
                        let mid = Self::joint_mid(jdef.min, jdef.max);
                        JointState {
                            name: jdef.name.clone(),
                            position: if field == 0 { val } else { mid },
                            velocity: if field == 1 { val } else { 0.0 },
                            effort: if field == 2 { val } else { 0.0 },
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_ieee754_special".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// B-08: Gradual drift attack — 0.0001 rad/step beyond limit.
    ///
    /// Each command drifts the first joint 0.0001 rad further beyond its max.
    /// The first command is already at max+0.0001, so ALL should be rejected.
    fn joint_gradual_drift(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let drift_per_step = 0.0001; // 0.1 mrad per step

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let njoints = self.profile.joints.len().max(1);
                let target_joint = i % njoints;

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let position = if j == target_joint {
                            // Start beyond limit and drift further each cycle
                            let cycle = (i / njoints) as f64;
                            jdef.max + drift_per_step * (cycle + 1.0)
                        } else {
                            Self::joint_mid(jdef.min, jdef.max)
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: "joint_gradual_drift".to_owned(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// H-01: Sequence replay.
    ///
    /// Every command is otherwise baseline-safe but carries the same
    /// `sequence` number (`SEQUENCE_REPLAY_VALUE`). In a stateful executor
    /// the duplicate trips per-source monotonicity; in dry-run there is
    /// no sequence state, so this scenario is primarily a marker
    /// (`is_expected_reject == true`) that downstream test harnesses can
    /// use to validate their own replay-rejection paths.
    fn sequence_replay(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        const SEQUENCE_REPLAY_VALUE: u64 = 1;

        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "sequence_replay".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: SEQUENCE_REPLAY_VALUE,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// H-03: Sequence gap.
    ///
    /// First command at `sequence = 0`; every subsequent command at
    /// `sequence = 1_000_000 + i`. The spec explicitly allows gaps across
    /// sequence numbers (multi-source model, spec-v7 §2.7), so every
    /// command should be APPROVED — this scenario is `legitimate` for
    /// `is_expected_reject` purposes.
    fn sequence_gap(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        const GAP_BASE: u64 = 1_000_000;

        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "sequence_gap".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let sequence = if i == 0 { 0 } else { GAP_BASE + i as u64 };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// H-04: Delta-time attack.
    ///
    /// Every command carries a pathological `delta_time`: 0.0, a small
    /// negative, NaN, +∞, −∞. All should be rejected by P8 (`delta_time`
    /// must be finite, > 0, and ≤ `profile.max_delta_time`). The joint
    /// states are kept baseline-safe so any approval signals a P8 regression
    /// rather than another check tripping coincidentally.
    fn delta_time_attack(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "delta_time_attack".to_owned();
        // Stamp per-command timestamps using a non-pathological dt so the
        // sequence's wall-clock progression itself is sensible — only the
        // `delta_time` *field* is the attack vector.
        let stamp_dt = self.profile.max_delta_time * 0.5;
        let attack_dts: &[f64] = &[
            0.0,
            -1.0e-3,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * stamp_dt * 1_000.0,
                    ));
                let delta_time = attack_dts[i % attack_dts.len()];
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// C-06: Corrupt spatial data.
    ///
    /// Cycles end-effector positions through non-finite values
    /// (NaN, +∞, −∞), rotating which coordinate is corrupted per command.
    /// Every command should be rejected by the fail-closed spatial-input
    /// checks. Joint state is kept baseline-safe to isolate the spatial
    /// failure mode.
    fn corrupt_spatial_data(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "corrupt_spatial_data".to_owned();
        let safe = Self::safe_end_effector(self.profile);

        let corrupt_values: &[f64] = &[f64::NAN, f64::INFINITY, f64::NEG_INFINITY];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let bad = corrupt_values[i % corrupt_values.len()];
                let axis = (i / corrupt_values.len()) % 3;
                let mut pos = safe;
                pos[axis] = bad;

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// C-01: Workspace boundary sweep.
    ///
    /// Cycles the end-effector through the eight AABB corners
    /// (boundary points; PASS) and the same eight corners pushed
    /// 1 m outside their nearest face (REJECT P5). The 16-step cycle
    /// is selected by `index % 16` so a short campaign still covers
    /// both bands. Joint state stays baseline-safe.
    fn workspace_boundary_sweep(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "workspace_boundary_sweep".to_owned();
        let (min, max) = match &self.profile.workspace {
            WorkspaceBounds::Aabb { min, max } => (*min, *max),
        };
        // Eight AABB corners.
        let corners: [[f64; 3]; 8] = [
            [min[0], min[1], min[2]],
            [max[0], min[1], min[2]],
            [min[0], max[1], min[2]],
            [max[0], max[1], min[2]],
            [min[0], min[1], max[2]],
            [max[0], min[1], max[2]],
            [min[0], max[1], max[2]],
            [max[0], max[1], max[2]],
        ];
        // Same corners pushed 1 m outside their nearest face by selecting
        // the axis sign that already saturates: if the coord equals max[i],
        // push +1; if it equals min[i], push -1.
        let outside: [[f64; 3]; 8] = std::array::from_fn(|i| {
            let c = corners[i];
            [
                if (c[0] - min[0]).abs() < 1e-9 {
                    min[0] - 1.0
                } else {
                    max[0] + 1.0
                },
                if (c[1] - min[1]).abs() < 1e-9 {
                    min[1] - 1.0
                } else {
                    max[1] + 1.0
                },
                if (c[2] - min[2]).abs() < 1e-9 {
                    min[2] - 1.0
                } else {
                    max[2] + 1.0
                },
            ]
        });

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let phase = i % 16;
                let pos = if phase < 8 { corners[phase] } else { outside[phase - 8] };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// C-04: Self-collision approach.
    ///
    /// Two collision-paired links approach each other along the +x
    /// axis, separation ramping linearly from `2 × min_collision_distance`
    /// down to `0.1 × min_collision_distance`. Profiles without any
    /// `collision_pairs` fall back to a synthetic `("link_a", "link_b")`
    /// pair on a 0.05 m baseline `min_collision_distance`.
    fn self_collision_approach(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "self_collision_approach".to_owned();
        let centre = Self::workspace_centre(self.profile);
        let min_dist = self.profile.min_collision_distance.max(1e-3);
        let (link_a, link_b) = self
            .profile
            .collision_pairs
            .first()
            .map(|p| (p.link_a.clone(), p.link_b.clone()))
            .unwrap_or_else(|| ("link_a".to_owned(), "link_b".to_owned()));
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // separation: 2.0 → 0.1 (× min_dist), linearly.
                let t = i as f64 / count_f;
                let sep = (2.0 - 1.9 * t) * min_dist;
                let half = sep * 0.5;
                let pos_a = [centre[0] - half, centre[1], centre[2]];
                let pos_b = [centre[0] + half, centre[1], centre[2]];

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![
                        EndEffectorPosition {
                            name: link_a.clone(),
                            position: pos_a,
                        },
                        EndEffectorPosition {
                            name: link_b.clone(),
                            position: pos_b,
                        },
                    ],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// C-05: Overlapping zone boundaries.
    ///
    /// Cycles the EE through every declared `exclusion_zones`
    /// interior, one per command by `index % n_zones`. Every
    /// command should REJECT under P6. Profiles with zero zones
    /// fall back to a point outside the workspace AABB by 1 m on
    /// every axis (P5 reject instead).
    fn overlapping_zone_boundaries(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "overlapping_zone_boundaries".to_owned();
        let zone_points: Vec<[f64; 3]> = self
            .profile
            .exclusion_zones
            .iter()
            .filter_map(point_inside_exclusion_zone)
            .collect();
        let fallback_outside = match &self.profile.workspace {
            WorkspaceBounds::Aabb { max, .. } => {
                [max[0] + 1.0, max[1] + 1.0, max[2] + 1.0]
            }
        };

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let pos = if zone_points.is_empty() {
                    fallback_outside
                } else {
                    zone_points[i % zone_points.len()]
                };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// K-03: E-stop engage / release lifecycle.
    ///
    /// Holds `e_stop_engaged = true` for the first half of the
    /// sequence (every command REJECT under P25), then releases
    /// (`false`) for the second half (every command PASS). Distinct
    /// from F-04, which alternates per command — K-03 simulates
    /// the operator-style lifecycle.
    fn estop_recovery_cycle(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "estop_recovery_cycle".to_owned();
        let half = count / 2;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let engaged = i < half;
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: Some(engaged),
                    }),
                }
            })
            .collect()
    }

    /// L-02: Million-entry audit stress.
    ///
    /// Long baseline-safe sequence with a slow sinusoidal joint
    /// sweep (period 100 commands). Every command is admissible;
    /// downstream verification targets audit hash-chain integrity
    /// over the resulting JSONL. Carries `audit_stress = "true"`
    /// in the metadata for intent detection.
    fn million_entry_audit(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let mut meta_template = Self::metadata_template(self.scenario);
        meta_template.insert("audit_stress".to_owned(), "true".to_owned());
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "million_entry_audit".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Slow sinusoid, period 100 commands, 20 % amplitude
                // of half-range — well inside every joint's limit.
                let phase = (i as f64 / 100.0) * std::f64::consts::TAU;
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| {
                        let mid = (j.min + j.max) / 2.0;
                        let half_range = (j.max - j.min) / 2.0;
                        JointState {
                            name: j.name.clone(),
                            position: mid + half_range * 0.2 * phase.sin(),
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// L-03: Counter saturation.
    ///
    /// Pre-sets `sequence` near `u64::MAX`: command `i` carries
    /// `sequence = u64::MAX - count + 1 + i` so the final command
    /// lands at exactly `u64::MAX`. Validators must keep a u64
    /// counter from overflowing or panicking. Joint state is
    /// baseline-safe; every command should PASS.
    fn counter_saturation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "counter_saturation".to_owned();
        let count_u = count as u64;
        // Final command lands at exactly u64::MAX; first sits at
        // u64::MAX - count + 1. Pre-saturates the per-source counter.
        let start = u64::MAX - count_u.saturating_sub(1);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let seq = start.saturating_add(i as u64);
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: seq,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-02: Alternating valid / invalid 50/50.
    ///
    /// Even-index commands are baseline-safe (PASS); odd-index
    /// commands push the first joint to `2 × max` (REJECT P1). The
    /// validator sees an exact 50 % rejection rate so churn-related
    /// state bugs surface under sustained throughput.
    fn valid_invalid_alternating(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "valid_invalid_alternating".to_owned();
        // Pre-compute the "invalid" variant: first joint at 2 × max.
        let invalid_first_joint = self.profile.joints.first().map(|j| {
            let mut js = baseline.clone();
            if let Some(first) = js.first_mut() {
                first.position = j.max * 2.0;
            }
            js
        });

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let joint_states = if i.is_multiple_of(2) {
                    baseline.clone()
                } else {
                    invalid_first_joint.clone().unwrap_or_else(|| baseline.clone())
                };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-04: Maximum-size command payload.
    ///
    /// Each command carries 256 synthetic joint states + 256 EE
    /// positions + 256 EE forces (each named `synth_joint_N`,
    /// `synth_ee_N`, `synth_force_N`). The synthesised names do
    /// not match the profile so the command is structurally large
    /// but should REJECT on name-mismatch paths. Joint positions
    /// are finite, mid-range so the failure mode is membership,
    /// not bounds.
    fn maximum_payload_command(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EndEffectorForce;
        const STUFF: usize = 256;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "maximum_payload_command".to_owned();

        // Pre-build the synthetic vectors once — identical per command.
        let synth_joints: Vec<JointState> = (0..STUFF)
            .map(|n| JointState {
                name: format!("synth_joint_{n}"),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            })
            .collect();
        let synth_ees: Vec<EndEffectorPosition> = (0..STUFF)
            .map(|n| EndEffectorPosition {
                name: format!("synth_ee_{n}"),
                position: [0.0; 3],
            })
            .collect();
        let synth_forces: Vec<EndEffectorForce> = (0..STUFF)
            .map(|n| EndEffectorForce {
                name: format!("synth_force_{n}"),
                force: [0.0; 3],
                torque: [0.0; 3],
                grasp_force: None,
            })
            .collect();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: synth_joints.clone(),
                    delta_time,
                    end_effector_positions: synth_ees.clone(),
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: synth_forces.clone(),
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-05: Minimum valid command.
    ///
    /// Single joint state (first profile joint, mid-range), zero
    /// EE positions, zero forces, no sensor readings, no
    /// `EnvironmentState`. Tests that the validator does not
    /// require optional fields to be populated.
    fn minimum_valid_command(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "minimum_valid_command".to_owned();
        let one_joint: Vec<JointState> = self
            .profile
            .joints
            .first()
            .map(|j| {
                vec![JointState {
                    name: j.name.clone(),
                    position: Self::joint_mid(j.min, j.max),
                    velocity: 0.0,
                    effort: 0.0,
                }]
            })
            .unwrap_or_default();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: one_joint.clone(),
                    delta_time,
                    end_effector_positions: vec![],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-03: NaN injection → authority bypass.
    ///
    /// First joint position = NaN AND `pca_chain` empty. Whichever
    /// check the validator runs first must still fail-closed, and
    /// removing either failure mode must surface a regression.
    fn nan_authority_bypass(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        // Empty PCA chain — the "authority bypass" half of the
        // compound attack.
        let authority = Self::authority("", ops);
        let source = "nan_authority_bypass".to_owned();

        let baseline = self.baseline_joint_states();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut joint_states = baseline.clone();
                if let Some(first) = joint_states.first_mut() {
                    first.position = f64::NAN;
                }
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-06: Profile probing → targeted attack.
    ///
    /// First half: probe phase — each joint sweeps from `0.5 × max`
    /// up to `0.99 × max` (linear), all PASS. Second half: targeted
    /// attack — every joint sits at `max + ε` with
    /// `ε = max(1e-6 × range, 1e-9)`, REJECT P1. Models the
    /// adversary that learns limits then pushes past them by the
    /// smallest detectable margin.
    fn profile_probing_targeted(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "profile_probing_targeted".to_owned();
        let half = count / 2;
        let count_f = half.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| {
                        let range = j.max - j.min;
                        let position = if i < half {
                            // Probe phase: 0.5 × max → 0.99 × max linear sweep.
                            let t = i as f64 / count_f;
                            j.max * (0.5 + 0.49 * t)
                        } else {
                            // Targeted attack: max + ε, smallest detectable margin.
                            let eps = (range * 1e-6).max(1e-9);
                            j.max + eps
                        };
                        JointState {
                            name: j.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-08: Multi-robot coordination attack.
    ///
    /// Even-index commands come from `"robot_a"` (baseline-safe,
    /// PASS); odd-index commands come from `"robot_b"` (first
    /// joint at `2 × max`, REJECT P1). Each source maintains its
    /// own monotonic `sequence` so per-source state checks are
    /// not the failure mode. Distinct from `MultiAgentHandoff`
    /// (sequence disorder): J-08 keeps both streams monotonic
    /// but `robot_b` consistently violates physics.
    fn multi_robot_distraction(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        // Pre-compute the "invalid" variant once: first joint at 2 × max.
        let invalid = self.profile.joints.first().map(|j| {
            let mut js = baseline.clone();
            if let Some(first) = js.first_mut() {
                first.position = j.max * 2.0;
            }
            js
        });

        let mut seq_a: u64 = 1;
        let mut seq_b: u64 = 1;
        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let (source, joint_states, seq) = if i.is_multiple_of(2) {
                    let s = seq_a;
                    seq_a += 1;
                    ("robot_a".to_owned(), baseline.clone(), s)
                } else {
                    let s = seq_b;
                    seq_b += 1;
                    (
                        "robot_b".to_owned(),
                        invalid.clone().unwrap_or_else(|| baseline.clone()),
                        s,
                    )
                };
                Command {
                    timestamp,
                    source,
                    sequence: seq,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// K-02: Watchdog recovery cycle.
    ///
    /// First third: normal `delta_time = 0.5 × max_delta_time`
    /// (PASS). Middle third: `delta_time = 5 × max_delta_time`
    /// (heartbeat missed, REJECT P8 upper bound). Final third:
    /// normal `delta_time` again (heartbeat resumed, PASS).
    /// Validates the watchdog latch engages and releases cleanly.
    fn watchdog_recovery_cycle(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let normal_dt = self.profile.max_delta_time * 0.5;
        let missed_dt = self.profile.max_delta_time * 5.0;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "watchdog_recovery_cycle".to_owned();
        let third = count / 3;
        let two_thirds = third * 2;

        (0..count)
            .map(|i| {
                let delta_time = if i >= third && i < two_thirds {
                    missed_dt
                } else {
                    normal_dt
                };
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * normal_dt * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-02: Distraction flooding.
    ///
    /// Nine baseline-safe commands then one violation (first
    /// joint at `2 × max`), repeating. The spec calls for a
    /// 999:1 ratio but a 9:1 cycle ensures even short test runs
    /// include the attack phase.
    fn distraction_flooding(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline = self.baseline_joint_states();
        let invalid = self.profile.joints.first().map(|j| {
            let mut js = baseline.clone();
            if let Some(first) = js.first_mut() {
                first.position = j.max * 2.0;
            }
            js
        });
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "distraction_flooding".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // 9 valid + 1 invalid per cycle of 10.
                let joint_states = if i % 10 == 9 {
                    invalid.clone().unwrap_or_else(|| baseline.clone())
                } else {
                    baseline.clone()
                };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-05: Error mining.
    ///
    /// Each command cycles through four physics violation modes
    /// by `index % 4`: P1 (position), P2 (velocity), P3 (effort),
    /// P5 (workspace AABB escape). Every command should REJECT
    /// but on a different check — the adversary observes which
    /// fields appear in the rejection reason to map the
    /// validator's internal structure.
    fn error_mining(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "error_mining".to_owned();
        let first_joint = self.profile.joints.first();
        let (max_pos, max_vel, max_torque) = first_joint
            .map(|j| (j.max, j.max_velocity, j.max_torque))
            .unwrap_or((1.0, 1.0, 1.0));
        let outside_ws = match &self.profile.workspace {
            WorkspaceBounds::Aabb { max, .. } => [max[0] + 1.0, max[1] + 1.0, max[2] + 1.0],
        };

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut joint_states = baseline.clone();
                let mut ee = ee_pos;
                match i % 4 {
                    0 => {
                        if let Some(first) = joint_states.first_mut() {
                            first.position = max_pos * 2.0;
                        }
                    }
                    1 => {
                        if let Some(first) = joint_states.first_mut() {
                            first.velocity = max_vel * 2.0;
                        }
                    }
                    2 => {
                        if let Some(first) = joint_states.first_mut() {
                            first.effort = max_torque * 2.0;
                        }
                    }
                    _ => {
                        ee = outside_ws;
                    }
                }
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-01: Cognitive gradual drift escape.
    ///
    /// First joint starts at midpoint and drifts toward `max` by
    /// `0.0001 rad` per step. Most commands stay within bounds (PASS);
    /// once the cumulative drift carries the position past `max`,
    /// remaining commands REJECT under P1. The 0.0001 rad/step delta is
    /// from the spec (§3 row I-01) and is deliberately small enough that
    /// any per-step jitter detector tuned to typical motion noise would
    /// miss it.
    ///
    /// Distinct from `JointGradualDrift` (B-08) which starts already over
    /// the limit (pure reject). I-01 is the cognitive-escape pattern: a
    /// mostly-legitimate trajectory that ends out of bounds.
    fn gradual_drift_escape(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "gradual_drift_escape".to_owned();
        let drift_per_step = 0.0001_f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let position = if j == 0 {
                            let mid = Self::joint_mid(jdef.min, jdef.max);
                            mid + drift_per_step * (i as f64)
                        } else {
                            Self::joint_mid(jdef.min, jdef.max)
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-03: Semantic confusion.
    ///
    /// Within each command the joint-name slots are rotated by `index %
    /// njoints`: slot `j` reports the position from profile joint
    /// `(j + rotate) % n` but carries the *name* of profile joint `j`
    /// shifted by `rotate`. The first command (rotate = 0) is the
    /// baseline name/position alignment; subsequent commands swap
    /// names. The validator must REJECT once names no longer pair with
    /// the expected joint identity rather than silently accept the
    /// command on positional order alone.
    ///
    /// Profiles with fewer than two joints fall back to baseline output —
    /// the swap is undefined with a single joint.
    fn semantic_confusion(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "semantic_confusion".to_owned();
        let n = self.profile.joints.len();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                // Skip rotate=0 (identity) so every command actually swaps
                // names. For profiles with n=1 there is nothing to swap and
                // the scenario degenerates to baseline output.
                let rotate = if n > 1 { (i % (n - 1)) + 1 } else { 0 };
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let src = &self.profile.joints[(j + rotate) % n.max(1)];
                        JointState {
                            name: jdef.name.clone(),
                            position: Self::joint_mid(src.min, src.max),
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// J-04: Watchdog timeout → replay attack.
    ///
    /// First third of the sequence carries `delta_time = 5 ×
    /// profile.max_delta_time` (REJECT P8 upper bound). The remaining
    /// two thirds replay the *first* command's `sequence` value — every
    /// such command shares one sequence number so a stateful per-source
    /// monotonicity tracker rejects them. Joint state stays
    /// baseline-safe so the failure modes are isolated to P8 (phase 1)
    /// and per-source sequence monotonicity (phase 2). Source tag is
    /// `"watchdog_timeout_replay"` so the per-source counter sees a
    /// fresh stream.
    fn watchdog_timeout_replay(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let normal_delta_time = self.profile.max_delta_time * 0.5;
        let missed_heartbeat_dt = self.profile.max_delta_time * 5.0;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "watchdog_timeout_replay".to_owned();
        let phase_boundary = count / 3;
        let replay_sequence: u64 = 1;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * normal_delta_time * 1_000.0,
                    ));
                let (delta_time, sequence) = if i < phase_boundary {
                    (missed_heartbeat_dt, i as u64 + 1)
                } else {
                    (normal_delta_time, replay_sequence)
                };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-09: Timing exploitation.
    ///
    /// Tight `delta_time` (1 ms or `min(max_delta_time, 0.001)`),
    /// alternating baseline-safe (PASS) with a first-joint violation
    /// at `2 × max` (REJECT P1). The high cadence models the 1 kHz
    /// TOCTOU race the spec calls out — any validator that updates
    /// state out of order with verdict emission would let an odd-
    /// index reject leak through. Mixed pattern (50/50).
    fn timing_exploitation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time.clamp(1e-4, 0.001);
        let baseline = self.baseline_joint_states();
        let invalid = self.profile.joints.first().map(|j| {
            let mut js = baseline.clone();
            if let Some(first) = js.first_mut() {
                first.position = j.max * 2.0;
            }
            js
        });
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "timing_exploitation".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let joint_states = if i.is_multiple_of(2) {
                    baseline.clone()
                } else {
                    invalid.clone().unwrap_or_else(|| baseline.clone())
                };

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-01: Rate-stress sustained throughput.
    ///
    /// Baseline-safe commands at a fixed 1 ms `delta_time` (1 kHz),
    /// stamped with `rate_stress = "true"` metadata. Every command
    /// should PASS; the scenario exists so downstream harnesses can
    /// drive a sustained-throughput latency measurement without
    /// per-scenario configuration. Per the spec row M-01: "1000
    /// commands/sec sustained for 60s".
    fn rate_stress_sustained(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time.clamp(1e-4, 0.001);
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "rate_stress_sustained".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("rate_stress".to_owned(), "true".to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-05: ISO 15066 human-proximity force.
    ///
    /// Places the EE at the centre of the first declared `proximity_zone`
    /// (falling back to the workspace centre if the profile declares
    /// none) and applies a `200 N` force on the +x axis. Per spec row
    /// E-05 the validator must REJECT above the ISO 15066 face limit
    /// (`65 N`); profiles whose `max_force_n` is below 200 N also REJECT
    /// under generic P11 regardless of proximity. Carries
    /// `iso_15066 = "true"` metadata so a proximity-aware harness can
    /// credit the scenario distinctly from E-01.
    fn iso_15066_human_proximity_force(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "iso_15066_human_proximity_force".to_owned();
        let zone_centre = self
            .profile
            .proximity_zones
            .first()
            .map(|z| match z {
                ProximityZone::Sphere { center, .. } => *center,
                _ => Self::safe_end_effector(self.profile),
            })
            .unwrap_or_else(|| Self::safe_end_effector(self.profile));
        let ee_name = self
            .profile
            .end_effectors
            .first()
            .map(|e| e.name.clone())
            .unwrap_or_else(|| "end_effector".to_owned());

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("iso_15066".to_owned(), "true".to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: ee_name.clone(),
                        position: zone_centre,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![EndEffectorForce {
                        name: ee_name.clone(),
                        force: [200.0, 0.0, 0.0],
                        torque: [0.0, 0.0, 0.0],
                        grasp_force: None,
                    }],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-06: Bimanual coordination — combined-weight overload.
    ///
    /// Emits two synthetic end-effector forces (`bimanual_left` /
    /// `bimanual_right`) each at `0.6 × max_force_n` on +x, so per-arm
    /// individually below the limit but combined `1.2 × max_force_n`
    /// — bimanual coordination overload. Single-arm profiles see a
    /// name-mismatch reject (M-04-style) on the synthetic arms;
    /// bimanual humanoid profiles see the genuine combined-force
    /// failure mode. Carries `bimanual = "true"` metadata.
    fn bimanual_coordination(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "bimanual_coordination".to_owned();
        let max_force = self
            .profile
            .end_effectors
            .first()
            .map(|e| e.max_force_n)
            .unwrap_or(100.0);
        let per_arm = 0.6 * max_force;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("bimanual".to_owned(), "true".to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![
                        EndEffectorForce {
                            name: "bimanual_left".to_owned(),
                            force: [per_arm, 0.0, 0.0],
                            torque: [0.0, 0.0, 0.0],
                            grasp_force: None,
                        },
                        EndEffectorForce {
                            name: "bimanual_right".to_owned(),
                            force: [per_arm, 0.0, 0.0],
                            torque: [0.0, 0.0, 0.0],
                            grasp_force: None,
                        },
                    ],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-06: Mixed profiles in a single audit log.
    ///
    /// Baseline-safe physics; `source` cycles through three logical
    /// robots (`robot_alpha` / `robot_beta` / `robot_gamma`) by `index
    /// % 3`. Each source keeps its own monotonic sequence (`i / 3 +
    /// 1`) so a per-source counter sees a clean stream per robot while
    /// the merged audit log interleaves all three. Pure-PASS; exists
    /// to exercise log-rotation and Merkle continuity across mixed
    /// sources.
    fn mixed_profiles_audit(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let sources = ["robot_alpha", "robot_beta", "robot_gamma"];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let source_idx = i % sources.len();
                let source = sources[source_idx].to_owned();
                // Per-source monotonic sequence: count the prior commands
                // sharing this source slot.
                let per_source_seq = (i / sources.len()) as u64 + 1;

                Command {
                    timestamp,
                    source,
                    sequence: per_source_seq,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-07: Profile probing — binary search on every limit.
    ///
    /// First joint position binary-searches the `[mid, max]` interval:
    /// step `i` lands at `mid + (1 - 2^{-(i+1)}) × (max - mid)` so the
    /// sequence is `mid, mid + 0.5Δ, mid + 0.75Δ, mid + 0.875Δ, …`,
    /// approaching `max` as `i → ∞` but never reaching it. Every
    /// command is in-band so should PASS; the scenario fingerprints
    /// the binary-search adversary by the geometric step pattern.
    fn profile_probing_binary_search(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "profile_probing_binary_search".to_owned();
        let first = self.profile.joints.first();
        let (mid, delta) = first
            .map(|j| {
                let mid = Self::joint_mid(j.min, j.max);
                (mid, j.max - mid)
            })
            .unwrap_or((0.0, 1.0));

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Fraction of the [mid, max] margin consumed at step i.
                // (1 - 1 / 2^(i+1)) gives 0.5, 0.75, 0.875, …
                let frac = 1.0 - (1.0 / (1u64 << ((i as u32) % 60).min(60)) as f64);
                let probe = mid + frac * delta;
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let position = if j == 0 {
                            probe
                        } else {
                            Self::joint_mid(jdef.min, jdef.max)
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-10: Rollback replay.
    ///
    /// Joint state is baseline-safe; the `sequence` field cycles
    /// `1, 2, 3` (by `index % 3`). Models the adversary replaying
    /// captured signed commands with stale sequence numbers. Source
    /// is stable so per-source counters observe the collision.
    fn rollback_replay(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "rollback_replay".to_owned();
        let recorded: [u64; 3] = [1, 2, 3];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: recorded[i % recorded.len()],
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// K-05: Profile reload during operation.
    ///
    /// Baseline-safe physics with `profile_reload="true"` and
    /// `tighter_limits="true"` metadata stamps plus a per-generation
    /// counter. Generator-level only; the actual hot-reload is the
    /// harness's responsibility. Pure-PASS scenario.
    fn profile_reload_during_operation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "profile_reload_during_operation".to_owned();
        let segments = 3_usize; // three reload generations across the run
        let segment_size = count.div_ceil(segments).max(1);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let generation = (i / segment_size) + 1;
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("profile_reload".to_owned(), "true".to_owned());
                metadata.insert("tighter_limits".to_owned(), "true".to_owned());
                metadata.insert(
                    "reload_generation".to_owned(),
                    generation.to_string(),
                );

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// M-03: Pure-fuzz commands.
    ///
    /// Deterministic LCG over `(index, 0xCAFE_BABE)` drives the first
    /// joint into one of four garbage regimes by `index % 4`: a large
    /// finite value > `max`, a large finite < `min`, NaN, +Infinity.
    /// All command structure is otherwise well-formed so the failure
    /// mode is isolated to the joint value. Every command should
    /// REJECT under P1 (finite-bounds) or the fail-closed spatial
    /// input check.
    fn pure_fuzz(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "pure_fuzz".to_owned();
        let first = self.profile.joints.first();
        let (jmin, jmax) = first.map(|j| (j.min, j.max)).unwrap_or((-1.0, 1.0));

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Deterministic LCG (Numerical Recipes) over (index, seed)
                let mut state: u64 = 0xCAFE_BABE_u64
                    .wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let r = (state >> 33) as f64 / (1u64 << 31) as f64; // [0, 1)
                let bad = match i % 4 {
                    0 => jmax + 10.0 + r * 100.0, // large finite > max
                    1 => jmin - 10.0 - r * 100.0, // large finite < min
                    2 => f64::NAN,
                    _ => f64::INFINITY,
                };
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let position = if j == 0 {
                            bad
                        } else {
                            Self::joint_mid(jdef.min, jdef.max)
                        };
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-04: Authority laundering.
    ///
    /// Cycles `required_ops` through progressively wider scopes by
    /// `index % 4`: `actuate:joint_0`, `actuate:joint_*`,
    /// `actuate:*`, `*`. Every command carries an empty `pca_chain`
    /// (no operator delegation) so authority rejects on every step.
    /// Joint state is baseline-safe to isolate the failure mode.
    fn authority_laundering(&self, count: usize, _ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "authority_laundering".to_owned();
        // Pre-build the four scope tiers once. `Operation::new` validates
        // each; bare `*` and trailing `:*` are both legal per the grammar.
        let tiers: [Vec<Operation>; 4] = [
            vec![Operation::new("actuate:joint:0").expect("tier 1 op valid")],
            vec![Operation::new("actuate:joint:*").expect("tier 2 op valid")],
            vec![Operation::new("actuate:*").expect("tier 3 op valid")],
            vec![Operation::new("*").expect("tier 4 op valid")],
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let tier_idx = i % tiers.len();
                let required_ops = tiers[tier_idx].clone();
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "scope_breadth".to_owned(),
                    (tier_idx as u64 + 1).to_string(),
                );

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: String::new(),
                        required_ops,
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-06: Watchdog manipulation.
    ///
    /// Three phases: missed heartbeats → authority dropped →
    /// heartbeat + fresh authority re-establishment. Joint state
    /// stays baseline-safe across all three. Phase boundaries are
    /// stamped into `metadata["phase"]` as `A`, `B`, or `C`.
    fn watchdog_manipulation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let normal_dt = self.profile.max_delta_time * 0.5;
        let missed_dt = self.profile.max_delta_time * 5.0;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "watchdog_manipulation".to_owned();
        let third = (count / 3).max(1);
        let two_thirds = (third * 2).min(count);

        (0..count)
            .map(|i| {
                let (delta_time, pca_chain, phase) = if i < third {
                    // Phase A: heartbeats missed, authority still present.
                    (missed_dt, pca_chain_b64.to_owned(), "A")
                } else if i < two_thirds {
                    // Phase B: still missed heartbeats, authority dropped.
                    (missed_dt, String::new(), "B")
                } else {
                    // Phase C: heartbeats resumed, authority re-established.
                    (normal_dt, pca_chain_b64.to_owned(), "C")
                };
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * normal_dt * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("phase".to_owned(), phase.to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain,
                        required_ops: ops.to_vec(),
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// I-08: Multi-agent collusion.
    ///
    /// Two cognitive agents alternate by parity. Each carries a
    /// narrow scope individually; the combined set across the two
    /// sources spans a wider scope than either agent could claim
    /// alone. Both carry an empty `pca_chain` so authority rejects.
    /// Per-source `sequence` is strictly monotonic so the failure
    /// mode isolates authority, not order.
    fn multi_agent_collusion(&self, count: usize) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let agent_a_ops =
            vec![Operation::new("actuate:joint_0").expect("agent a op valid")];
        let agent_b_ops =
            vec![Operation::new("sensor.read:imu").expect("agent b op valid")];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let is_a = i % 2 == 0;
                let source = if is_a {
                    "cognitive_agent_a".to_owned()
                } else {
                    "cognitive_agent_b".to_owned()
                };
                // Per-source monotonic sequence: index within this agent's stream.
                let per_source_seq = (i / 2) as u64 + 1;
                let required_ops = if is_a {
                    agent_a_ops.clone()
                } else {
                    agent_b_ops.clone()
                };
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "colluding_agent".to_owned(),
                    if is_a { "a" } else { "b" }.to_owned(),
                );
                metadata.insert("coordinated_attack".to_owned(), "true".to_owned());

                Command {
                    timestamp,
                    source,
                    sequence: per_source_seq,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: String::new(),
                        required_ops,
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// K-06: Validator restart.
    ///
    /// First half uses source `"pre_restart"` with per-source
    /// `sequence = i + 1`; the boundary command stamps
    /// `restart_event="true"`; second half switches to source
    /// `"post_restart"` and resets `sequence` to start at 1.
    /// Baseline-safe physics throughout; a properly reset validator
    /// admits every command (pure-PASS).
    fn validator_restart(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let half = (count / 2).max(1);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let (source, sequence) = if i < half {
                    ("pre_restart".to_owned(), i as u64 + 1)
                } else {
                    ("post_restart".to_owned(), (i - half) as u64 + 1)
                };
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                if i == half {
                    metadata.insert("restart_event".to_owned(), "true".to_owned());
                }

                Command {
                    timestamp,
                    source,
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-01: Valid authority chain — happy path baseline.
    ///
    /// Pass-through `pca_chain_b64`; baseline-safe physics; metadata
    /// stamps `chain_class="valid"`. Pure-PASS at the generator level.
    fn valid_authority_chain(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "valid_authority_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("chain_class".to_owned(), "valid".to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-03: Forged signature.
    ///
    /// Each command tampers the harness's `pca_chain_b64` with a
    /// per-index suffix mutation (`"_SIG_FLIP_<i>"` + base64 padding).
    /// Falls back to a `"FORGED_SIG_<i>"` sentinel when the input is
    /// empty.
    fn forged_signature(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "forged_signature_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Deterministic per-command tampered envelope. Stays in
                // the base64 alphabet so the validator's parse path
                // exercises the *signature* check, not the decoder.
                let tampered = if pca_chain_b64.is_empty() {
                    format!("FORGEDSIG{i:08}AAAAAAAAAAAAAAAA==")
                } else {
                    format!("{pca_chain_b64}SIGFLIP{i:08}==")
                };
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "forged_signature".to_owned(),
                );

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: tampered,
                        required_ops: ops.to_vec(),
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-05: Privilege escalation.
    ///
    /// Pass-through `pca_chain_b64` (presumed structurally valid)
    /// paired with progressively widening `required_ops`: command `i`
    /// claims `(i % 4) + 1` operations drawn from the four-tier
    /// scope ladder (narrowest → widest). The validator's
    /// scope-mismatch check must reject any command whose claimed
    /// ops exceed what the chain authorises.
    fn privilege_escalation(&self, count: usize, pca_chain_b64: &str) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "privilege_escalation_agent".to_owned();
        // Same four-tier ladder as I-04 AuthorityLaundering.
        let tier_ladder: [Operation; 4] = [
            Operation::new("actuate:joint:0").expect("tier 1 op valid"),
            Operation::new("actuate:joint:*").expect("tier 2 op valid"),
            Operation::new("actuate:*").expect("tier 3 op valid"),
            Operation::new("*").expect("tier 4 op valid"),
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let breadth = (i % tier_ladder.len()) + 1;
                let required_ops: Vec<Operation> =
                    tier_ladder.iter().take(breadth).cloned().collect();
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "privilege_escalation".to_owned(),
                );
                metadata.insert("escalation_index".to_owned(), i.to_string());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: pca_chain_b64.to_owned(),
                        required_ops,
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-08: Expired authority chain.
    ///
    /// Pass-through `pca_chain_b64`; every command's `timestamp` is
    /// 1 year before the generation epoch so the validator's
    /// temporal-window check (A3) rejects.
    fn expired_chain(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        const ONE_YEAR_SECONDS: i64 = 365 * 24 * 3600;
        let now: DateTime<Utc> = Utc::now();
        let base_ts = now - Duration::seconds(ONE_YEAR_SECONDS);
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "expired_chain_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("chain_class".to_owned(), "expired".to_owned());
                metadata.insert(
                    "seconds_in_past".to_owned(),
                    ONE_YEAR_SECONDS.to_string(),
                );

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-04: Key substitution.
    ///
    /// Each command synthesises a deterministic per-index PCA envelope
    /// whose decoded JSON declares an untrusted signer key id
    /// (`kid="untrusted_kid_<i>"`) and a 64-byte zero signature. The
    /// validator's trusted-key-set lookup (or, failing that, the
    /// Ed25519 verify) rejects every command. The harness-supplied
    /// `pca_chain_b64` is deliberately *not* used — this scenario
    /// stands in for a chain signed with an entirely different key.
    fn key_substitution(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "key_substitution_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let kid = format!("untrusted_kid_{i:08}");
                // Synthetic SignedPca-shaped JSON: one hop, untrusted
                // kid, deterministic 64-byte zero signature (base64).
                // The validator will refuse the kid lookup; if it
                // somehow trusts the kid, the signature verify will
                // refuse the zero signature.
                let envelope_json = format!(
                    "[{{\"kid\":\"{kid}\",\"signature\":\"\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                     \",\"payload\":\"key_substitution_{i}\"}}]"
                );
                let pca = STANDARD.encode(envelope_json.as_bytes());
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "key_substitution".to_owned(),
                );
                metadata.insert("untrusted_kid".to_owned(), kid);

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: pca,
                        required_ops: ops.to_vec(),
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-06: Provenance mutation.
    ///
    /// Emits a synthetic two-hop chain whose hop 0 declares
    /// `principal_0="agent_alpha"` but hop 1's `principal_0=
    /// "agent_beta_<i>"` — violating A1 (origin-principal continuity).
    /// The validator must reject every command.
    fn provenance_mutation(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "provenance_mutation_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mutated_p0 = format!("agent_beta_{i:08}");
                // Two-hop synthetic chain: hop 0 names "agent_alpha"
                // as p_0; hop 1 mutates p_0 to "agent_beta_<i>".
                let envelope_json = format!(
                    "[\
                     {{\"kid\":\"hop0_kid\",\"principal_0\":\"agent_alpha\",\
                     \"signature\":\"AAAA\",\"payload\":\"hop0_{i}\"}},\
                     {{\"kid\":\"hop1_kid\",\"principal_0\":\"{mutated_p0}\",\
                     \"signature\":\"AAAA\",\"payload\":\"hop1_{i}\"}}\
                     ]"
                );
                let pca = STANDARD.encode(envelope_json.as_bytes());
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "provenance_mutation".to_owned(),
                );
                metadata.insert("mutated_p0".to_owned(), mutated_p0);

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: pca,
                        required_ops: ops.to_vec(),
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-07: Wildcard exploitation.
    ///
    /// Pass-through `pca_chain_b64` (presumed to grant `actuate:*`) but
    /// `required_ops` claims a non-actuate op from a four-op rotation —
    /// `actuate:*` does not subsume reads or admin/debug scopes, so
    /// scope-check rejects every command.
    fn wildcard_exploit(&self, count: usize, pca_chain_b64: &str) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "wildcard_exploit_agent".to_owned();
        // Operations that lie OUTSIDE the actuate scope tree, so
        // `actuate:*` in the chain cannot cover them.
        let outside_scope_ops: [&str; 4] = [
            "sensor.read:imu",
            "read:sensor",
            "admin:profile.reload",
            "debug:trace.export",
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let op_str = outside_scope_ops[i % outside_scope_ops.len()];
                let required_ops = vec![Operation::new(op_str).expect("outside-scope op valid")];
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "wildcard_exploit".to_owned(),
                );
                metadata.insert("outside_scope_op".to_owned(), op_str.to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: pca_chain_b64.to_owned(),
                        required_ops,
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-04: Payload overload.
    ///
    /// Linear ramp of `estimated_payload_kg` from 0 to `3 × max_payload_kg`
    /// of the first end-effector. Early commands pass; later commands
    /// exceed P14 and should be rejected. Profiles without any
    /// `end_effectors` entry fall back to a 1.0 kg ceiling so the
    /// generator still produces a sweep — but no real validator would be
    /// constructed against such a profile.
    fn payload_overload(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "payload_overload".to_owned();
        let max_payload = self
            .profile
            .end_effectors
            .first()
            .map(|ee| ee.max_payload_kg)
            .unwrap_or(1.0);
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Ramp 0 → 3.0 across the sequence.
                let ramp = (i as f64 / count_f) * 3.0;
                let payload = max_payload * ramp;

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: Some(payload),
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-01: End-effector force ramp.
    ///
    /// Linear ramp of the EE force-vector magnitude (applied along the +x
    /// axis) from 0 to `3 × max_force_n` of the first end-effector. Early
    /// commands pass; later commands exceed P11 and should be rejected.
    /// Profiles without an `end_effectors` entry fall back to 100 N so the
    /// generator never panics — a real validator wouldn't be built against
    /// such a profile.
    fn force_limit_sweep(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EndEffectorForce;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "force_limit_sweep".to_owned();
        let (max_force, ee_name) = self
            .profile
            .end_effectors
            .first()
            .map(|e| (e.max_force_n, e.name.clone()))
            .unwrap_or_else(|| (100.0, "gripper".to_owned()));
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Ramp 0 → 3.0 across the sequence.
                let ramp = (i as f64 / count_f) * 3.0;
                let force_val = max_force * ramp;

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![EndEffectorForce {
                        name: ee_name.clone(),
                        force: [force_val, 0.0, 0.0],
                        torque: [0.0, 0.0, 0.0],
                        grasp_force: None,
                    }],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-02: Grasp-force envelope.
    ///
    /// Cycles grasp-force through five regimes against the first
    /// end-effector's `[min_grasp_force_n, max_grasp_force_n]` window:
    /// below-min (`0.5 × min`), at-min, mid-band, at-max, above-max
    /// (`1.5 × max`). Below-min and above-max should reject under P12;
    /// the three in-band values are valid grasp forces.
    fn grasp_force_envelope(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EndEffectorForce;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "grasp_force_envelope".to_owned();
        let (min_grasp, max_grasp, ee_name) = self
            .profile
            .end_effectors
            .first()
            .map(|e| (e.min_grasp_force_n, e.max_grasp_force_n, e.name.clone()))
            .unwrap_or_else(|| (1.0, 100.0, "gripper".to_owned()));
        let mid = 0.5 * (min_grasp + max_grasp);
        let regimes: &[f64] = &[
            0.5 * min_grasp,
            min_grasp,
            mid,
            max_grasp,
            1.5 * max_grasp,
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let grasp = regimes[i % regimes.len()];
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![EndEffectorForce {
                        name: ee_name.clone(),
                        force: [0.0, 0.0, 0.0],
                        torque: [0.0, 0.0, 0.0],
                        grasp_force: Some(grasp),
                    }],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// E-03: Force-rate spike.
    ///
    /// Alternates zero force (odd-sequence) and a large spike
    /// (`max_force_rate_n_per_s × delta_time × 3`, even-sequence) so each
    /// even-sequence command's force-rate of change exceeds P13 by ~3×.
    /// Mirrors the `injector::inject_force_rate_spike` policy so a
    /// stateful validator with `previous_forces` storage sees the
    /// violation deterministically from index 1 onwards.
    fn force_rate_spike(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EndEffectorForce;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "force_rate_spike".to_owned();
        let (max_rate, ee_name) = self
            .profile
            .end_effectors
            .first()
            .map(|e| (e.max_force_rate_n_per_s, e.name.clone()))
            .unwrap_or_else(|| (500.0, "gripper".to_owned()));
        let spike = max_rate * delta_time * 3.0;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let sequence = i as u64 + 1;
                let force_val = if sequence.is_multiple_of(2) { spike } else { 0.0 };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![EndEffectorForce {
                        name: ee_name.clone(),
                        force: [force_val, 0.0, 0.0],
                        torque: [0.0, 0.0, 0.0],
                        grasp_force: None,
                    }],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// H-06: Future-dated sensor.
    ///
    /// Every command carries one `SignedSensorReading` whose
    /// `reading.timestamp` is 10 seconds past the command's wall-clock
    /// timestamp. The signature is a placeholder (32 zero bytes,
    /// base64-encoded) and the signer kid is the literal
    /// `"h06-future-stub"` — neither cryptographically valid nor in any
    /// trusted set. Under `SensorTrustPolicy::RequireSigned` /
    /// `PreferSigned` the freshness check rejects the command before
    /// the signature would even be evaluated. Under `AcceptUnsigned`
    /// (the default), this scenario produces no rejection — callers
    /// who want to exercise the rejection path must flip the
    /// validator's policy.
    fn future_dated_sensor(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use base64::Engine as _;
        use invariant_robotics::sensor::{SensorPayload, SensorReading, SignedSensorReading};
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "future_dated_sensor".to_owned();
        // 10 seconds of look-ahead is the spec citation (spec-15m-campaign
        // §3 H-06). A typical sensor max_age window is a few hundred ms,
        // so this is comfortably outside.
        let future_offset = Duration::seconds(10);
        let stub_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let reading = SensorReading {
                    sensor_name: "future_imu".to_owned(),
                    timestamp: timestamp + future_offset,
                    payload: SensorPayload::Position {
                        position: [0.0, 0.0, 0.0],
                    },
                    sequence: i as u64,
                };
                let signed = SignedSensorReading {
                    reading,
                    signature: stub_sig.clone(),
                    signer_kid: "h06-future-stub".to_owned(),
                };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![signed],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// F-01: Actuator-temperature ramp.
    ///
    /// Linearly ramps a common per-joint temperature from 20 °C
    /// (ambient) to `2 × max_operating_temperature_c`. The ramp crosses
    /// `warning_temperature_c` (entering the derate band) and then the
    /// hard limit `max_operating_temperature_c` (REJECT under P22).
    /// Profiles without an `environment` config fall back to the same
    /// defaults the validator uses (warning 65 °C, max 80 °C).
    fn temperature_ramp(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::{ActuatorTemperature, EnvironmentState};
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "temperature_ramp".to_owned();
        let max_temp = self
            .profile
            .environment
            .as_ref()
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        let ambient = 20.0_f64;
        let peak = 2.0 * max_temp;
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let t = ambient + (peak - ambient) * (i as f64 / count_f);
                let temps: Vec<ActuatorTemperature> = self
                    .profile
                    .joints
                    .iter()
                    .map(|j| ActuatorTemperature {
                        joint_name: j.name.clone(),
                        temperature_celsius: t,
                    })
                    .collect();
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: temps,
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }),
                }
            })
            .collect()
    }

    /// F-02: Battery drain.
    ///
    /// `battery_percentage` ramps linearly from 100 % to 0 %. Early
    /// commands sit above `low_battery_pct` (accepted), mid commands
    /// derate (below low, above critical), late commands REJECT below
    /// `critical_battery_pct` (P23).
    fn battery_drain(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "battery_drain".to_owned();
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let pct = 100.0 * (1.0 - (i as f64 / count_f));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: Some(pct),
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }),
                }
            })
            .collect()
    }

    /// F-03: Communication-latency spike.
    ///
    /// Linearly ramps `communication_latency_ms` from 0 to
    /// `5 × max_latency_ms`. Crosses `warning_latency_ms` (derate) and
    /// `max_latency_ms` (REJECT, P24).
    fn latency_spike(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "latency_spike".to_owned();
        let max_latency = self
            .profile
            .environment
            .as_ref()
            .map(|e| e.max_latency_ms)
            .unwrap_or(100.0);
        let peak = 5.0 * max_latency;
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let latency = peak * (i as f64 / count_f);
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: Some(latency),
                        e_stop_engaged: None,
                    }),
                }
            })
            .collect()
    }

    /// F-04: E-stop engage/release cycle.
    ///
    /// Alternates `e_stop_engaged = true` (odd sequence — REJECT under
    /// P25) and `e_stop_engaged = false` (even sequence — accepted).
    /// Validates that the latch transitions correctly rather than a
    /// steady-state engaged state.
    fn estop_engage_release(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "estop_engage_release".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let engaged = !i.is_multiple_of(2);
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: None,
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: Some(engaged),
                    }),
                }
            })
            .collect()
    }

    /// F-05: Sensor range plausibility (SR1).
    ///
    /// Cycles through three implausible env-side sensor values, one per
    /// command (by `index % 3`): IMU pitch = 2π rad, actuator temperature
    /// = -300 °C, battery percentage = 500 %. All three are finite values
    /// outside the SR1 plausible window and should be rejected by
    /// `check_sensor_range_env` (`SR1.sensor-range-env`). Joint state
    /// stays baseline-safe so the failure mode is unambiguously SR1.
    fn sensor_range_implausible(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::{ActuatorTemperature, EnvironmentState};
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "sensor_range_implausible".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut env = EnvironmentState {
                    imu_pitch_rad: None,
                    imu_roll_rad: None,
                    actuator_temperatures: vec![],
                    battery_percentage: None,
                    communication_latency_ms: None,
                    e_stop_engaged: None,
                };
                match i % 3 {
                    0 => {
                        // Mode A: IMU pitch outside ±π plausible window.
                        env.imu_pitch_rad = Some(2.0 * std::f64::consts::PI);
                    }
                    1 => {
                        // Mode B: temperature below absolute zero on every joint.
                        env.actuator_temperatures = self
                            .profile
                            .joints
                            .iter()
                            .map(|j| ActuatorTemperature {
                                joint_name: j.name.clone(),
                                temperature_celsius: -300.0,
                            })
                            .collect();
                    }
                    _ => {
                        // Mode C: battery percentage outside [0, 100].
                        env.battery_percentage = Some(500.0);
                    }
                }
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(env),
                }
            })
            .collect()
    }

    /// F-06: Sensor payload range (SR2).
    ///
    /// Cycles through three implausible payload-side sensor values, one
    /// per command (by `index % 3`): a single joint position at `5π` rad
    /// (> 4π SR2 max), an EE position with one axis at 2000 m (> 1000 m
    /// SR2 max), and an EE force vector with magnitude 200 kN (> 100 kN
    /// SR2 max). All three are finite values outside the SR2 plausible
    /// window and should be rejected by `check_sensor_range_payload`
    /// (`SR2.sensor-range-payload`).
    fn sensor_payload_range(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EndEffectorForce;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline_joints = self.baseline_joint_states();
        let safe_ee = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "sensor_payload_range".to_owned();
        let over_joint = 5.0 * std::f64::consts::PI; // > 4π
        let over_ee_m = 2_000.0_f64; // > 1000 m
        let over_force_n = 200_000.0_f64; // > 100 kN

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut joint_states = baseline_joints.clone();
                let mut ee_pos = safe_ee;
                let mut forces: Vec<EndEffectorForce> = vec![];
                match i % 3 {
                    0 => {
                        // Mode A: implausibly large joint position.
                        if let Some(js) = joint_states.first_mut() {
                            js.position = over_joint;
                        }
                    }
                    1 => {
                        // Mode B: implausibly large EE position axis.
                        ee_pos[0] = over_ee_m;
                    }
                    _ => {
                        // Mode C: implausibly large EE force magnitude.
                        forces.push(EndEffectorForce {
                            name: "end_effector".to_owned(),
                            force: [over_force_n, 0.0, 0.0],
                            torque: [0.0, 0.0, 0.0],
                            grasp_force: None,
                        });
                    }
                }
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: forces,
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// F-07: Sensor-fusion inconsistency.
    ///
    /// Every command carries two `SignedSensorReading`s with the same
    /// `sensor_name` ("fusion_pos") but `Position` payloads that diverge
    /// by 10 m on the x-axis — well past any reasonable
    /// `max_position_divergence_m` tolerance the fusion check is
    /// configured with. Stub signatures (`signer_kid =
    /// "f07-fusion-stub"`) keep the generator self-contained; the failure
    /// is exercised by `check_sensor_fusion`, which compares payloads
    /// after signature verification in the production pipeline.
    fn sensor_fusion_inconsistency(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use base64::Engine as _;
        use invariant_robotics::sensor::{SensorPayload, SensorReading, SignedSensorReading};
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "sensor_fusion_inconsistency".to_owned();
        let stub_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let signer = "f07-fusion-stub".to_owned();
        let divergence_m = 10.0_f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let reading_a = SensorReading {
                    sensor_name: "fusion_pos".to_owned(),
                    timestamp,
                    payload: SensorPayload::Position {
                        position: [0.0, 0.0, 0.0],
                    },
                    sequence: 2 * i as u64,
                };
                let reading_b = SensorReading {
                    sensor_name: "fusion_pos".to_owned(),
                    timestamp,
                    payload: SensorPayload::Position {
                        position: [divergence_m, 0.0, 0.0],
                    },
                    sequence: 2 * i as u64 + 1,
                };
                let signed_a = SignedSensorReading {
                    reading: reading_a,
                    signature: stub_sig.clone(),
                    signer_kid: signer.clone(),
                };
                let signed_b = SignedSensorReading {
                    reading: reading_b,
                    signature: stub_sig.clone(),
                    signer_kid: signer.clone(),
                };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![signed_a, signed_b],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// D-01: COM stability sweep.
    ///
    /// Cycles the centre-of-mass through four positions relative to the
    /// profile's support polygon (by `index % 4`): polygon centroid
    /// (PASS), first vertex (boundary — PASS by inclusion), midpoint
    /// between vertices 0 and 1 (interior — PASS), and a point
    /// translated 10 m beyond the centroid along +x (well outside the
    /// polygon — REJECT P9). Profiles without a stability config fall
    /// back to a symmetric unit square at z = 1 m so the generator
    /// remains exercisable for unit testing on any profile.
    fn com_stability_sweep(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "com_stability_sweep".to_owned();
        // Fall back to a unit square if the profile lacks a stability config —
        // the failure mode (centroid vs. far-outside) is what we exercise.
        let (polygon, com_z) = match self.profile.stability.as_ref() {
            Some(s) if s.enabled && s.support_polygon.len() >= 3 => {
                (s.support_polygon.clone(), s.com_height_estimate)
            }
            _ => (
                vec![[-0.25, -0.25], [0.25, -0.25], [0.25, 0.25], [-0.25, 0.25]],
                1.0,
            ),
        };
        let n = polygon.len() as f64;
        let cx = polygon.iter().map(|v| v[0]).sum::<f64>() / n;
        let cy = polygon.iter().map(|v| v[1]).sum::<f64>() / n;
        let v0 = polygon[0];
        let v1 = polygon[1];
        let mid01 = [(v0[0] + v1[0]) * 0.5, (v0[1] + v1[1]) * 0.5];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let com = match i % 4 {
                    0 => [cx, cy, com_z],
                    1 => [v0[0], v0[1], com_z],
                    2 => [mid01[0], mid01[1], com_z],
                    _ => [cx + 10.0, cy, com_z],
                };
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Some(com),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// D-02: Walking gait validation.
    ///
    /// Full gait cycle where every locomotion field sits at 50–75 % of
    /// the profile maxima. The swing foot alternates left/right by
    /// index so the contact pattern flips each step. Joint state and
    /// COM stay baseline-safe. Every command should PASS — this
    /// exercises the legitimate gait path that P15/P16/P19/P20 must
    /// NOT reject.
    fn walking_gait_validation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "walking_gait_validation".to_owned();
        let loco = self.profile.locomotion.as_ref();
        let max_vel = loco.map(|l| l.max_locomotion_velocity).unwrap_or(1.5);
        let max_step = loco.map(|l| l.max_step_length).unwrap_or(0.4);
        let max_height = loco.map(|l| l.max_step_height).unwrap_or(0.5);
        let max_heading = loco.map(|l| l.max_heading_rate).unwrap_or(1.0);
        let min_clear = loco.map(|l| l.min_foot_clearance).unwrap_or(0.02);
        let swing_h = ((min_clear + max_height) * 0.5).max(min_clear * 1.5);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let mut loco_state = Self::baseline_locomotion_state();
                loco_state.base_velocity = [max_vel * 0.5, 0.0, 0.0];
                loco_state.heading_rate = max_heading * 0.25;
                loco_state.step_length = max_step * 0.6;
                // Alternate swing foot by index parity.
                let (stance_idx, swing_idx) = if i.is_multiple_of(2) { (0, 1) } else { (1, 0) };
                loco_state.feet[stance_idx].contact = true;
                loco_state.feet[stance_idx].position[2] = 0.0;
                loco_state.feet[stance_idx].ground_reaction_force = Some([0.0, 0.0, 400.0]);
                loco_state.feet[swing_idx].contact = false;
                loco_state.feet[swing_idx].position[2] = swing_h;
                loco_state.feet[swing_idx].ground_reaction_force = None;
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco_state),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// D-07: Step overextension.
    ///
    /// Ramps `step_length` linearly from `0.5 × max_step_length` to
    /// `3 × max_step_length`. Crosses `max_step_length` (REJECT P19);
    /// early commands PASS, later commands REJECT.
    fn step_overextension(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "step_overextension".to_owned();
        let max_step = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.6);
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let t = i as f64 / count_f;
                // Linear ramp from 0.5× max to 3× max.
                let step = max_step * (0.5 + 2.5 * t);
                let mut loco_state = Self::baseline_locomotion_state();
                loco_state.step_length = step;
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco_state),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// D-08: Heading spinout.
    ///
    /// Ramps `heading_rate` linearly from 0 to `5 × max_heading_rate`.
    /// Crosses `max_heading_rate` (REJECT P20).
    fn heading_spinout(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "heading_spinout".to_owned();
        let max_heading = self
            .profile
            .locomotion
            .as_ref()
            .map(|l| l.max_heading_rate)
            .unwrap_or(1.0);
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let t = i as f64 / count_f;
                let rate = max_heading * 5.0 * t;
                let mut loco_state = Self::baseline_locomotion_state();
                loco_state.heading_rate = rate;
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco_state),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// D-10: Incline walking.
    ///
    /// Ramps `imu_pitch_rad` linearly from 0 to 30° (≈ 0.5236 rad),
    /// crossing the profile's `warning_pitch_rad` (derate band) and
    /// `max_safe_pitch_rad` (REJECT, P21). Joint and locomotion state
    /// stay baseline-safe.
    fn incline_walking(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        use invariant_robotics::models::command::EnvironmentState;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "incline_walking".to_owned();
        let peak_rad: f64 = 30.0_f64.to_radians();
        let count_f = count.max(1) as f64;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let pitch = peak_rad * (i as f64 / count_f);
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: Some(EnvironmentState {
                        imu_pitch_rad: Some(pitch),
                        imu_roll_rad: None,
                        actuator_temperatures: vec![],
                        battery_percentage: None,
                        communication_latency_ms: None,
                        e_stop_engaged: None,
                    }),
                }
            })
            .collect()
    }

    /// H-05: Stale command.
    ///
    /// Every command carries `delta_time = profile.max_delta_time × 2` — a
    /// finite, positive, but over-limit value. All should be rejected by P8
    /// (upper bound). Companion to [`Self::delta_time_attack`] which
    /// targets the non-finite / non-positive cases.
    fn stale_command(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "stale_command".to_owned();
        let stale_dt = self.profile.max_delta_time * 2.0;
        let stamp_dt = self.profile.max_delta_time * 0.5;

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * stamp_dt * 1_000.0,
                    ));
                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time: stale_dt,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Category N (v11 2.11) — red-team fuzz scenarios
    // -----------------------------------------------------------------------

    /// Deterministic LCG step used by every N-* generator that needs
    /// uniform-ish per-index entropy. Seed `0xFA251234` is fixed so the
    /// generated trace is reproducible bytewise from `(index, seed)`.
    fn redteam_lcg(seed: u64, i: usize) -> f64 {
        let mut state: u64 = seed.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as f64 / (1u64 << 31) as f64 // [0, 1)
    }

    /// N-01: Generation-based red-team fuzz.
    fn redteam_fuzz_generation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        const SEED: u64 = 0xFA25_1234;
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "redteam_fuzz_gen".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let joint_states: Vec<JointState> = self
                    .profile
                    .joints
                    .iter()
                    .enumerate()
                    .map(|(j, jdef)| {
                        let range = jdef.max - jdef.min;
                        // Sample uniformly from [min - range, max + range]
                        // → ~50% PASS (inside [min, max]) and ~50% REJECT.
                        let r = Self::redteam_lcg(SEED ^ (j as u64), i);
                        let position = jdef.min - range + r * (3.0 * range);
                        JointState {
                            name: jdef.name.clone(),
                            position,
                            velocity: 0.0,
                            effort: 0.0,
                        }
                    })
                    .collect();
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("redteam_class".to_owned(), "generation".to_owned());
                metadata.insert("seed".to_owned(), format!("{:#x}", SEED));

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// N-02: Mutation-based red-team fuzz.
    fn redteam_fuzz_mutation(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let base_delta = self.profile.max_delta_time * 0.5;
        let baseline_joints = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "redteam_fuzz_mut".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * base_delta * 1_000.0,
                    ));
                let mut joint_states = baseline_joints.clone();
                let mut delta_time = base_delta;
                let mut sequence = i as u64 + 1;
                let mut ee_x_sign = 1.0_f64;
                let mutation_kind = match i % 5 {
                    0 => {
                        // bit-flip on first joint's position
                        if let Some(j0) = joint_states.first_mut() {
                            let bits = j0.position.to_bits();
                            let flip = 1u64 << ((i % 32) as u64);
                            j0.position = f64::from_bits(bits ^ flip);
                        }
                        "bitflip"
                    }
                    1 => {
                        // swap two joint positions if we have ≥ 2 joints
                        if joint_states.len() >= 2 {
                            let p0 = joint_states[0].position;
                            joint_states[0].position = joint_states[1].position;
                            joint_states[1].position = p0;
                        }
                        "swap"
                    }
                    2 => {
                        delta_time = 1e-18;
                        "dt"
                    }
                    3 => {
                        ee_x_sign = -1.0;
                        "ee"
                    }
                    _ => {
                        sequence ^= 0xDEAD_BEEF;
                        "seq"
                    }
                };
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("redteam_class".to_owned(), "mutation".to_owned());
                metadata.insert("mutation_kind".to_owned(), mutation_kind.to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: [ee_x_sign * ee_pos[0], ee_pos[1], ee_pos[2]],
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// N-08: Unicode adversarial joint names.
    fn redteam_fuzz_unicode(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let baseline_joints = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "redteam_fuzz_unicode".to_owned();
        // (label, decorator applied to the first joint's name)
        let kinds: [(&str, &str); 4] = [
            ("zws", "\u{200B}"), // zero-width space appended
            ("cyrillic", "\u{043E}"), // homoglyph appended (Cyrillic small o)
            ("rlo", "\u{202E}"),      // right-to-left override appended
            ("nul", "\u{0000}"),      // NUL byte appended
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let (kind, decorator) = kinds[i % kinds.len()];
                let mut joint_states = baseline_joints.clone();
                if let Some(j0) = joint_states.first_mut() {
                    let mut decorated = j0.name.clone();
                    decorated.push_str(decorator);
                    j0.name = decorated;
                }
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("redteam_class".to_owned(), "unicode".to_owned());
                metadata.insert("unicode_kind".to_owned(), kind.to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states,
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// G-09: Cross-chain splice. Emits a synthetic two-hop chain whose
    /// hop 1 carries a `predecessor_digest` that does NOT match
    /// `sha256(canonical_bytes(hop 0))`. Mirrors the in-tree
    /// `g09_splice_replaces_middle_hop_with_different_parent` unit test
    /// at the scenario layer, so downstream tooling that parses the
    /// envelope (or the validator running in v11 1.2 opt-in detection
    /// mode) detects the mismatch and rejects every command with
    /// `AuthorityError::PredecessorDigestMismatch { hop: 1 }`.
    fn cross_chain_splice(&self, count: usize, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let source = "cross_chain_splice_agent".to_owned();

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                // Deterministic per-index mismatched-digest byte so each
                // command's spliced chain is distinct and the failure
                // mode is fingerprintable.
                let mismatched_byte: u8 = 0xAB ^ (i as u8);
                let hex_digest: String =
                    (0..32).map(|_| format!("{:02x}", mismatched_byte)).collect();
                // Two-hop synthetic chain: hop 0 root with zero
                // predecessor_digest, hop 1 with the spliced (wrong)
                // digest. Shape mirrors G-04 / G-06 envelope tooling.
                let envelope_json = format!(
                    "[\
                     {{\"kid\":\"hop0_kid\",\"predecessor_digest\":\"\
                     0000000000000000000000000000000000000000000000000000000000000000\",\
                     \"signature\":\"AAAA\",\"payload\":\"hop0_{i}\"}},\
                     {{\"kid\":\"hop1_kid\",\"predecessor_digest\":\"{hex_digest}\",\
                     \"signature\":\"AAAA\",\"payload\":\"hop1_{i}\"}}\
                     ]"
                );
                let pca = STANDARD.encode(envelope_json.as_bytes());
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert(
                    "chain_class".to_owned(),
                    "cross_chain_splice".to_owned(),
                );
                metadata.insert(
                    "mismatched_digest_byte".to_owned(),
                    format!("{:#04x}", mismatched_byte),
                );

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence: i as u64 + 1,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: CommandAuthority {
                        pca_chain: pca,
                        required_ops: ops.to_vec(),
                    },
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }

    /// N-10: Integer-boundary red-team fuzz on `sequence`.
    fn redteam_fuzz_integer_boundary(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        let delta_time = self.profile.max_delta_time * 0.5;
        let joint_states = self.baseline_joint_states();
        let ee_pos = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);
        let authority = Self::authority(pca_chain_b64, ops);
        let source = "redteam_fuzz_intbound".to_owned();
        let bounds: [(u64, &str); 5] = [
            (0, "zero"),
            (1, "one"),
            (u64::MAX, "umax"),
            (u64::MAX - 1, "umaxm1"),
            (i64::MAX as u64, "imax"),
        ];

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));
                let (sequence, kind) = bounds[i % bounds.len()];
                let mut metadata = Self::metadata_stamp(&meta_template, i);
                metadata.insert("redteam_class".to_owned(), "integer_boundary".to_owned());
                metadata.insert("bound_kind".to_owned(), kind.to_owned());

                Command {
                    timestamp,
                    source: source.clone(),
                    sequence,
                    joint_states: joint_states.clone(),
                    delta_time,
                    end_effector_positions: vec![EndEffectorPosition {
                        name: "end_effector".to_owned(),
                        position: ee_pos,
                    }],
                    center_of_mass: Self::valid_com(self.profile),
                    authority: authority.clone(),
                    metadata,
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                    signed_sensor_readings: vec![],
                    zone_overrides: HashMap::new(),
                    environment_state: None,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Geometry helpers (private)
// ---------------------------------------------------------------------------

/// Returns `true` if `point` is inside the workspace AABB.
fn point_in_workspace(point: [f64; 3], profile: &RobotProfile) -> bool {
    match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => {
            point[0] >= min[0]
                && point[0] <= max[0]
                && point[1] >= min[1]
                && point[1] <= max[1]
                && point[2] >= min[2]
                && point[2] <= max[2]
        }
    }
}

/// Returns `true` if `point` is inside any of the given exclusion zones.
fn point_in_any_exclusion_zone(point: [f64; 3], zones: &[ExclusionZone]) -> bool {
    zones.iter().any(|z| point_in_exclusion_zone(point, z))
}

/// Returns `true` if `point` is inside the given exclusion zone.
fn point_in_exclusion_zone(point: [f64; 3], zone: &ExclusionZone) -> bool {
    match zone {
        ExclusionZone::Aabb { min, max, .. } => {
            point[0] >= min[0]
                && point[0] <= max[0]
                && point[1] >= min[1]
                && point[1] <= max[1]
                && point[2] >= min[2]
                && point[2] <= max[2]
        }
        ExclusionZone::Sphere { center, radius, .. } => {
            let dx = point[0] - center[0];
            let dy = point[1] - center[1];
            let dz = point[2] - center[2];
            // F27: compare squared distance to avoid unnecessary sqrt().
            dx * dx + dy * dy + dz * dz <= radius * radius
        }
        // Non-exhaustive: unknown variants do not contribute a hit.
        _ => false,
    }
}

/// Return a point that is strictly inside `zone`, or `None` if the zone shape
/// is not recognised.
fn point_inside_exclusion_zone(zone: &ExclusionZone) -> Option<[f64; 3]> {
    match zone {
        ExclusionZone::Aabb { min, max, .. } => Some([
            (min[0] + max[0]) / 2.0,
            (min[1] + max[1]) / 2.0,
            (min[2] + max[2]) / 2.0,
        ]),
        ExclusionZone::Sphere { center, .. } => Some(*center),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_robotics::profiles::load_builtin;

    fn panda() -> RobotProfile {
        load_builtin("franka_panda").expect("franka_panda profile must load")
    }

    fn ops() -> Vec<Operation> {
        vec![Operation::new("actuate:arm:*").unwrap()]
    }

    const FAKE_PCA: &str = "dGVzdA=="; // base64("test")

    // --- Scenario count ---

    #[test]
    fn baseline_generates_correct_count() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 10);
    }

    #[test]
    fn all_scenarios_generate_requested_count() {
        let profile = panda();
        for scenario in [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::PickAndPlace,
            ScenarioType::CollaborativeWork,
            ScenarioType::DexterousManipulation,
            ScenarioType::MultiRobotCoordinated,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
            ScenarioType::JointPositionBoundary,
            ScenarioType::JointVelocityBoundary,
            ScenarioType::JointTorqueBoundary,
            ScenarioType::JointAccelerationRamp,
            ScenarioType::JointCoordinatedViolation,
            ScenarioType::JointDirectionReversal,
            ScenarioType::JointIeee754Special,
            ScenarioType::JointGradualDrift,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            assert_eq!(
                cmds.len(),
                5,
                "scenario {scenario:?} should produce 5 commands"
            );
        }
    }

    // --- Joint state count matches profile ---

    #[test]
    fn baseline_joint_count_matches_profile() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(
                cmd.joint_states.len(),
                profile.joints.len(),
                "joint count mismatch"
            );
        }
    }

    // --- Sequence numbers ---

    #[test]
    fn baseline_sequences_are_monotonic() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        for w in seqs.windows(2) {
            assert!(w[1] > w[0], "expected monotonic sequences");
        }
    }

    #[test]
    fn multi_agent_has_non_monotonic_sequences() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiAgentHandoff);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        // Must contain at least one repeat or out-of-order pair.
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        let has_disorder = seqs.windows(2).any(|w| w[1] <= w[0]);
        assert!(
            has_disorder,
            "MultiAgentHandoff should produce disordered sequences"
        );
    }

    // --- Authority fields ---

    #[test]
    fn authority_escalation_has_empty_pca_chain() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "AuthorityEscalation must have empty pca_chain"
            );
        }
    }

    #[test]
    fn chain_forgery_has_non_empty_pca_chain() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                !cmd.authority.pca_chain.is_empty(),
                "ChainForgery must have non-empty (garbage) pca_chain"
            );
        }
    }

    #[test]
    fn baseline_preserves_pca_chain() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(cmd.authority.pca_chain, FAKE_PCA);
        }
    }

    // --- Position / velocity constraints ---

    #[test]
    fn baseline_positions_within_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "Baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn aggressive_velocities_within_scaled_limit() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "Aggressive velocity {:.4} exceeds scaled limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    // --- Category A: Normal operation scenario tests ---

    #[test]
    fn pick_and_place_positions_within_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PickAndPlace);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "PickAndPlace position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn pick_and_place_has_payload() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PickAndPlace);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        assert!(
            cmds.iter().all(|c| c.estimated_payload_kg.is_some()),
            "PickAndPlace commands must carry estimated_payload_kg"
        );
    }

    #[test]
    fn walking_gait_has_locomotion_state() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::WalkingGait);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.locomotion_state.is_some(),
                "WalkingGait must have locomotion_state"
            );
        }
    }

    #[test]
    fn walking_gait_velocity_within_limit() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::WalkingGait);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        for cmd in &cmds {
            let loco = cmd.locomotion_state.as_ref().unwrap();
            let [vx, vy, vz] = loco.base_velocity;
            let speed = (vx * vx + vy * vy + vz * vz).sqrt();
            assert!(
                speed <= max_vel,
                "WalkingGait speed {speed:.3} exceeds max {max_vel:.3}"
            );
        }
    }

    #[test]
    fn walking_gait_step_length_within_limit() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::WalkingGait);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        let max_step = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.4);
        for cmd in &cmds {
            let loco = cmd.locomotion_state.as_ref().unwrap();
            assert!(
                loco.step_length <= max_step,
                "WalkingGait step_length {:.3} exceeds max {max_step:.3}",
                loco.step_length
            );
        }
    }

    #[test]
    fn collaborative_work_velocities_within_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CollaborativeWork);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "CollaborativeWork velocity {:.4} exceeds limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn cnc_tending_full_cycle_generates_correct_count() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTendingFullCycle);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 20);
    }

    #[test]
    fn dexterous_manipulation_positions_within_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::DexterousManipulation);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "DexterousManipulation position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn dexterous_manipulation_velocities_within_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::DexterousManipulation);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "DexterousManipulation velocity {:.4} exceeds limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn multi_robot_coordinated_sequences_are_monotonic() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiRobotCoordinated);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        for w in seqs.windows(2) {
            assert!(
                w[1] > w[0],
                "MultiRobotCoordinated must have monotonic sequences"
            );
        }
    }

    #[test]
    fn multi_robot_coordinated_has_two_sources() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiRobotCoordinated);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let sources: HashSet<&str> = cmds.iter().map(|c| c.source.as_str()).collect();
        assert_eq!(
            sources.len(),
            2,
            "MultiRobotCoordinated must use exactly 2 sources"
        );
    }

    #[test]
    fn prompt_injection_positions_exceed_limits() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        let any_violation = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max)
        });
        assert!(
            any_violation,
            "PromptInjection must produce out-of-bounds joint positions"
        );
    }

    // --- Exclusion zone ---

    #[test]
    fn exclusion_zone_ee_inside_zone() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let any_in_zone = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| point_in_any_exclusion_zone(ee.position, &profile.exclusion_zones))
        });
        assert!(
            any_in_zone,
            "ExclusionZone scenario must place EE inside an exclusion zone"
        );
    }

    // --- Delta time ---

    #[test]
    fn baseline_delta_time_within_max() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.delta_time <= profile.max_delta_time,
                "delta_time {:.6} exceeds max {:.6}",
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    // --- Metadata ---

    #[test]
    fn commands_have_metadata() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(2, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(cmd.metadata.contains_key("scenario"));
            assert!(cmd.metadata.contains_key("index"));
        }
    }

    // --- Serde round-trip for ScenarioType ---

    #[test]
    fn scenario_type_serde_round_trip() {
        let variants = [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ScenarioType = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // --- Finding 79: safe_end_effector behaviour when exclusion zone covers workspace centre ---

    /// Build a minimal `RobotProfile` with one joint and a given workspace and
    /// exclusion zones, without a collision distance constraint.
    fn minimal_profile_with_exclusion(
        workspace_min: [f64; 3],
        workspace_max: [f64; 3],
        exclusion_zones: Vec<invariant_robotics::models::profile::ExclusionZone>,
    ) -> RobotProfile {
        use invariant_robotics::models::profile::{
            JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
        };
        RobotProfile {
            name: "test_robot".to_owned(),
            version: "1.0.0".to_owned(),
            joints: vec![JointDefinition {
                name: "j1".to_owned(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 1.0,
                max_torque: 10.0,
                max_acceleration: 5.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: workspace_min,
                max: workspace_max,
            },
            exclusion_zones,
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            end_effectors: vec![],
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
        }
    }

    /// When the workspace centre is NOT inside any exclusion zone, the safe
    /// end-effector should return the centre itself.
    #[test]
    fn safe_end_effector_returns_centre_when_no_exclusion_zone_covers_it() {
        use invariant_robotics::models::profile::ExclusionZone;

        let profile = minimal_profile_with_exclusion(
            [-1.0, -1.0, -1.0],
            [1.0, 1.0, 1.0],
            vec![ExclusionZone::Aabb {
                name: "corner_zone".to_owned(),
                min: [0.8, 0.8, 0.8],
                max: [1.0, 1.0, 1.0],
                conditional: false,
            }],
        );
        let centre = ScenarioGenerator::workspace_centre(&profile);
        let safe = ScenarioGenerator::safe_end_effector(&profile);
        // Centre is [0,0,0], which is NOT in the corner zone.
        assert_eq!(
            safe, centre,
            "should return workspace centre when it is safe"
        );
    }

    /// When the exclusion zone covers ALL five candidate points (centre and the
    /// four ±0.1 offsets), `safe_end_effector` falls back to the workspace centre
    /// as a last resort.  This documents the known limitation: the returned point
    /// may still be inside an exclusion zone when no candidate is clear.
    ///
    /// LIMITATION: `safe_end_effector` tries only 5 candidate points.  If the
    /// exclusion zone is large enough to cover all of them the function falls
    /// back to the workspace centre rather than expanding its search.  This is
    /// acceptable for test/campaign use where profiles are not expected to have
    /// exclusion zones that entirely cover the workspace interior, but callers
    /// that require a guaranteed clear position should verify the result.
    #[test]
    fn safe_end_effector_falls_back_to_centre_when_all_candidates_blocked() {
        use invariant_robotics::models::profile::ExclusionZone;

        // Workspace: [-0.5, -0.5, -0.5] to [0.5, 0.5, 0.5].
        // Centre: [0, 0, 0].  All five candidates are within 0.1 m of centre.
        // Use a sphere exclusion zone of radius 0.5 centred at the origin,
        // which covers all five candidate points.
        let profile = minimal_profile_with_exclusion(
            [-0.5, -0.5, -0.5],
            [0.5, 0.5, 0.5],
            vec![ExclusionZone::Sphere {
                name: "full_coverage".to_owned(),
                center: [0.0, 0.0, 0.0],
                radius: 0.5, // covers everything within 0.5 m of origin
                conditional: false,
            }],
        );
        let centre = ScenarioGenerator::workspace_centre(&profile);
        let safe = ScenarioGenerator::safe_end_effector(&profile);
        // All candidates are blocked; fallback must be the workspace centre.
        assert_eq!(
            safe, centre,
            "fallback must be workspace centre when all candidates are in exclusion zone"
        );
        // Document that the result IS inside the exclusion zone (known limitation).
        assert!(
            point_in_any_exclusion_zone(safe, &profile.exclusion_zones),
            "known limitation: fallback point is inside exclusion zone when no candidate is clear"
        );
    }

    /// When the exclusion zone covers only the workspace centre, one of the
    /// offset candidates should be outside the zone.
    #[test]
    fn safe_end_effector_finds_clear_point_when_only_centre_blocked() {
        use invariant_robotics::models::profile::ExclusionZone;

        // Workspace: [-1.0, -1.0, -1.0] to [1.0, 1.0, 1.0].
        // Centre: [0, 0, 0]. Exclusion sphere radius 0.05 — only covers the centre.
        let profile = minimal_profile_with_exclusion(
            [-1.0, -1.0, -1.0],
            [1.0, 1.0, 1.0],
            vec![ExclusionZone::Sphere {
                name: "small_zone".to_owned(),
                center: [0.0, 0.0, 0.0],
                radius: 0.05, // covers centre but not the ±0.1 offsets
                conditional: false,
            }],
        );
        let safe = ScenarioGenerator::safe_end_effector(&profile);
        // The result must be outside the exclusion zone.
        assert!(
            !point_in_any_exclusion_zone(safe, &profile.exclusion_zones),
            "safe_end_effector must find a point outside the exclusion zone when one exists"
        );
    }

    // --- Zero commands ---

    #[test]
    fn zero_count_returns_empty_vec() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(0, FAKE_PCA, &ops());
        assert!(cmds.is_empty());
    }

    // --- CNC Tending scenario ---

    fn cnc_profile() -> RobotProfile {
        load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell profile must load")
    }

    #[test]
    fn cnc_tending_generates_commands() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 20);
    }

    #[test]
    fn cnc_tending_first_half_has_zone_disabled() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());

        // First 5 commands (loading phase): zone override = false (disabled).
        for cmd in &cmds[..5] {
            let override_val = cmd.zone_overrides.get("haas_spindle_zone");
            assert_eq!(
                override_val,
                Some(&false),
                "loading phase should disable spindle zone"
            );
        }
    }

    #[test]
    fn cnc_tending_second_half_has_zone_active() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());

        // Last 5 commands (cutting phase): zone override = true (active).
        for cmd in &cmds[5..] {
            let override_val = cmd.zone_overrides.get("haas_spindle_zone");
            assert_eq!(
                override_val,
                Some(&true),
                "cutting phase should activate spindle zone"
            );
        }
    }

    #[test]
    fn cnc_tending_ee_inside_conditional_zone() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());

        // All commands should have an EE positioned inside the haas_spindle_zone
        // (bounds: [-1.2, 0.5, 0.3] to [-0.3, 1.2, 1.2]).
        for cmd in &cmds {
            let ee = &cmd.end_effector_positions[0];
            assert!(
                ee.position[0] >= -1.2 && ee.position[0] <= -0.3,
                "EE x={} should be inside haas_spindle_zone X range [-1.2, -0.3]",
                ee.position[0]
            );
        }
    }

    #[test]
    fn cnc_tending_serde_round_trip() {
        let st = ScenarioType::CncTending;
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json, "\"cnc_tending\"");
        let back: ScenarioType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ScenarioType::CncTending);
    }

    // =========================================================================
    // Profile helpers for new test groups
    // =========================================================================

    fn ur10() -> RobotProfile {
        load_builtin("ur10").expect("ur10 profile must load")
    }

    fn quadruped() -> RobotProfile {
        load_builtin("quadruped_12dof").expect("quadruped_12dof profile must load")
    }

    fn humanoid() -> RobotProfile {
        load_builtin("humanoid_28dof").expect("humanoid_28dof profile must load")
    }

    // =========================================================================
    // UR10 tests
    // =========================================================================

    #[test]
    fn ur10_baseline_generates_correct_count() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 10);
    }

    #[test]
    fn ur10_all_core_scenarios_generate_requested_count() {
        let profile = ur10();
        for scenario in [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(7, FAKE_PCA, &ops());
            assert_eq!(
                cmds.len(),
                7,
                "ur10 scenario {scenario:?} should produce 7 commands"
            );
        }
    }

    #[test]
    fn ur10_baseline_joint_count_matches_profile() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(cmd.joint_states.len(), 6, "ur10 must have 6 joints");
            assert_eq!(cmd.joint_states.len(), profile.joints.len());
        }
    }

    #[test]
    fn ur10_baseline_sequences_are_monotonic() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        for w in seqs.windows(2) {
            assert!(w[1] > w[0], "ur10 baseline sequences must be monotonic");
        }
    }

    #[test]
    fn ur10_baseline_positions_within_limits() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "ur10 baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn ur10_aggressive_velocities_within_limit() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "ur10 aggressive velocity {:.4} exceeds scaled limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn ur10_prompt_injection_positions_exceed_limits() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        let any_violation = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max)
        });
        assert!(
            any_violation,
            "ur10 PromptInjection must produce out-of-bounds joint positions"
        );
    }

    #[test]
    fn ur10_authority_escalation_empty_pca() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "ur10 AuthorityEscalation must have empty pca_chain"
            );
        }
    }

    #[test]
    fn ur10_chain_forgery_non_empty_pca() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                !cmd.authority.pca_chain.is_empty(),
                "ur10 ChainForgery must have non-empty (garbage) pca_chain"
            );
        }
    }

    #[test]
    fn ur10_baseline_preserves_pca_chain() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(
                cmd.authority.pca_chain, FAKE_PCA,
                "ur10 baseline must preserve pca_chain"
            );
        }
    }

    #[test]
    fn ur10_exclusion_zone_ee_inside_zone() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let any_in_zone = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| point_in_any_exclusion_zone(ee.position, &profile.exclusion_zones))
        });
        assert!(
            any_in_zone,
            "ur10 ExclusionZone scenario must place EE inside an exclusion zone"
        );
    }

    #[test]
    fn ur10_baseline_delta_time_within_max() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.delta_time <= profile.max_delta_time,
                "ur10 delta_time {:.6} exceeds max {:.6}",
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    #[test]
    fn ur10_multi_agent_has_non_monotonic_sequences() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiAgentHandoff);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        let has_disorder = seqs.windows(2).any(|w| w[1] <= w[0]);
        assert!(
            has_disorder,
            "ur10 MultiAgentHandoff should produce disordered sequences"
        );
    }

    #[test]
    fn ur10_commands_have_metadata() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(2, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.metadata.contains_key("scenario"),
                "ur10 command missing 'scenario' metadata key"
            );
            assert!(
                cmd.metadata.contains_key("index"),
                "ur10 command missing 'index' metadata key"
            );
        }
    }

    #[test]
    fn ur10_zero_count_returns_empty_vec() {
        let profile = ur10();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(0, FAKE_PCA, &ops());
        assert!(cmds.is_empty(), "ur10 zero count must return empty vec");
    }

    // =========================================================================
    // Quadruped tests
    // =========================================================================

    #[test]
    fn quadruped_baseline_generates_correct_count() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 10);
    }

    #[test]
    fn quadruped_all_core_scenarios_generate_requested_count() {
        let profile = quadruped();
        for scenario in [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(6, FAKE_PCA, &ops());
            assert_eq!(
                cmds.len(),
                6,
                "quadruped scenario {scenario:?} should produce 6 commands"
            );
        }
    }

    #[test]
    fn quadruped_baseline_joint_count_matches_profile() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(cmd.joint_states.len(), 12, "quadruped must have 12 joints");
            assert_eq!(cmd.joint_states.len(), profile.joints.len());
        }
    }

    #[test]
    fn quadruped_baseline_sequences_are_monotonic() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        for w in seqs.windows(2) {
            assert!(
                w[1] > w[0],
                "quadruped baseline sequences must be monotonic"
            );
        }
    }

    #[test]
    fn quadruped_baseline_positions_within_limits() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "quadruped baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn quadruped_aggressive_velocities_within_limit() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "quadruped aggressive velocity {:.4} exceeds scaled limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn quadruped_prompt_injection_positions_exceed_limits() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        let any_violation = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max)
        });
        assert!(
            any_violation,
            "quadruped PromptInjection must produce out-of-bounds joint positions"
        );
    }

    #[test]
    fn quadruped_authority_escalation_empty_pca() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "quadruped AuthorityEscalation must have empty pca_chain"
            );
        }
    }

    #[test]
    fn quadruped_chain_forgery_non_empty_pca() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                !cmd.authority.pca_chain.is_empty(),
                "quadruped ChainForgery must have non-empty (garbage) pca_chain"
            );
        }
    }

    #[test]
    fn quadruped_baseline_preserves_pca_chain() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(
                cmd.authority.pca_chain, FAKE_PCA,
                "quadruped baseline must preserve pca_chain"
            );
        }
    }

    #[test]
    fn quadruped_exclusion_zone_ee_inside_zone() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let any_in_zone = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| point_in_any_exclusion_zone(ee.position, &profile.exclusion_zones))
        });
        assert!(
            any_in_zone,
            "quadruped ExclusionZone scenario must place EE inside an exclusion zone"
        );
    }

    #[test]
    fn quadruped_baseline_delta_time_within_max() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.delta_time <= profile.max_delta_time,
                "quadruped delta_time {:.6} exceeds max {:.6}",
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    #[test]
    fn quadruped_commands_have_metadata() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(2, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.metadata.contains_key("scenario"),
                "quadruped command missing 'scenario' metadata"
            );
            assert!(
                cmd.metadata.contains_key("index"),
                "quadruped command missing 'index' metadata"
            );
        }
    }

    #[test]
    fn quadruped_locomotion_runaway_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionRunaway);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "quadruped LocomotionRunaway should produce 8 commands"
        );
    }

    #[test]
    fn quadruped_locomotion_slip_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionSlip);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "quadruped LocomotionSlip should produce 8 commands"
        );
    }

    #[test]
    fn quadruped_locomotion_trip_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionTrip);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "quadruped LocomotionTrip should produce 8 commands"
        );
    }

    #[test]
    fn quadruped_locomotion_stomp_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionStomp);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "quadruped LocomotionStomp should produce 8 commands"
        );
    }

    #[test]
    fn quadruped_locomotion_fall_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionFall);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "quadruped LocomotionFall should produce 8 commands"
        );
    }

    #[test]
    fn quadruped_locomotion_scenarios_have_locomotion_state() {
        let profile = quadruped();
        for scenario in [
            ScenarioType::LocomotionRunaway,
            ScenarioType::LocomotionSlip,
            ScenarioType::LocomotionTrip,
            ScenarioType::LocomotionStomp,
            ScenarioType::LocomotionFall,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(6, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert!(
                    cmd.locomotion_state.is_some(),
                    "quadruped {scenario:?} command must have locomotion_state != None"
                );
            }
        }
    }

    #[test]
    fn quadruped_environment_fault_generates_commands() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            10,
            "quadruped EnvironmentFault should produce 10 commands"
        );
    }

    #[test]
    fn quadruped_environment_fault_has_environment_state() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.environment_state.is_some(),
                "quadruped EnvironmentFault command must have environment_state != None"
            );
        }
    }

    // =========================================================================
    // Humanoid tests
    // =========================================================================

    #[test]
    fn humanoid_baseline_generates_correct_count() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 10);
    }

    #[test]
    fn humanoid_all_core_scenarios_generate_requested_count() {
        let profile = humanoid();
        for scenario in [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(6, FAKE_PCA, &ops());
            assert_eq!(
                cmds.len(),
                6,
                "humanoid scenario {scenario:?} should produce 6 commands"
            );
        }
    }

    #[test]
    fn humanoid_baseline_joint_count_matches_profile() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(cmd.joint_states.len(), 28, "humanoid must have 28 joints");
            assert_eq!(cmd.joint_states.len(), profile.joints.len());
        }
    }

    #[test]
    fn humanoid_baseline_sequences_are_monotonic() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let seqs: Vec<u64> = cmds.iter().map(|c| c.sequence).collect();
        for w in seqs.windows(2) {
            assert!(w[1] > w[0], "humanoid baseline sequences must be monotonic");
        }
    }

    #[test]
    fn humanoid_baseline_positions_within_limits() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "humanoid baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn humanoid_aggressive_velocities_within_limit() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "humanoid aggressive velocity {:.4} exceeds scaled limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn humanoid_prompt_injection_positions_exceed_limits() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        let any_violation = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max)
        });
        assert!(
            any_violation,
            "humanoid PromptInjection must produce out-of-bounds joint positions"
        );
    }

    #[test]
    fn humanoid_authority_escalation_empty_pca() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "humanoid AuthorityEscalation must have empty pca_chain"
            );
        }
    }

    #[test]
    fn humanoid_chain_forgery_non_empty_pca() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                !cmd.authority.pca_chain.is_empty(),
                "humanoid ChainForgery must have non-empty (garbage) pca_chain"
            );
        }
    }

    #[test]
    fn humanoid_baseline_preserves_pca_chain() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(
                cmd.authority.pca_chain, FAKE_PCA,
                "humanoid baseline must preserve pca_chain"
            );
        }
    }

    #[test]
    fn humanoid_exclusion_zone_ee_inside_zone() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let any_in_zone = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| point_in_any_exclusion_zone(ee.position, &profile.exclusion_zones))
        });
        assert!(
            any_in_zone,
            "humanoid ExclusionZone scenario must place EE inside an exclusion zone"
        );
    }

    #[test]
    fn humanoid_baseline_delta_time_within_max() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.delta_time <= profile.max_delta_time,
                "humanoid delta_time {:.6} exceeds max {:.6}",
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    #[test]
    fn humanoid_commands_have_metadata() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(2, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.metadata.contains_key("scenario"),
                "humanoid command missing 'scenario' metadata"
            );
            assert!(
                cmd.metadata.contains_key("index"),
                "humanoid command missing 'index' metadata"
            );
        }
    }

    #[test]
    fn humanoid_locomotion_runaway_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionRunaway);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "humanoid LocomotionRunaway should produce 8 commands"
        );
    }

    #[test]
    fn humanoid_locomotion_slip_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionSlip);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "humanoid LocomotionSlip should produce 8 commands"
        );
    }

    #[test]
    fn humanoid_locomotion_trip_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionTrip);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "humanoid LocomotionTrip should produce 8 commands"
        );
    }

    #[test]
    fn humanoid_locomotion_stomp_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionStomp);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "humanoid LocomotionStomp should produce 8 commands"
        );
    }

    #[test]
    fn humanoid_locomotion_fall_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionFall);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            8,
            "humanoid LocomotionFall should produce 8 commands"
        );
    }

    #[test]
    fn humanoid_locomotion_scenarios_have_locomotion_state() {
        let profile = humanoid();
        for scenario in [
            ScenarioType::LocomotionRunaway,
            ScenarioType::LocomotionSlip,
            ScenarioType::LocomotionTrip,
            ScenarioType::LocomotionStomp,
            ScenarioType::LocomotionFall,
        ] {
            let gen = ScenarioGenerator::new(&profile, scenario);
            let cmds = gen.generate_commands(6, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert!(
                    cmd.locomotion_state.is_some(),
                    "humanoid {scenario:?} command must have locomotion_state != None"
                );
            }
        }
    }

    #[test]
    fn humanoid_environment_fault_generates_commands() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            10,
            "humanoid EnvironmentFault should produce 10 commands"
        );
    }

    #[test]
    fn humanoid_environment_fault_has_environment_state() {
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.environment_state.is_some(),
                "humanoid EnvironmentFault command must have environment_state != None"
            );
        }
    }

    // =========================================================================
    // UR10e Haas Cell tests
    // =========================================================================

    #[test]
    fn ur10e_haas_baseline_generates_correct_count() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 10);
    }

    #[test]
    fn ur10e_haas_baseline_joint_count_matches_profile() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert_eq!(
                cmd.joint_states.len(),
                6,
                "ur10e_haas_cell must have 6 joints"
            );
            assert_eq!(cmd.joint_states.len(), profile.joints.len());
        }
    }

    #[test]
    fn ur10e_haas_baseline_positions_within_limits() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jdef.min && js.position <= jdef.max,
                    "ur10e_haas baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                    js.position,
                    jdef.min,
                    jdef.max,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn ur10e_haas_aggressive_velocities_within_limit() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity.abs() <= limit,
                    "ur10e_haas aggressive velocity {:.4} exceeds scaled limit {:.4} for {}",
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn ur10e_haas_authority_escalation_empty_pca() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "ur10e_haas AuthorityEscalation must have empty pca_chain"
            );
        }
    }

    #[test]
    fn ur10e_haas_exclusion_zone_ee_inside_zone() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let any_in_zone = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| point_in_any_exclusion_zone(ee.position, &profile.exclusion_zones))
        });
        assert!(
            any_in_zone,
            "ur10e_haas ExclusionZone scenario must place EE inside an exclusion zone"
        );
    }

    #[test]
    fn ur10e_haas_baseline_delta_time_within_max() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.delta_time <= profile.max_delta_time,
                "ur10e_haas delta_time {:.6} exceeds max {:.6}",
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    #[test]
    fn ur10e_haas_cnc_tending_zone_override_cycle() {
        // Full zone override cycle: first half disables, second half activates the spindle zone.
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 20);

        // First half (indices 0..10): loading phase — spindle zone disabled (false).
        for cmd in &cmds[..10] {
            let override_val = cmd.zone_overrides.get("haas_spindle_zone");
            assert_eq!(
                override_val,
                Some(&false),
                "ur10e_haas CncTending loading phase must disable spindle zone"
            );
        }

        // Second half (indices 10..20): cutting phase — spindle zone active (true).
        for cmd in &cmds[10..] {
            let override_val = cmd.zone_overrides.get("haas_spindle_zone");
            assert_eq!(
                override_val,
                Some(&true),
                "ur10e_haas CncTending cutting phase must activate spindle zone"
            );
        }
    }

    #[test]
    fn ur10e_haas_environment_fault_generates_commands() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        assert_eq!(
            cmds.len(),
            10,
            "ur10e_haas EnvironmentFault should produce 10 commands"
        );
    }

    #[test]
    fn ur10e_haas_environment_fault_has_environment_state() {
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                cmd.environment_state.is_some(),
                "ur10e_haas EnvironmentFault command must have environment_state != None"
            );
        }
    }

    // =========================================================================
    // Cross-profile comprehensive tests
    // =========================================================================

    /// Helper: returns all five built-in profiles used in cross-profile tests.
    fn all_profiles() -> Vec<RobotProfile> {
        vec![panda(), ur10(), quadruped(), humanoid(), cnc_profile()]
    }

    #[test]
    fn all_profiles_baseline_generates_requested_count() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
            assert_eq!(
                cmds.len(),
                10,
                "profile '{}' Baseline should produce 10 commands",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_joint_count_matches() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert_eq!(
                    cmd.joint_states.len(),
                    profile.joints.len(),
                    "profile '{}' joint count mismatch",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn all_profiles_baseline_positions_within_limits() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                    assert!(
                        js.position >= jdef.min && js.position <= jdef.max,
                        "profile '{}' baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                        profile.name,
                        js.position,
                        jdef.min,
                        jdef.max,
                        jdef.name
                    );
                }
            }
        }
    }

    #[test]
    fn all_profiles_baseline_velocities_within_limits() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                    let limit = jdef.max_velocity * profile.global_velocity_scale;
                    assert!(
                        js.velocity.abs() <= limit,
                        "profile '{}' baseline velocity {:.4} exceeds limit {:.4} for {}",
                        profile.name,
                        js.velocity,
                        limit,
                        jdef.name
                    );
                }
            }
        }
    }

    #[test]
    fn all_profiles_baseline_delta_time_within_max() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert!(
                    cmd.delta_time <= profile.max_delta_time,
                    "profile '{}' delta_time {:.6} exceeds max {:.6}",
                    profile.name,
                    cmd.delta_time,
                    profile.max_delta_time
                );
            }
        }
    }

    #[test]
    fn all_profiles_aggressive_positions_within_limits() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                    assert!(
                        js.position >= jdef.min && js.position <= jdef.max,
                        "profile '{}' aggressive position {:.4} out of [{:.4}, {:.4}] for {}",
                        profile.name,
                        js.position,
                        jdef.min,
                        jdef.max,
                        jdef.name
                    );
                }
            }
        }
    }

    #[test]
    fn all_profiles_authority_escalation_empty_pca() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
            let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert!(
                    cmd.authority.pca_chain.is_empty(),
                    "profile '{}' AuthorityEscalation must have empty pca_chain",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn all_profiles_prompt_injection_exceeds_limits() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
            let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
            let any_violation = cmds.iter().any(|cmd| {
                cmd.joint_states
                    .iter()
                    .zip(profile.joints.iter())
                    .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max)
            });
            assert!(
                any_violation,
                "profile '{}' PromptInjection must produce out-of-bounds joint positions",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_all_thirteen_scenarios_generate_correct_count() {
        let all_scenarios = [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
            ScenarioType::LocomotionRunaway,
            ScenarioType::LocomotionSlip,
            ScenarioType::LocomotionTrip,
            ScenarioType::LocomotionStomp,
            ScenarioType::LocomotionFall,
            ScenarioType::CncTending,
            ScenarioType::EnvironmentFault,
            ScenarioType::CompoundAuthorityPhysics,
            ScenarioType::CompoundSensorSpatial,
            ScenarioType::CompoundDriftThenViolation,
            ScenarioType::CompoundEnvironmentPhysics,
            ScenarioType::RecoverySafeStop,
            ScenarioType::RecoveryAuditIntegrity,
            ScenarioType::LongRunningStability,
            ScenarioType::LongRunningThreat,
            ScenarioType::JointPositionBoundary,
            ScenarioType::JointVelocityBoundary,
            ScenarioType::JointTorqueBoundary,
            ScenarioType::JointAccelerationRamp,
            ScenarioType::JointCoordinatedViolation,
            ScenarioType::JointDirectionReversal,
            ScenarioType::JointIeee754Special,
            ScenarioType::JointGradualDrift,
        ];
        assert_eq!(all_scenarios.len(), 30, "must cover all 30 scenario types");

        for profile in all_profiles() {
            for scenario in all_scenarios {
                let gen = ScenarioGenerator::new(&profile, scenario);
                let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
                assert_eq!(
                    cmds.len(),
                    4,
                    "profile '{}' scenario {scenario:?} should produce 4 commands",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn all_profiles_commands_have_source_and_timestamp() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
            for cmd in &cmds {
                assert!(
                    !cmd.source.is_empty(),
                    "profile '{}' command source must be non-empty",
                    profile.name
                );
                // Timestamp must be a recent UTC time (within 60 seconds of now).
                let now = chrono::Utc::now();
                let diff = (now - cmd.timestamp).num_seconds().abs();
                assert!(
                    diff < 60,
                    "profile '{}' command timestamp should be recent (diff={diff}s)",
                    profile.name
                );
            }
        }
    }

    // =========================================================================
    // Serde round-trip tests
    // =========================================================================

    #[test]
    fn all_scenario_types_serde_round_trip() {
        let all_scenarios = [
            ScenarioType::Baseline,
            ScenarioType::Aggressive,
            ScenarioType::ExclusionZone,
            ScenarioType::AuthorityEscalation,
            ScenarioType::ChainForgery,
            ScenarioType::PromptInjection,
            ScenarioType::MultiAgentHandoff,
            ScenarioType::LocomotionRunaway,
            ScenarioType::LocomotionSlip,
            ScenarioType::LocomotionTrip,
            ScenarioType::LocomotionStomp,
            ScenarioType::LocomotionFall,
            ScenarioType::CncTending,
            ScenarioType::EnvironmentFault,
            ScenarioType::CompoundAuthorityPhysics,
            ScenarioType::CompoundSensorSpatial,
            ScenarioType::CompoundDriftThenViolation,
            ScenarioType::CompoundEnvironmentPhysics,
            ScenarioType::RecoverySafeStop,
            ScenarioType::RecoveryAuditIntegrity,
            ScenarioType::LongRunningStability,
            ScenarioType::LongRunningThreat,
            ScenarioType::JointPositionBoundary,
            ScenarioType::JointVelocityBoundary,
            ScenarioType::JointTorqueBoundary,
            ScenarioType::JointAccelerationRamp,
            ScenarioType::JointCoordinatedViolation,
            ScenarioType::JointDirectionReversal,
            ScenarioType::JointIeee754Special,
            ScenarioType::JointGradualDrift,
        ];
        assert_eq!(all_scenarios.len(), 30, "must cover all 30 scenario types");

        for variant in all_scenarios {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ScenarioType = serde_json::from_str(&json).unwrap();
            assert_eq!(
                variant, back,
                "serde round-trip failed for {variant:?}: serialized as {json}"
            );
        }
    }

    #[test]
    fn environment_fault_serde_round_trip() {
        let st = ScenarioType::EnvironmentFault;
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(
            json, "\"environment_fault\"",
            "EnvironmentFault must serialize to snake_case"
        );
        let back: ScenarioType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ScenarioType::EnvironmentFault);
    }

    // =========================================================================
    // Environment fault scenario phase structure verification
    // =========================================================================
    // The EnvironmentFault scenario distributes commands across 5 phases:
    // 0-19% pitch, 20-39% temp, 40-59% battery, 60-79% latency, 80-100% e-stop.
    // These tests verify each phase produces the correct environment_state fields.

    fn cnc_tending_profile() -> RobotProfile {
        load_builtin("ur10e_cnc_tending").expect("ur10e_cnc_tending must load")
    }

    #[test]
    fn environment_fault_25_commands_all_have_environment_state() {
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 25);
        for (i, cmd) in cmds.iter().enumerate() {
            assert!(
                cmd.environment_state.is_some(),
                "command {i} must have environment_state"
            );
        }
    }

    #[test]
    fn environment_fault_pitch_phase_has_imu_pitch() {
        // With 25 commands, commands 0-4 (frac 0.0-0.167) are pitch phase.
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        let env = cmds[0].environment_state.as_ref().unwrap();
        assert!(
            env.imu_pitch_rad.is_some(),
            "pitch phase (cmd 0) must have imu_pitch_rad set"
        );
        let pitch = env.imu_pitch_rad.unwrap();
        let max_pitch = profile
            .environment
            .as_ref()
            .map(|e| e.max_safe_pitch_rad)
            .unwrap_or(0.2618);
        assert!(
            pitch > max_pitch,
            "pitch {pitch:.4} must exceed max_safe_pitch_rad {max_pitch:.4}"
        );
    }

    #[test]
    fn environment_fault_temperature_phase_has_actuator_temps() {
        // Commands in the 20-39% range (indices ~5-9 out of 25).
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        // Index 6 → frac = 6/24 = 0.25 → temperature phase
        let env = cmds[6].environment_state.as_ref().unwrap();
        assert!(
            !env.actuator_temperatures.is_empty(),
            "temperature phase must populate actuator_temperatures"
        );
        let max_temp = profile
            .environment
            .as_ref()
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        for temp in &env.actuator_temperatures {
            assert!(
                temp.temperature_celsius > max_temp,
                "temp {:.1}°C must exceed max {max_temp:.1}°C",
                temp.temperature_celsius
            );
        }
    }

    #[test]
    fn environment_fault_battery_phase_has_zero_battery() {
        // Commands in 40-59% range (indices ~10-14 out of 25).
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        // Index 12 → frac = 12/24 = 0.50 → battery phase
        let env = cmds[12].environment_state.as_ref().unwrap();
        assert_eq!(
            env.battery_percentage,
            Some(0.0),
            "battery phase must set battery_percentage to 0%"
        );
    }

    #[test]
    fn environment_fault_latency_phase_has_high_latency() {
        // Commands in 60-79% range (indices ~15-19 out of 25).
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        // Index 18 → frac = 18/24 = 0.75 → latency phase
        let env = cmds[18].environment_state.as_ref().unwrap();
        let max_latency = profile
            .environment
            .as_ref()
            .map(|e| e.max_latency_ms)
            .unwrap_or(100.0);
        assert!(
            env.communication_latency_ms.unwrap() > max_latency,
            "latency must exceed max {max_latency:.1}ms"
        );
    }

    #[test]
    fn environment_fault_estop_phase_has_estop_engaged() {
        // Commands in 80-100% range (indices ~20-24 out of 25).
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(25, FAKE_PCA, &ops());
        // Last command (index 24, frac=1.0) is e-stop phase
        let env = cmds[24].environment_state.as_ref().unwrap();
        assert_eq!(
            env.e_stop_engaged,
            Some(true),
            "e-stop phase must set e_stop_engaged=true"
        );
    }

    // =========================================================================
    // Locomotion scenario structure verification
    // =========================================================================

    #[test]
    fn locomotion_runaway_velocity_exceeds_profile_max() {
        let profile = quadruped();
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionRunaway);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        // At least some commands should have base_velocity exceeding max.
        let any_over = cmds.iter().any(|cmd| {
            if let Some(loco) = &cmd.locomotion_state {
                let [vx, vy, vz] = loco.base_velocity;
                (vx * vx + vy * vy + vz * vz).sqrt() > max_vel
            } else {
                false
            }
        });
        assert!(
            any_over,
            "LocomotionRunaway must produce at least one command with speed > {max_vel}"
        );
    }

    #[test]
    fn locomotion_slip_friction_cone_violated() {
        let profile = quadruped();
        let friction = profile
            .locomotion
            .as_ref()
            .map(|l| l.friction_coefficient)
            .unwrap_or(0.6);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionSlip);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        let any_slip = cmds.iter().any(|cmd| {
            if let Some(loco) = &cmd.locomotion_state {
                loco.feet.iter().any(|f| {
                    if let Some(grf) = &f.ground_reaction_force {
                        let tang = (grf[0] * grf[0] + grf[1] * grf[1]).sqrt();
                        grf[2] > 0.0 && tang / grf[2] > friction
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        });
        assert!(
            any_slip,
            "LocomotionSlip must violate friction cone (tangential/normal > {friction})"
        );
    }

    #[test]
    fn locomotion_trip_clearance_below_minimum() {
        let profile = quadruped();
        let min_clearance = profile
            .locomotion
            .as_ref()
            .map(|l| l.min_foot_clearance)
            .unwrap_or(0.02);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionTrip);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let any_below = cmds.iter().any(|cmd| {
            if let Some(loco) = &cmd.locomotion_state {
                loco.feet
                    .iter()
                    .any(|f| !f.contact && f.position[2] < min_clearance)
            } else {
                false
            }
        });
        assert!(
            any_below,
            "LocomotionTrip must produce swing foot below min clearance {min_clearance}"
        );
    }

    #[test]
    fn locomotion_stomp_clearance_above_maximum() {
        let profile = quadruped();
        let max_height = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_height)
            .unwrap_or(0.5);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionStomp);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let any_above = cmds.iter().any(|cmd| {
            if let Some(loco) = &cmd.locomotion_state {
                loco.feet
                    .iter()
                    .any(|f| !f.contact && f.position[2] > max_height)
            } else {
                false
            }
        });
        assert!(
            any_above,
            "LocomotionStomp must produce swing foot above max_step_height {max_height}"
        );
    }

    #[test]
    fn locomotion_fall_has_com_outside_support_polygon() {
        // LocomotionFall sets COM to [10,10,2] — outside any support polygon.
        let profile = humanoid();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionFall);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            let com = cmd
                .center_of_mass
                .expect("LocomotionFall must set center_of_mass");
            // The humanoid support polygon is ±0.15×±0.10. COM at [10,10,2] is
            // way outside on both axes.
            assert!(
                com[0].abs() > 0.15 || com[1].abs() > 0.10,
                "COM {:?} must be outside humanoid support polygon (±0.15×±0.10)",
                com
            );
        }
    }

    #[test]
    fn locomotion_fall_also_has_overspeed() {
        // LocomotionFall combines P9 (COM) + P15 (overspeed) + P19 (overextension).
        let profile = quadruped();
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionFall);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            let loco = cmd
                .locomotion_state
                .as_ref()
                .expect("LocomotionFall must set locomotion_state");
            let [vx, vy, vz] = loco.base_velocity;
            let speed = (vx * vx + vy * vy + vz * vz).sqrt();
            assert!(
                speed > max_vel,
                "LocomotionFall speed {speed:.2} must exceed max {max_vel}"
            );
        }
    }

    #[test]
    fn locomotion_fall_also_has_step_overextension() {
        let profile = humanoid();
        let max_step = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.6);
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionFall);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            let loco = cmd.locomotion_state.as_ref().unwrap();
            assert!(
                loco.step_length > max_step,
                "LocomotionFall step {:.2} must exceed max {max_step}",
                loco.step_length
            );
        }
    }

    // =========================================================================
    // CNC tending zone name correctness
    // =========================================================================

    #[test]
    fn cnc_tending_uses_correct_conditional_zone_name_haas_cell() {
        // ur10e_haas_cell has conditional zone "haas_spindle_zone"
        let profile = cnc_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        // All commands should have a zone_override for the conditional zone
        for cmd in &cmds {
            assert!(
                !cmd.zone_overrides.is_empty(),
                "CncTending must set zone_overrides"
            );
            assert!(
                cmd.zone_overrides.contains_key("haas_spindle_zone"),
                "CncTending zone_override key must be 'haas_spindle_zone', got: {:?}",
                cmd.zone_overrides.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn cnc_tending_uses_correct_conditional_zone_name_cnc_tending() {
        // ur10e_cnc_tending has conditional zone "haas_spindle_area"
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        for cmd in &cmds {
            assert!(
                !cmd.zone_overrides.is_empty(),
                "CncTending must set zone_overrides"
            );
            assert!(
                cmd.zone_overrides.contains_key("haas_spindle_area"),
                "CncTending zone_override key must be 'haas_spindle_area', got: {:?}",
                cmd.zone_overrides.keys().collect::<Vec<_>>()
            );
        }
    }

    // =========================================================================
    // Baseline end-effector workspace containment
    // =========================================================================

    #[test]
    fn all_profiles_baseline_ee_inside_workspace() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for ee in &cmd.end_effector_positions {
                    assert!(
                        point_in_workspace(ee.position, &profile),
                        "profile '{}' baseline EE {:?} must be inside workspace",
                        profile.name,
                        ee.position
                    );
                }
            }
        }
    }

    #[test]
    fn all_profiles_aggressive_ee_inside_workspace() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for ee in &cmd.end_effector_positions {
                    assert!(
                        point_in_workspace(ee.position, &profile),
                        "profile '{}' aggressive EE {:?} must be inside workspace",
                        profile.name,
                        ee.position
                    );
                }
            }
        }
    }

    // =========================================================================
    // Baseline torque within limits
    // =========================================================================

    #[test]
    fn all_profiles_baseline_torques_within_limits() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
            for cmd in &cmds {
                for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                    assert!(
                        js.effort.abs() <= jdef.max_torque,
                        "profile '{}' baseline effort {:.2} exceeds max_torque {:.2} for {}",
                        profile.name,
                        js.effort,
                        jdef.max_torque,
                        jdef.name
                    );
                }
            }
        }
    }

    // =========================================================================
    // Gap-filling tests
    // =========================================================================

    #[test]
    fn aggressive_velocity_is_at_least_90_percent_of_effective_limit() {
        // The effective limit accounts for margins AND proximity zone scaling.
        // Aggressive produces velocity at 97% of the effective limit, so > 90%
        // should hold even with all tightening factors applied.
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let vel_margin = profile
            .real_world_margins
            .as_ref()
            .map(|m| m.velocity_margin)
            .unwrap_or(0.0);
        // Compute the proximity scale at the EE position used by aggressive
        let ee_pos = ScenarioGenerator::safe_end_effector(&profile);
        let prox_scale = ScenarioGenerator::proximity_scale_at(&profile, ee_pos);
        let any_near_limit = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| {
                    let effective = jdef.max_velocity
                        * profile.global_velocity_scale
                        * (1.0 - vel_margin)
                        * prox_scale;
                    js.velocity.abs() > 0.90 * effective
                })
        });
        assert!(
            any_near_limit,
            "Aggressive must produce velocities near (>90%) the effective limit \
             (accounting for margins and proximity scaling)"
        );
    }

    #[test]
    fn aggressive_delta_time_is_at_least_90_percent_of_max() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(5, FAKE_PCA, &ops());
        let any_near_max = cmds
            .iter()
            .any(|cmd| cmd.delta_time > 0.90 * profile.max_delta_time);
        assert!(
            any_near_max,
            "Aggressive must produce delta_time > 90% of max_delta_time"
        );
    }

    #[test]
    fn aggressive_positions_near_boundary() {
        // Aggressive uses positions at 95% of range from each end (5% margin from limit).
        // A position at max - range*0.05 is 90% of the way from midpoint to boundary.
        // Threshold is set to 85% to robustly capture positions in the 90–95% range.
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Aggressive);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let any_near_boundary = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| {
                    let mid = (jdef.min + jdef.max) / 2.0;
                    let half_range = (jdef.max - jdef.min) / 2.0;
                    // At least 85% of the way from midpoint to a boundary
                    (js.position - mid).abs() >= 0.85 * half_range
                })
        });
        assert!(
            any_near_boundary,
            "Aggressive must produce at least one joint position >=85% from midpoint to boundary"
        );
    }

    #[test]
    fn prompt_injection_positions_are_extreme() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        // PromptInjection uses 10× outside limits. At least one joint must exceed
        // 5× the half-range beyond its boundary.
        let any_extreme = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| {
                    let range = jdef.max - jdef.min;
                    js.position.abs() > jdef.max.abs() + 5.0 * range
                        || js.position < jdef.min - 5.0 * range
                })
        });
        assert!(
            any_extreme,
            "PromptInjection must produce positions that exceed limits by at least 5× the range"
        );
    }

    #[test]
    fn prompt_injection_velocities_are_extreme() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::PromptInjection);
        let cmds = gen.generate_commands(4, FAKE_PCA, &ops());
        // PromptInjection uses 5× max velocity; at least one joint must exceed 3× max.
        let any_extreme = cmds.iter().any(|cmd| {
            cmd.joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.velocity.abs() > 3.0 * jdef.max_velocity)
        });
        assert!(
            any_extreme,
            "PromptInjection must produce velocities exceeding 3× max velocity"
        );
    }

    #[test]
    fn chain_forgery_pca_chain_is_not_valid_base64_json() {
        use base64::Engine;
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        for cmd in &cmds {
            let decoded =
                base64::engine::general_purpose::STANDARD.decode(&cmd.authority.pca_chain);
            // Either decode fails (not valid base64) or the decoded bytes aren't
            // valid SignedPca JSON.
            let is_garbage = match decoded {
                Err(_) => true,
                Ok(bytes) => serde_json::from_slice::<
                    Vec<invariant_robotics::models::authority::SignedPca>,
                >(&bytes)
                .is_err(),
            };
            assert!(is_garbage, "ChainForgery must produce invalid PCA chain");
        }
    }

    #[test]
    fn multi_agent_handoff_has_multiple_sources() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiAgentHandoff);
        let cmds = gen.generate_commands(8, FAKE_PCA, &ops());
        let sources: std::collections::HashSet<&str> =
            cmds.iter().map(|c| c.source.as_str()).collect();
        assert!(
            sources.len() >= 2,
            "MultiAgentHandoff must produce at least 2 distinct source values, got: {sources:?}"
        );
    }

    #[test]
    fn exclusion_zone_ee_not_in_workspace_centre() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
        let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
        let centre = ScenarioGenerator::workspace_centre(&profile);
        // The EE must NOT be at the workspace centre — the generator targets a zone.
        let any_not_centre = cmds.iter().any(|cmd| {
            cmd.end_effector_positions
                .iter()
                .any(|ee| ee.position != centre)
        });
        assert!(
            any_not_centre,
            "ExclusionZone EE must not be at the workspace centre"
        );
    }

    #[test]
    fn single_command_baseline_is_valid() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(1, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 1, "count=1 must produce exactly 1 command");
        let cmd = &cmds[0];
        assert_eq!(cmd.joint_states.len(), profile.joints.len());
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.position >= jdef.min && js.position <= jdef.max,
                "single-command baseline position {:.4} out of [{:.4}, {:.4}] for {}",
                js.position,
                jdef.min,
                jdef.max,
                jdef.name
            );
        }
        assert!(
            cmd.delta_time > 0.0 && cmd.delta_time <= profile.max_delta_time,
            "single-command baseline delta_time {:.6} must be in (0, max_delta_time]",
            cmd.delta_time
        );
    }

    #[test]
    fn single_command_locomotion_runaway_has_locomotion_state() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionRunaway);
        let cmds = gen.generate_commands(1, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 1);
        assert!(
            cmds[0].locomotion_state.is_some(),
            "count=1 LocomotionRunaway must have locomotion_state"
        );
    }

    #[test]
    fn single_command_environment_fault_has_environment_state() {
        let profile = cnc_tending_profile();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::EnvironmentFault);
        let cmds = gen.generate_commands(1, FAKE_PCA, &ops());
        assert_eq!(cmds.len(), 1);
        assert!(
            cmds[0].environment_state.is_some(),
            "count=1 EnvironmentFault must have environment_state"
        );
    }

    #[test]
    fn locomotion_runaway_velocity_ramps_upward() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionRunaway);
        let cmds = gen.generate_commands(20, FAKE_PCA, &ops());
        let speed = |cmd: &invariant_robotics::models::command::Command| {
            let loco = cmd.locomotion_state.as_ref().expect("must have loco state");
            let [vx, vy, vz] = loco.base_velocity;
            (vx * vx + vy * vy + vz * vz).sqrt()
        };
        let first_speed = speed(&cmds[0]);
        let last_speed = speed(cmds.last().unwrap());
        assert!(
            last_speed > first_speed,
            "LocomotionRunaway: last speed {last_speed:.3} must be greater than first speed {first_speed:.3}"
        );
    }

    #[test]
    fn locomotion_slip_tangential_force_increases() {
        let profile = quadruped();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::LocomotionSlip);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        let tangential = |cmd: &invariant_robotics::models::command::Command| {
            let loco = cmd.locomotion_state.as_ref().expect("must have loco state");
            loco.feet
                .iter()
                .filter_map(|f| f.ground_reaction_force.as_ref())
                .map(|grf| (grf[0] * grf[0] + grf[1] * grf[1]).sqrt())
                .fold(0.0_f64, f64::max)
        };
        let first = tangential(&cmds[0]);
        let last = tangential(cmds.last().unwrap());
        assert!(
            last > first,
            "LocomotionSlip: last tangential force {last:.3} must exceed first {first:.3}"
        );
    }

    #[test]
    fn baseline_timestamps_are_monotonically_increasing() {
        let profile = panda();
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let cmds = gen.generate_commands(10, FAKE_PCA, &ops());
        for w in cmds.windows(2) {
            assert!(
                w[1].timestamp >= w[0].timestamp,
                "baseline timestamps must be non-decreasing: {:?} >= {:?}",
                w[1].timestamp,
                w[0].timestamp
            );
        }
    }

    #[test]
    fn all_profiles_baseline_joint_names_match_profile() {
        for profile in all_profiles() {
            let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
            let cmds = gen.generate_commands(3, FAKE_PCA, &ops());
            for cmd in &cmds {
                for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                    assert_eq!(
                        js.name, jdef.name,
                        "profile '{}': joint_state name '{}' must match profile joint name '{}'",
                        profile.name, js.name, jdef.name
                    );
                }
            }
        }
    }
}
