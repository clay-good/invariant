// Built-in simulation scenarios.
//
// Each `ScenarioType` produces a deterministic sequence of `Command` values
// designed to exercise a specific failure mode (or the happy path) of the
// Invariant safety firewall.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use invariant_core::models::authority::Operation;
use invariant_core::models::command::{
    Command, CommandAuthority, EndEffectorPosition, FootState, JointState, LocomotionState,
};
use invariant_core::models::profile::{ExclusionZone, RobotProfile, WorkspaceBounds};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ScenarioType
// ---------------------------------------------------------------------------

/// Built-in scenario classes for the 15M campaign.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::scenario::ScenarioType;
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
    /// use invariant_robotics_sim::scenario::{ScenarioGenerator, ScenarioType};
    /// use invariant_core::models::authority::Operation;
    ///
    /// // Load the built-in franka_panda profile for the generator.
    /// let profile = invariant_core::profiles::load_builtin("franka_panda")
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
            ScenarioType::CollaborativeWork => {
                self.collaborative_work(count, pca_chain_b64, ops)
            }
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
        use invariant_core::models::profile::ProximityZone;
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
    fn pick_and_place(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
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
    fn walking_gait(
        &self,
        count: usize,
        pca_chain_b64: &str,
        ops: &[Operation],
    ) -> Vec<Command> {
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
        let max_grf = loco_cfg.map(|l| l.max_ground_reaction_force).unwrap_or(1000.0);

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
        use invariant_core::models::command::{ActuatorTemperature, EnvironmentState};

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
        use invariant_core::models::command::EnvironmentState;

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
    use invariant_core::profiles::load_builtin;

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
        exclusion_zones: Vec<invariant_core::models::profile::ExclusionZone>,
    ) -> RobotProfile {
        use invariant_core::models::profile::{
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
        use invariant_core::models::profile::ExclusionZone;

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
        use invariant_core::models::profile::ExclusionZone;

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
        use invariant_core::models::profile::ExclusionZone;

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
        ];
        assert_eq!(all_scenarios.len(), 22, "must cover all 22 scenario types");

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
        ];
        assert_eq!(all_scenarios.len(), 22, "must cover all 22 scenario types");

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
                    Vec<invariant_core::models::authority::SignedPca>,
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
        let speed = |cmd: &invariant_core::models::command::Command| {
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
        let tangential = |cmd: &invariant_core::models::command::Command| {
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
