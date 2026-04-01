// Built-in simulation scenarios (7 types).
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

/// The eleven built-in scenario classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioType {
    /// Normal operation: all joint states and positions stay within limits.
    Baseline,
    /// Boundary stress: commands at 95–100 % of every limit.
    Aggressive,
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
    // -- Locomotion adversarial scenarios (Step 52) --
    /// Runaway: base velocity gradually increases past the locomotion limit (P15).
    LocomotionRunaway,
    /// Slip: foot forces exceed friction cone while walking (P18).
    LocomotionSlip,
    /// Trip: swing foot clearance drops below minimum during gait (P16).
    LocomotionTrip,
    /// Fall: centre-of-mass + base velocity combine to cause instability (P9+P15+P19).
    LocomotionFall,
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
            ScenarioType::ExclusionZone => self.exclusion_zone(count, pca_chain_b64, ops),
            ScenarioType::AuthorityEscalation => self.authority_escalation(count, ops),
            ScenarioType::ChainForgery => self.chain_forgery(count, ops),
            ScenarioType::PromptInjection => self.prompt_injection(count, pca_chain_b64, ops),
            ScenarioType::MultiAgentHandoff => self.multi_agent_handoff(count, pca_chain_b64, ops),
            ScenarioType::LocomotionRunaway => {
                self.locomotion_runaway(count, pca_chain_b64, ops)
            }
            ScenarioType::LocomotionSlip => self.locomotion_slip(count, pca_chain_b64, ops),
            ScenarioType::LocomotionTrip => self.locomotion_trip(count, pca_chain_b64, ops),
            ScenarioType::LocomotionFall => self.locomotion_fall(count, pca_chain_b64, ops),
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
        for (i, name) in link_names.iter().enumerate() {
            let offset = (i + 1) as f64 * step;
            result.push(EndEffectorPosition {
                name: name.clone(),
                // Offset along X; clamp to workspace if needed.
                position: match &profile.workspace {
                    WorkspaceBounds::Aabb { min, max } => {
                        let x = (base[0] + offset).min(max[0] - 0.01).max(min[0] + 0.01);
                        [x, base[1], base[2]]
                    }
                },
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

    /// Build joint states near the limits (95 % of range/velocity).
    fn aggressive_joint_states(&self, index: usize) -> Vec<JointState> {
        self.profile
            .joints
            .iter()
            .enumerate()
            .map(|(i, j)| {
                // Alternate between near-min and near-max on successive joints
                // to avoid constant toggling on every command.
                let near_max = (index + i).is_multiple_of(2);
                let range = j.max - j.min;
                let position = if near_max {
                    j.max - range * 0.05
                } else {
                    j.min + range * 0.05
                };
                let velocity = j.max_velocity * self.profile.global_velocity_scale * 0.97;
                let effort = j.max_torque * 0.97;
                JointState {
                    name: j.name.clone(),
                    position,
                    velocity,
                    effort,
                }
            })
            .collect()
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
                    center_of_mass: None,
                    authority: authority.clone(),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                }
            })
            .collect()
    }

    fn aggressive(&self, count: usize, pca_chain_b64: &str, ops: &[Operation]) -> Vec<Command> {
        let base_ts: DateTime<Utc> = Utc::now();
        // Use delta_time at 98 % of the maximum.
        let delta_time = self.profile.max_delta_time * 0.98;

        // End-effector near the workspace boundary (97 % toward max corner)
        // but still strictly inside the workspace.
        let ee_pos = match &self.profile.workspace {
            WorkspaceBounds::Aabb { min, max } => [
                min[0] + (max[0] - min[0]) * 0.97,
                min[1] + (max[1] - min[1]) * 0.97,
                min[2] + (max[2] - min[2]) * 0.97,
            ],
        };

        // Collect all unique link names from collision pairs and assign safe,
        // well-separated positions so the self-collision check passes.
        // Use a HashSet for O(n) deduplication instead of O(n^2) Vec::contains.
        let mut seen: HashSet<&str> = HashSet::new();
        let mut link_names: Vec<String> = Vec::new();
        for pair in &self.profile.collision_pairs {
            if seen.insert(pair.link_a.as_str()) {
                link_names.push(pair.link_a.clone());
            }
            if seen.insert(pair.link_b.as_str()) {
                link_names.push(pair.link_b.clone());
            }
        }
        let step = self.profile.min_collision_distance.max(0.01) * 20.0;
        let safe_base = Self::safe_end_effector(self.profile);
        let meta_template = Self::metadata_template(self.scenario);

        (0..count)
            .map(|i| {
                let timestamp = base_ts
                    + Duration::milliseconds(Self::ms_offset_to_i64(
                        i as f64 * delta_time * 1_000.0,
                    ));

                let mut end_effector_positions = vec![EndEffectorPosition {
                    name: "end_effector".to_owned(),
                    position: ee_pos,
                }];
                // Add collision-pair links at safe positions (relative to the
                // safe-end-effector base, not the aggressive boundary position).
                for (k, name) in link_names.iter().enumerate() {
                    let offset = (k + 1) as f64 * step;
                    let link_pos = match &self.profile.workspace {
                        WorkspaceBounds::Aabb { min, max } => {
                            let x = (safe_base[0] + offset)
                                .min(max[0] - 0.01)
                                .max(min[0] + 0.01);
                            [x, safe_base[1], safe_base[2]]
                        }
                    };
                    end_effector_positions.push(EndEffectorPosition {
                        name: name.clone(),
                        position: link_pos,
                    });
                }

                Command {
                    timestamp,
                    source: "aggressive_agent".to_owned(),
                    sequence: i as u64,
                    joint_states: self.aggressive_joint_states(i),
                    delta_time,
                    end_effector_positions,
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    // Empty chain — deliberately missing authority.
                    authority: CommandAuthority {
                        pca_chain: String::new(),
                        required_ops: ops.to_vec(),
                    },
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: CommandAuthority {
                        pca_chain: garbage,
                        required_ops: ops.to_vec(),
                    },
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: None,
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Locomotion adversarial scenarios (Step 52)
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
                    center_of_mass: None,
                    authority: Self::authority(pca_chain_b64, ops),
                    metadata: Self::metadata_stamp(&meta_template, i),
                    locomotion_state: Some(loco),
                    end_effector_forces: vec![],
                    estimated_payload_kg: None,
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
}
