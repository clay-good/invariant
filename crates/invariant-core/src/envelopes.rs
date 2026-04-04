// Built-in standard task envelopes (Section 17.3, Step 76).
//
// Pre-defined safety envelopes for common humanoid/manipulator tasks.
// Each envelope tightens limits from the base profile for a specific task
// type. Companies can define custom envelopes; these are the defaults.

use crate::models::profile::TaskEnvelope;

/// Return all 8 standard task envelopes from Section 17.3.
pub fn builtin_envelopes() -> Vec<TaskEnvelope> {
    vec![
        delicate_pickup(),
        standard_pickup(),
        heavy_lift(),
        human_handoff(),
        cleaning_surface(),
        door_operation(),
        inspection_only(),
        emergency_stop(),
    ]
}

/// Look up a built-in envelope by name. Returns `None` for unknown names.
pub fn builtin_envelope(name: &str) -> Option<TaskEnvelope> {
    builtin_envelopes().into_iter().find(|e| e.name == name)
}

/// Cups, glasses, eggs — very slow, minimal force, light payload.
pub fn delicate_pickup() -> TaskEnvelope {
    TaskEnvelope {
        name: "delicate_pickup".into(),
        description: "Pick up fragile or lightweight objects (cups, glasses, eggs)".into(),
        global_velocity_scale: Some(0.3),
        max_payload_kg: Some(0.5),
        end_effector_force_limit_n: Some(5.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Plates, books, tools — moderate speed and force.
pub fn standard_pickup() -> TaskEnvelope {
    TaskEnvelope {
        name: "standard_pickup".into(),
        description: "Pick up standard objects (plates, books, tools)".into(),
        global_velocity_scale: Some(0.7),
        max_payload_kg: Some(5.0),
        end_effector_force_limit_n: Some(30.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Boxes, equipment — slower but high payload and force.
pub fn heavy_lift() -> TaskEnvelope {
    TaskEnvelope {
        name: "heavy_lift".into(),
        description: "Lift heavy objects (boxes, equipment)".into(),
        global_velocity_scale: Some(0.5),
        max_payload_kg: Some(15.0),
        end_effector_force_limit_n: Some(80.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Handing an object to a human — very slow, gentle force.
pub fn human_handoff() -> TaskEnvelope {
    TaskEnvelope {
        name: "human_handoff".into(),
        description: "Hand an object to a human (requires proximity awareness)".into(),
        global_velocity_scale: Some(0.2),
        max_payload_kg: Some(2.0),
        end_effector_force_limit_n: Some(10.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Wiping, sweeping — moderate speed, light contact force.
pub fn cleaning_surface() -> TaskEnvelope {
    TaskEnvelope {
        name: "cleaning_surface".into(),
        description: "Wipe or sweep a surface".into(),
        global_velocity_scale: Some(0.5),
        max_payload_kg: Some(1.0),
        end_effector_force_limit_n: Some(15.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Door handles, drawers — moderate force, no payload.
pub fn door_operation() -> TaskEnvelope {
    TaskEnvelope {
        name: "door_operation".into(),
        description: "Operate door handles, drawers, or latches".into(),
        global_velocity_scale: Some(0.4),
        max_payload_kg: None, // N/A for door operation
        end_effector_force_limit_n: Some(40.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// Looking only, no contact — minimal everything.
pub fn inspection_only() -> TaskEnvelope {
    TaskEnvelope {
        name: "inspection_only".into(),
        description: "Visual inspection only, no physical contact".into(),
        global_velocity_scale: Some(0.3),
        max_payload_kg: Some(0.0),
        end_effector_force_limit_n: Some(0.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

/// All movement ceases immediately.
pub fn emergency_stop() -> TaskEnvelope {
    TaskEnvelope {
        name: "emergency_stop".into(),
        description: "Emergency stop — all movement ceases".into(),
        global_velocity_scale: Some(0.0),
        max_payload_kg: Some(0.0),
        end_effector_force_limit_n: Some(0.0),
        workspace: None,
        additional_exclusion_zones: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_envelopes_returns_8() {
        let envs = builtin_envelopes();
        assert_eq!(envs.len(), 8);
    }

    #[test]
    fn all_envelopes_have_unique_names() {
        let envs = builtin_envelopes();
        let mut names: Vec<&str> = envs.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn builtin_envelope_lookup() {
        assert!(builtin_envelope("delicate_pickup").is_some());
        assert!(builtin_envelope("heavy_lift").is_some());
        assert!(builtin_envelope("emergency_stop").is_some());
        assert!(builtin_envelope("nonexistent").is_none());
    }

    #[test]
    fn delicate_pickup_values_match_spec() {
        let e = delicate_pickup();
        assert_eq!(e.name, "delicate_pickup");
        assert_eq!(e.global_velocity_scale, Some(0.3));
        assert_eq!(e.max_payload_kg, Some(0.5));
        assert_eq!(e.end_effector_force_limit_n, Some(5.0));
    }

    #[test]
    fn emergency_stop_zeroes_everything() {
        let e = emergency_stop();
        assert_eq!(e.global_velocity_scale, Some(0.0));
        assert_eq!(e.max_payload_kg, Some(0.0));
        assert_eq!(e.end_effector_force_limit_n, Some(0.0));
    }

    #[test]
    fn door_operation_has_no_payload() {
        let e = door_operation();
        assert!(e.max_payload_kg.is_none());
        assert_eq!(e.end_effector_force_limit_n, Some(40.0));
    }

    #[test]
    fn all_envelopes_have_descriptions() {
        for e in builtin_envelopes() {
            assert!(
                !e.description.is_empty(),
                "envelope '{}' has no description",
                e.name
            );
        }
    }

    #[test]
    fn all_envelopes_serialize_to_json() {
        for e in builtin_envelopes() {
            let json = serde_json::to_string(&e).unwrap();
            let back: TaskEnvelope = serde_json::from_str(&json).unwrap();
            assert_eq!(e.name, back.name);
        }
    }
}
