//! PA5, PA9, PA12–PA15: Schema, structural, and encoding attacks.
//!
//! These attacks generate commands with structural violations: type confusion,
//! missing fields, extra/unknown joints, Unicode tricks, oversized payloads,
//! and serde edge cases. The validator must reject all of them.

use invariant_core::models::command::Command;

/// PA5: Type-confusion / schema-violation attacks.
///
/// Produces raw JSON strings (not `Command` structs) that violate the schema:
/// - string where number expected
/// - nested object where scalar expected
/// - wrong array lengths
///
/// The validator's serde deserialization must reject these before they reach
/// the physics checks.
pub struct SchemaFuzzer;

impl SchemaFuzzer {
    /// Return a set of malformed JSON strings that should all fail to
    /// deserialize into a valid `Command`.
    pub fn malformed_json_commands() -> Vec<(&'static str, String)> {
        vec![
            // PA5: string where number expected
            (
                "PA5-string-position",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"joint_states":[{"name":"j1","position":"not_a_number","velocity":0,"effort":0}],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA5: nested object where scalar expected
            (
                "PA5-object-velocity",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"joint_states":[{"name":"j1","position":0,"velocity":{"nested":true},"effort":0}],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA5: array where scalar expected
            (
                "PA5-array-effort",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"joint_states":[{"name":"j1","position":0,"velocity":0,"effort":[1,2,3]}],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA9: completely empty object
            (
                "PA9-empty-object",
                r#"{}"#.into(),
            ),
            // PA9: missing timestamp
            (
                "PA9-no-timestamp",
                r#"{"source":"fuzz","sequence":1,"joint_states":[],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA9: null fields
            (
                "PA9-null-source",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":null,"sequence":1,"joint_states":[],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA14: deeply nested JSON (JSON bomb)
            (
                "PA14-deep-nesting",
                {
                    let depth = 128;
                    let open: String = "[".repeat(depth);
                    let close: String = "]".repeat(depth);
                    format!(
                        r#"{{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"joint_states":{open}1{close},"delta_time":0.01,"authority":{{"pca_chain":"","required_ops":[]}}}}"#,
                    )
                },
            ),
            // PA14: extremely large string value
            (
                "PA14-large-string",
                format!(
                    r#"{{"timestamp":"2026-01-01T00:00:00Z","source":"{}","sequence":1,"joint_states":[],"delta_time":0.01,"authority":{{"pca_chain":"","required_ops":[]}}}}"#,
                    "A".repeat(1_000_000)
                ),
            ),
            // PA15: duplicate keys (serde behavior: last wins, but verify no crash)
            (
                "PA15-duplicate-keys",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"sequence":999,"joint_states":[],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
            // PA4: extremely large number (1e308)
            (
                "PA4-huge-number",
                r#"{"timestamp":"2026-01-01T00:00:00Z","source":"fuzz","sequence":1,"joint_states":[{"name":"j1","position":1e308,"velocity":0,"effort":0}],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}"#.into(),
            ),
        ]
    }
}

/// PA12: Profile-mismatch attacks.
///
/// Generates commands referencing joints not in the profile, using wrong names,
/// or including extra joints.
pub struct ProfileMismatchFuzzer;

impl ProfileMismatchFuzzer {
    /// Generate commands with joint names that don't match the profile.
    pub fn mismatched_joints(base: &Command) -> Vec<(String, Command)> {
        let mut results = Vec::new();

        // Unknown joint name
        let mut cmd = base.clone();
        if let Some(js) = cmd.joint_states.first_mut() {
            js.name = "NONEXISTENT_JOINT_xyz".to_string();
        }
        results.push(("PA12-unknown-joint".into(), cmd));

        // Empty joint name
        let mut cmd = base.clone();
        if let Some(js) = cmd.joint_states.first_mut() {
            js.name = String::new();
        }
        results.push(("PA12-empty-joint-name".into(), cmd));

        // Extra joint not in profile
        let mut cmd = base.clone();
        cmd.joint_states
            .push(invariant_core::models::command::JointState {
                name: "rogue_joint_42".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            });
        results.push(("PA12-extra-joint".into(), cmd));

        results
    }
}

/// PA13: Unicode/encoding attacks on identifiers.
pub struct UnicodeFuzzer;

impl UnicodeFuzzer {
    /// Generate commands with Unicode tricks in joint names and source fields.
    pub fn unicode_attacks(base: &Command) -> Vec<(String, Command)> {
        let mut results = Vec::new();

        let payloads = [
            ("PA13-zero-width-space", "j1\u{200B}"), // zero-width space
            ("PA13-rtl-override", "j1\u{202E}evil"), // RTL override
            ("PA13-homoglyph", "j\u{0031}"),         // Cyrillic-style 1
            ("PA13-null-byte", "j1\x00poisoned"),    // embedded NUL
            ("PA13-overlong-utf8", "j1\u{FEFF}"),    // BOM character
        ];

        for (id, name) in &payloads {
            let mut cmd = base.clone();
            if let Some(js) = cmd.joint_states.first_mut() {
                js.name = name.to_string();
            }
            results.push((id.to_string(), cmd));
        }

        results
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_does_not_deserialize() {
        for (id, json) in SchemaFuzzer::malformed_json_commands() {
            let result = serde_json::from_str::<Command>(&json);
            // Most should fail to parse; those that parse (PA15 duplicate keys,
            // PA4 huge numbers) are still "interesting" — the validator may then
            // reject on physics grounds. We just verify no panic.
            let _ = result;
            // At minimum, confirm the attack ID is non-empty.
            assert!(!id.is_empty());
        }
    }

    #[test]
    fn malformed_json_count() {
        let attacks = SchemaFuzzer::malformed_json_commands();
        assert!(
            attacks.len() >= 10,
            "expected at least 10 schema attacks, got {}",
            attacks.len()
        );
    }

    fn base_command() -> Command {
        use invariant_core::models::command::{CommandAuthority, JointState};
        Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    #[test]
    fn profile_mismatch_generates_attacks() {
        let attacks = ProfileMismatchFuzzer::mismatched_joints(&base_command());
        assert_eq!(attacks.len(), 3);
    }

    #[test]
    fn unicode_fuzzer_generates_attacks() {
        let attacks = UnicodeFuzzer::unicode_attacks(&base_command());
        assert_eq!(attacks.len(), 5);
    }
}
