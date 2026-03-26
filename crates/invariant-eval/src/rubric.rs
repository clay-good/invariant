// Custom YAML/JSON rubric loader

/// A rubric rule for trace evaluation.
#[derive(Debug, Clone)]
pub struct RubricRule {
    pub name: String,
    pub check_name: String,
    pub expected_passed: bool,
}

/// A loaded rubric containing evaluation rules.
#[derive(Debug, Clone)]
pub struct Rubric {
    pub name: String,
    pub rules: Vec<RubricRule>,
}

/// Load a rubric from a JSON string.
///
/// # Status
///
/// **Not yet implemented.** This function is a stub that always returns an
/// error. The `--rubric` flag in the `eval` subcommand is intentionally
/// blocked until this loader is complete.  Callers must not rely on this
/// function returning a valid `Rubric` until the TODO below is resolved.
///
/// # TODO
///
/// Implement JSON rubric deserialization:
/// 1. Define a serde-deserializable mirror struct for the JSON schema.
/// 2. Parse `_json` with `serde_json::from_str`.
/// 3. Validate that each `RubricRule.check_name` is non-empty.
/// 4. Return `Err` with a descriptive message on parse or validation failure.
pub fn load_rubric_json(_json: &str) -> Result<Rubric, String> {
    // TODO: implement JSON rubric loading (see doc comment above).
    Err("rubric loading is not yet implemented; \
         the --rubric flag is currently unsupported"
        .into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rubric_json_returns_error_for_any_input() {
        // Stub always returns an error until the full implementation lands.
        let result = load_rubric_json(r#"{"name":"test","rules":[]}"#);
        assert!(result.is_err(), "stub must return an error");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not yet implemented") || msg.contains("currently unsupported"),
            "error message should explain the stub status, got: {msg}"
        );
    }

    #[test]
    fn load_rubric_json_returns_error_for_empty_input() {
        let result = load_rubric_json("");
        assert!(result.is_err());
    }

    #[test]
    fn rubric_rule_fields_are_accessible() {
        // Verify the public struct API is usable without going through the
        // unimplemented loader.
        let rule = RubricRule {
            name: "authority_must_pass".into(),
            check_name: "authority".into(),
            expected_passed: true,
        };
        assert_eq!(rule.name, "authority_must_pass");
        assert_eq!(rule.check_name, "authority");
        assert!(rule.expected_passed);
    }

    #[test]
    fn rubric_fields_are_accessible() {
        let rubric = Rubric {
            name: "safety-rubric".into(),
            rules: vec![RubricRule {
                name: "r1".into(),
                check_name: "joint_limits".into(),
                expected_passed: true,
            }],
        };
        assert_eq!(rubric.name, "safety-rubric");
        assert_eq!(rubric.rules.len(), 1);
        assert_eq!(rubric.rules[0].check_name, "joint_limits");
    }
}
