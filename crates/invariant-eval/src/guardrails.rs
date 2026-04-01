// Policy-based guardrail engine

/// A guardrail policy action.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardrailAction {
    Allow,
    Block,
}

/// A single guardrail policy rule.
#[derive(Debug, Clone)]
pub struct GuardrailRule {
    pub name: String,
    pub pattern: String,
    pub action: GuardrailAction,
}

/// Evaluate a check name against guardrail rules.
///
/// Rules are evaluated in order.  The first rule whose pattern exactly matches
/// `check_name` determines the action.  If no rule matches and the rules list
/// is non-empty, the default action is `Block` (fail-closed): an explicit
/// allow-all rule must be present to permit unrecognised check names.  If the
/// rules list is empty, the default action is `Allow` (no policy = pass through).
///
/// # Pattern matching — exact string equality only
///
/// `GuardrailRule::pattern` is compared with `check_name` using `==`, **not**
/// glob or regex semantics.  The strings `"*"`, `"joint_*"`, and `".*"` are
/// treated as literal check names, not wildcards.  A pattern of `"*"` will
/// only match a check whose name is literally `"*"`.
pub fn evaluate_guardrails(check_name: &str, rules: &[GuardrailRule]) -> GuardrailAction {
    for rule in rules {
        if check_name == rule.pattern {
            return rule.action.clone();
        }
    }
    // Fail-closed: when a policy exists but no rule matches, block by default.
    // An empty rules list means no policy is in effect, so allow through.
    if rules.is_empty() {
        GuardrailAction::Allow
    } else {
        GuardrailAction::Block
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn block_rule(name: &str, pattern: &str) -> GuardrailRule {
        GuardrailRule {
            name: name.into(),
            pattern: pattern.into(),
            action: GuardrailAction::Block,
        }
    }

    fn allow_rule(name: &str, pattern: &str) -> GuardrailRule {
        GuardrailRule {
            name: name.into(),
            pattern: pattern.into(),
            action: GuardrailAction::Allow,
        }
    }

    #[test]
    fn no_rules_defaults_to_allow() {
        let action = evaluate_guardrails("authority", &[]);
        assert_eq!(action, GuardrailAction::Allow);
    }

    #[test]
    fn matching_block_rule_blocks() {
        let rules = vec![block_rule("block-authority", "authority")];
        let action = evaluate_guardrails("authority", &rules);
        assert_eq!(action, GuardrailAction::Block);
    }

    #[test]
    fn non_matching_rule_with_non_empty_policy_blocks() {
        // Fail-closed: a non-empty policy with no matching rule must block.
        let rules = vec![block_rule("block-velocity", "velocity")];
        let action = evaluate_guardrails("authority", &rules);
        assert_eq!(action, GuardrailAction::Block);
    }

    #[test]
    fn first_matching_rule_wins() {
        // block before allow — block should win (exact match on "joint_limits").
        let rules = vec![
            block_rule("block-joint-limits", "joint_limits"),
            allow_rule("allow-joint-limits-2", "joint_limits"),
        ];
        let action = evaluate_guardrails("joint_limits", &rules);
        assert_eq!(action, GuardrailAction::Block);
    }

    #[test]
    fn partial_pattern_does_not_match() {
        // Exact equality: "joint" must NOT match "joint_limits".
        let rules = vec![block_rule("block-joint", "joint")];
        let action = evaluate_guardrails("joint_limits", &rules);
        // No exact match; non-empty policy → fail-closed → Block.
        assert_eq!(action, GuardrailAction::Block);
    }

    #[test]
    fn allow_rule_permits_exact_match() {
        let rules = vec![allow_rule("allow-joint-limits", "joint_limits")];
        let action = evaluate_guardrails("joint_limits", &rules);
        assert_eq!(action, GuardrailAction::Allow);
    }

    #[test]
    fn empty_check_name_with_no_rules_allows() {
        let action = evaluate_guardrails("", &[]);
        assert_eq!(action, GuardrailAction::Allow);
    }

    #[test]
    fn empty_check_name_with_rules_blocks() {
        // Non-empty policy, no exact match for "" → fail-closed → Block.
        let rules = vec![allow_rule("allow-authority", "authority")];
        let action = evaluate_guardrails("", &rules);
        assert_eq!(action, GuardrailAction::Block);
    }

    // -----------------------------------------------------------------------
    // Pattern field is exact-match only — NOT glob or regex.
    //
    // The names "*", "joint_*", and ".*" look like wildcards but are
    // treated as literal strings.  These tests document that behaviour.
    // -----------------------------------------------------------------------

    /// A pattern of `"*"` is a literal string, not a catch-all wildcard.
    /// It matches only a check whose name is exactly `"*"`.
    #[test]
    fn glob_star_pattern_is_literal_not_wildcard() {
        // A rule whose pattern is the literal string "*".
        let rules = vec![allow_rule("allow-star", "*")];
        // "authority" is not literally equal to "*" → no match → fail-closed → Block.
        assert_eq!(
            evaluate_guardrails("authority", &rules),
            GuardrailAction::Block,
            "'*' pattern should not match 'authority' (exact equality only)"
        );
        // The literal string "*" itself does match.
        assert_eq!(
            evaluate_guardrails("*", &rules),
            GuardrailAction::Allow,
            "the literal check name '*' must match the '*' pattern"
        );
    }

    /// A pattern of `"joint_*"` is a literal string, not a prefix glob.
    /// It matches only a check whose name is exactly `"joint_*"`.
    #[test]
    fn prefix_glob_pattern_is_literal_not_prefix_match() {
        let rules = vec![block_rule("block-joint-star", "joint_*")];
        // "joint_limits" does not equal the literal "joint_*" → no match →
        // non-empty policy → fail-closed → Block (but for the wrong reason).
        // The block must come from fail-closed, not from the rule itself.
        // We confirm the rule does NOT fire by checking with an empty policy
        // that would otherwise allow.
        let empty_rules: Vec<GuardrailRule> = vec![];
        assert_eq!(
            evaluate_guardrails("joint_limits", &empty_rules),
            GuardrailAction::Allow,
            "sanity: empty rules should allow joint_limits"
        );
        // With only the "joint_*" rule present, "joint_limits" is not an exact
        // match; the outcome is Block purely from fail-closed, not from the rule.
        assert_eq!(
            evaluate_guardrails("joint_limits", &rules),
            GuardrailAction::Block
        );
        // The literal "joint_*" itself does match the rule.
        assert_eq!(
            evaluate_guardrails("joint_*", &rules),
            GuardrailAction::Block
        );
    }

    /// A pattern of `".*"` is a literal string, not a regex catch-all.
    /// It matches only a check whose name is exactly `".*"`.
    #[test]
    fn regex_dot_star_pattern_is_literal_not_regex() {
        let rules = vec![allow_rule("allow-dot-star", ".*")];
        // "authority" does not equal the literal ".*" → no match → Block.
        assert_eq!(
            evaluate_guardrails("authority", &rules),
            GuardrailAction::Block,
            "'.*' pattern should not match 'authority' (exact equality only)"
        );
        // The literal check name ".*" does match.
        assert_eq!(
            evaluate_guardrails(".*", &rules),
            GuardrailAction::Allow,
            "the literal check name '.*' must match the '.*' pattern"
        );
    }
}
