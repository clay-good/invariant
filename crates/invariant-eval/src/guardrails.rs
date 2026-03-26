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
}
