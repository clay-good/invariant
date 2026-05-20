//! Protocol-payload invariants PR1–PR4.
//!
//! Step 9 wires the previously-ignored `SynthesisPayload::Protocol` variant
//! into the validator pipeline. The four invariants here focus on the
//! *structure* of a lab-automation protocol — step count, vocabulary,
//! nesting, and aggregate volume — rather than on biology / chemistry per
//! se. They run for every bundle but always pass for non-protocol payloads.
//!
//! ## Allowed-vocabulary policy
//!
//! Profiles do not yet carry a per-installation step whitelist. PR2 falls
//! back to a conservative built-in vocabulary covering common ECL / Opentrons
//! / synthesizer verbs. The profile field can be added later without
//! breaking PR2's contract: any new vocabulary entries simply replace this
//! built-in list.

use serde::{Deserialize, Serialize};

use super::{Invariant, InvariantContext, InvariantId, InvariantStatus};
use crate::models::bundle::{SynthesisBundle, SynthesisPayload};

/// Vocabulary version for the built-in allowed verb list.
///
/// Increment this constant whenever the built-in verb list changes. All
/// deployed profiles must re-validate after a version bump because existing
/// `allowed_protocol_steps` entries may reference verbs that were removed.
/// New verbs can only be added via an RFC process — see `docs/rfcs/README.md`.
pub const PROTOCOL_STEP_VOCAB_VERSION: u32 = 1;

/// Hard upper bound on protocol step count, regardless of profile.
const MAX_STEPS: usize = 256;

/// Built-in allowed step verbs. Each protocol step is matched
/// case-insensitively against the first whitespace-delimited token.
const ALLOWED_VERBS: &[&str] = &[
    "aspirate",
    "dispense",
    "mix",
    "incubate",
    "centrifuge",
    "transfer",
    "wash",
    "elute",
    "heat",
    "cool",
    "shake",
    "vortex",
    "ligate",
    "digest",
    "amplify",
    "anneal",
    "denature",
    "extend",
    "couple",
    "deprotect",
    "cleave",
    "wait",
    "measure",
    "image",
    "log",
];

/// Tokens that indicate a nested protocol invocation.
const NESTED_TOKENS: &[&str] = &["protocol:", "include:", "subprotocol:", "run-protocol"];

/// Returns `true` if `verb` is in the built-in allowed verb list.
pub fn is_builtin_verb(verb: &str) -> bool {
    ALLOWED_VERBS.contains(&verb)
}

fn protocol_steps(bundle: &SynthesisBundle) -> Option<&[String]> {
    match &bundle.payload {
        SynthesisPayload::Protocol { steps } => Some(steps.as_slice()),
        _ => None,
    }
}

fn fail(reason: impl Into<String>) -> InvariantStatus {
    InvariantStatus::Fail {
        reason: reason.into(),
    }
}

fn advisory(note: impl Into<String>) -> InvariantStatus {
    InvariantStatus::Advisory { note: note.into() }
}

// ---------------------------------------------------------------------------
// PR1 — Step count bound
// ---------------------------------------------------------------------------

/// PR1 — Step-count bound.
///
/// Empty protocols are infeasible (no work). Protocols longer than the
/// internal `MAX_STEPS` constant (256) are rejected as runaway and almost
/// always indicate a planner loop or copy-paste error rather than
/// legitimate research.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolStepCount;

impl Invariant for ProtocolStepCount {
    fn id(&self) -> InvariantId {
        InvariantId::Pr1
    }
    fn name(&self) -> &'static str {
        "protocol_step_count"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(steps) = protocol_steps(bundle) else {
            return InvariantStatus::Pass;
        };
        if steps.is_empty() {
            return fail("protocol has zero steps".to_string());
        }
        if steps.len() > MAX_STEPS {
            return fail(format!(
                "protocol has {} steps (cap {MAX_STEPS})",
                steps.len()
            ));
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// PR2 — Allowed step vocabulary
// ---------------------------------------------------------------------------

/// PR2 — Step-vocabulary check.
///
/// Each step's first token (case-insensitive) must appear in the built-in
/// allowed verb list. Steps with verbs outside that list fail; advisories
/// are out of scope here because executor platforms reject unknown verbs
/// hard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAllowedVocabulary;

impl Invariant for ProtocolAllowedVocabulary {
    fn id(&self) -> InvariantId {
        InvariantId::Pr2
    }
    fn name(&self) -> &'static str {
        "protocol_allowed_vocabulary"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(steps) = protocol_steps(bundle) else {
            return InvariantStatus::Pass;
        };
        let mut bad: Vec<(usize, String)> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let verb = step
                .split_whitespace()
                .next()
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if verb.is_empty() {
                bad.push((i, "<empty>".to_string()));
                continue;
            }
            // Strip trailing punctuation (e.g. "aspirate," → "aspirate").
            let verb = verb.trim_end_matches([',', ':', ';', '(']);
            if !ALLOWED_VERBS.contains(&verb) {
                bad.push((i, verb.to_string()));
            }
        }
        if bad.is_empty() {
            InvariantStatus::Pass
        } else {
            let summary = bad
                .iter()
                .map(|(i, v)| format!("step {i}: {v:?}"))
                .collect::<Vec<_>>()
                .join("; ");
            fail(format!("disallowed step verbs: {summary}"))
        }
    }

    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(steps) = protocol_steps(bundle) else {
            return InvariantStatus::Pass;
        };
        // Use profile-supplied list if present, otherwise fall back to built-in default.
        let allowed_verbs: Vec<&str> =
            if let Some(ref profile_steps) = ctx.profile.allowed_protocol_steps {
                profile_steps.iter().map(|s| s.as_str()).collect()
            } else {
                ALLOWED_VERBS.to_vec()
            };

        let mut bad: Vec<(usize, String)> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let verb = step
                .split_whitespace()
                .next()
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if verb.is_empty() {
                bad.push((i, "<empty>".to_string()));
                continue;
            }
            let verb = verb.trim_end_matches([',', ':', ';', '(']);
            if !allowed_verbs.contains(&verb) {
                bad.push((i, verb.to_string()));
            }
        }
        if bad.is_empty() {
            InvariantStatus::Pass
        } else {
            let summary = bad
                .iter()
                .map(|(i, v)| format!("step {i}: {v:?}"))
                .collect::<Vec<_>>()
                .join("; ");
            fail(format!("disallowed step verbs: {summary}"))
        }
    }
}

// ---------------------------------------------------------------------------
// PR3 — No nested protocols
// ---------------------------------------------------------------------------

/// PR3 — No-nested-protocol rule.
///
/// Protocol steps must not invoke other protocols (e.g. via `protocol:foo`
/// or `include:bar` directives). Nested protocols circumvent the
/// per-bundle invariant pipeline and are therefore rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolNoNested;

impl Invariant for ProtocolNoNested {
    fn id(&self) -> InvariantId {
        InvariantId::Pr3
    }
    fn name(&self) -> &'static str {
        "protocol_no_nested"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(steps) = protocol_steps(bundle) else {
            return InvariantStatus::Pass;
        };
        for (i, step) in steps.iter().enumerate() {
            let lower = step.to_ascii_lowercase();
            for tok in NESTED_TOKENS {
                if lower.contains(tok) {
                    return fail(format!("step {i} invokes nested protocol token {tok:?}"));
                }
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// PR4 — Aggregate volume vs profile cap
// ---------------------------------------------------------------------------

/// PR4 — Aggregate-volume budget.
///
/// Sums any explicit volume tokens of the form `<number>(uL|ul|mL|ml|L)`
/// embedded in step strings and compares the total (in mL) against the
/// profile's `max_synthesis_volume_ml`. Steps without parsable volumes are
/// ignored — this is a fail-safe upper-bound check, not a planner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAggregateVolume;

impl Invariant for ProtocolAggregateVolume {
    fn id(&self) -> InvariantId {
        InvariantId::Pr4
    }
    fn name(&self) -> &'static str {
        "protocol_aggregate_volume"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(steps) = protocol_steps(bundle) else {
            return InvariantStatus::Pass;
        };
        let cap_ml = ctx.profile.max_synthesis_volume_ml;
        let mut total_ml = 0.0f64;
        for step in steps {
            for vol_ml in extract_volumes_ml(step) {
                total_ml += vol_ml;
            }
        }
        if total_ml > cap_ml {
            fail(format!(
                "aggregate volume {:.3} mL exceeds profile cap {:.3} mL",
                total_ml, cap_ml
            ))
        } else if total_ml > 0.5 * cap_ml {
            advisory(format!(
                "aggregate volume {:.3} mL is over half of profile cap {:.3} mL",
                total_ml, cap_ml
            ))
        } else {
            InvariantStatus::Pass
        }
    }
}

/// Pull every `<number><unit>` volume token from `step`, normalizing to mL.
/// Recognised units: `uL`, `ul`, `µL`, `mL`, `ml`, `L`. Unknown / missing
/// units yield no contribution.
fn extract_volumes_ml(step: &str) -> Vec<f64> {
    let bytes = step.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        // Find a digit start.
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let num_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let num_end = i;
        // Skip whitespace between number and unit.
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &step[unit_start..i];
        let Some(num_str) = step.get(num_start..num_end) else {
            continue;
        };
        let Ok(num) = num_str.parse::<f64>() else {
            continue;
        };
        let factor_to_ml = match unit.to_ascii_lowercase().as_str() {
            "ul" => Some(0.001),
            "ml" => Some(1.0),
            "l" => Some(1000.0),
            _ => None,
        };
        if let Some(f) = factor_to_ml {
            out.push(num * f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use crate::models::profile::BioProfile;
    use chrono::Utc;

    fn protocol(steps: Vec<&str>) -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Protocol {
                steps: steps.into_iter().map(String::from).collect(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    fn dna_bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Dna {
                sequence: "ATGCGT".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    fn profile(cap_ml: f64) -> BioProfile {
        BioProfile {
            name: "t".into(),
            version: "0.1.0".into(),
            bsl_level: 2,
            allowed_substrates: vec!["protocol".into()],
            max_synthesis_volume_ml: cap_ml,
            export_controlled: false,
            profile_signature: None,
            profile_signer_kid: None,
            codon_usage_organism: None,
            codon_entropy_band: None,
            protein_kmer_k: None,
            protein_kmer_threshold: None,
            allowed_protocol_steps: None,
            allow_stale_screening: false,
            stale_screening_max_days: None,
            max_authority_chain_depth: 5,
            max_dna_length_bp: None,
            max_peptide_length_aa: None,
            max_smiles_length_chars: None,
        }
    }

    fn ctx<'a>(prof: &'a BioProfile) -> InvariantContext<'a> {
        InvariantContext {
            screening_hits: &[],
            profile: prof,
        }
    }

    // ---- PR1 ----
    #[test]
    fn pr1_empty_protocol_fails() {
        assert!(matches!(
            ProtocolStepCount.evaluate(&protocol(vec![])),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn pr1_oversized_protocol_fails() {
        let many: Vec<&str> = (0..MAX_STEPS + 1).map(|_| "aspirate 10uL").collect();
        assert!(matches!(
            ProtocolStepCount.evaluate(&protocol(many)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn pr1_normal_protocol_passes() {
        assert!(matches!(
            ProtocolStepCount.evaluate(&protocol(vec!["aspirate 10uL"])),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn pr1_non_protocol_passes() {
        assert!(matches!(
            ProtocolStepCount.evaluate(&dna_bundle()),
            InvariantStatus::Pass
        ));
    }

    // ---- PR2 ----
    #[test]
    fn pr2_allowed_verbs_pass() {
        let p = protocol(vec!["aspirate 10uL", "dispense 10uL", "mix 5"]);
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate(&p),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn pr2_disallowed_verb_fails() {
        let p = protocol(vec!["aspirate 10uL", "explode chamber"]);
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate(&p),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn pr2_empty_step_fails() {
        let p = protocol(vec!["aspirate 10uL", ""]);
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate(&p),
            InvariantStatus::Fail { .. }
        ));
    }

    // ---- PR3 ----
    #[test]
    fn pr3_clean_passes() {
        let p = protocol(vec!["aspirate 10uL"]);
        assert!(matches!(
            ProtocolNoNested.evaluate(&p),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn pr3_protocol_token_fails() {
        let p = protocol(vec!["protocol:foo"]);
        assert!(matches!(
            ProtocolNoNested.evaluate(&p),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn pr3_include_token_fails() {
        let p = protocol(vec!["include:other-protocol"]);
        assert!(matches!(
            ProtocolNoNested.evaluate(&p),
            InvariantStatus::Fail { .. }
        ));
    }

    // ---- PR4 ----
    #[test]
    fn pr4_under_cap_passes() {
        let prof = profile(10.0);
        let p = protocol(vec!["aspirate 100uL", "dispense 200uL"]);
        assert!(matches!(
            ProtocolAggregateVolume.evaluate_with(&p, &ctx(&prof)),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn pr4_over_cap_fails() {
        let prof = profile(0.5);
        let p = protocol(vec!["aspirate 600uL"]);
        assert!(matches!(
            ProtocolAggregateVolume.evaluate_with(&p, &ctx(&prof)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn pr4_over_half_advisory() {
        let prof = profile(1.0);
        // 600 uL = 0.6 mL, > 0.5 * 1.0
        let p = protocol(vec!["aspirate 600uL"]);
        assert!(matches!(
            ProtocolAggregateVolume.evaluate_with(&p, &ctx(&prof)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn pr4_no_volumes_passes() {
        let prof = profile(1.0);
        let p = protocol(vec!["mix"]);
        assert!(matches!(
            ProtocolAggregateVolume.evaluate_with(&p, &ctx(&prof)),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn pr4_unit_aware() {
        let prof = profile(0.5);
        // 1 mL > 0.5 mL cap.
        let p = protocol(vec!["dispense 1mL"]);
        assert!(matches!(
            ProtocolAggregateVolume.evaluate_with(&p, &ctx(&prof)),
            InvariantStatus::Fail { .. }
        ));
    }

    // ---- PR2 profile-driven vocabulary ----
    #[test]
    fn pr2_profile_restricted_list_rejects_default_verb() {
        // Profile only allows "aspirate" and "dispense"
        let mut prof = profile(10.0);
        prof.allowed_protocol_steps = Some(vec!["aspirate".into(), "dispense".into()]);
        let c = ctx(&prof);
        let p = protocol(vec!["aspirate 10uL", "mix 5"]); // "mix" not in restricted list
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate_with(&p, &c),
            InvariantStatus::Fail { .. }
        ));
    }

    #[test]
    fn pr2_empty_profile_list_rejects_everything() {
        let mut prof = profile(10.0);
        prof.allowed_protocol_steps = Some(vec![]);
        let c = ctx(&prof);
        let p = protocol(vec!["aspirate 10uL"]);
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate_with(&p, &c),
            InvariantStatus::Fail { .. }
        ));
    }

    #[test]
    fn pr2_no_profile_field_uses_default() {
        let prof = profile(10.0);
        let c = ctx(&prof);
        let p = protocol(vec!["aspirate 10uL", "dispense 10uL"]);
        assert!(matches!(
            ProtocolAllowedVocabulary.evaluate_with(&p, &c),
            InvariantStatus::Pass
        ));
    }

    #[test]
    fn pr2_non_subset_profile_fails_validation() {
        use crate::models::error::Validate;
        let mut prof = profile(10.0);
        prof.allowed_protocol_steps = Some(vec!["aspirate".into(), "nuke_it".into()]);
        assert!(prof.validate().is_err());
    }

    // ---- Volume parser ----
    #[test]
    fn extract_volumes_ml_handles_common_units() {
        assert_eq!(extract_volumes_ml("aspirate 100uL"), vec![0.1]);
        assert_eq!(extract_volumes_ml("dispense 2.5 mL"), vec![2.5]);
        assert_eq!(extract_volumes_ml("transfer 1L"), vec![1000.0]);
        assert!(extract_volumes_ml("mix").is_empty());
        assert!(extract_volumes_ml("incubate at 37C").is_empty()); // 37C is not a volume unit.
    }
}
