// Intent-to-operations pipeline (Section 15).
//
// Converts human intent into a signed PCA_0 with explicit operations. Three
// modes, all producing the same artifact:
//
// - **Template-based** (Option B): Predefined task templates with parameter
//   substitution. Operator selects a template and fills in parameters.
// - **Direct specification** (Option C): Operator specifies raw operations
//   directly.
// - **LLM-assisted** (Option A): External LLM extracts structured intent,
//   which is then fed through the template or direct path. Not implemented
//   here — this module provides the deterministic backend that Option A calls.
//
// Design: no I/O, no LLM, no network. Pure functions that take intent
// parameters and produce a Pca claim ready for signing.
//
// Bio adaptation: the robotics task templates (`pick_and_place`,
// `bimanual_pickup`, etc.) are replaced with bio-relevant templates
// (`synthesize_dna_fragment`, `run_peptide_coupling`, `dispense_reagent`).
// The narrowing algebra is verbatim from the robotics port.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use invariant_core::models::authority::{Operation, Pca};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the intent-to-operations pipeline.
#[derive(Debug, Error)]
pub enum IntentError {
    /// The named template does not exist in the built-in template set.
    #[error("unknown template: {name}")]
    UnknownTemplate {
        /// The unknown template name.
        name: String,
    },

    /// A required template parameter was not supplied in the `params` map.
    #[error("missing parameter: {param} (required by template {template})")]
    MissingParameter {
        /// Template that required the missing parameter.
        template: String,
        /// Name of the missing parameter.
        param: String,
    },

    /// An operation string produced by template substitution or direct spec is invalid.
    #[error("invalid operation: {reason}")]
    InvalidOperation {
        /// Description of why the operation string is invalid.
        reason: String,
    },

    /// No operations were specified (empty list).
    #[error("empty operations: at least one operation must be specified")]
    EmptyOperations,

    /// The provided duration is not positive and finite.
    #[error("invalid duration: {seconds}s (must be positive and finite)")]
    InvalidDuration {
        /// The invalid duration value in seconds.
        seconds: f64,
    },
}

// ---------------------------------------------------------------------------
// Task template (Option B)
// ---------------------------------------------------------------------------

/// A predefined task template with parameterized operation patterns.
///
/// Parameters are denoted by `{name}` in the operation pattern strings.
/// Example: `"synthesize:{substrate}:*"` with parameter `substrate = "dna"`
/// produces `"synthesize:dna:*"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTemplate {
    /// Template name (e.g., "synthesize_dna_fragment").
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Operation patterns with `{param}` placeholders.
    pub operation_patterns: Vec<String>,
    /// Names of required parameters (must be supplied by the operator).
    pub required_params: Vec<String>,
    /// Default duration in seconds (operator can override).
    #[serde(default = "default_duration")]
    pub default_duration_s: f64,
}

fn default_duration() -> f64 {
    3600.0
}

/// The standard bio task templates shipped with Invariant Biosynthesis.
pub fn builtin_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            name: "synthesize_dna_fragment".into(),
            description: "Synthesize a DNA fragment of a specified length on a specific platform"
                .into(),
            operation_patterns: vec!["synthesize:dna:{platform}".into()],
            required_params: vec!["platform".into()],
            default_duration_s: 3600.0,
        },
        TaskTemplate {
            name: "run_peptide_coupling".into(),
            description: "Run a peptide coupling step on a synthesizer for a given residue type"
                .into(),
            operation_patterns: vec!["synthesize:peptide:couple".into()],
            required_params: vec![],
            default_duration_s: 600.0,
        },
        TaskTemplate {
            name: "dispense_reagent".into(),
            description: "Dispense a controlled-volume reagent into a labware destination".into(),
            operation_patterns: vec!["liquid:dispense:{platform}".into()],
            required_params: vec!["platform".into()],
            default_duration_s: 60.0,
        },
        TaskTemplate {
            name: "synthesize_chemical".into(),
            description: "Run an automated small-molecule synthesis on a chemspeed-class platform"
                .into(),
            operation_patterns: vec!["synthesize:chemical:{platform}".into()],
            required_params: vec!["platform".into()],
            default_duration_s: 7200.0,
        },
        TaskTemplate {
            name: "execute_protocol".into(),
            description: "Execute a multi-step lab protocol on a single automation platform".into(),
            operation_patterns: vec![
                "protocol:execute:{platform}".into(),
                "liquid:dispense:{platform}".into(),
            ],
            required_params: vec!["platform".into()],
            default_duration_s: 3600.0,
        },
        TaskTemplate {
            name: "prepare_chemical_compound".into(),
            description:
                "Prepare a small-molecule compound from a target SMILES on the given platform"
                    .into(),
            operation_patterns: vec![
                "synthesize:chemical:{platform}".into(),
                "liquid:dispense:{platform}".into(),
            ],
            required_params: vec!["platform".into()],
            default_duration_s: 7200.0,
        },
        TaskTemplate {
            name: "assemble_plasmid".into(),
            description: "Assemble a plasmid from DNA fragments on a Golden-Gate-class assembler"
                .into(),
            operation_patterns: vec![
                "synthesize:dna:{platform}".into(),
                "assemble:plasmid:{platform}".into(),
            ],
            required_params: vec!["platform".into()],
            default_duration_s: 7200.0,
        },
        TaskTemplate {
            name: "screen_library".into(),
            description: "Screen a compound or fragment library against a target on a plate reader"
                .into(),
            operation_patterns: vec![
                "screen:library:{platform}".into(),
                "measure:plate:{platform}".into(),
            ],
            required_params: vec!["platform".into()],
            default_duration_s: 14400.0,
        },
        TaskTemplate {
            name: "purify_product".into(),
            description: "Purify a synthesis product on the given chromatography platform".into(),
            operation_patterns: vec!["purify:product:{platform}".into()],
            required_params: vec!["platform".into()],
            default_duration_s: 1800.0,
        },
    ]
}

/// Find a built-in template by name.
pub fn find_template(name: &str) -> Option<TaskTemplate> {
    builtin_templates().into_iter().find(|t| t.name == name)
}

// ---------------------------------------------------------------------------
// Intent specification (shared output of all three modes)
// ---------------------------------------------------------------------------

/// The output of intent resolution: everything needed to build a signed PCA_0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIntent {
    /// The principal who authorized this intent (operator identity).
    pub principal: String,
    /// Concrete operations granted.
    pub operations: Vec<String>,
    /// Key identifier for signing.
    pub kid: String,
    /// Expiry time (None = no expiry).
    pub expiry: Option<DateTime<Utc>>,
    /// How this intent was resolved.
    pub source: IntentSource,
}

/// How the intent was resolved (for audit trail).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentSource {
    /// Template-based (Option B).
    Template {
        /// Name of the task template that was instantiated.
        template_name: String,
    },
    /// Direct specification (Option C).
    Direct,
}

// ---------------------------------------------------------------------------
// Template-based resolution (Option B)
// ---------------------------------------------------------------------------

/// Resolve a task template with supplied parameters, producing a `ResolvedIntent`.
///
/// `params` maps parameter names to their values (e.g., `"platform" -> "twist"`).
/// All `required_params` in the template must be present in `params`.
pub fn resolve_template(
    template: &TaskTemplate,
    params: &std::collections::HashMap<String, String>,
    principal: &str,
    kid: &str,
    duration_override_s: Option<f64>,
) -> Result<ResolvedIntent, IntentError> {
    // Check all required parameters are present.
    for req in &template.required_params {
        if !params.contains_key(req) {
            return Err(IntentError::MissingParameter {
                template: template.name.clone(),
                param: req.clone(),
            });
        }
    }

    // Substitute parameters in operation patterns.
    let mut operations = Vec::new();
    for pattern in &template.operation_patterns {
        let mut resolved = pattern.clone();
        for (key, value) in params {
            resolved = resolved.replace(&format!("{{{key}}}"), value);
        }
        // Validate the resolved operation string.
        Operation::new(&resolved).map_err(|e| IntentError::InvalidOperation {
            reason: e.to_string(),
        })?;
        operations.push(resolved);
    }

    if operations.is_empty() {
        return Err(IntentError::EmptyOperations);
    }

    let duration_s = duration_override_s.unwrap_or(template.default_duration_s);
    let expiry = make_expiry(duration_s)?;

    Ok(ResolvedIntent {
        principal: principal.to_string(),
        operations,
        kid: kid.to_string(),
        expiry,
        source: IntentSource::Template {
            template_name: template.name.clone(),
        },
    })
}

// ---------------------------------------------------------------------------
// Direct specification (Option C)
// ---------------------------------------------------------------------------

/// Build a `ResolvedIntent` from directly-specified operations (expert mode).
///
/// Each operation string is validated via `Operation::new()`.
pub fn resolve_direct(
    operations: &[String],
    principal: &str,
    kid: &str,
    duration_s: Option<f64>,
) -> Result<ResolvedIntent, IntentError> {
    if operations.is_empty() {
        return Err(IntentError::EmptyOperations);
    }

    // Validate each operation.
    for op_str in operations {
        Operation::new(op_str).map_err(|e| IntentError::InvalidOperation {
            reason: e.to_string(),
        })?;
    }

    let expiry = match duration_s {
        Some(d) => make_expiry(d)?,
        None => None,
    };

    Ok(ResolvedIntent {
        principal: principal.to_string(),
        operations: operations.to_vec(),
        kid: kid.to_string(),
        expiry,
        source: IntentSource::Direct,
    })
}

// ---------------------------------------------------------------------------
// PCA construction
// ---------------------------------------------------------------------------

/// Convert a `ResolvedIntent` into a `Pca` claim ready for signing.
///
/// This is the common exit point: all three intent modes (template, direct,
/// LLM-assisted) produce a `ResolvedIntent`, which is then converted to a
/// `Pca` and signed with the operator's key.
pub fn intent_to_pca(intent: &ResolvedIntent) -> Result<Pca, IntentError> {
    let mut ops = BTreeSet::new();
    for op_str in &intent.operations {
        let op = Operation::new(op_str).map_err(|e| IntentError::InvalidOperation {
            reason: e.to_string(),
        })?;
        ops.insert(op);
    }

    if ops.is_empty() {
        return Err(IntentError::EmptyOperations);
    }

    Ok(Pca {
        p_0: intent.principal.clone(),
        ops,
        kid: intent.kid.clone(),
        exp: intent.expiry,
        nbf: None,
        predecessor_digest: [0u8; 32],
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_expiry(duration_s: f64) -> Result<Option<DateTime<Utc>>, IntentError> {
    if !duration_s.is_finite() || duration_s <= 0.0 {
        return Err(IntentError::InvalidDuration {
            seconds: duration_s,
        });
    }
    let millis = (duration_s * 1000.0) as i64;
    Ok(Some(Utc::now() + Duration::milliseconds(millis)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -- builtin_templates --

    #[test]
    fn builtin_templates_are_non_empty() {
        let templates = builtin_templates();
        assert!(!templates.is_empty());
        assert!(templates.len() >= 5);
    }

    #[test]
    fn find_template_known() {
        assert!(find_template("synthesize_dna_fragment").is_some());
        assert!(find_template("dispense_reagent").is_some());
    }

    #[test]
    fn find_template_unknown() {
        assert!(find_template("nonexistent_task").is_none());
    }

    // -- resolve_template --

    #[test]
    fn resolve_template_synthesize_dna_fragment() {
        let template = find_template("synthesize_dna_fragment").unwrap();
        let mut params = HashMap::new();
        params.insert("platform".into(), "twist".into());

        let result = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        assert_eq!(result.principal, "alice");
        assert_eq!(result.operations, vec!["synthesize:dna:twist"]);
        assert_eq!(result.kid, "key-1");
        assert!(result.expiry.is_some());
        assert!(matches!(result.source, IntentSource::Template { .. }));
    }

    #[test]
    fn resolve_template_missing_param() {
        let template = find_template("synthesize_dna_fragment").unwrap();
        let params = HashMap::new(); // platform is missing

        let result = resolve_template(&template, &params, "alice", "key-1", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing parameter"));
    }

    #[test]
    fn resolve_template_run_peptide_coupling_no_params_needed() {
        let template = find_template("run_peptide_coupling").unwrap();
        let params = HashMap::new();

        let result = resolve_template(&template, &params, "bob", "key-2", None).unwrap();
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0], "synthesize:peptide:couple");
    }

    #[test]
    fn resolve_template_duration_override() {
        let template = find_template("synthesize_dna_fragment").unwrap();
        let mut params = HashMap::new();
        params.insert("platform".into(), "idt".into());

        let result = resolve_template(&template, &params, "alice", "key-1", Some(10.0)).unwrap();
        // Expiry should be ~10s from now, not 3600s.
        let expiry = result.expiry.unwrap();
        let now = Utc::now();
        let diff = (expiry - now).num_seconds();
        assert!(
            (8..=12).contains(&diff),
            "expiry should be ~10s from now, got {diff}s"
        );
    }

    #[test]
    fn resolve_template_execute_protocol_produces_two_ops() {
        let template = find_template("execute_protocol").unwrap();
        let mut params = HashMap::new();
        params.insert("platform".into(), "tecan".into());

        let result = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        assert_eq!(result.operations.len(), 2);
        assert_eq!(result.operations[0], "protocol:execute:tecan");
        assert_eq!(result.operations[1], "liquid:dispense:tecan");
    }

    #[test]
    fn resolve_template_invalid_param_value() {
        let template = find_template("synthesize_dna_fragment").unwrap();
        let mut params = HashMap::new();
        // A value with spaces would produce an invalid operation.
        params.insert("platform".into(), "twist bioscience".into());

        let result = resolve_template(&template, &params, "alice", "key-1", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid operation"));
    }

    // -- resolve_direct --

    #[test]
    fn resolve_direct_single_op() {
        let ops = vec!["synthesize:dna:fragment".to_string()];
        let result = resolve_direct(&ops, "alice", "key-1", Some(30.0)).unwrap();
        assert_eq!(result.principal, "alice");
        assert_eq!(result.operations.len(), 1);
        assert!(result.expiry.is_some());
        assert!(matches!(result.source, IntentSource::Direct));
    }

    #[test]
    fn resolve_direct_multiple_ops() {
        let ops = vec![
            "synthesize:dna:fragment".to_string(),
            "synthesize:peptide:couple".to_string(),
            "liquid:dispense:tecan".to_string(),
        ];
        let result = resolve_direct(&ops, "alice", "key-1", None).unwrap();
        assert_eq!(result.operations.len(), 3);
        assert!(result.expiry.is_none()); // no duration -> no expiry
    }

    #[test]
    fn resolve_direct_empty_ops_fails() {
        let result = resolve_direct(&[], "alice", "key-1", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty operations"));
    }

    #[test]
    fn resolve_direct_invalid_op_fails() {
        let ops = vec!["synthesize::double_colon".to_string()]; // invalid
        let result = resolve_direct(&ops, "alice", "key-1", None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_direct_invalid_duration() {
        let ops = vec!["synthesize:dna:fragment".to_string()];
        let result = resolve_direct(&ops, "alice", "key-1", Some(-5.0));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duration"));
    }

    // -- intent_to_pca --

    #[test]
    fn intent_to_pca_from_template() {
        let template = find_template("synthesize_dna_fragment").unwrap();
        let mut params = HashMap::new();
        params.insert("platform".into(), "twist".into());

        let intent = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        let pca = intent_to_pca(&intent).unwrap();

        assert_eq!(pca.p_0, "alice");
        assert_eq!(pca.kid, "key-1");
        assert_eq!(pca.ops.len(), 1);
        assert!(pca
            .ops
            .iter()
            .any(|op| op.as_str() == "synthesize:dna:twist"));
        assert!(pca.exp.is_some());
        assert!(pca.nbf.is_none());
    }

    #[test]
    fn intent_to_pca_from_direct() {
        let intent = resolve_direct(
            &[
                "synthesize:dna:fragment".to_string(),
                "synthesize:peptide:couple".to_string(),
            ],
            "bob",
            "key-2",
            Some(60.0),
        )
        .unwrap();
        let pca = intent_to_pca(&intent).unwrap();

        assert_eq!(pca.p_0, "bob");
        assert_eq!(pca.ops.len(), 2);
        assert!(pca.exp.is_some());
    }

    #[test]
    fn intent_to_pca_ops_are_deduped() {
        // BTreeSet deduplicates identical operations.
        let intent = resolve_direct(
            &[
                "synthesize:dna:fragment".to_string(),
                "synthesize:dna:fragment".to_string(),
            ],
            "alice",
            "key-1",
            None,
        )
        .unwrap();
        let pca = intent_to_pca(&intent).unwrap();
        assert_eq!(pca.ops.len(), 1);
    }

    // -- round-trip: intent -> pca -> sign -> verify --

    #[test]
    fn full_round_trip_intent_to_signed_pca() {
        use crate::authority::crypto::{generate_keypair, sign_pca, verify_signed_pca};
        use rand::rngs::OsRng;

        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let template = find_template("synthesize_dna_fragment").unwrap();
        let mut params = HashMap::new();
        params.insert("platform".into(), "ansa".into());

        let intent =
            resolve_template(&template, &params, "operator_alice", "key-1", Some(30.0)).unwrap();
        let pca = intent_to_pca(&intent).unwrap();
        let signed = sign_pca(&pca, &sk).unwrap();

        // Verify the signature.
        assert!(verify_signed_pca(&signed, &vk, 0).is_ok());
    }
}
