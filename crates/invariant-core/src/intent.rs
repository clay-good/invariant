// Intent-to-operations pipeline (Section 15).
//
// Converts human intent into a signed PCA_0 with explicit operations. Three
// modes, all producing the same artifact:
//
// - **Template-based** (Option B): Predefined task templates with parameter
//   substitution. Operator selects a template and fills in parameters.
// - **Direct specification** (Option C): Operator specifies raw operations,
//   workspace, and duration directly.
// - **LLM-assisted** (Option A): External LLM extracts structured intent,
//   which is then fed through the template or direct path. Not implemented
//   here — this module provides the deterministic backend that Option A calls.
//
// Design: no I/O, no LLM, no network. Pure functions that take intent
// parameters and produce a Pca claim ready for signing.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::models::authority::{Operation, Pca};

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
/// Example: `"actuate:{limb}:*"` with parameter `limb = "left_arm"` produces
/// `"actuate:left_arm:*"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTemplate {
    /// Template name (e.g., "pick_and_place").
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
    30.0
}

/// The standard task templates shipped with Invariant (Section 15.2, Option B).
pub fn builtin_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            name: "pick_and_place".into(),
            description: "Pick up an object and place it at a target location".into(),
            operation_patterns: vec!["actuate:{limb}:*".into()],
            required_params: vec!["limb".into()],
            default_duration_s: 30.0,
        },
        TaskTemplate {
            name: "bimanual_pickup".into(),
            description: "Two-handed pickup of a larger object".into(),
            operation_patterns: vec!["actuate:left_arm:*".into(), "actuate:right_arm:*".into()],
            required_params: vec![],
            default_duration_s: 45.0,
        },
        TaskTemplate {
            name: "inspect".into(),
            description: "Visual inspection only — no contact authorized".into(),
            operation_patterns: vec![
                "actuate:{limb}:shoulder".into(),
                "actuate:{limb}:elbow".into(),
            ],
            required_params: vec!["limb".into()],
            default_duration_s: 20.0,
        },
        TaskTemplate {
            name: "wipe_surface".into(),
            description: "Wipe or clean a surface with one arm".into(),
            operation_patterns: vec!["actuate:{limb}:*".into()],
            required_params: vec!["limb".into()],
            default_duration_s: 60.0,
        },
        TaskTemplate {
            name: "door_operation".into(),
            description: "Open or close a door handle".into(),
            operation_patterns: vec![
                "actuate:{limb}:shoulder".into(),
                "actuate:{limb}:elbow".into(),
                "actuate:{limb}:wrist".into(),
            ],
            required_params: vec!["limb".into()],
            default_duration_s: 15.0,
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
/// `params` maps parameter names to their values (e.g., `"limb" -> "left_arm"`).
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
        assert!(find_template("pick_and_place").is_some());
        assert!(find_template("inspect").is_some());
    }

    #[test]
    fn find_template_unknown() {
        assert!(find_template("nonexistent_task").is_none());
    }

    // -- resolve_template --

    #[test]
    fn resolve_template_pick_and_place() {
        let template = find_template("pick_and_place").unwrap();
        let mut params = HashMap::new();
        params.insert("limb".into(), "left_arm".into());

        let result = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        assert_eq!(result.principal, "alice");
        assert_eq!(result.operations, vec!["actuate:left_arm:*"]);
        assert_eq!(result.kid, "key-1");
        assert!(result.expiry.is_some());
        assert!(matches!(result.source, IntentSource::Template { .. }));
    }

    #[test]
    fn resolve_template_missing_param() {
        let template = find_template("pick_and_place").unwrap();
        let params = HashMap::new(); // limb is missing

        let result = resolve_template(&template, &params, "alice", "key-1", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing parameter"));
    }

    #[test]
    fn resolve_template_bimanual_no_params_needed() {
        let template = find_template("bimanual_pickup").unwrap();
        let params = HashMap::new();

        let result = resolve_template(&template, &params, "bob", "key-2", None).unwrap();
        assert_eq!(result.operations.len(), 2);
        assert!(result
            .operations
            .contains(&"actuate:left_arm:*".to_string()));
        assert!(result
            .operations
            .contains(&"actuate:right_arm:*".to_string()));
    }

    #[test]
    fn resolve_template_duration_override() {
        let template = find_template("pick_and_place").unwrap();
        let mut params = HashMap::new();
        params.insert("limb".into(), "right_arm".into());

        let result = resolve_template(&template, &params, "alice", "key-1", Some(10.0)).unwrap();
        // Expiry should be ~10s from now, not 30s.
        let expiry = result.expiry.unwrap();
        let now = Utc::now();
        let diff = (expiry - now).num_seconds();
        assert!(
            (8..=12).contains(&diff),
            "expiry should be ~10s from now, got {diff}s"
        );
    }

    #[test]
    fn resolve_template_inspect_produces_two_ops() {
        let template = find_template("inspect").unwrap();
        let mut params = HashMap::new();
        params.insert("limb".into(), "left_arm".into());

        let result = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        assert_eq!(result.operations.len(), 2);
        assert_eq!(result.operations[0], "actuate:left_arm:shoulder");
        assert_eq!(result.operations[1], "actuate:left_arm:elbow");
    }

    #[test]
    fn resolve_template_invalid_param_value() {
        let template = find_template("pick_and_place").unwrap();
        let mut params = HashMap::new();
        // A value with spaces would produce an invalid operation.
        params.insert("limb".into(), "left arm".into());

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
        let ops = vec!["actuate:left_arm:shoulder".to_string()];
        let result = resolve_direct(&ops, "alice", "key-1", Some(30.0)).unwrap();
        assert_eq!(result.principal, "alice");
        assert_eq!(result.operations.len(), 1);
        assert!(result.expiry.is_some());
        assert!(matches!(result.source, IntentSource::Direct));
    }

    #[test]
    fn resolve_direct_multiple_ops() {
        let ops = vec![
            "actuate:left_arm:shoulder".to_string(),
            "actuate:left_arm:elbow".to_string(),
            "actuate:left_arm:wrist".to_string(),
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
        let ops = vec!["actuate::double_colon".to_string()]; // invalid
        let result = resolve_direct(&ops, "alice", "key-1", None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_direct_invalid_duration() {
        let ops = vec!["actuate:j1".to_string()];
        let result = resolve_direct(&ops, "alice", "key-1", Some(-5.0));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duration"));
    }

    // -- intent_to_pca --

    #[test]
    fn intent_to_pca_from_template() {
        let template = find_template("pick_and_place").unwrap();
        let mut params = HashMap::new();
        params.insert("limb".into(), "left_arm".into());

        let intent = resolve_template(&template, &params, "alice", "key-1", None).unwrap();
        let pca = intent_to_pca(&intent).unwrap();

        assert_eq!(pca.p_0, "alice");
        assert_eq!(pca.kid, "key-1");
        assert_eq!(pca.ops.len(), 1);
        assert!(pca.ops.iter().any(|op| op.as_str() == "actuate:left_arm:*"));
        assert!(pca.exp.is_some());
        assert!(pca.nbf.is_none());
    }

    #[test]
    fn intent_to_pca_from_direct() {
        let intent = resolve_direct(
            &[
                "actuate:left_arm:shoulder".to_string(),
                "actuate:left_arm:elbow".to_string(),
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
            &["actuate:j1".to_string(), "actuate:j1".to_string()],
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

        let template = find_template("pick_and_place").unwrap();
        let mut params = HashMap::new();
        params.insert("limb".into(), "right_arm".into());

        let intent =
            resolve_template(&template, &params, "operator_alice", "key-1", Some(30.0)).unwrap();
        let pca = intent_to_pca(&intent).unwrap();
        let signed = sign_pca(&pca, &sk).unwrap();

        // Verify the signature.
        assert!(verify_signed_pca(&signed, &vk, 0).is_ok());
    }

    // -----------------------------------------------------------------------
    // v12-N-15: intent ↔ PCA round-trip property test
    //
    // The contract: any `ResolvedIntent` that round-trips through
    // `intent_to_pca` and back has the same authority closure. The
    // "authority closure" of a `Pca` is `(p_0, ops, kid, exp, nbf)`. We
    // assert byte-for-byte structural equality, which subsumes the
    // operational claim that "a command admitted by the original chain is
    // also admitted by the chain reconstructed from the intent" — because
    // chain admission only reads those five fields.
    //
    // proptest is not on the workspace dep list (verified against
    // `Cargo.toml` at HEAD), so the test uses a seeded `StdRng` and 256
    // hand-shrunk cases. On failure it writes the offending intent JSON
    // to `tests/regressions/intent_roundtrip_<hash>.json` so the case can
    // be re-loaded into a focused debug run.

    fn random_intent(rng: &mut rand::rngs::StdRng) -> ResolvedIntent {
        use rand::seq::SliceRandom;
        use rand::Rng;

        // Principals drawn from a small pool of valid identifier shapes.
        const PRINCIPALS: &[&str] =
            &["alice", "bob", "carol", "ops-1", "ops-2", "forge", "root"];
        const KIDS: &[&str] = &["key-1", "key-2", "key-alice", "key-root"];
        // A spread of `Operation::new`-accepted strings. Mixing wildcards
        // ("*") and concrete leaves exercises the BTreeSet ordering.
        const OPS: &[&str] = &[
            "actuate:left_arm:*",
            "actuate:right_arm:*",
            "actuate:left_arm:shoulder",
            "actuate:right_arm:gripper",
            "sense:vision:*",
            "sense:proximity:tcp",
            "actuate:base:wheel_left",
            "actuate:base:wheel_right",
        ];

        let principal = PRINCIPALS.choose(rng).unwrap().to_string();
        let kid = KIDS.choose(rng).unwrap().to_string();
        let op_count = rng.gen_range(1..=OPS.len());
        let mut operations: Vec<String> = OPS
            .choose_multiple(rng, op_count)
            .map(|s| s.to_string())
            .collect();
        // Inject a few duplicates so the BTreeSet dedup path is exercised.
        if !operations.is_empty() && rng.gen_bool(0.25) {
            operations.push(operations[0].clone());
        }

        // Mix `Some`/`None` expiry and `Some`/`None` nbf via duration.
        // ResolvedIntent only carries `expiry`; we'll inject nbf at the PCA
        // layer after the first round-trip.
        let expiry = if rng.gen_bool(0.5) {
            Some(Utc::now() + Duration::seconds(rng.gen_range(1..=3600)))
        } else {
            None
        };

        ResolvedIntent {
            principal,
            operations,
            kid,
            expiry,
            source: IntentSource::Direct,
        }
    }

    /// Build a fresh `ResolvedIntent` from a `Pca`. This is the structural
    /// inverse of `intent_to_pca`; the round-trip property is that
    /// `intent_to_pca(pca_to_intent(intent_to_pca(i))) == intent_to_pca(i)`.
    fn pca_to_intent(pca: &Pca) -> ResolvedIntent {
        ResolvedIntent {
            principal: pca.p_0.clone(),
            operations: pca.ops.iter().map(|o| o.as_str().to_string()).collect(),
            kid: pca.kid.clone(),
            expiry: pca.exp,
            source: IntentSource::Direct,
        }
    }

    fn short_hash(intent: &ResolvedIntent) -> String {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(intent).expect("intent must serialize");
        let h = Sha256::digest(&bytes);
        // 8 hex characters is enough to disambiguate 256 cases.
        format!("{:016x}", u64::from_be_bytes(h[..8].try_into().unwrap()))
    }

    fn record_failure(intent: &ResolvedIntent) {
        // Best-effort: write a regression fixture so the failing case can
        // be loaded into a focused test. Ignore I/O errors — the assertion
        // that follows is the actual failure signal.
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dir = manifest_dir.join("tests").join("regressions");
        if std::fs::create_dir_all(&dir).is_ok() {
            let path = dir.join(format!("intent_roundtrip_{}.json", short_hash(intent)));
            let _ = std::fs::write(
                &path,
                serde_json::to_vec_pretty(intent).unwrap_or_default(),
            );
        }
    }

    fn assert_round_trip(intent: &ResolvedIntent) {
        // First leg: intent → PCA.
        let pca1 = match intent_to_pca(intent) {
            Ok(p) => p,
            Err(e) => {
                record_failure(intent);
                panic!("intent_to_pca failed on a generated intent: {e}");
            }
        };

        // Second leg: PCA → intent → PCA. The reconstructed PCA must
        // match `pca1` field-for-field.
        let intent2 = pca_to_intent(&pca1);
        let pca2 = match intent_to_pca(&intent2) {
            Ok(p) => p,
            Err(e) => {
                record_failure(intent);
                panic!("intent_to_pca failed on the reconstructed intent: {e}");
            }
        };

        if pca1.p_0 != pca2.p_0
            || pca1.ops != pca2.ops
            || pca1.kid != pca2.kid
            || pca1.exp != pca2.exp
            || pca1.nbf != pca2.nbf
        {
            record_failure(intent);
            panic!(
                "round-trip mismatch — original PCA closure differs from \
                 reconstructed PCA closure.\n  original: p_0={} ops={:?} \
                 kid={} exp={:?} nbf={:?}\n  reconstructed: p_0={} ops={:?} \
                 kid={} exp={:?} nbf={:?}",
                pca1.p_0, pca1.ops, pca1.kid, pca1.exp, pca1.nbf,
                pca2.p_0, pca2.ops, pca2.kid, pca2.exp, pca2.nbf,
            );
        }
    }

    #[test]
    fn intent_pca_round_trip_property_256_cases() {
        use rand::SeedableRng;
        // Fixed seed: deterministic across runs, regenerates the same 256
        // intents on every CI invocation.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0);
        for _ in 0..256 {
            let intent = random_intent(&mut rng);
            assert_round_trip(&intent);
        }
    }

    #[test]
    fn intent_pca_round_trip_deduplicates_operations() {
        // A direct intent with a duplicate operation must produce a PCA
        // whose `ops` set has the duplicate folded out. The round-trip
        // back must therefore drop the duplicate, and a second round-trip
        // must be a fixed point.
        let intent = ResolvedIntent {
            principal: "alice".into(),
            operations: vec![
                "actuate:left_arm:*".into(),
                "actuate:left_arm:*".into(),
                "sense:vision:*".into(),
            ],
            kid: "key-1".into(),
            expiry: Some(Utc::now() + Duration::seconds(30)),
            source: IntentSource::Direct,
        };
        let pca1 = intent_to_pca(&intent).unwrap();
        assert_eq!(pca1.ops.len(), 2, "BTreeSet must dedup the input list");

        let pca2 = intent_to_pca(&pca_to_intent(&pca1)).unwrap();
        assert_eq!(pca1.ops, pca2.ops);
        assert_eq!(pca1.p_0, pca2.p_0);
        assert_eq!(pca1.kid, pca2.kid);
        assert_eq!(pca1.exp, pca2.exp);
    }
}
