//! Validator pipeline: authority -> invariants -> signed verdict.
//!
//! Step 3a wiring: this module composes the PCA chain check with the
//! deterministic invariant set defined in [`crate::invariants`] and emits a
//! signed verdict. Each invariant's [`crate::invariants::InvariantResult`]
//! is folded into a `CheckResult` so legacy verdict consumers (audit, CLI,
//! sim) continue to work; the per-invariant detail is also preserved as
//! `Verdict::invariant_results` for richer downstream reporting.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::attestation::{AttestationVerifier, AttestedInput};
use crate::threat::ThreatScorer;
use crate::authority::chain::{check_required_ops, verify_chain_with_max_depth};
use crate::bundle::canonical_hash;
use crate::invariants::{
    self, InvariantContext, InvariantFamily, InvariantResult, InvariantSelection, InvariantStatus,
};
use crate::models::authority::SignedPca;
use crate::models::bundle::SynthesisBundle;
use crate::models::error::{Validate, ValidationError};
use crate::models::profile::BioProfile;
use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
use crate::screening::{HazardHit, HazardScreener};
use crate::util::sha256_hex_json;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the validator.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// Configuration was rejected during construction.
    #[error("validator config invalid: {0}")]
    InvalidConfig(String),
    /// Profile failed structural validation.
    #[error("profile validation failed: {0}")]
    InvalidProfile(#[from] ValidationError),
    /// Serialization of a verdict or component failed.
    #[error("serialization failed: {reason}")]
    Serialization {
        /// Human-readable reason for the serialization failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Validator configuration: profile, trusted keys, signing key, signer kid,
/// invariant selection.
pub struct ValidatorConfig {
    /// Bio profile under which bundles are validated.
    pub profile: BioProfile,
    /// Trusted PCA signer keys, keyed by `kid`.
    pub trusted_keys: HashMap<String, VerifyingKey>,
    /// Signing key for the verdict signature.
    pub signing_key: SigningKey,
    /// Key identifier of the verdict signer.
    pub signer_kid: String,
    /// Pre-computed canonical profile hash (`sha256:...`).
    profile_hash: Arc<str>,
    /// Subset of invariants to evaluate (default: all 30).
    pub invariant_selection: InvariantSelection,
    /// Policy for [`InvariantStatus::Unimplemented`] results.
    ///
    /// When `false` (the default, fail-closed), any invariant returning
    /// `Unimplemented` causes the bundle to be rejected; the verdict's
    /// authority/invariant `CheckResult` for each unimplemented entry is
    /// recorded as a non-pass and the verdict carries the names of every
    /// unimplemented invariant. When `true`, `Unimplemented` is treated as
    /// advisory: the entry is still recorded but does not gate approval.
    ///
    /// This flag exists so partial implementations of Steps 3–8 cannot
    /// accidentally produce a "pass" verdict in production while still letting
    /// development environments run end-to-end with stub invariants.
    pub allow_unimplemented_invariants: bool,
    /// Hazard database used to screen the bundle's payload before invariants
    /// run.
    ///
    /// `None` is treated as fail-closed: validation will still run, but the
    /// resulting verdict will carry a non-pass `screening` check explaining
    /// that no hazard database was configured, and approval is blocked.
    /// Production deployments must always supply a database; tests may opt
    /// into a permissive configuration via
    /// [`Self::with_allow_missing_hazard_db`].
    pub hazard_db: Option<Arc<dyn HazardScreener>>,
    /// When `true`, missing-hazard-database is treated as advisory rather
    /// than fail-closed. Default: `false`.
    pub allow_missing_hazard_db: bool,
    /// Optional threat scorer for continuous adversarial monitoring. When
    /// `None` (the default), no threat analysis is performed and the verdict's
    /// `threat_analysis` field is left as `None`.
    pub threat_scorer: Option<Arc<Mutex<ThreatScorer>>>,
    /// Composite threat score above which the threat check fails and approval
    /// is blocked. Default: `0.7`.
    pub threat_alert_threshold: f64,
    /// Stateful fragmentation-bypass detector (S1). Default-on with a
    /// default-configured detector. Set to `None` to disable (opt-out).
    pub stateful_detector: Option<Arc<Mutex<crate::invariants::stateful::FragmentationBypassDetector>>>,
    /// Reason string supplied to [`Self::with_stateful_detector_bypass`].
    /// When `Some`, the validator emits a warning at validation time.
    pub stateful_bypass_reason: Option<String>,
}

impl ValidatorConfig {
    /// Construct a new validator configuration. Validates the profile.
    pub fn new(
        profile: BioProfile,
        trusted_keys: HashMap<String, VerifyingKey>,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, ValidatorError> {
        if signer_kid.trim().is_empty() {
            return Err(ValidatorError::InvalidConfig(
                "signer_kid must be non-empty".into(),
            ));
        }
        profile.validate()?;
        let profile_hash: Arc<str> = sha256_hex_json(&profile)
            .map_err(|e| ValidatorError::Serialization {
                reason: e.to_string(),
            })?
            .into();
        // Auto-wire threat scorer for BSL ≥ 3 (CROSS-1 / GAP-H2): high-BSL
        // profiles must always run adversarial monitoring by default. The
        // caller may opt out via `without_threat_scorer()`.
        let threat_scorer = if profile.bsl_level >= 3 {
            Some(Arc::new(Mutex::new(ThreatScorer::with_defaults())))
        } else {
            None
        };
        Ok(Self {
            profile,
            trusted_keys,
            signing_key,
            signer_kid,
            profile_hash,
            invariant_selection: InvariantSelection::default(),
            allow_unimplemented_invariants: false,
            hazard_db: None,
            allow_missing_hazard_db: false,
            threat_scorer,
            threat_alert_threshold: 0.7,
            stateful_detector: Some(Arc::new(Mutex::new(
                crate::invariants::stateful::FragmentationBypassDetector::default(),
            ))),
            stateful_bypass_reason: None,
        })
    }

    /// Attach a hazard-database screener used by the validator before
    /// invariants run.
    pub fn with_hazard_db(mut self, db: Arc<dyn HazardScreener>) -> Self {
        self.hazard_db = Some(db);
        self
    }

    /// Override the missing-hazard-database policy. When `true`, missing
    /// databases produce only an advisory check rather than blocking
    /// approval. Default: `false`.
    pub fn with_allow_missing_hazard_db(mut self, allow: bool) -> Self {
        self.allow_missing_hazard_db = allow;
        self
    }

    /// Attach a threat scorer for continuous adversarial monitoring. When set,
    /// each validation call will invoke the scorer and append a
    /// `"threat_analysis"` [`CheckResult`]. If the composite score meets or
    /// exceeds `threat_alert_threshold`, approval is blocked.
    pub fn with_threat_scorer(mut self, scorer: Arc<Mutex<ThreatScorer>>) -> Self {
        self.threat_scorer = Some(scorer);
        self
    }

    /// Override the composite-threat-score threshold above which the threat
    /// check fails and approval is blocked. Default: `0.7`.
    pub fn with_threat_alert_threshold(mut self, threshold: f64) -> Self {
        self.threat_alert_threshold = threshold;
        self
    }

    /// Attach a stateful fragmentation-bypass detector (S1). When set, each
    /// validation call will evaluate the bundle against the per-principal k-mer
    /// window and append an `"s1_fragmentation_bypass_detector"` `CheckResult`.
    /// A `Fail` result blocks approval.
    pub fn with_stateful_detector(
        mut self,
        detector: Arc<Mutex<crate::invariants::stateful::FragmentationBypassDetector>>,
    ) -> Self {
        self.stateful_detector = Some(detector);
        self
    }

    /// Disable the stateful fragmentation-bypass detector (opt-out).
    ///
    /// Returns `Err(ValidatorError::InvalidConfig)` when the profile's
    /// `bsl_level` is ≥ 3; disabling fragmentation detection at those
    /// biosafety levels is a configuration error. Use
    /// [`Self::with_stateful_detector_bypass`] to acknowledge the bypass
    /// explicitly (e.g. for testing).
    pub fn without_stateful_detector(mut self) -> Result<Self, ValidatorError> {
        if self.profile.bsl_level >= 3 {
            return Err(ValidatorError::InvalidConfig(
                "stateful fragmentation detector must be enabled for BSL ≥ 3 profiles; \
                 use with_stateful_detector_bypass(reason) to acknowledge this explicitly"
                    .into(),
            ));
        }
        self.stateful_detector = None;
        Ok(self)
    }

    /// Disable the stateful fragmentation-bypass detector with an explicit
    /// acknowledgment reason. This is the only way to disable the detector
    /// for BSL ≥ 3 profiles. The reason is stored and printed to stderr as
    /// a warning at validation time.
    ///
    /// Use this only for testing or when you have a documented operational
    /// reason; never use it in production without review.
    pub fn with_stateful_detector_bypass(mut self, reason: &str) -> Self {
        self.stateful_detector = None;
        self.stateful_bypass_reason = Some(reason.to_string());
        self
    }

    /// Remove the threat scorer from this configuration. The threat scorer
    /// is automatically wired for BSL ≥ 3 profiles by [`Self::new`]; this
    /// method allows tests and controlled environments to opt out.
    pub fn without_threat_scorer(mut self) -> Self {
        self.threat_scorer = None;
        self
    }

    /// Override the invariant selection (e.g. to disable irrelevant substrate
    /// families).
    pub fn with_invariant_selection(mut self, sel: InvariantSelection) -> Self {
        self.invariant_selection = sel;
        self
    }

    /// Override the unimplemented-invariant policy. See
    /// [`Self::allow_unimplemented_invariants`].
    pub fn with_allow_unimplemented_invariants(mut self, allow: bool) -> Self {
        self.allow_unimplemented_invariants = allow;
        self
    }

    /// Validate a bundle and produce a signed verdict.
    pub fn validate(
        &self,
        bundle: &SynthesisBundle,
        now: DateTime<Utc>,
        _extra: Option<&[u8]>,
    ) -> Result<ValidationOutput, ValidatorError> {
        self.validate_with_attested_inputs(bundle, &[], None, now)
    }

    /// Validate a bundle with optional attested inputs verified through
    /// `verifier`. Attested-input failures surface as a `screening_attestation`
    /// `CheckResult` (fail-closed) and prevent approval.
    pub fn validate_with_attested_inputs(
        &self,
        bundle: &SynthesisBundle,
        attested_inputs: &[AttestedInput],
        verifier: Option<&mut AttestationVerifier>,
        now: DateTime<Utc>,
    ) -> Result<ValidationOutput, ValidatorError> {
        // Emit a warning when the stateful detector was explicitly bypassed.
        if let Some(ref reason) = self.stateful_bypass_reason {
            eprintln!(
                "WARNING [invariant-bio]: stateful fragmentation detector bypassed \
                 (BSL {}): {reason}",
                self.profile.bsl_level
            );
        }
        // Run attestation verification up front so the rest of the pipeline
        // can include the result in the verdict alongside other checks.
        let mut attestation_passed = true;
        let attestation_check: Option<CheckResult> = match (attested_inputs.is_empty(), verifier) {
            (true, _) => None,
            (false, None) => {
                attestation_passed = false;
                Some(CheckResult::new(
                    "screening_attestation",
                    "attestation",
                    false,
                    format!(
                        "{} attested input(s) presented but no verifier configured",
                        attested_inputs.len()
                    ),
                ))
            }
            (false, Some(v)) => {
                let mut errors: Vec<String> = Vec::new();
                for input in attested_inputs {
                    if let Err(e) = v.verify_input(input, now) {
                        errors.push(format!("{}: {e}", input.source));
                    }
                }
                if errors.is_empty() {
                    Some(CheckResult::new(
                        "screening_attestation",
                        "attestation",
                        true,
                        format!("{} attested input(s) verified", attested_inputs.len()),
                    ))
                } else {
                    attestation_passed = false;
                    Some(CheckResult::new(
                        "screening_attestation",
                        "attestation",
                        false,
                        format!("attested-input failures: {}", errors.join("; ")),
                    ))
                }
            }
        };
        self.validate_inner(bundle, attestation_check, attestation_passed, now)
    }

    fn validate_inner(
        &self,
        bundle: &SynthesisBundle,
        attestation_check: Option<CheckResult>,
        attestation_passed: bool,
        now: DateTime<Utc>,
    ) -> Result<ValidationOutput, ValidatorError> {
        // ---- Bundle shape pre-check (V10-2, V10-3, V10-4) ----
        // Validates source length, metadata bounds, and payload-size caps
        // before any authority/screening/invariant processing.
        bundle
            .validate_bundle_shape(&self.profile)
            .map_err(ValidatorError::InvalidProfile)?;

        let mut checks: Vec<CheckResult> = Vec::new();
        if let Some(c) = attestation_check {
            checks.push(c);
        }

        // ---- Authority ----
        let chain_hops = decode_chain(&bundle.authority.pca_chain);
        let (authority_summary, authority_passed) = match chain_hops {
            Err(reason) => {
                checks.push(CheckResult::new(
                    "authority",
                    "authority",
                    false,
                    format!("could not decode PCA chain: {reason}"),
                ));
                (
                    AuthoritySummary {
                        origin_principal: String::new(),
                        hop_count: 0,
                        operations_granted: vec![],
                        operations_required: bundle
                            .authority
                            .required_ops
                            .iter()
                            .map(|o| o.as_str().to_string())
                            .collect(),
                    },
                    false,
                )
            }
            Ok(hops) => match verify_chain_with_max_depth(&hops, &self.trusted_keys, now, self.profile.max_authority_chain_depth) {
                Err(e) => {
                    checks.push(CheckResult::new(
                        "authority",
                        "authority",
                        false,
                        format!("PCA chain verification failed: {e}"),
                    ));
                    (
                        AuthoritySummary {
                            origin_principal: String::new(),
                            hop_count: hops.len(),
                            operations_granted: vec![],
                            operations_required: bundle
                                .authority
                                .required_ops
                                .iter()
                                .map(|o| o.as_str().to_string())
                                .collect(),
                        },
                        false,
                    )
                }
                Ok(chain) => {
                    let granted: Vec<String> = chain
                        .final_ops()
                        .iter()
                        .map(|o| o.as_str().to_string())
                        .collect();
                    let required: Vec<String> = bundle
                        .authority
                        .required_ops
                        .iter()
                        .map(|o| o.as_str().to_string())
                        .collect();
                    let summary = AuthoritySummary {
                        origin_principal: chain.origin_principal().to_string(),
                        hop_count: hops.len(),
                        operations_granted: granted,
                        operations_required: required,
                    };
                    match check_required_ops(&chain, &bundle.authority.required_ops) {
                        Ok(()) => {
                            checks.push(CheckResult::new(
                                "authority",
                                "authority",
                                true,
                                "PCA chain valid; required ops covered".to_string(),
                            ));
                            (summary, true)
                        }
                        Err(e) => {
                            checks.push(CheckResult::new(
                                "authority",
                                "authority",
                                false,
                                format!("required ops not covered: {e}"),
                            ));
                            (summary, false)
                        }
                    }
                }
            },
        };

        // ---- Hazard-database screening (Step 5) ----
        // Run before invariants so the verdict surfaces hazardous payloads
        // even if every invariant is still a stub. Hits are also exposed to
        // callers via `ValidationOutput::screening_hits`.
        let mut screening_passed = true;
        let screening_hits: Vec<HazardHit> = match &self.hazard_db {
            Some(db) => {
                let hits = db.screen_payload(&bundle.payload);
                if hits.is_empty() {
                    checks.push(CheckResult::new(
                        "screening",
                        "screening",
                        true,
                        "no hazard-database hits".to_string(),
                    ));
                } else {
                    screening_passed = false;
                    let summary: Vec<String> = hits
                        .iter()
                        .map(|h| format!("{} ({})", h.entry.id, h.entry.hazard_class))
                        .collect();
                    checks.push(CheckResult::new(
                        "screening",
                        "screening",
                        false,
                        format!("hazard-database hits: {}", summary.join(", ")),
                    ));
                }
                hits
            }
            None => {
                let passed = self.allow_missing_hazard_db;
                if !passed {
                    screening_passed = false;
                }
                let policy = if self.allow_missing_hazard_db {
                    "advisory"
                } else {
                    "fail-closed"
                };
                checks.push(CheckResult::new(
                    "screening",
                    "screening",
                    passed,
                    format!("no hazard database configured ({policy})"),
                ));
                Vec::new()
            }
        };

        // ---- Invariants (D1-D10, P1-P10, C1-C10) ----
        let inv_ctx = InvariantContext {
            screening_hits: &screening_hits,
            profile: &self.profile,
        };
        let invariant_results = invariants::run_all(bundle, &self.invariant_selection, &inv_ctx);
        let mut all_invariants_passed = true;
        let mut unimplemented_ids: Vec<String> = Vec::new();
        for r in &invariant_results {
            let (passed, details) = match &r.status {
                InvariantStatus::Pass => (true, "pass".to_string()),
                InvariantStatus::Fail { reason } => {
                    all_invariants_passed = false;
                    (false, format!("fail: {reason}"))
                }
                InvariantStatus::DbStale { reason } => {
                    // When allow_stale_screening is true, check whether the
                    // DB age is within the profile's configured window.
                    let db_age_days = self
                        .hazard_db
                        .as_ref()
                        .map(|db| db.freshness().as_secs() / 86400)
                        .unwrap_or(u64::MAX);
                    let max_days = self
                        .profile
                        .stale_screening_max_days
                        .unwrap_or(30) as u64;
                    if self.profile.allow_stale_screening && db_age_days <= max_days {
                        (true, format!("db-stale (advisory — within {max_days}-day window): {reason}"))
                    } else {
                        all_invariants_passed = false;
                        (false, format!("db-stale (fail-closed): {reason}"))
                    }
                }
                InvariantStatus::Advisory { note } => (true, format!("advisory: {note}")),
                InvariantStatus::Unimplemented => {
                    unimplemented_ids.push(r.id.as_str().to_string());
                    if !self.allow_unimplemented_invariants {
                        all_invariants_passed = false;
                    }
                    (false, "unimplemented (Step 3b)".to_string())
                }
            };
            checks.push(CheckResult::new(
                format!("{}_{}", r.id.as_str().to_lowercase(), r.name),
                category_for(r.family),
                passed,
                details,
            ));
        }

        // Synthesize a single aggregate check describing the unimplemented set
        // so verdict consumers see the full list (and the policy that applied)
        // without having to re-walk per-invariant results.
        if !unimplemented_ids.is_empty() {
            let policy = if self.allow_unimplemented_invariants {
                "advisory"
            } else {
                "fail-closed"
            };
            let passed = self.allow_unimplemented_invariants;
            let details = format!(
                "unimplemented invariants ({policy}): {}",
                unimplemented_ids.join(", ")
            );
            checks.push(CheckResult::new(
                "invariants_unimplemented",
                "invariant.policy",
                passed,
                details,
            ));
        }

        // ---- Homology engine calibration status ----
        // The k-mer Jaccard engine is uncalibrated: k and threshold are
        // heuristic defaults, not derived from evaluation against a curated
        // reference set. Surface this as a passed-but-informational check so
        // operators know the acceptance gate (FN ≤ 1e-4, FP ≤ 1e-3 with
        // Clopper–Pearson bounds) has not yet been met.
        #[cfg(not(feature = "hmmer"))]
        {
            let k = self.profile.protein_kmer_k.unwrap_or(
                crate::invariants::dna::DEFAULT_PROTEIN_KMER_K,
            );
            let t = self.profile.protein_kmer_threshold.unwrap_or(
                crate::invariants::dna::DEFAULT_PROTEIN_KMER_THRESHOLD,
            );
            checks.push(CheckResult::new(
                "homology_engine_status",
                "invariant.dna",
                true, // advisory — does not block approval
                format!(
                    "protein-space rescreen uses uncalibrated k-mer engine (k={k}, threshold={t:.2}); \
                     acceptance gate (FN ≤ 1e-4, FP ≤ 1e-3) not yet validated"
                ),
            ));
        }
        #[cfg(feature = "hmmer")]
        {
            checks.push(CheckResult::new(
                "homology_engine_status",
                "invariant.dna",
                true,
                "protein-space rescreen uses HMMER profile-HMM engine".to_string(),
            ));
        }

        // ---- Chemistry engine calibration status ----
        // The heuristic SMILES engine uses substring matching rather than real
        // SMARTS substructure search. Surface this as a passed-but-informational
        // check so operators know that the chemical invariants (C1–C10) are
        // running in heuristic mode with known FP/FN characteristics.
        {
            let rule_ver = crate::invariants::molecule::SMARTS_RULE_LIBRARY_VERSION;
            checks.push(CheckResult::new(
                "chemistry_engine_status",
                "invariant.chemical",
                true, // advisory — does not block approval
                format!(
                    "chemical invariants use heuristic SMILES engine (SMARTS rule library v{rule_ver}); \
                     full substructure matching requires RDKit/OpenBabel backend"
                ),
            ));
        }

        // ---- Stateful invariants (fragmentation detection) ----
        if let Some(ref detector) = self.stateful_detector {
            let principal = &authority_summary.origin_principal;
            if let Ok(mut det) = detector.lock() {
                let status = det.evaluate_bundle(bundle, principal, &screening_hits);
                let (passed, details) = match &status {
                    InvariantStatus::Pass => (true, "pass".to_string()),
                    InvariantStatus::Fail { reason } => {
                        all_invariants_passed = false;
                        (false, format!("fail: {reason}"))
                    }
                    InvariantStatus::Advisory { note } => (true, format!("advisory: {note}")),
                    _ => (true, "pass".to_string()),
                };
                checks.push(CheckResult::new(
                    "s1_fragmentation_bypass_detector",
                    "invariant.stateful",
                    passed,
                    details,
                ));
            }
        }

        // ---- Threat scoring ----
        let principal = authority_summary.origin_principal.clone();
        let mut threat_blocked = false;
        let mut threat_analysis_result: Option<crate::models::verdict::ThreatAnalysis> = None;

        if let Some(scorer_arc) = &self.threat_scorer {
            // Compute whether the bundle would be tentatively approved before
            // the threat gate itself. The scorer uses this to decide whether to
            // record the bundle in the rejected window.
            let tentatively_approved =
                authority_passed && screening_passed && all_invariants_passed && attestation_passed;

            let analysis = scorer_arc
                .lock()
                .expect("threat scorer mutex poisoned")
                .score(
                    bundle,
                    &self.profile,
                    authority_passed,
                    &principal,
                    tentatively_approved,
                );

            let threat_passed = analysis.composite_threat_score < self.threat_alert_threshold;
            if !threat_passed {
                threat_blocked = true;
            }
            checks.push(CheckResult::new(
                "threat_analysis",
                "threat",
                threat_passed,
                format!(
                    "composite threat score {:.4} (threshold {:.4})",
                    analysis.composite_threat_score, self.threat_alert_threshold
                ),
            ));
            threat_analysis_result = Some(analysis);
        }

        // ---- Aggregate ----
        // Approval requires a valid authority chain, a clean screening pass
        // (or an advisory miss when explicitly allowed), AND no Fail/DbStale
        // invariants. Unimplemented invariants block approval unless
        // `allow_unimplemented_invariants` is set; see that field's docs.
        let approved = authority_passed
            && screening_passed
            && all_invariants_passed
            && attestation_passed
            && !threat_blocked;

        let verdict = Verdict {
            approved,
            command_hash: canonical_hash(bundle),
            command_sequence: bundle.sequence,
            timestamp: now,
            checks,
            profile_name: self.profile.name.clone(),
            profile_hash: (*self.profile_hash).to_string(),
            authority_summary,
            threat_analysis: threat_analysis_result.clone(),
        };

        // ---- Sign verdict ----
        let canonical = sha256_hex_json(&verdict).map_err(|e| ValidatorError::Serialization {
            reason: e.to_string(),
        })?;
        let signature = self.signing_key.sign(canonical.as_bytes());
        let signed = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: self.signer_kid.clone(),
        };

        Ok(ValidationOutput {
            signed_verdict: signed,
            invariant_results,
            screening_hits,
            threat_analysis: threat_analysis_result,
        })
    }
}

fn category_for(f: InvariantFamily) -> &'static str {
    match f {
        InvariantFamily::Dna => "invariant.dna",
        InvariantFamily::Peptide => "invariant.peptide",
        InvariantFamily::Chemical => "invariant.chemical",
        InvariantFamily::Protocol => "invariant.protocol",
    }
}

fn decode_chain(b64: &str) -> Result<Vec<SignedPca>, String> {
    if b64.trim().is_empty() {
        return Ok(Vec::new());
    }
    let bytes = STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))?;
    serde_json::from_slice::<Vec<SignedPca>>(&bytes).map_err(|e| format!("json decode: {e}"))
}

/// Output of a successful validation call.
pub struct ValidationOutput {
    /// The signed verdict.
    pub signed_verdict: SignedVerdict,
    /// Per-invariant results (one per evaluated invariant in canonical order).
    pub invariant_results: Vec<InvariantResult>,
    /// Hazard-database hits surfaced during the screening phase. Empty if no
    /// database was configured (and `allow_missing_hazard_db` was set), or if
    /// the payload had no matches.
    pub screening_hits: Vec<HazardHit>,
    /// Threat analysis produced by the threat scorer, if one was configured.
    /// `None` when no scorer is attached to the validator configuration.
    pub threat_analysis: Option<crate::models::verdict::ThreatAnalysis>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariants::InvariantId;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_profile() -> BioProfile {
        BioProfile {
            name: "test_profile".into(),
            version: "0.1.0".into(),
            bsl_level: 2,
            allowed_substrates: vec!["dna".into()],
            max_synthesis_volume_ml: 5.0,
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

    fn make_bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGCGT".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(), // empty chain -> authority fails
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    #[test]
    fn validator_config_rejects_empty_signer_kid() {
        let sk = SigningKey::generate(&mut OsRng);
        let res = ValidatorConfig::new(make_profile(), HashMap::new(), sk, String::new());
        assert!(matches!(res, Err(ValidatorError::InvalidConfig(_))));
    }

    #[test]
    fn validator_emits_thirty_invariant_check_results() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert_eq!(out.invariant_results.len(), 34);
        // 1 authority + 1 screening + 34 invariants + 1 homology_engine_status + 1 chemistry_engine_status + 1 stateful detector.
        assert_eq!(out.signed_verdict.verdict.checks.len(), 39);
    }

    #[test]
    fn validator_no_unimplemented_policy_when_all_invariants_real() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .all(|c| c.name != "invariants_unimplemented"));
        // Approval still gated by authority (empty chain fails) and missing
        // hazard DB.
        assert!(!out.signed_verdict.verdict.approved);
    }

    #[test]
    fn validator_rejects_when_authority_chain_empty() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(!out.signed_verdict.verdict.approved);
    }

    #[test]
    fn validator_signs_verdict_with_configured_kid() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert_eq!(out.signed_verdict.signer_kid, "validator-key-1");
        assert!(!out.signed_verdict.verdict_signature.is_empty());
    }

    #[test]
    fn validator_invariant_selection_disables_subset() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut sel = InvariantSelection::default();
        for id in InvariantId::all() {
            if matches!(
                id.family(),
                InvariantFamily::Peptide | InvariantFamily::Chemical | InvariantFamily::Protocol
            ) {
                sel.disabled.insert(*id);
            }
        }
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_invariant_selection(sel);
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert_eq!(out.invariant_results.len(), 10);
    }

    // ---- Step 5: hazard-database wiring ----

    use crate::screening::{
        sign_body_for_tests, FileBackedHazardDatabase, HazardDatabaseBody, HazardEntry,
    };

    fn db_with_dna_pattern(pattern: &str) -> Arc<dyn HazardScreener> {
        let body = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: vec![HazardEntry {
                id: "dna-test".into(),
                label: "test-hazard".into(),
                hazard_class: "test".into(),
                pattern: pattern.into(),
            }],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let issuer = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body, "issuer-test", &issuer);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let mut keys = HashMap::new();
        keys.insert("issuer-test".to_string(), issuer.verifying_key());
        Arc::new(FileBackedHazardDatabase::from_bytes(&bytes, &keys).unwrap())
    }

    #[test]
    fn validator_missing_hazard_db_is_fail_closed_by_default() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let screening = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening")
            .expect("screening check present");
        assert!(!screening.passed);
        assert!(screening.details.contains("no hazard database configured"));
        assert!(screening.details.contains("fail-closed"));
        assert!(!out.signed_verdict.verdict.approved);
        assert!(out.screening_hits.is_empty());
    }

    #[test]
    fn validator_allow_missing_hazard_db_is_advisory() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_allow_missing_hazard_db(true);
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let screening = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening")
            .expect("screening check present");
        assert!(screening.passed);
        assert!(screening.details.contains("advisory"));
    }

    #[test]
    fn validator_screening_pass_when_no_hits() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_hazard_db(db_with_dna_pattern("ZZZZZZ"));
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let screening = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening")
            .expect("screening check present");
        assert!(screening.passed);
        assert!(out.screening_hits.is_empty());
    }

    #[test]
    fn validator_screening_fail_when_hits_present() {
        let sk = SigningKey::generate(&mut OsRng);
        // Bundle DNA is "ATGCGT" -> upper "ATGCGT". Pattern "ATGCGT" hits.
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_hazard_db(db_with_dna_pattern("ATGCGT"));
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let screening = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening")
            .expect("screening check present");
        assert!(!screening.passed);
        assert!(screening.details.contains("dna-test"));
        assert_eq!(out.screening_hits.len(), 1);
        assert_eq!(out.screening_hits[0].entry.id, "dna-test");
        assert!(!out.signed_verdict.verdict.approved);
    }

    // ---- Step 10: attested-input wiring ----

    use crate::attestation::{sign_attested_input, AttestationVerifier};

    fn cfg_for_attestation_tests() -> ValidatorConfig {
        let sk = SigningKey::generate(&mut OsRng);
        ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into()).unwrap()
    }

    #[test]
    fn validator_attested_inputs_pass_verifies() {
        let cfg = cfg_for_attestation_tests();
        let signer = SigningKey::generate(&mut OsRng);
        let mut keys = HashMap::new();
        keys.insert("att-1".into(), signer.verifying_key());
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let input = sign_attested_input("scr", now, "n1", "{}", "att-1", &signer);
        let out = cfg
            .validate_with_attested_inputs(&make_bundle(), &[input], Some(&mut v), now)
            .unwrap();
        let att = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening_attestation")
            .expect("attestation check present");
        assert!(att.passed);
        assert!(att.details.contains("verified"));
    }

    #[test]
    fn validator_missing_verifier_fails_closed_when_inputs_present() {
        let cfg = cfg_for_attestation_tests();
        let signer = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let input = sign_attested_input("scr", now, "n2", "{}", "att-1", &signer);
        let out = cfg
            .validate_with_attested_inputs(&make_bundle(), &[input], None, now)
            .unwrap();
        let att = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening_attestation")
            .expect("attestation check present");
        assert!(!att.passed);
        assert!(att.details.contains("no verifier"));
        assert!(!out.signed_verdict.verdict.approved);
    }

    #[test]
    fn validator_attested_input_failure_blocks_approval() {
        let cfg = cfg_for_attestation_tests();
        // No trusted keys -> verification fails on UnknownKid.
        let mut v = AttestationVerifier::new(HashMap::new());
        let signer = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let input = sign_attested_input("scr", now, "n3", "{}", "att-1", &signer);
        let out = cfg
            .validate_with_attested_inputs(&make_bundle(), &[input], Some(&mut v), now)
            .unwrap();
        let att = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "screening_attestation")
            .expect("attestation check present");
        assert!(!att.passed);
        assert!(att.details.contains("att-1"));
        assert!(!out.signed_verdict.verdict.approved);
    }

    #[test]
    fn validator_no_attested_inputs_no_attestation_check() {
        let cfg = cfg_for_attestation_tests();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .all(|c| c.name != "screening_attestation"));
    }

    // ---- Phase 2 Step 2: threat scorer wiring ----

    use crate::threat::{ThreatScorer, ThreatScorerConfig};

    /// When no scorer is configured the verdict carries no threat_analysis check
    /// and ValidationOutput::threat_analysis is None.
    #[test]
    fn threat_scorer_absent_no_check() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .all(|c| c.name != "threat_analysis"));
        assert!(out.threat_analysis.is_none());
        assert!(out.signed_verdict.verdict.threat_analysis.is_none());
    }

    /// When a scorer is configured and the bundle produces a low composite score
    /// the threat_analysis check passes and the ThreatAnalysis struct is populated
    /// in both ValidationOutput and the verdict.
    #[test]
    fn threat_scorer_below_threshold_passes() {
        let sk = SigningKey::generate(&mut OsRng);
        let scorer = Arc::new(Mutex::new(ThreatScorer::with_defaults()));
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_threat_scorer(scorer);
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();

        let threat_check = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "threat_analysis")
            .expect("threat_analysis check should be present");
        // A single bundle with no window history should score well below 0.7.
        assert!(threat_check.passed, "threat check should pass on first bundle");
        assert!(out.threat_analysis.is_some());
        assert!(out.signed_verdict.verdict.threat_analysis.is_some());
    }

    /// When the threshold is set to 0.0, any non-zero composite score blocks
    /// approval and the threat_analysis check fails.
    #[test]
    fn threat_scorer_above_threshold_blocks() {
        let sk = SigningKey::generate(&mut OsRng);
        // Use a scorer whose internal alert_threshold matches the validator
        // threshold so the scorer's own `alert` flag is consistent.
        let scorer_cfg = ThreatScorerConfig {
            alert_threshold: 0.0,
            ..Default::default()
        };
        let scorer = Arc::new(Mutex::new(ThreatScorer::new(scorer_cfg)));
        // Drive the scorer with several rejected bundles so authority_probing
        // accumulates a non-zero score, then check the blocking behaviour.
        {
            let mut s = scorer.lock().unwrap();
            let pf = make_profile();
            for i in 0..6u64 {
                let b = SynthesisBundle {
                    timestamp: Utc::now(),
                    source: "t".into(),
                    sequence: i,
                    payload: crate::models::bundle::SynthesisPayload::Dna {
                        sequence: "ATGCGTATGCGTATGCGTATGCGT".into(),
                    },
                    delta_time: 0.0,
                    authority: crate::models::bundle::BundleAuthority {
                        pca_chain: String::new(),
                        required_ops: vec![],
                    },
                    metadata: Default::default(),
                };
                let _ = s.score(&b, &pf, false, "mallory", false);
            }
        }
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_threat_scorer(scorer)
                .with_threat_alert_threshold(0.0);
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();

        let threat_check = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "threat_analysis")
            .expect("threat_analysis check should be present");
        assert!(!threat_check.passed, "threat check should fail at threshold 0.0");
        assert!(!out.signed_verdict.verdict.approved, "approval should be blocked");
    }

    /// The ThreatAnalysis struct returned in ValidationOutput contains individual
    /// component scores and the composite.
    #[test]
    fn threat_analysis_surfaces_in_output() {
        let sk = SigningKey::generate(&mut OsRng);
        let scorer = Arc::new(Mutex::new(ThreatScorer::with_defaults()));
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .with_threat_scorer(scorer);
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();

        let analysis = out.threat_analysis.expect("ThreatAnalysis should be present");
        // All component scores must be in [0.0, 1.0].
        assert!(analysis.boundary_clustering_score >= 0.0);
        assert!(analysis.boundary_clustering_score <= 1.0);
        assert!(analysis.authority_probing_score >= 0.0);
        assert!(analysis.authority_probing_score <= 1.0);
        assert!(analysis.replay_similarity_score >= 0.0);
        assert!(analysis.replay_similarity_score <= 1.0);
        assert!(analysis.drift_score >= 0.0);
        assert!(analysis.drift_score <= 1.0);
        assert!(analysis.anomaly_score >= 0.0);
        assert!(analysis.anomaly_score <= 1.0);
        assert!(analysis.composite_threat_score >= 0.0);
        assert!(analysis.composite_threat_score <= 1.0);
        // Verdict carries the same struct.
        assert_eq!(
            out.signed_verdict.verdict.threat_analysis.as_ref(),
            Some(&analysis)
        );
    }

    // ---- D-family gap closure: S1 default-on, homology engine status ----

    #[test]
    fn stateful_detector_is_default_on() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        assert!(
            cfg.stateful_detector.is_some(),
            "S1 fragmentation detector must be default-on"
        );
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let s1 = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "s1_fragmentation_bypass_detector")
            .expect("S1 check must appear in verdict when default-on");
        assert!(s1.passed);
    }

    #[test]
    fn stateful_detector_can_be_disabled_for_bsl2() {
        let sk = SigningKey::generate(&mut OsRng);
        // BSL-2 profile: without_stateful_detector() succeeds.
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap()
                .without_stateful_detector()
                .unwrap();
        assert!(cfg.stateful_detector.is_none());
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .all(|c| c.name != "s1_fragmentation_bypass_detector"));
    }

    #[test]
    fn homology_engine_status_check_present() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "validator-key-1".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        let status = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "homology_engine_status")
            .expect("homology_engine_status check must be present");
        // Advisory — passes but informs operator of calibration status.
        assert!(status.passed);
        assert!(status.details.contains("k-mer"));
        assert!(status.details.contains("acceptance gate"));
    }

    // ---- CROSS-1: BSL ≥ 3 stateful-detector guard ----

    fn make_bsl3_profile() -> BioProfile {
        BioProfile {
            bsl_level: 3,
            ..make_profile()
        }
    }

    #[test]
    fn without_stateful_detector_rejected_for_bsl3() {
        let sk = SigningKey::generate(&mut OsRng);
        let result =
            ValidatorConfig::new(make_bsl3_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap()
                .without_stateful_detector();
        assert!(
            matches!(result, Err(ValidatorError::InvalidConfig(_))),
            "without_stateful_detector must fail for BSL ≥ 3"
        );
    }

    #[test]
    fn without_stateful_detector_allowed_for_bsl2() {
        let sk = SigningKey::generate(&mut OsRng);
        let result =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap()
                .without_stateful_detector();
        assert!(result.is_ok(), "without_stateful_detector must succeed for BSL ≤ 2");
        assert!(result.unwrap().stateful_detector.is_none());
    }

    #[test]
    fn with_stateful_detector_bypass_disables_for_bsl3() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_bsl3_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap()
                .with_stateful_detector_bypass("testing");
        assert!(cfg.stateful_detector.is_none());
        assert_eq!(cfg.stateful_bypass_reason.as_deref(), Some("testing"));
        // Validation must still run without panicking.
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .all(|c| c.name != "s1_fragmentation_bypass_detector"));
    }

    // ---- GAP-H2: threat scorer default-on for BSL ≥ 3 ----

    #[test]
    fn threat_scorer_default_on_for_bsl3() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_bsl3_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap();
        assert!(
            cfg.threat_scorer.is_some(),
            "threat scorer must be auto-wired for BSL ≥ 3"
        );
    }

    #[test]
    fn threat_scorer_default_off_for_bsl2() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_profile(), HashMap::new(), sk, "v-key".into()).unwrap();
        assert!(
            cfg.threat_scorer.is_none(),
            "threat scorer must NOT be auto-wired for BSL ≤ 2"
        );
    }

    #[test]
    fn without_threat_scorer_clears_for_bsl3() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_bsl3_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap()
                .without_threat_scorer();
        assert!(
            cfg.threat_scorer.is_none(),
            "without_threat_scorer must clear the scorer"
        );
    }

    #[test]
    fn bsl3_validator_produces_threat_analysis_by_default() {
        let sk = SigningKey::generate(&mut OsRng);
        let cfg =
            ValidatorConfig::new(make_bsl3_profile(), HashMap::new(), sk, "v-key".into())
                .unwrap();
        let out = cfg.validate(&make_bundle(), Utc::now(), None).unwrap();
        assert!(
            out.threat_analysis.is_some(),
            "BSL-3 validator must produce ThreatAnalysis by default"
        );
        let threat_check = out
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "threat_analysis")
            .expect("threat_analysis check must be in verdict for BSL ≥ 3");
        assert!(
            threat_check.passed,
            "threat check must pass on first bundle (no history)"
        );
    }
}
