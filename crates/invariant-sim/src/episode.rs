// Episode output: per-episode data produced by the 15M campaign.
//
// Every episode in the campaign emits four artifacts:
//   1. Signed verdict chain  – hash-linked, Ed25519-signed AuditEntry list.
//   2. Seed                  – hex-encoded 32-byte value for deterministic replay.
//   3. Per-step trace        – ordered command + verdict pairs (Trace).
//   4. Aggregate statistics  – CampaignReport produced by the campaign reporter.
//
// This module owns types 1-3. The aggregate statistics (type 4) are returned
// as `CampaignReport` by `run_dry_campaign` and are not duplicated here.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use invariant_core::models::audit::{AuditEntry, SignedAuditEntry};
use invariant_core::models::command::Command;
use invariant_core::models::trace::Trace;
use invariant_core::models::verdict::SignedVerdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// EpisodeOutput
// ---------------------------------------------------------------------------

/// All data outputs produced by a single simulation episode.
///
/// Bundling the four data artifacts into one type ensures that consumers
/// (replay tools, audit verifiers, analysis pipelines) can obtain everything
/// they need from a single value without re-running the campaign.
///
/// # Data Items
///
/// | Field           | Spec item                              |
/// |-----------------|----------------------------------------|
/// | `trace`         | Per-step command + verdict pairs       |
/// | `verdict_chain` | Signed verdict chain (hash-linked)     |
/// | `seed`          | Seed for deterministic replay          |
///
/// Aggregate statistics are returned separately as `CampaignReport`.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_sim::episode::{EpisodeOutput, VerdictChainBuilder};
/// use invariant_core::models::trace::Trace;
///
/// // An episode with no steps and no seed.
/// let trace = Trace {
///     id: "ep-0".to_string(),
///     episode: 0,
///     environment_id: 0,
///     scenario: "Baseline".to_string(),
///     profile_name: "franka_panda".to_string(),
///     steps: vec![],
///     metadata: HashMap::new(),
/// };
///
/// let output = EpisodeOutput::new(trace, vec![], None);
/// assert_eq!(output.trace.id, "ep-0");
/// assert!(output.verdict_chain.is_empty());
/// assert!(output.seed.is_none());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeOutput {
    /// Ordered sequence of command + verdict pairs for this episode.
    pub trace: Trace,
    /// Hash-linked, Ed25519-signed verdict chain.
    ///
    /// Each entry carries a `previous_hash` linking it to the preceding entry,
    /// and an `entry_hash` covering the entry's own content. The `entry_signature`
    /// is an Ed25519 signature over the canonical JSON of the entry. Together
    /// these fields form a tamper-proof audit log that can be verified offline.
    pub verdict_chain: Vec<SignedAuditEntry>,
    /// Hex-encoded 32-byte seed used to initialise the campaign RNG, enabling
    /// byte-for-byte deterministic replay of this episode. `None` when the
    /// episode was run with OS entropy (non-deterministic).
    pub seed: Option<String>,
}

impl EpisodeOutput {
    /// Construct an `EpisodeOutput` from its components.
    ///
    /// * `trace`         – per-step command + verdict pairs.
    /// * `verdict_chain` – hash-linked, Ed25519-signed verdict chain.
    /// * `seed`          – raw 32-byte seed; hex-encoded in the output, or
    ///   `None` for non-deterministic campaigns.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use invariant_robotics_sim::episode::EpisodeOutput;
    /// use invariant_core::models::trace::Trace;
    ///
    /// let trace = Trace {
    ///     id: "ep-1".to_string(),
    ///     episode: 1,
    ///     environment_id: 0,
    ///     scenario: "Aggressive".to_string(),
    ///     profile_name: "ur10".to_string(),
    ///     steps: vec![],
    ///     metadata: HashMap::new(),
    /// };
    ///
    /// // With a fixed seed — hex-encoded as 32 zero bytes.
    /// let seed = [0u8; 32];
    /// let output = EpisodeOutput::new(trace, vec![], Some(seed));
    /// let hex = output.seed.as_deref().unwrap();
    /// assert_eq!(hex.len(), 64); // 32 bytes × 2 hex chars
    /// assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));
    /// ```
    pub fn new(trace: Trace, verdict_chain: Vec<SignedAuditEntry>, seed: Option<[u8; 32]>) -> Self {
        EpisodeOutput {
            trace,
            verdict_chain,
            seed: seed.map(hex_encode_seed),
        }
    }
}

// ---------------------------------------------------------------------------
// VerdictChainBuilder
// ---------------------------------------------------------------------------

/// Builds a hash-linked, Ed25519-signed verdict chain for one simulation episode.
///
/// Each call to [`append`](VerdictChainBuilder::append) adds an [`AuditEntry`]
/// to the chain:
///
/// 1. The entry's `previous_hash` is set to the SHA-256 hex digest of the
///    *previous* entry's canonical JSON (or the empty string for the genesis
///    entry), forming a cryptographic hash chain.
/// 2. The entry's `entry_hash` is the SHA-256 hex digest of the entry's own
///    canonical JSON with `entry_hash` set to `""`.
/// 3. The whole entry is signed with an Ed25519 key, producing a
///    [`SignedAuditEntry`] with a base64-encoded `entry_signature`.
///
/// Call [`build`](VerdictChainBuilder::build) to consume the builder and
/// obtain the completed chain.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
/// use invariant_robotics_sim::episode::VerdictChainBuilder;
///
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let mut builder = VerdictChainBuilder::new(signing_key, "validator-key-1".to_string());
///
/// // An empty chain produces an empty Vec.
/// let chain = builder.build();
/// assert!(chain.is_empty());
/// ```
pub struct VerdictChainBuilder {
    signing_key: SigningKey,
    signer_kid: String,
    entries: Vec<SignedAuditEntry>,
    /// SHA-256 hex digest of the previous entry, or "" for the genesis entry.
    previous_hash: String,
    sequence: u64,
}

impl VerdictChainBuilder {
    /// Create a new builder.
    ///
    /// * `signing_key` – Ed25519 signing key used to sign each audit entry.
    /// * `signer_kid`  – key identifier embedded in each `SignedAuditEntry`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use rand::rngs::OsRng;
    /// use invariant_robotics_sim::episode::VerdictChainBuilder;
    ///
    /// let signing_key = SigningKey::generate(&mut OsRng);
    /// let builder = VerdictChainBuilder::new(signing_key, "kid-abc".to_string());
    /// assert!(builder.build().is_empty());
    /// ```
    pub fn new(signing_key: SigningKey, signer_kid: String) -> Self {
        VerdictChainBuilder {
            signing_key,
            signer_kid,
            entries: Vec::new(),
            previous_hash: String::new(),
            sequence: 0,
        }
    }

    /// Append a command + verdict pair to the chain.
    ///
    /// The entry is hash-linked to its predecessor and signed with the
    /// builder's `signing_key`.  Entries are appended in call order.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use chrono::Utc;
    /// use ed25519_dalek::SigningKey;
    /// use rand::rngs::OsRng;
    /// use invariant_robotics_sim::episode::VerdictChainBuilder;
    /// use invariant_core::models::command::{Command, CommandAuthority};
    /// use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    ///
    /// let signing_key = SigningKey::generate(&mut OsRng);
    /// let mut builder = VerdictChainBuilder::new(signing_key, "kid".to_string());
    ///
    /// let cmd = Command {
    ///     timestamp: Utc::now(),
    ///     source: "sim".to_string(),
    ///     sequence: 0,
    ///     joint_states: vec![],
    ///     delta_time: 0.005,
    ///     end_effector_positions: vec![],
    ///     center_of_mass: None,
    ///     authority: CommandAuthority { pca_chain: "".to_string(), required_ops: vec![] },
    ///     metadata: HashMap::new(),
    ///     locomotion_state: None,
    ///     end_effector_forces: vec![],
    ///     estimated_payload_kg: None,
    ///     signed_sensor_readings: vec![],
    ///     zone_overrides: HashMap::new(),
    ///     environment_state: None,
    /// };
    /// let verdict = SignedVerdict {
    ///     verdict: Verdict {
    ///         approved: true,
    ///         command_hash: "sha256:abc".to_string(),
    ///         command_sequence: 0,
    ///         timestamp: Utc::now(),
    ///         checks: vec![],
    ///         profile_name: "franka_panda".to_string(),
    ///         profile_hash: "sha256:def".to_string(),
    ///         threat_analysis: None,
    ///         authority_summary: AuthoritySummary {
    ///             origin_principal: "op".to_string(),
    ///             hop_count: 1,
    ///             operations_granted: vec![],
    ///             operations_required: vec![],
    ///         },
    ///     },
    ///     verdict_signature: "sig".to_string(),
    ///     signer_kid: "kid".to_string(),
    /// };
    ///
    /// builder.append(cmd, verdict);
    /// let chain = builder.build();
    /// assert_eq!(chain.len(), 1);
    /// // Genesis entry: previous_hash is empty.
    /// assert!(chain[0].entry.previous_hash.is_empty());
    /// // entry_hash is a sha256: prefixed hex digest.
    /// assert!(chain[0].entry.entry_hash.starts_with("sha256:"));
    /// // entry_signature is non-empty base64.
    /// assert!(!chain[0].entry_signature.is_empty());
    /// ```
    pub fn append(&mut self, command: Command, verdict: SignedVerdict) {
        // Step 1: build entry with placeholder entry_hash (empty string).
        let mut entry = AuditEntry {
            sequence: self.sequence,
            previous_hash: self.previous_hash.clone(),
            command,
            verdict,
            entry_hash: String::new(),
        };

        // Step 2: compute SHA-256 of canonical JSON with entry_hash == "".
        // serde_json serialises struct fields in declaration order, so the
        // result is stable across calls.
        let pre_json = serde_json::to_vec(&entry).expect("AuditEntry serialization must not fail");
        let digest = Sha256::digest(&pre_json);
        let hash = format!("sha256:{}", hex_encode_bytes(digest.as_slice()));
        entry.entry_hash = hash.clone();

        // Step 3: sign the *final* entry JSON (with entry_hash set).
        let final_json =
            serde_json::to_vec(&entry).expect("AuditEntry serialization must not fail");
        let signature = self.signing_key.sign(&final_json);
        let sig_b64 = STANDARD.encode(signature.to_bytes());

        let signed = SignedAuditEntry {
            entry,
            entry_signature: sig_b64,
            signer_kid: self.signer_kid.clone(),
        };

        // Advance chain state.
        self.previous_hash = hash;
        self.sequence += 1;
        self.entries.push(signed);
    }

    /// Consume the builder and return the completed chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use rand::rngs::OsRng;
    /// use invariant_robotics_sim::episode::VerdictChainBuilder;
    ///
    /// let key = SigningKey::generate(&mut OsRng);
    /// let builder = VerdictChainBuilder::new(key, "k".to_string());
    /// let chain = builder.build();
    /// assert!(chain.is_empty());
    /// ```
    pub fn build(self) -> Vec<SignedAuditEntry> {
        self.entries
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a byte slice as a lowercase hex string.
fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encode a 32-byte seed as a 64-character lowercase hex string.
fn hex_encode_seed(seed: [u8; 32]) -> String {
    hex_encode_bytes(&seed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use invariant_core::models::command::{Command, CommandAuthority};
    use invariant_core::models::verdict::{AuthoritySummary, SignedVerdict, Verdict};
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    // --- Helpers ---

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_command(seq: u64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: seq,
            joint_states: vec![],
            delta_time: 0.005,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    fn make_verdict(approved: bool, seq: u64) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("sha256:{seq:064x}"),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks: vec![],
                profile_name: "franka_panda".into(),
                profile_hash: "sha256:abc".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "op".into(),
                    hop_count: 1,
                    operations_granted: vec![],
                    operations_required: vec![],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid".into(),
        }
    }

    fn empty_trace(id: &str) -> Trace {
        Trace {
            id: id.into(),
            episode: 0,
            environment_id: 0,
            scenario: "Baseline".into(),
            profile_name: "franka_panda".into(),
            steps: vec![],
            metadata: HashMap::new(),
        }
    }

    // --- VerdictChainBuilder ---

    #[test]
    fn empty_builder_produces_empty_chain() {
        let builder = VerdictChainBuilder::new(fresh_key(), "k".into());
        assert!(builder.build().is_empty());
    }

    #[test]
    fn single_entry_genesis_has_empty_previous_hash() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        let chain = builder.build();
        assert_eq!(chain.len(), 1);
        assert!(
            chain[0].entry.previous_hash.is_empty(),
            "genesis entry must have empty previous_hash"
        );
    }

    #[test]
    fn single_entry_has_sha256_prefixed_hash() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        let chain = builder.build();
        assert!(
            chain[0].entry.entry_hash.starts_with("sha256:"),
            "entry_hash must start with 'sha256:'"
        );
    }

    #[test]
    fn single_entry_hash_is_64_hex_chars_after_prefix() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(false, 0));
        let chain = builder.build();
        let hex_part = chain[0].entry.entry_hash.trim_start_matches("sha256:");
        assert_eq!(
            hex_part.len(),
            64,
            "SHA-256 digest must produce 64 hex characters"
        );
        assert!(
            hex_part.chars().all(|c| "0123456789abcdef".contains(c)),
            "entry_hash hex must be lowercase"
        );
    }

    #[test]
    fn single_entry_signature_is_nonempty_base64() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        let chain = builder.build();
        assert!(
            !chain[0].entry_signature.is_empty(),
            "entry_signature must not be empty"
        );
        // Ed25519 signature is 64 bytes → 88 base64 chars (no padding or with ==).
        let sig_bytes = STANDARD
            .decode(&chain[0].entry_signature)
            .expect("entry_signature must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn two_entries_hash_chain_linked() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        builder.append(make_command(1), make_verdict(false, 1));
        let chain = builder.build();
        assert_eq!(chain.len(), 2);
        // Second entry's previous_hash must equal first entry's entry_hash.
        assert_eq!(
            chain[1].entry.previous_hash, chain[0].entry.entry_hash,
            "entry[1].previous_hash must equal entry[0].entry_hash"
        );
    }

    #[test]
    fn n_entries_hash_chain_fully_linked() {
        let n = 10usize;
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        for i in 0..n as u64 {
            builder.append(make_command(i), make_verdict(i % 2 == 0, i));
        }
        let chain = builder.build();
        assert_eq!(chain.len(), n);
        // Genesis.
        assert!(chain[0].entry.previous_hash.is_empty());
        // Each subsequent entry must link to its predecessor.
        for i in 1..n {
            assert_eq!(
                chain[i].entry.previous_hash,
                chain[i - 1].entry.entry_hash,
                "chain link broken at entry {i}"
            );
        }
    }

    #[test]
    fn sequence_numbers_are_monotonically_increasing() {
        let n = 5u64;
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        for i in 0..n {
            builder.append(make_command(i), make_verdict(true, i));
        }
        let chain = builder.build();
        for (i, entry) in chain.iter().enumerate() {
            assert_eq!(
                entry.entry.sequence, i as u64,
                "sequence number mismatch at index {i}"
            );
        }
    }

    #[test]
    fn signer_kid_propagated_to_all_entries() {
        let kid = "test-validator-key";
        let mut builder = VerdictChainBuilder::new(fresh_key(), kid.into());
        for i in 0..3u64 {
            builder.append(make_command(i), make_verdict(true, i));
        }
        let chain = builder.build();
        for (i, entry) in chain.iter().enumerate() {
            assert_eq!(entry.signer_kid, kid, "signer_kid mismatch at index {i}");
        }
    }

    #[test]
    fn entry_hashes_are_all_distinct() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        for i in 0..5u64 {
            builder.append(make_command(i), make_verdict(i % 2 == 0, i));
        }
        let chain = builder.build();
        let hashes: Vec<&str> = chain.iter().map(|e| e.entry.entry_hash.as_str()).collect();
        let unique: std::collections::HashSet<&str> = hashes.iter().copied().collect();
        assert_eq!(
            hashes.len(),
            unique.len(),
            "all entry_hash values must be distinct"
        );
    }

    #[test]
    fn chain_rejects_modification_detected_via_previous_hash() {
        // Simulate tampering: if an attacker modifies entry[0].entry_hash, the
        // verification that entry[1].previous_hash == entry[0].entry_hash fails.
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        builder.append(make_command(1), make_verdict(true, 1));
        let mut chain = builder.build();
        // Tamper with entry[0].
        chain[0].entry.entry_hash = "sha256:deadbeef".into();
        // The link check must now fail.
        assert_ne!(
            chain[1].entry.previous_hash, chain[0].entry.entry_hash,
            "tampered chain should fail link check"
        );
    }

    // --- EpisodeOutput ---

    #[test]
    fn episode_output_no_seed_is_none() {
        let output = EpisodeOutput::new(empty_trace("ep-0"), vec![], None);
        assert!(output.seed.is_none());
    }

    #[test]
    fn episode_output_zero_seed_produces_64_hex_zeros() {
        let output = EpisodeOutput::new(empty_trace("ep-0"), vec![], Some([0u8; 32]));
        let seed = output.seed.as_deref().unwrap();
        assert_eq!(seed, "0".repeat(64));
    }

    #[test]
    fn episode_output_seed_is_64_hex_chars() {
        let seed_bytes = [42u8; 32];
        let output = EpisodeOutput::new(empty_trace("ep-0"), vec![], Some(seed_bytes));
        let seed = output.seed.as_deref().unwrap();
        assert_eq!(seed.len(), 64);
        assert!(seed.chars().all(|c| "0123456789abcdef".contains(c)));
    }

    #[test]
    fn episode_output_seed_round_trips_correctly() {
        // Seed with distinct bytes: each byte encodes to a predictable hex pair.
        let mut seed_bytes = [0u8; 32];
        for (i, b) in seed_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let output = EpisodeOutput::new(empty_trace("ep-0"), vec![], Some(seed_bytes));
        let hex = output.seed.as_deref().unwrap();
        // First byte (0x00) → "00", second (0x01) → "01", …
        assert_eq!(&hex[0..2], "00");
        assert_eq!(&hex[2..4], "01");
        assert_eq!(&hex[4..6], "02");
        assert_eq!(&hex[62..64], "1f");
    }

    #[test]
    fn episode_output_trace_fields_preserved() {
        let trace = Trace {
            id: "ep-42".into(),
            episode: 42,
            environment_id: 3,
            scenario: "ExclusionZone".into(),
            profile_name: "ur10".into(),
            steps: vec![],
            metadata: HashMap::new(),
        };
        let output = EpisodeOutput::new(trace, vec![], None);
        assert_eq!(output.trace.id, "ep-42");
        assert_eq!(output.trace.episode, 42);
        assert_eq!(output.trace.environment_id, 3);
        assert_eq!(output.trace.scenario, "ExclusionZone");
        assert_eq!(output.trace.profile_name, "ur10");
    }

    #[test]
    fn episode_output_verdict_chain_preserved() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        for i in 0..3u64 {
            builder.append(make_command(i), make_verdict(true, i));
        }
        let chain = builder.build();
        let chain_len = chain.len();
        let output = EpisodeOutput::new(empty_trace("ep-0"), chain, None);
        assert_eq!(output.verdict_chain.len(), chain_len);
    }

    #[test]
    fn episode_output_serializes_and_deserializes() {
        let mut builder = VerdictChainBuilder::new(fresh_key(), "kid".into());
        builder.append(make_command(0), make_verdict(true, 0));
        let chain = builder.build();
        let output = EpisodeOutput::new(empty_trace("serde-ep"), chain, Some([1u8; 32]));
        let json = serde_json::to_string(&output).expect("EpisodeOutput must serialize");
        let back: EpisodeOutput =
            serde_json::from_str(&json).expect("EpisodeOutput must deserialize");
        assert_eq!(back.trace.id, "serde-ep");
        assert_eq!(back.verdict_chain.len(), 1);
        assert!(back.seed.is_some());
    }

    #[test]
    fn episode_output_seed_field_in_json() {
        let seed = [0xdeu8; 32];
        let output = EpisodeOutput::new(empty_trace("ep-0"), vec![], Some(seed));
        let json = serde_json::to_string(&output).expect("must serialize");
        // Hex of 0xde repeated 32 times.
        let expected_hex = "de".repeat(32);
        assert!(
            json.contains(&expected_hex),
            "JSON must contain hex-encoded seed"
        );
    }

    // --- hex_encode_bytes ---

    #[test]
    fn hex_encode_empty_slice() {
        assert_eq!(hex_encode_bytes(&[]), "");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex_encode_bytes(&[0x00]), "00");
        assert_eq!(hex_encode_bytes(&[0xff]), "ff");
        assert_eq!(hex_encode_bytes(&[0x0a]), "0a");
    }

    #[test]
    fn hex_encode_all_zero_seed() {
        assert_eq!(hex_encode_seed([0u8; 32]), "0".repeat(64));
    }

    #[test]
    fn hex_encode_all_ff_seed() {
        assert_eq!(hex_encode_seed([0xffu8; 32]), "ff".repeat(32));
    }
}
