//! Synthesis-bundle decoding + canonicalization helpers.
//!
//! Keeps bundle-specific parsing / canonical-bytes helpers in one place so the
//! validator and CLI don't both reinvent them. Step 3a defines a stable
//! canonical-bytes scheme based on `serde_json` of the bundle (which already
//! enforces field ordering for `BTreeMap`-backed types). A full RFC 8785 JCS
//! implementation can replace this transparently in a future step.

use crate::models::bundle::SynthesisBundle;
use crate::util::sha256_hex_json;

/// Compute the canonical SHA-256 hash of a [`SynthesisBundle`].
///
/// Returns a `"sha256:<hex>"` string. The canonical bytes are the
/// `serde_json` serialization streamed directly into a SHA-256 hasher.
pub fn canonical_hash(bundle: &SynthesisBundle) -> String {
    sha256_hex_json(bundle).expect("SynthesisBundle is always JSON-serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use chrono::Utc;

    fn bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGC".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    #[test]
    fn canonical_hash_starts_with_prefix() {
        let h = canonical_hash(&bundle());
        assert!(h.starts_with("sha256:"));
    }

    #[test]
    fn canonical_hash_deterministic() {
        let b = bundle();
        assert_eq!(canonical_hash(&b), canonical_hash(&b));
    }
}
