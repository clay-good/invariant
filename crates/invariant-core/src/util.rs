use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Compute SHA-256 hash and return as `"sha256:<hex>"` string.
/// Uses a single pre-allocated String instead of per-byte format! calls.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let mut hex = String::with_capacity(7 + 64); // "sha256:" + 64 hex chars
    hex.push_str("sha256:");
    for b in hash.iter() {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_format() {
        let result = sha256_hex(b"hello world");
        assert!(result.starts_with("sha256:"));
        assert_eq!(result.len(), 7 + 64);
        let hex_part = &result[7..];
        assert!(hex_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256 of empty input is well-known.
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex(b"test data");
        let b = sha256_hex(b"test data");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_hex_different_inputs_differ() {
        let a = sha256_hex(b"foo");
        let b = sha256_hex(b"bar");
        assert_ne!(a, b);
    }
}
