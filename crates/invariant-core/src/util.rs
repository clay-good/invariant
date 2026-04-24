use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Compute SHA-256 hash and return as `"sha256:<hex>"` string.
/// Uses a single pre-allocated String instead of per-byte format! calls.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format_sha256_digest(&hash)
}

/// Compute the SHA-256 hash of the canonical JSON serialization of `value`,
/// streaming the JSON directly into the hasher to avoid an intermediate
/// `Vec<u8>` allocation.
///
/// Returns the same `"sha256:<hex>"` string as `sha256_hex(&serde_json::to_vec(value))`,
/// but without the heap allocation for the serialized JSON.
pub fn sha256_hex_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    /// Adapter that implements `std::io::Write` by feeding bytes into a
    /// SHA-256 hasher. This lets `serde_json::to_writer` stream directly
    /// into the digest without a temporary buffer.
    struct HashWriter(Sha256);

    impl std::io::Write for HashWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let writer = HashWriter(Sha256::new());
    let mut ser = serde_json::Serializer::new(writer);
    value.serialize(&mut ser)?;
    let hash = ser.into_inner().0.finalize();
    Ok(format_sha256_digest(&hash))
}

/// Format a raw SHA-256 digest as a `"sha256:<hex>"` string.
fn format_sha256_digest(hash: &[u8]) -> String {
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

    #[test]
    fn sha256_hex_json_matches_to_vec() {
        // The streaming hash must produce exactly the same result as
        // serializing to Vec<u8> first, then hashing.
        let value = serde_json::json!({
            "name": "test",
            "values": [1, 2, 3],
            "nested": {"a": true, "b": null}
        });
        let via_vec = sha256_hex(&serde_json::to_vec(&value).unwrap());
        let via_stream = sha256_hex_json(&value).unwrap();
        assert_eq!(via_vec, via_stream);
    }

    #[test]
    fn sha256_hex_json_empty_object() {
        let value = serde_json::json!({});
        let via_vec = sha256_hex(&serde_json::to_vec(&value).unwrap());
        let via_stream = sha256_hex_json(&value).unwrap();
        assert_eq!(via_vec, via_stream);
    }

    #[test]
    fn sha256_hex_json_string() {
        let value = "hello world";
        let via_vec = sha256_hex(&serde_json::to_vec(&value).unwrap());
        let via_stream = sha256_hex_json(&value).unwrap();
        assert_eq!(via_vec, via_stream);
    }
}
