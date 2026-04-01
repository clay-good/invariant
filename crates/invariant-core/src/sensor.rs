// Signed sensor data for zero-trust sensor integrity (Step 64).
//
// In the current design, the cognitive layer reports end-effector positions,
// forces, and locomotion state as bare floating-point values inside each
// Command. A compromised cognitive layer can lie about these values to bypass
// physics checks (Attack #12: sensor spoofing).
//
// This module adds a cryptographic attestation layer: sensor hardware (or its
// driver) signs each reading with Ed25519. Invariant verifies the signature
// before using the sensor data for physics checks, ensuring the data actually
// came from a trusted sensor and wasn't tampered with in transit.
//
// Design:
// - `SensorReading` — a timestamped, named reading with a payload.
// - `SignedSensorReading` — a reading + Ed25519 signature + signer kid.
// - `sign_sensor_reading()` / `verify_sensor_reading()` — sign and verify.
// - `SensorTrustPolicy` — how the validator handles signed vs unsigned data:
//   `RequireSigned` (reject unsigned), `PreferSigned` (accept unsigned with
//   flag), or `AcceptUnsigned` (backwards compatible, no signature check).

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("sensor signature verification failed for '{sensor_name}': {reason}")]
    SignatureInvalid { sensor_name: String, reason: String },

    #[error("sensor reading expired: age {age_ms}ms exceeds max {max_ms}ms")]
    ReadingExpired { age_ms: u64, max_ms: u64 },

    #[error("serialization error: {reason}")]
    Serialization { reason: String },

    #[error("unsigned sensor data rejected by RequireSigned policy")]
    UnsignedRejected,
}

// ---------------------------------------------------------------------------
// Sensor reading types
// ---------------------------------------------------------------------------

/// The payload type of a sensor reading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SensorPayload {
    /// End-effector position [x, y, z] in world frame.
    Position { position: [f64; 3] },
    /// Force/torque reading [fx, fy, fz] in Newtons.
    Force { force: [f64; 3] },
    /// Joint encoder reading: position (rad) and velocity (rad/s).
    JointEncoder { position: f64, velocity: f64 },
    /// Center-of-mass estimate [x, y, z].
    CenterOfMass { com: [f64; 3] },
    /// Ground reaction force [fx, fy, fz] in Newtons.
    GroundReaction { grf: [f64; 3] },
}

/// A timestamped sensor reading from a named sensor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorReading {
    /// Name identifying the sensor (e.g., "left_hand_fts", "joint_0_encoder").
    pub sensor_name: String,
    /// Timestamp when the reading was taken.
    pub timestamp: DateTime<Utc>,
    /// The sensor data.
    pub payload: SensorPayload,
    /// Monotonic sequence number from the sensor driver.
    pub sequence: u64,
}

/// A sensor reading with an Ed25519 signature from the sensor hardware/driver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedSensorReading {
    /// The reading data (signed payload).
    pub reading: SensorReading,
    /// Base64-encoded Ed25519 signature over the canonical JSON of `reading`.
    pub signature: String,
    /// Key identifier of the sensor's signing key.
    pub signer_kid: String,
}

// ---------------------------------------------------------------------------
// Trust policy
// ---------------------------------------------------------------------------

/// How the validator handles sensor data trust.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorTrustPolicy {
    /// Reject commands that include unsigned sensor data. All sensor readings
    /// must be signed and verified. For production Guardian mode.
    RequireSigned,
    /// Accept unsigned data but flag it in the verdict. For Shadow mode and
    /// gradual rollout.
    PreferSigned,
    /// No signature verification. Backwards compatible with existing commands.
    /// For Forge mode and development.
    #[default]
    AcceptUnsigned,
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a sensor reading with Ed25519.
pub fn sign_sensor_reading(
    reading: &SensorReading,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<SignedSensorReading, SensorError> {
    let payload_json = serde_json::to_vec(reading).map_err(|e| SensorError::Serialization {
        reason: e.to_string(),
    })?;

    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&payload_json);

    Ok(SignedSensorReading {
        reading: reading.clone(),
        signature: STANDARD.encode(signature.to_bytes()),
        signer_kid: kid.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify the Ed25519 signature on a signed sensor reading.
pub fn verify_sensor_reading(
    signed: &SignedSensorReading,
    verifying_key: &VerifyingKey,
) -> Result<(), SensorError> {
    let payload_json =
        serde_json::to_vec(&signed.reading).map_err(|e| SensorError::Serialization {
            reason: e.to_string(),
        })?;

    let sig_bytes = STANDARD.decode(&signed.signature).map_err(|e| {
        SensorError::SignatureInvalid {
            sensor_name: signed.reading.sensor_name.clone(),
            reason: format!("base64 decode: {e}"),
        }
    })?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        SensorError::SignatureInvalid {
            sensor_name: signed.reading.sensor_name.clone(),
            reason: format!("invalid signature bytes: {e}"),
        }
    })?;

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&payload_json, &signature)
        .map_err(|e| SensorError::SignatureInvalid {
            sensor_name: signed.reading.sensor_name.clone(),
            reason: e.to_string(),
        })
}

/// Check that a sensor reading is not older than `max_age_ms` relative to `now`.
pub fn check_sensor_freshness(
    reading: &SensorReading,
    now: DateTime<Utc>,
    max_age_ms: u64,
) -> Result<(), SensorError> {
    let age_ms = (now - reading.timestamp).num_milliseconds().unsigned_abs();
    if age_ms > max_age_ms {
        return Err(SensorError::ReadingExpired {
            age_ms,
            max_ms: max_age_ms,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/// Verify a batch of signed sensor readings against a set of trusted keys.
///
/// Returns the list of verified readings (stripped of signatures) on success,
/// or the first verification error encountered.
pub fn verify_sensor_batch(
    readings: &[SignedSensorReading],
    trusted_keys: &std::collections::HashMap<String, VerifyingKey>,
    now: DateTime<Utc>,
    max_age_ms: u64,
) -> Result<Vec<SensorReading>, SensorError> {
    let mut verified = Vec::with_capacity(readings.len());

    for signed in readings {
        // Look up the trusted key.
        let vk = trusted_keys
            .get(&signed.signer_kid)
            .ok_or_else(|| SensorError::SignatureInvalid {
                sensor_name: signed.reading.sensor_name.clone(),
                reason: format!("unknown signer kid '{}'", signed.signer_kid),
            })?;

        // Verify signature.
        verify_sensor_reading(signed, vk)?;

        // Check freshness.
        check_sensor_freshness(&signed.reading, now, max_age_ms)?;

        verified.push(signed.reading.clone());
    }

    Ok(verified)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::generate_keypair;
    use chrono::Duration;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_reading(name: &str, pos: [f64; 3]) -> SensorReading {
        SensorReading {
            sensor_name: name.to_string(),
            timestamp: Utc::now(),
            payload: SensorPayload::Position { position: pos },
            sequence: 1,
        }
    }

    fn make_force_reading(name: &str, force: [f64; 3]) -> SensorReading {
        SensorReading {
            sensor_name: name.to_string(),
            timestamp: Utc::now(),
            payload: SensorPayload::Force { force },
            sequence: 1,
        }
    }

    // -- Sign + verify round-trip --

    #[test]
    fn sign_verify_position_reading() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = make_reading("left_hand", [0.3, 0.1, 1.2]);
        let signed = sign_sensor_reading(&reading, &sk, "sensor-key-001").unwrap();

        assert_eq!(signed.signer_kid, "sensor-key-001");
        assert!(!signed.signature.is_empty());

        assert!(verify_sensor_reading(&signed, &vk).is_ok());
    }

    #[test]
    fn sign_verify_force_reading() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = make_force_reading("right_hand_fts", [10.0, -5.0, 0.0]);
        let signed = sign_sensor_reading(&reading, &sk, "fts-key").unwrap();

        assert!(verify_sensor_reading(&signed, &vk).is_ok());
    }

    #[test]
    fn sign_verify_joint_encoder() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = SensorReading {
            sensor_name: "joint_0_encoder".to_string(),
            timestamp: Utc::now(),
            payload: SensorPayload::JointEncoder {
                position: 0.5,
                velocity: 1.2,
            },
            sequence: 42,
        };
        let signed = sign_sensor_reading(&reading, &sk, "enc-key").unwrap();
        assert!(verify_sensor_reading(&signed, &vk).is_ok());
    }

    #[test]
    fn sign_verify_com_reading() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = SensorReading {
            sensor_name: "imu".to_string(),
            timestamp: Utc::now(),
            payload: SensorPayload::CenterOfMass {
                com: [0.0, 0.0, 0.9],
            },
            sequence: 1,
        };
        let signed = sign_sensor_reading(&reading, &sk, "imu-key").unwrap();
        assert!(verify_sensor_reading(&signed, &vk).is_ok());
    }

    #[test]
    fn sign_verify_grf_reading() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = SensorReading {
            sensor_name: "left_foot_fts".to_string(),
            timestamp: Utc::now(),
            payload: SensorPayload::GroundReaction {
                grf: [0.0, 0.0, 400.0],
            },
            sequence: 1,
        };
        let signed = sign_sensor_reading(&reading, &sk, "foot-key").unwrap();
        assert!(verify_sensor_reading(&signed, &vk).is_ok());
    }

    // -- Tamper detection --

    #[test]
    fn tampered_reading_rejected() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = make_reading("left_hand", [0.3, 0.1, 1.2]);
        let mut signed = sign_sensor_reading(&reading, &sk, "key").unwrap();

        // Tamper: change the position.
        signed.reading.payload = SensorPayload::Position {
            position: [999.0, 999.0, 999.0],
        };

        assert!(verify_sensor_reading(&signed, &vk).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = generate_keypair(&mut OsRng);
        let wrong_sk = generate_keypair(&mut OsRng);
        let wrong_vk = wrong_sk.verifying_key();

        let reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        let signed = sign_sensor_reading(&reading, &sk, "key").unwrap();

        assert!(verify_sensor_reading(&signed, &wrong_vk).is_err());
    }

    #[test]
    fn corrupted_signature_rejected() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        let mut signed = sign_sensor_reading(&reading, &sk, "key").unwrap();

        // Corrupt the base64 signature.
        signed.signature = "not-valid-base64!!!".to_string();

        assert!(verify_sensor_reading(&signed, &vk).is_err());
    }

    // -- Freshness check --

    #[test]
    fn fresh_reading_passes() {
        let reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        let now = Utc::now();
        assert!(check_sensor_freshness(&reading, now, 1000).is_ok());
    }

    #[test]
    fn stale_reading_rejected() {
        let mut reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() - Duration::seconds(5);
        let now = Utc::now();

        let result = check_sensor_freshness(&reading, now, 100); // 100ms max
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    // -- Batch verification --

    #[test]
    fn batch_verify_all_valid() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let r1 = make_reading("sensor_a", [1.0, 0.0, 0.0]);
        let r2 = make_reading("sensor_b", [0.0, 1.0, 0.0]);

        let s1 = sign_sensor_reading(&r1, &sk, "k").unwrap();
        let s2 = sign_sensor_reading(&r2, &sk, "k").unwrap();

        let mut trusted = HashMap::new();
        trusted.insert("k".to_string(), vk);

        let verified = verify_sensor_batch(&[s1, s2], &trusted, Utc::now(), 5000).unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].sensor_name, "sensor_a");
        assert_eq!(verified[1].sensor_name, "sensor_b");
    }

    #[test]
    fn batch_verify_unknown_kid_fails() {
        let sk = generate_keypair(&mut OsRng);

        let reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        let signed = sign_sensor_reading(&reading, &sk, "unknown-key").unwrap();

        let trusted: HashMap<String, VerifyingKey> = HashMap::new(); // empty

        let result = verify_sensor_batch(&[signed], &trusted, Utc::now(), 5000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown signer kid"));
    }

    #[test]
    fn batch_verify_one_tampered_fails() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let r1 = make_reading("good", [0.0, 0.0, 0.0]);
        let r2 = make_reading("bad", [0.0, 0.0, 0.0]);

        let s1 = sign_sensor_reading(&r1, &sk, "k").unwrap();
        let mut s2 = sign_sensor_reading(&r2, &sk, "k").unwrap();
        s2.reading.payload = SensorPayload::Position {
            position: [999.0, 0.0, 0.0],
        };

        let mut trusted = HashMap::new();
        trusted.insert("k".to_string(), vk);

        let result = verify_sensor_batch(&[s1, s2], &trusted, Utc::now(), 5000);
        assert!(result.is_err());
    }

    #[test]
    fn batch_verify_stale_reading_fails() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let mut reading = make_reading("sensor", [0.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() - Duration::seconds(10);
        let signed = sign_sensor_reading(&reading, &sk, "k").unwrap();

        let mut trusted = HashMap::new();
        trusted.insert("k".to_string(), vk);

        let result = verify_sensor_batch(&[signed], &trusted, Utc::now(), 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    // -- Serde round-trip --

    #[test]
    fn sensor_reading_serde_round_trip() {
        let reading = make_reading("sensor", [1.0, 2.0, 3.0]);
        let json = serde_json::to_string(&reading).unwrap();
        let back: SensorReading = serde_json::from_str(&json).unwrap();
        assert_eq!(reading, back);
    }

    #[test]
    fn signed_sensor_reading_serde_round_trip() {
        let sk = generate_keypair(&mut OsRng);
        let reading = make_reading("sensor", [1.0, 2.0, 3.0]);
        let signed = sign_sensor_reading(&reading, &sk, "k").unwrap();

        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedSensorReading = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, back);
    }

    // -- Policy enum default --

    #[test]
    fn default_policy_is_accept_unsigned() {
        assert_eq!(SensorTrustPolicy::default(), SensorTrustPolicy::AcceptUnsigned);
    }
}
