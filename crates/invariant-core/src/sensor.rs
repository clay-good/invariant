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

/// Errors that can occur during sensor reading signing, verification, or validation.
#[derive(Debug, Error)]
pub enum SensorError {
    /// The Ed25519 signature on a sensor reading could not be verified.
    #[error("sensor signature verification failed for '{sensor_name}': {reason}")]
    SignatureInvalid {
        /// Name of the sensor whose signature failed verification.
        sensor_name: String,
        /// Human-readable description of the verification failure.
        reason: String,
    },

    /// The sensor reading timestamp is older than the permitted maximum age.
    #[error("sensor reading expired: age {age_ms}ms exceeds max {max_ms}ms")]
    ReadingExpired {
        /// Age of the reading in milliseconds relative to the check time.
        age_ms: u64,
        /// Maximum permitted age in milliseconds.
        max_ms: u64,
    },

    /// The sensor reading timestamp is in the future, indicating a possible replay attack.
    #[error("sensor reading is {ahead_ms}ms in the future (possible replay extension attack)")]
    ReadingFromFuture {
        /// How many milliseconds in the future the reading timestamp is.
        ahead_ms: u64,
    },

    /// A JSON serialization step failed while preparing sensor data for signing.
    #[error("serialization error: {reason}")]
    Serialization {
        /// Human-readable description of the serialization failure.
        reason: String,
    },

    /// An unsigned sensor reading was presented but the policy requires signatures.
    #[error("unsigned sensor data rejected by RequireSigned policy")]
    UnsignedRejected,

    /// A sensor payload value is outside physically plausible bounds.
    #[error("sensor '{sensor_name}' payload out of physical range: {reason}")]
    PayloadOutOfRange {
        /// Name of the sensor that produced the out-of-range value.
        sensor_name: String,
        /// Human-readable description of which bound was exceeded.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Sensor reading types
// ---------------------------------------------------------------------------

/// The payload type of a sensor reading.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::SensorPayload;
///
/// let pos = SensorPayload::Position { position: [1.0, 2.0, 3.0] };
/// let force = SensorPayload::Force { force: [0.0, 0.0, 9.8] };
/// let encoder = SensorPayload::JointEncoder { position: 0.5, velocity: 0.1 };
/// let com = SensorPayload::CenterOfMass { com: [0.0, 0.0, 0.5] };
/// let grf = SensorPayload::GroundReaction { grf: [0.0, 0.0, 100.0] };
///
/// // All variants serialize to JSON.
/// assert!(serde_json::to_string(&pos).is_ok());
/// assert!(serde_json::to_string(&force).is_ok());
/// assert!(serde_json::to_string(&encoder).is_ok());
/// assert!(serde_json::to_string(&com).is_ok());
/// assert!(serde_json::to_string(&grf).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SensorPayload {
    /// End-effector position [x, y, z] in world frame.
    Position {
        /// Position vector `[x, y, z]` in metres.
        position: [f64; 3],
    },
    /// Force/torque reading [fx, fy, fz] in Newtons.
    Force {
        /// Force vector `[fx, fy, fz]` in Newtons.
        force: [f64; 3],
    },
    /// Joint encoder reading: position (rad) and velocity (rad/s).
    JointEncoder {
        /// Joint position in radians.
        position: f64,
        /// Joint velocity in radians per second.
        velocity: f64,
    },
    /// Center-of-mass estimate [x, y, z].
    CenterOfMass {
        /// Center-of-mass position `[x, y, z]` in metres.
        com: [f64; 3],
    },
    /// Ground reaction force [fx, fy, fz] in Newtons.
    GroundReaction {
        /// Ground reaction force vector `[fx, fy, fz]` in Newtons.
        grf: [f64; 3],
    },
}

/// A timestamped sensor reading from a named sensor.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::{SensorReading, SensorPayload};
/// use chrono::Utc;
///
/// let reading = SensorReading {
///     sensor_name: "joint_0_encoder".to_string(),
///     timestamp: Utc::now(),
///     payload: SensorPayload::JointEncoder { position: 0.5, velocity: 0.1 },
///     sequence: 0,
/// };
///
/// assert_eq!(reading.sensor_name, "joint_0_encoder");
/// assert_eq!(reading.sequence, 0);
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::SensorTrustPolicy;
///
/// // Default is AcceptUnsigned for backward compatibility.
/// let policy = SensorTrustPolicy::default();
/// assert_eq!(policy, SensorTrustPolicy::AcceptUnsigned);
///
/// let strict = SensorTrustPolicy::RequireSigned;
/// let lenient = SensorTrustPolicy::PreferSigned;
/// assert_ne!(strict, lenient);
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::{sign_sensor_reading, SensorReading, SensorPayload};
/// use chrono::Utc;
/// use ed25519_dalek::SigningKey;
///
/// let signing_key = SigningKey::from_bytes(&[5u8; 32]);
/// let reading = SensorReading {
///     sensor_name: "left_hand_fts".to_string(),
///     timestamp: Utc::now(),
///     payload: SensorPayload::Force { force: [0.0, 0.0, 10.0] },
///     sequence: 0,
/// };
///
/// let signed = sign_sensor_reading(&reading, &signing_key, "sensor-kid").unwrap();
/// assert_eq!(signed.signer_kid, "sensor-kid");
/// assert!(!signed.signature.is_empty());
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::{
///     sign_sensor_reading, verify_sensor_reading, SensorReading, SensorPayload,
/// };
/// use chrono::Utc;
/// use ed25519_dalek::SigningKey;
///
/// let signing_key = SigningKey::from_bytes(&[6u8; 32]);
/// let verifying_key = signing_key.verifying_key();
///
/// let reading = SensorReading {
///     sensor_name: "joint_0_encoder".to_string(),
///     timestamp: Utc::now(),
///     payload: SensorPayload::JointEncoder { position: 1.2, velocity: 0.0 },
///     sequence: 1,
/// };
///
/// let signed = sign_sensor_reading(&reading, &signing_key, "sensor-kid").unwrap();
///
/// // Verification with correct key succeeds.
/// assert!(verify_sensor_reading(&signed, &verifying_key).is_ok());
///
/// // Verification with wrong key fails.
/// let wrong_key = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
/// assert!(verify_sensor_reading(&signed, &wrong_key).is_err());
/// ```
pub fn verify_sensor_reading(
    signed: &SignedSensorReading,
    verifying_key: &VerifyingKey,
) -> Result<(), SensorError> {
    let payload_json =
        serde_json::to_vec(&signed.reading).map_err(|e| SensorError::Serialization {
            reason: e.to_string(),
        })?;

    let sig_bytes =
        STANDARD
            .decode(&signed.signature)
            .map_err(|e| SensorError::SignatureInvalid {
                sensor_name: signed.reading.sensor_name.clone(),
                reason: format!("base64 decode: {e}"),
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

/// Check that a sensor reading is not older than `max_age_ms` relative to `now`
/// and is not dated in the future.
///
/// Future-dated readings are rejected because a compromised sensor driver could
/// post-date readings to extend their replay validity window.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::sensor::{check_sensor_freshness, SensorReading, SensorPayload};
/// use chrono::{Duration, Utc};
///
/// let now = Utc::now();
/// let recent_reading = SensorReading {
///     sensor_name: "imu".to_string(),
///     timestamp: now - Duration::milliseconds(50),
///     payload: SensorPayload::Position { position: [0.0, 0.0, 0.0] },
///     sequence: 0,
/// };
///
/// // Reading is 50ms old, max_age is 100ms — should pass.
/// assert!(check_sensor_freshness(&recent_reading, now, 100).is_ok());
///
/// // Reading is 50ms old, max_age is 10ms — should fail.
/// assert!(check_sensor_freshness(&recent_reading, now, 10).is_err());
///
/// // Future-dated reading — should fail.
/// let future_reading = SensorReading {
///     sensor_name: "imu".to_string(),
///     timestamp: now + Duration::milliseconds(500),
///     payload: SensorPayload::Position { position: [0.0, 0.0, 0.0] },
///     sequence: 1,
/// };
/// assert!(check_sensor_freshness(&future_reading, now, 1000).is_err());
/// ```
pub fn check_sensor_freshness(
    reading: &SensorReading,
    now: DateTime<Utc>,
    max_age_ms: u64,
) -> Result<(), SensorError> {
    let delta = now - reading.timestamp;
    let delta_ms = delta.num_milliseconds();

    // Reject future-dated readings (negative delta means reading is in the future).
    if delta_ms < 0 {
        return Err(SensorError::ReadingFromFuture {
            ahead_ms: (-delta_ms) as u64,
        });
    }

    let age_ms = delta_ms as u64;
    if age_ms > max_age_ms {
        return Err(SensorError::ReadingExpired {
            age_ms,
            max_ms: max_age_ms,
        });
    }
    Ok(())
}

/// Check that a sensor reading's payload values are within physical plausibility
/// bounds (Step 109).
///
/// Rejects values that no real sensor can produce:
/// - Any vector component that is NaN or infinite
/// - Position coordinates beyond ±1000 m (no robot workspace exceeds this)
/// - Force components beyond ±100,000 N (beyond any actuator's capability)
/// - Joint encoder position beyond ±4π rad (covers multi-turn joints)
/// - Joint encoder velocity beyond ±1000 rad/s (no actuator spins this fast)
/// - Center-of-mass beyond ±100 m
/// - Ground reaction force beyond ±100,000 N
///
/// These are NOT threshold checks — those are handled by P1-P25. These are
/// plausibility bounds catching corrupted or spoofed sensor drivers.
pub fn check_payload_range(reading: &SensorReading) -> Result<(), SensorError> {
    let err = |reason: String| SensorError::PayloadOutOfRange {
        sensor_name: reading.sensor_name.clone(),
        reason,
    };

    match &reading.payload {
        SensorPayload::Position { position } => {
            for (i, &v) in position.iter().enumerate() {
                if !v.is_finite() {
                    return Err(err(format!("position[{i}] is NaN or infinite")));
                }
                if v.abs() > 1000.0 {
                    return Err(err(format!(
                        "position[{i}] = {v:.1} m exceeds ±1000 m plausibility limit"
                    )));
                }
            }
        }
        SensorPayload::Force { force } => {
            for (i, &v) in force.iter().enumerate() {
                if !v.is_finite() {
                    return Err(err(format!("force[{i}] is NaN or infinite")));
                }
                if v.abs() > 100_000.0 {
                    return Err(err(format!(
                        "force[{i}] = {v:.1} N exceeds ±100,000 N plausibility limit"
                    )));
                }
            }
        }
        SensorPayload::JointEncoder { position, velocity } => {
            if !position.is_finite() {
                return Err(err("encoder position is NaN or infinite".into()));
            }
            if position.abs() > 4.0 * std::f64::consts::PI {
                return Err(err(format!(
                    "encoder position {position:.4} rad exceeds ±4π rad plausibility limit"
                )));
            }
            if !velocity.is_finite() {
                return Err(err("encoder velocity is NaN or infinite".into()));
            }
            if velocity.abs() > 1000.0 {
                return Err(err(format!(
                    "encoder velocity {velocity:.1} rad/s exceeds ±1000 rad/s plausibility limit"
                )));
            }
        }
        SensorPayload::CenterOfMass { com } => {
            for (i, &v) in com.iter().enumerate() {
                if !v.is_finite() {
                    return Err(err(format!("com[{i}] is NaN or infinite")));
                }
                if v.abs() > 100.0 {
                    return Err(err(format!(
                        "com[{i}] = {v:.1} m exceeds ±100 m plausibility limit"
                    )));
                }
            }
        }
        SensorPayload::GroundReaction { grf } => {
            for (i, &v) in grf.iter().enumerate() {
                if !v.is_finite() {
                    return Err(err(format!("grf[{i}] is NaN or infinite")));
                }
                if v.abs() > 100_000.0 {
                    return Err(err(format!(
                        "grf[{i}] = {v:.1} N exceeds ±100,000 N plausibility limit"
                    )));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sensor fusion consistency (spec-v1.md Section 3.3)
// ---------------------------------------------------------------------------

/// Check that overlapping sensor readings are consistent with each other
/// within the given tolerance.
///
/// Compares all pairs of Position readings — if two sensors report the same
/// named position but disagree by more than `max_position_divergence_m`, the
/// readings are inconsistent (possible spoofing or hardware fault).
///
/// Similarly compares Force readings for the same named sensor.
///
/// Returns a list of inconsistency descriptions. An empty list means all
/// readings are consistent.
pub fn check_sensor_fusion(
    readings: &[SensorReading],
    max_position_divergence_m: f64,
    max_force_divergence_n: f64,
) -> Vec<String> {
    let mut inconsistencies = Vec::new();

    // Group readings by sensor_name and payload type.
    for i in 0..readings.len() {
        for j in (i + 1)..readings.len() {
            if readings[i].sensor_name != readings[j].sensor_name {
                continue;
            }
            match (&readings[i].payload, &readings[j].payload) {
                (
                    SensorPayload::Position { position: a },
                    SensorPayload::Position { position: b },
                ) => {
                    let dist =
                        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2))
                            .sqrt();
                    if dist > max_position_divergence_m {
                        inconsistencies.push(format!(
                            "'{}': position divergence {:.4} m exceeds {:.4} m tolerance (seq {} vs {})",
                            readings[i].sensor_name, dist, max_position_divergence_m,
                            readings[i].sequence, readings[j].sequence
                        ));
                    }
                }
                (SensorPayload::Force { force: a }, SensorPayload::Force { force: b }) => {
                    let diff =
                        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2))
                            .sqrt();
                    if diff > max_force_divergence_n {
                        inconsistencies.push(format!(
                            "'{}': force divergence {:.1} N exceeds {:.1} N tolerance (seq {} vs {})",
                            readings[i].sensor_name, diff, max_force_divergence_n,
                            readings[i].sequence, readings[j].sequence
                        ));
                    }
                }
                _ => {} // different payload types for same sensor — not comparable
            }
        }
    }

    inconsistencies
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
        let vk =
            trusted_keys
                .get(&signed.signer_kid)
                .ok_or_else(|| SensorError::SignatureInvalid {
                    sensor_name: signed.reading.sensor_name.clone(),
                    reason: format!("unknown signer kid '{}'", signed.signer_kid),
                })?;

        // Verify signature.
        verify_sensor_reading(signed, vk)?;

        // Check freshness.
        check_sensor_freshness(&signed.reading, now, max_age_ms)?;

        // Check physical plausibility (Step 109).
        check_payload_range(&signed.reading)?;

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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown signer kid"));
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
        assert_eq!(
            SensorTrustPolicy::default(),
            SensorTrustPolicy::AcceptUnsigned
        );
    }

    // ── Sensor freshness: future-dated reading rejection (Step 100) ───

    #[test]
    fn freshness_rejects_future_dated_reading() {
        let mut reading = make_reading("sensor_a", [0.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() + Duration::seconds(10);
        let result = check_sensor_freshness(&reading, Utc::now(), 500);
        assert!(
            matches!(result, Err(SensorError::ReadingFromFuture { ahead_ms }) if ahead_ms >= 9000),
            "future-dated reading must be rejected, got {result:?}"
        );
    }

    #[test]
    fn freshness_accepts_recent_past_reading() {
        let mut reading = make_reading("sensor_a", [0.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() - Duration::milliseconds(100);
        let result = check_sensor_freshness(&reading, Utc::now(), 500);
        assert!(
            result.is_ok(),
            "100ms old reading within 500ms window must pass"
        );
    }

    #[test]
    fn freshness_rejects_stale_reading() {
        let mut reading = make_reading("sensor_a", [0.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() - Duration::seconds(2);
        let result = check_sensor_freshness(&reading, Utc::now(), 500);
        assert!(
            matches!(result, Err(SensorError::ReadingExpired { .. })),
            "2s old reading must be expired for 500ms window"
        );
    }

    #[test]
    fn batch_verify_rejects_future_dated_in_batch() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let mut reading = make_reading("sensor_a", [1.0, 0.0, 0.0]);
        reading.timestamp = Utc::now() + Duration::seconds(60);
        let signed = sign_sensor_reading(&reading, &sk, "k1").unwrap();

        let mut keys = HashMap::new();
        keys.insert("k1".to_string(), vk);

        let result = verify_sensor_batch(&[signed], &keys, Utc::now(), 500);
        assert!(result.is_err(), "batch with future-dated reading must fail");
    }

    // ── Sensor payload range validation (Step 109) ────────────────────

    fn make_payload_reading(name: &str, payload: SensorPayload) -> SensorReading {
        SensorReading {
            sensor_name: name.to_string(),
            timestamp: Utc::now(),
            payload,
            sequence: 1,
        }
    }

    // -- Position --

    #[test]
    fn payload_range_valid_position_passes() {
        let r = make_payload_reading(
            "ee",
            SensorPayload::Position {
                position: [1.0, 2.0, 0.5],
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    #[test]
    fn payload_range_position_nan_rejected() {
        let r = make_payload_reading(
            "ee",
            SensorPayload::Position {
                position: [f64::NAN, 0.0, 0.0],
            },
        );
        let err = check_payload_range(&r).unwrap_err();
        assert!(matches!(err, SensorError::PayloadOutOfRange { .. }));
    }

    #[test]
    fn payload_range_position_beyond_1000m_rejected() {
        let r = make_payload_reading(
            "ee",
            SensorPayload::Position {
                position: [0.0, 0.0, 1500.0],
            },
        );
        let err = check_payload_range(&r).unwrap_err();
        match err {
            SensorError::PayloadOutOfRange { reason, .. } => {
                assert!(reason.contains("1000"), "must mention limit: {reason}");
            }
            other => panic!("expected PayloadOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn payload_range_position_at_boundary_passes() {
        let r = make_payload_reading(
            "ee",
            SensorPayload::Position {
                position: [1000.0, -1000.0, 0.0],
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    // -- Force --

    #[test]
    fn payload_range_valid_force_passes() {
        let r = make_payload_reading(
            "fts",
            SensorPayload::Force {
                force: [10.0, -5.0, 100.0],
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    #[test]
    fn payload_range_force_beyond_100k_rejected() {
        let r = make_payload_reading(
            "fts",
            SensorPayload::Force {
                force: [200_000.0, 0.0, 0.0],
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    #[test]
    fn payload_range_force_inf_rejected() {
        let r = make_payload_reading(
            "fts",
            SensorPayload::Force {
                force: [f64::INFINITY, 0.0, 0.0],
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    // -- JointEncoder --

    #[test]
    fn payload_range_valid_encoder_passes() {
        let r = make_payload_reading(
            "enc",
            SensorPayload::JointEncoder {
                position: 1.5,
                velocity: 2.0,
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    #[test]
    fn payload_range_encoder_position_beyond_4pi_rejected() {
        let r = make_payload_reading(
            "enc",
            SensorPayload::JointEncoder {
                position: 15.0, // > 4π ≈ 12.57
                velocity: 0.0,
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    #[test]
    fn payload_range_encoder_velocity_beyond_1000_rejected() {
        let r = make_payload_reading(
            "enc",
            SensorPayload::JointEncoder {
                position: 0.0,
                velocity: 1500.0,
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    #[test]
    fn payload_range_encoder_nan_position_rejected() {
        let r = make_payload_reading(
            "enc",
            SensorPayload::JointEncoder {
                position: f64::NAN,
                velocity: 0.0,
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    #[test]
    fn payload_range_encoder_nan_velocity_rejected() {
        let r = make_payload_reading(
            "enc",
            SensorPayload::JointEncoder {
                position: 0.0,
                velocity: f64::NAN,
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    // -- CenterOfMass --

    #[test]
    fn payload_range_valid_com_passes() {
        let r = make_payload_reading(
            "com",
            SensorPayload::CenterOfMass {
                com: [0.0, 0.0, 0.9],
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    #[test]
    fn payload_range_com_beyond_100m_rejected() {
        let r = make_payload_reading(
            "com",
            SensorPayload::CenterOfMass {
                com: [200.0, 0.0, 0.0],
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    // -- GroundReaction --

    #[test]
    fn payload_range_valid_grf_passes() {
        let r = make_payload_reading(
            "foot",
            SensorPayload::GroundReaction {
                grf: [0.0, 0.0, 400.0],
            },
        );
        assert!(check_payload_range(&r).is_ok());
    }

    #[test]
    fn payload_range_grf_beyond_100k_rejected() {
        let r = make_payload_reading(
            "foot",
            SensorPayload::GroundReaction {
                grf: [0.0, 0.0, 200_000.0],
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    #[test]
    fn payload_range_grf_nan_rejected() {
        let r = make_payload_reading(
            "foot",
            SensorPayload::GroundReaction {
                grf: [f64::NAN, 0.0, 0.0],
            },
        );
        assert!(check_payload_range(&r).is_err());
    }

    // ── Sensor fusion consistency tests ───────────────────────────────

    #[test]
    fn fusion_consistent_positions_no_inconsistencies() {
        let readings = vec![
            make_payload_reading(
                "ee",
                SensorPayload::Position {
                    position: [1.0, 0.0, 0.0],
                },
            ),
            make_payload_reading(
                "ee",
                SensorPayload::Position {
                    position: [1.01, 0.0, 0.0],
                },
            ),
        ];
        let issues = check_sensor_fusion(&readings, 0.1, 10.0);
        assert!(issues.is_empty(), "0.01m divergence within 0.1m tolerance");
    }

    #[test]
    fn fusion_divergent_positions_detected() {
        let readings = vec![
            make_payload_reading(
                "ee",
                SensorPayload::Position {
                    position: [1.0, 0.0, 0.0],
                },
            ),
            make_payload_reading(
                "ee",
                SensorPayload::Position {
                    position: [2.0, 0.0, 0.0],
                },
            ),
        ];
        let issues = check_sensor_fusion(&readings, 0.1, 10.0);
        assert_eq!(issues.len(), 1, "1.0m divergence exceeds 0.1m tolerance");
        assert!(issues[0].contains("position divergence"));
    }

    #[test]
    fn fusion_different_sensors_not_compared() {
        let readings = vec![
            make_payload_reading(
                "ee_left",
                SensorPayload::Position {
                    position: [0.0, 0.0, 0.0],
                },
            ),
            make_payload_reading(
                "ee_right",
                SensorPayload::Position {
                    position: [5.0, 5.0, 5.0],
                },
            ),
        ];
        let issues = check_sensor_fusion(&readings, 0.1, 10.0);
        assert!(
            issues.is_empty(),
            "different sensors should not be compared"
        );
    }

    #[test]
    fn fusion_divergent_forces_detected() {
        let readings = vec![
            make_payload_reading(
                "fts",
                SensorPayload::Force {
                    force: [10.0, 0.0, 0.0],
                },
            ),
            make_payload_reading(
                "fts",
                SensorPayload::Force {
                    force: [100.0, 0.0, 0.0],
                },
            ),
        ];
        let issues = check_sensor_fusion(&readings, 1.0, 5.0);
        assert_eq!(issues.len(), 1, "90N divergence exceeds 5N tolerance");
        assert!(issues[0].contains("force divergence"));
    }

    #[test]
    fn fusion_empty_readings_no_issues() {
        let issues = check_sensor_fusion(&[], 0.1, 10.0);
        assert!(issues.is_empty());
    }

    #[test]
    fn fusion_mixed_payload_types_not_compared() {
        let readings = vec![
            make_payload_reading(
                "sensor_a",
                SensorPayload::Position {
                    position: [0.0, 0.0, 0.0],
                },
            ),
            make_payload_reading(
                "sensor_a",
                SensorPayload::Force {
                    force: [100.0, 0.0, 0.0],
                },
            ),
        ];
        let issues = check_sensor_fusion(&readings, 0.001, 0.001);
        assert!(issues.is_empty(), "different payload types not comparable");
    }
}
