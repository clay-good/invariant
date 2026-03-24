// Signed actuation command generator.
//
// Produces a SignedActuationCommand for approved commands. The motor
// controller verifies the Ed25519 signature before executing any movement.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::Serialize;

use crate::models::actuation::SignedActuationCommand;
use crate::models::command::JointState;
use crate::validator::ValidatorError;

/// The unsigned payload that is serialized and signed. The verifier
/// reconstructs this struct from the SignedActuationCommand fields.
#[derive(Serialize)]
struct ActuationPayload<'a> {
    command_hash: &'a str,
    command_sequence: u64,
    joint_states: &'a [JointState],
    timestamp: DateTime<Utc>,
}

/// Build and sign an actuation command for an approved command.
///
/// The `actuation_signature` covers the canonical JSON of the payload fields
/// (command_hash, command_sequence, joint_states, timestamp). The motor
/// controller verifies this signature against the Invariant node's known
/// public key before executing any movement (M1).
pub fn build_signed_actuation_command(
    command_hash: &str,
    command_sequence: u64,
    joint_states: &[JointState],
    timestamp: DateTime<Utc>,
    signing_key: &SigningKey,
    signer_kid: &str,
) -> Result<SignedActuationCommand, ValidatorError> {
    let payload = ActuationPayload {
        command_hash,
        command_sequence,
        joint_states,
        timestamp,
    };

    let payload_json = serde_json::to_vec(&payload).map_err(|e| {
        ValidatorError::Serialization {
            reason: e.to_string(),
        }
    })?;

    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&payload_json);

    Ok(SignedActuationCommand {
        command_hash: command_hash.to_string(),
        command_sequence,
        joint_states: joint_states.to_vec(),
        timestamp,
        actuation_signature: STANDARD.encode(signature.to_bytes()),
        signer_kid: signer_kid.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::generate_keypair;
    use chrono::Utc;
    use ed25519_dalek::Verifier;
    use rand::rngs::OsRng;

    #[test]
    fn actuation_command_signature_verifiable() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let joints = vec![JointState {
            name: "j1".into(),
            position: 0.5,
            velocity: 1.0,
            effort: 10.0,
        }];

        let now = Utc::now();
        let cmd =
            build_signed_actuation_command("sha256:abc123", 42, &joints, now, &sk, "test-kid")
                .unwrap();

        assert_eq!(cmd.command_hash, "sha256:abc123");
        assert_eq!(cmd.command_sequence, 42);
        assert_eq!(cmd.signer_kid, "test-kid");

        // Verify signature.
        let payload = ActuationPayload {
            command_hash: &cmd.command_hash,
            command_sequence: cmd.command_sequence,
            joint_states: &cmd.joint_states,
            timestamp: cmd.timestamp,
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let sig_bytes = STANDARD.decode(&cmd.actuation_signature).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        assert!(vk.verify(&payload_json, &signature).is_ok());
    }

    #[test]
    fn deterministic_signatures() {
        let sk = generate_keypair(&mut OsRng);
        let joints = vec![JointState {
            name: "j1".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];
        let now = Utc::now();

        let cmd1 =
            build_signed_actuation_command("sha256:x", 1, &joints, now, &sk, "k").unwrap();
        let cmd2 =
            build_signed_actuation_command("sha256:x", 1, &joints, now, &sk, "k").unwrap();

        assert_eq!(cmd1.actuation_signature, cmd2.actuation_signature);
    }
}
