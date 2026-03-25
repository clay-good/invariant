use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use rand::rngs::OsRng;
use std::path::PathBuf;

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    /// Output path for the key file. Validated at the OS level via PathBuf (P3-8, P3-9).
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: PathBuf,
}

pub fn run(args: &KeygenArgs) -> i32 {
    let sk = invariant_core::authority::crypto::generate_keypair(&mut OsRng);
    let vk = sk.verifying_key();
    let kf = crate::key_file::KeyFile {
        kid: args.kid.clone(),
        public_key: STANDARD.encode(vk.as_bytes()),
        secret_key: Some(STANDARD.encode(sk.to_bytes())),
    };
    if let Err(e) = crate::key_file::write_key_file(&args.output, &kf) {
        eprintln!("error: {e}");
        return 2;
    }
    eprintln!("Generated Ed25519 keypair: {}", args.kid);
    0
}

