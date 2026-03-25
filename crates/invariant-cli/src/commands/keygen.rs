use clap::Args;
use rand::rngs::OsRng;
use std::path::PathBuf;

use invariant_core::keys::KeyFile;

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    /// Output path for the key file. Validated at the OS level via PathBuf (P3-8, P3-9).
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: PathBuf,
}

pub fn run(args: &KeygenArgs) -> i32 {
    let signing_key =
        invariant_core::authority::crypto::generate_keypair(&mut OsRng);

    let key_file = KeyFile::from_signing_key(&args.kid, &signing_key);

    if let Err(e) = key_file.save(&args.output) {
        eprintln!("invariant keygen: {e}");
        return 2;
    }

    println!(
        "Generated key pair \"{}\" -> {}",
        args.kid,
        args.output.display()
    );
    0
}
