use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long, value_name = "PUBKEY_FILE")]
    pub pubkey: PathBuf,
}

pub fn run(args: &VerifyArgs) -> i32 {
    // Load public key.
    let kf = match crate::key_file::load_key_file(&args.pubkey) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (vk, _kid) = match crate::key_file::load_verifying_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Read and verify the audit log.
    let content = match std::fs::read_to_string(&args.log) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to read audit log: {e}");
            return 2;
        }
    };
    match invariant_core::audit::verify_log(&content, &vk) {
        Ok(count) => {
            println!("OK. {count} entries. Hash chain intact. All signatures valid.");
            0
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    }
}

