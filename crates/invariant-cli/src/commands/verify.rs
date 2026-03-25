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

    // Verify the audit log.
    match invariant_core::audit::verify_audit_log(&args.log, &vk) {
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

