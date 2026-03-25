use clap::Args;
use std::path::PathBuf;

use invariant_core::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long)]
    pub last: Option<usize>,
}

pub fn run(args: &AuditArgs) -> i32 {
    let data = match std::fs::read_to_string(&args.log) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read {:?}: {e}", args.log);
            return 2;
        }
    };

    let mut entries: Vec<SignedAuditEntry> = Vec::new();
    for (i, line) in data.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<SignedAuditEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                eprintln!("error: parse error at line {}: {e}", i + 1);
                return 2;
            }
        }
    }

    // If --last N, take only the last N entries.
    let display = if let Some(n) = args.last {
        let start = entries.len().saturating_sub(n);
        &entries[start..]
    } else {
        &entries
    };

    for entry in display {
        match serde_json::to_string_pretty(entry) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("error: serialization failed: {e}");
                return 2;
            }
        }
    }

    0
}

