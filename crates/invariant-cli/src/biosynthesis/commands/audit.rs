use clap::{Args, Subcommand};
use std::collections::VecDeque;
use std::io::BufRead;
use std::path::PathBuf;

use invariant_biosynthesis::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Subcommand)]
pub enum AuditCommand {
    /// Display audit log entries (pretty-printed JSON)
    Show(AuditShowArgs),
    /// Verify audit log integrity (hash chain + signatures)
    Verify(super::verify::VerifyArgs),
}

#[derive(Args)]
pub struct AuditShowArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long)]
    pub last: Option<usize>,
}

pub fn run(args: &AuditArgs) -> i32 {
    match &args.command {
        AuditCommand::Show(show_args) => run_show(show_args),
        AuditCommand::Verify(verify_args) => super::verify::run(verify_args),
    }
}

fn run_show(args: &AuditShowArgs) -> i32 {
    let file = match std::fs::File::open(&args.log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: failed to open {:?}: {e}", args.log);
            return 2;
        }
    };
    let reader = std::io::BufReader::new(file);

    if let Some(last_n) = args.last {
        // Ring-buffer approach: keep only the last N entries so we never
        // hold the full file in memory.
        let mut ring: VecDeque<SignedAuditEntry> = VecDeque::with_capacity(last_n);
        for (i, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: I/O error at line {}: {e}", i + 1);
                    return 2;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<SignedAuditEntry>(trimmed) {
                Ok(entry) => {
                    if ring.len() == last_n {
                        ring.pop_front();
                    }
                    ring.push_back(entry);
                }
                Err(e) => {
                    eprintln!("error: parse error at line {}: {e}", i + 1);
                    return 2;
                }
            }
        }
        for entry in &ring {
            match serde_json::to_string_pretty(entry) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: serialization failed: {e}");
                    return 2;
                }
            }
        }
    } else {
        // Stream all entries; never accumulate the full log.
        for (i, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: I/O error at line {}: {e}", i + 1);
                    return 2;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<SignedAuditEntry>(trimmed) {
                Ok(entry) => match serde_json::to_string_pretty(&entry) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: serialization failed: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("error: parse error at line {}: {e}", i + 1);
                    return 2;
                }
            }
        }
    }

    0
}
