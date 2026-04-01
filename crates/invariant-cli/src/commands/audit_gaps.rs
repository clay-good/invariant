//! `invariant audit-gaps` — detect sequence number gaps in audit logs (Section 10.4).

use clap::Args;
use std::path::PathBuf;

use invariant_core::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditGapsArgs {
    /// Path to the audit log JSONL file.
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
}

pub fn run(args: &AuditGapsArgs) -> i32 {
    let data = match std::fs::read_to_string(&args.log) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read audit log: {e}");
            return 2;
        }
    };

    let mut entries: Vec<SignedAuditEntry> = Vec::new();
    for (i, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SignedAuditEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                eprintln!("error: failed to parse line {}: {e}", i + 1);
                return 2;
            }
        }
    }

    if entries.is_empty() {
        println!("Audit log is empty.");
        return 0;
    }

    // Check for sequence gaps.
    let mut gaps = Vec::new();
    for window in entries.windows(2) {
        let prev_seq = window[0].entry.sequence;
        let curr_seq = window[1].entry.sequence;
        if curr_seq != prev_seq + 1 && curr_seq != prev_seq {
            gaps.push((prev_seq, curr_seq));
        }
    }

    println!("Audit log: {} entries examined", entries.len());

    if gaps.is_empty() {
        println!("No sequence gaps detected.");
        0
    } else {
        println!("{} gap(s) detected:", gaps.len());
        for (prev, curr) in &gaps {
            println!("  gap between sequence {prev} and {curr}");
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_returns_2() {
        let args = AuditGapsArgs {
            log: PathBuf::from("/nonexistent/audit.jsonl"),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn empty_file_returns_0() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        let args = AuditGapsArgs { log: path };
        assert_eq!(run(&args), 0);
    }
}
