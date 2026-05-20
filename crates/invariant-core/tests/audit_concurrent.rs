//! v11 1.1 — Concurrent appends across executors.
//!
//! Spec.md §3.3 + spec-v7 §2.7 multi-source model: per-executor sequences
//! are monotonic, but the *aggregate* sequence may interleave across
//! executors. This test runs 16 threads × 1000 appends through a single
//! `Mutex<AuditLogger>` and asserts:
//!
//! 1. The total number of written entries equals 16 × 1000 = 16 000.
//! 2. Within each executor, monotonic_nanos is non-decreasing.
//! 3. The chain verifies end-to-end via `verify_log`.
//! 4. Aggregate entry hashes are unique (L2 ordering).

use ed25519_dalek::SigningKey;
use invariant_core::audit::{verify_log, AuditLogger};
use invariant_core::models::audit::{BindingContext, SignedAuditEntry};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Serialize, Deserialize, Clone)]
struct Cmd {
    thread: usize,
    iter: usize,
}

#[derive(Serialize, Deserialize, Clone)]
struct Verdict(bool);

const THREADS: usize = 16;
const PER_THREAD: usize = 1_000;

#[test]
fn concurrent_appends_across_executors_chain_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let mut sink: Vec<u8> = Vec::new();
    {
        let logger: AuditLogger<&mut Vec<u8>, Cmd, Verdict> =
            AuditLogger::new(&mut sink, sk, "concurrent-test-kid".into());
        let shared = Arc::new(Mutex::new(logger));
        thread::scope(|s| {
            for thread_idx in 0..THREADS {
                let shared = shared.clone();
                s.spawn(move || {
                    let executor = format!("executor-{thread_idx:02}");
                    for iter in 0..PER_THREAD {
                        // High bits = thread index, low bits = strictly
                        // increasing iteration. Within an executor, monotonic
                        // readings strictly increase; across executors there is
                        // no global tie-breaker requirement.
                        let mono = ((thread_idx as u64) << 32) | ((iter as u64) + 1);
                        let mut guard = shared.lock().unwrap();
                        guard.set_binding_context(BindingContext {
                            session_id: "concurrent-session".into(),
                            executor_id: executor.clone(),
                            monotonic_nanos: mono,
                            wall_clock_rfc3339: "2026-05-18T00:00:00Z".into(),
                        });
                        guard
                            .log(
                                &Cmd {
                                    thread: thread_idx,
                                    iter,
                                },
                                &Verdict(true),
                            )
                            .expect("log must succeed");
                    }
                });
            }
        });
    }

    let jsonl = String::from_utf8(sink).unwrap();
    let entries: Vec<SignedAuditEntry<Cmd, Verdict>> = jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse jsonl"))
        .collect();
    assert_eq!(entries.len(), THREADS * PER_THREAD);

    let mut per_exec_last: BTreeMap<String, u64> = BTreeMap::new();
    for e in &entries {
        let exec = e.entry.executor_id.clone();
        if let Some(&prev) = per_exec_last.get(&exec) {
            assert!(
                e.entry.monotonic_nanos >= prev,
                "monotonic regression for {exec}: prev={prev}, here={}",
                e.entry.monotonic_nanos
            );
        }
        per_exec_last.insert(exec, e.entry.monotonic_nanos);
    }
    assert_eq!(per_exec_last.len(), THREADS);

    let mut seen: HashSet<String> = HashSet::new();
    for e in &entries {
        assert!(
            seen.insert(e.entry.entry_hash.clone()),
            "duplicate entry_hash {}",
            e.entry.entry_hash
        );
    }

    let verified = verify_log::<Cmd, Verdict>(&jsonl, &vk).expect("verify_log must succeed");
    assert_eq!(verified as usize, THREADS * PER_THREAD);
}
