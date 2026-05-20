//! v11 1.1 — Per-executor monotonic-clock regression rejection.
//!
//! Asserts that once an executor has appended an entry at monotonic
//! nanoseconds `last`, a subsequent append with `monotonic_nanos < last`
//! for the *same* executor is refused with
//! `AuditError::ClockRegression` and is NOT written to the underlying
//! sink. A different executor at any monotonic value is unaffected
//! (spec-v7 §2.7 multi-source model).

use ed25519_dalek::SigningKey;
use invariant_core::audit::{AuditError, AuditLogger};
use invariant_core::models::audit::BindingContext;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Cmd(u32);

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Verdict(bool);

fn ctx(executor: &str, monotonic: u64) -> BindingContext {
    BindingContext {
        session_id: "sess-clock-regression-test".into(),
        executor_id: executor.into(),
        monotonic_nanos: monotonic,
        wall_clock_rfc3339: "2026-05-18T00:00:00Z".into(),
    }
}

#[test]
fn same_executor_backwards_clock_is_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let sink: Vec<u8> = Vec::new();
    let mut logger: AuditLogger<Vec<u8>, Cmd, Verdict> =
        AuditLogger::new(sink, sk, "test-kid".into());

    logger.set_binding_context(ctx("executor-alpha", 1_000));
    logger.log(&Cmd(1), &Verdict(true)).expect("first write");
    let sequence_after_first = logger.sequence();

    logger.set_binding_context(ctx("executor-alpha", 999));
    let err = logger
        .log(&Cmd(2), &Verdict(true))
        .expect_err("backwards clock must be rejected");
    match err {
        AuditError::ClockRegression {
            executor,
            last,
            attempted,
        } => {
            assert_eq!(executor, "executor-alpha");
            assert_eq!(last, 1_000);
            assert_eq!(attempted, 999);
        }
        other => panic!("expected ClockRegression, got {other:?}"),
    }

    // Hash-chain state must not advance for the rejected append.
    assert_eq!(
        logger.sequence(),
        sequence_after_first,
        "sequence must not advance on ClockRegression"
    );
}

#[test]
fn different_executor_below_first_executors_clock_is_allowed() {
    let sk = SigningKey::generate(&mut OsRng);
    let sink: Vec<u8> = Vec::new();
    let mut logger: AuditLogger<Vec<u8>, Cmd, Verdict> =
        AuditLogger::new(sink, sk, "test-kid".into());

    logger.set_binding_context(ctx("executor-alpha", 1_000));
    logger.log(&Cmd(1), &Verdict(true)).unwrap();

    // beta has no prior reading; even a tiny monotonic value is fine.
    logger.set_binding_context(ctx("executor-beta", 1));
    logger
        .log(&Cmd(2), &Verdict(true))
        .expect("different executor must not be gated by alpha's clock");
}

#[test]
fn same_executor_equal_clock_is_allowed() {
    // Spec wording: reject only when monotonic_nanos is *less than* the
    // last reading. Equal is still monotonic-non-decreasing.
    let sk = SigningKey::generate(&mut OsRng);
    let sink: Vec<u8> = Vec::new();
    let mut logger: AuditLogger<Vec<u8>, Cmd, Verdict> =
        AuditLogger::new(sink, sk, "test-kid".into());

    logger.set_binding_context(ctx("executor-alpha", 1_000));
    logger.log(&Cmd(1), &Verdict(true)).unwrap();
    logger.set_binding_context(ctx("executor-alpha", 1_000));
    logger
        .log(&Cmd(2), &Verdict(true))
        .expect("equal monotonic reading is allowed");
}

#[test]
fn empty_binding_disables_the_check_for_legacy_callers() {
    // Legacy call sites that never install a BindingContext stamp the
    // default (empty) binding. The clock check is skipped — pre-v11-1.1
    // behaviour is preserved.
    let sk = SigningKey::generate(&mut OsRng);
    let sink: Vec<u8> = Vec::new();
    let mut logger: AuditLogger<Vec<u8>, Cmd, Verdict> =
        AuditLogger::new(sink, sk, "test-kid".into());

    logger.log(&Cmd(1), &Verdict(true)).unwrap();
    logger.log(&Cmd(2), &Verdict(true)).unwrap();
    assert_eq!(logger.sequence(), 2);
}
