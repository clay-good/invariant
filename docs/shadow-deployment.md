# Shadow Deployment Runbook

**Audience:** robotics integration engineers running `invariant serve` alongside a production controller in observe-only mode.
**Scope:** robotics surface, UR10e CNC cell as the canonical pilot. The biosynthesis surface has its own pilot model and is out of scope here.
**Status:** v12-N-8; ratified after a complete shadow trial signs off per §5.

## 1. Goal

Accumulate **≥100 robot-hours** of `invariant serve` decisions on a UR10e CNC tending cell with the validator wired in observe-only — every command flowing to the controller is mirrored to the validator, but the validator's verdict does **not** gate execution. The trial succeeds when the validator's verdicts agree with the ground-truth controller within the divergence budget in §5 and zero P1 incidents fire across the window.

A shadow deployment is a measurement, not a release. Nothing about it implies the validator is ready to act as an enforcement point. Promoting from shadow to enforcement is a separate process with its own sign-off.

## 2. Pre-flight checklist

Before the first PCA is submitted, confirm every item below. Each line is a hard block — do not start the trial with any item unchecked.

- [ ] **Profile selected and reviewed.** The exact profile JSON file (`profiles/robotics/ur10e_*.json`) is committed, its commit hash is recorded in the trial log, and the kinematic limits match the physical cell as measured (not as listed in the vendor datasheet).
- [ ] **Audit destination reachable.** `invariant robotics audit` against the planned destination returns 0 with a non-empty verify summary. The destination has at least 10× the expected 100-robot-hour audit volume free.
- [ ] **Replication backend configured or explicitly disabled.** If S3 / webhook replication is enabled (v11 4.2), a synthetic test record is replicated end-to-end and verified offline. If disabled, the disable is recorded in the trial log with a one-line justification.
- [ ] **Watchdog tuned.** `watchdog_window_ms`, `watchdog_min_observations`, and the per-channel rate-of-change ceilings are set for *this* cell's cadence — not the validator defaults. Bench the cadence against an idle 30-minute run before flipping to live traffic.
- [ ] **Alert sinks point at a sandbox channel.** Webhook and syslog alert sinks (v11 4.3) are configured to deliver to a sandboxed channel, **not** the production on-call rotation. Confirm with a synthetic alert before opening the trial.
- [ ] **Authority chain materialized.** PIC root, intermediate PCAs, and the executor identity are loaded into the keystore that `serve` is bound to. `invariant robotics verify-self` exits 0.
- [ ] **Bridge framing capped.** The Isaac / ROS2 bridge (whichever the cell uses) has bounded reads enabled — confirm by inspecting the bridge invocation flags, not by trusting the default.
- [ ] **Time source verified.** Both the controller host and the validator host disciplines to the same NTP source. Drift > 50 ms triggers a B3 (temporal-window) false-positive storm.
- [ ] **Rollback plan documented.** Whoever is on call for the cell during the trial has a one-page rollback that disables the mirror and detaches the validator without touching the controller.

## 3. Metrics

Collect continuously throughout the trial. Every metric is timestamped with both wall-clock and monotonic-ns (per audit B1–B4 fields) so traces can be replayed against the audit log.

| Metric                            | Aggregation        | Sampling     | Why it matters |
|-----------------------------------|--------------------|--------------|----------------|
| Validation latency p50 / p95 / p99 | per 1-minute bucket| every request| Predicts whether enforcement mode can meet the controller cycle time. |
| Decisions/sec                      | per 1-minute bucket| every request| Indicates load; pairs with latency to spot saturation. |
| Divergence count vs. controller    | per shift          | every request| The headline trial metric. See §5 for the budget. |
| Divergence rate (divergent / total)| per shift          | derived       | Normalizes for traffic; gates sign-off. |
| Audit growth rate (MiB/h)          | per hour           | per append    | Sizes the production audit volume. |
| Watchdog firings / hour            | per hour           | per firing    | High rate → watchdog mis-tuned, not validator wrong. |
| Bridge frame-rejection rate        | per hour           | per rejection | Indicates framing or bounded-read issues. |
| Key-store latency p99              | per 1-minute bucket| per signing   | Backstop for HSM degradation under load. |

Dashboards live alongside the cell's existing observability stack — do not stand up a parallel one for the trial. Cross-link from the alert sinks so a triage starts at the dashboard.

## 4. Divergence triage protocol

A "divergence" is any request where the validator's verdict differs from the controller's effective decision for the same command in the same authority context. Every divergence runs through the loop below, no exceptions:

1. **Collect the artifacts.** PCA chain (full), command bytes, validator state snapshot, watchdog state, time-source diagnostic, controller decision and rationale. The PCA chain and command must be byte-identical to what `serve` saw; capture from the audit log, not from a re-derivation.
2. **Freeze the audit shard.** The shard containing the divergence is rotated and sealed; its Merkle root (post-v11-1.3) is recorded alongside the incident. This makes the divergence trivially reproducible later even if the audit destination is gardened.
3. **Open an incident** through the existing `incident.rs` flow with severity inferred from §5. Attach all artifacts collected in step 1.
4. **Rerun in dry-run mode.** Replay the captured command + PCA against `invariant robotics validate` in dry-run, with the captured profile and chain. If the verdict matches the trial verdict, the validator is deterministic on this input — proceed to step 5. If not, the divergence is a non-determinism bug and is escalated immediately regardless of cause.
5. **Classify.** Every divergence terminates in exactly one of:
   - **false-positive** — controller accepted, validator rejected, and the controller's behavior was correct under the spec. Counts against the divergence budget in §5.
   - **true-positive** — controller accepted, validator rejected, and replay shows the controller should have rejected. Trial does not abort, but the finding is escalated to the cell owners. Counts toward closing the shadow on success.
   - **configuration** — divergence is attributable to a mis-tuned profile, watchdog, or time source. Does **not** count against the budget once the configuration is corrected and the trial clock is restarted from that point.
   - **unknown** — triage could not arrive at one of the three above. P1 incident; trial pauses until classified.
6. **Update the divergence ledger.** A single CSV file under the trial workspace, append-only, one row per divergence: `timestamp, shard_id, audit_seq, classification, owner, link_to_incident`. The ledger is what §5 reads to decide sign-off.

## 5. Sign-off criteria

The trial closes successfully when **all** of:

- ≥ 100 robot-hours of *live* mirrored traffic accumulated. Idle minutes (no commands flowing) count at most 10% of the total.
- Divergence rate ≤ **0.01%** of total decisions, computed against false-positives only (true-positives are exonerating; configuration is exempt once corrected).
- **Zero P1 incidents** open at close. P1 = unknown-classification divergence, validator non-determinism, audit-log corruption, key-store unavailability lasting > 1 minute, or any divergence that would have caused unsafe motion if the validator had been gating.
- p99 validation latency ≤ the controller's per-command budget across every shift in the window. The budget is recorded at trial open and frozen for the duration.
- Audit log verifies end-to-end (`invariant robotics audit verify` plus, once v11 1.3 lands, `--merkle-root` against the trial-anchor root).

Sign-off is a two-signature event: the cell owner and the validator owner both attach their names to the ledger close row. Anything short of all five criteria is a trial extension or a failed trial, not a partial pass.

## 6. After sign-off

- Archive the divergence ledger, the trial profile snapshot, every frozen audit shard, and the dashboards into the cell's compliance store.
- File a one-pager summary in `docs/` covering: divergence rate, latency percentiles, configuration changes made mid-trial, and any pattern of true-positives that should be promoted to a new physics check or watchdog rule.
- Promoting the cell from shadow to enforcement is a separate runbook (out of scope here). The shadow trial is a precondition, not a permission.

## 7. References

- Authority binding fields B1–B4: `docs/robotics/spec.md` §3.3, v11 1.1.
- Audit log Merkle root: v11 1.3 (`merkle_root.txt`), N-11 (rotation continuity).
- Replication backends: v11 4.2.
- Alert sinks: v11 4.3.
- Watchdog isolation: v11 3.2.
- Incident flow: `crates/invariant-core/src/incident.rs`.
