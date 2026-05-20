# Step 8 — Testing Framework and Validation Pipeline

**Status:** v0.1 design. Implements `spec.md` Step 8.
**Prereqs:** validator pipeline (Step 0), invariants (Step 3), threat model (Step 2).

Testing a safety-critical firewall requires more than unit tests. This document specifies the four-stage validation pipeline that moves from dry-run simulation to supervised production deployment, plus the statistical machinery that gates each transition.

---

## 1. Four-Stage Pipeline

```
Stage 1: DRY-RUN SIMULATION
  |  (pass: adversarial suites + FP/FN bounds met)
  v
Stage 2: HARDWARE-IN-THE-LOOP
  |  (pass: HIL test matrix green on real synthesizers / simulators)
  v
Stage 3: SHADOW MODE
  |  (pass: statistical acceptance per §4; expert-review concordance)
  v
Stage 4: GUARDIAN MODE
     (supervised autonomous operation; continuous monitoring)
```

Each stage has entry criteria, exit criteria, and a standard test corpus. A component failing at a stage returns to the previous stage until fixed.

---

## 2. Stage 1 — Dry-Run Simulation

Pure software, no hardware, no human subjects.

### 2.1 Components

- **Adversarial fuzz suites** (`crates/invariant-biosynthesis-fuzz/`). Four categories inherited from robotics:
  - **Protocol attacks (PA1–PA15)**: malformed bundles, signature-edge-cases, nonce-replay, canonical-form violations.
  - **Authority attacks (AA1–AA10)**: chain forgery, scope-widening, expired-cert reuse, multi-sig bypass.
  - **System attacks (SA1–SA15)**: DB poisoning, stale-DB bypass, trust-root rollback.
  - **Cognitive attacks (CE1–CE10)**: prompt-injected bundles targeting D/P/C invariants — the bio-specific set, replacing the robotics cognitive suite.

- **Scenario harness** (`crates/invariant-biosynthesis-sim/`). Dry-run campaigns of 1K → 1M bundles. Each campaign is a YAML file describing bundle generation parameters (org mix, sequence length distributions, authority chain variants, adversarial injection rate).

- **Corpus libraries** (`corpora/`):
  - `dna_benign/` — 10k DNA sequences from peer-reviewed synbio papers, flagged benign.
  - `dna_hazardous/` — curated hazardous sequences (select-agent genes, toxin ORFs) held under access control. Not in public repo.
  - `peptide_benign/` — published therapeutic peptides.
  - `peptide_hazardous/` — known AMPs and membrane-active peptides from literature.
  - `small_mol_benign/` — PubChem random sample.
  - `small_mol_hazardous/` — CWC annex + explosives + controlled substances.
  - `adversarial_cognitive/` — prompt-injected bundle corpus (§5.3 of threat-model.md).

### 2.2 Test generation

Probabilistic generators seed the corpus library:
- **Benign expansion**: real-sequence-derived variants with codon-shuffling, silent mutations, point substitutions at non-critical positions.
- **Hazardous adversarial**: known-hazard variants with codon-substituted homologs, fragmentation across 2–5 bundles, synonymous-mutation camouflage.
- **Edge cases**: empty sequences, maximum-length sequences, mixed-case IUPAC ambiguity codes, unusual amino acids, zwitterionic small molecules.
- **Boundary cases**: sequences exactly at screening thresholds (length, GC content, similarity cutoff).

### 2.3 Exit criteria

- Zero escapes across all adversarial suites on the current release commit.
- D1 false-negative rate ≤ 0.1% on the hazardous corpus (Clopper-Pearson upper bound at 95% confidence).
- D1 false-positive rate ≤ 5% on the benign corpus.
- C1 false-negative rate ≤ 0.01% on CWC corpus (higher bar — CWC list is enumerable).
- Full 100K-bundle campaign completes in < 30 min on reference hardware.
- Profile-specific invariant suite green for each shipped profile.

---

## 3. Stage 2 — Hardware-in-the-Loop

Real synthesis platform, without actual synthesis of hazardous content.

### 3.1 What's tested

- Platform-integration round-trip: bundle → firewall → ExecutionToken → platform → Attestation → audit.
- HSM operation at production-rate throughput.
- Kill-switch response: signed `SafeStopAction::HaltSynthesis` propagates in ≤1s.
- Replay attempt: submitting the same nonce twice is rejected by the platform.
- Failure recovery: platform loses network mid-synthesis; does not forget the nonce; does not emit a different attestation on reconnect.
- Signature-verification timing measured end-to-end; p99 < 1s per §Step 6 §4.

### 3.2 Test matrix

Every certified platform adapter runs the same matrix:
- 1000 benign bundles successfully synthesized and attested.
- 100 bundles with bad signature: 100 platform-side rejections.
- 100 bundles with expired token: 100 platform-side rejections.
- 10 kill-switch events during active synthesis: 10 halts within SLA.
- 5 power-cycle mid-synthesis: 5 clean restarts with no lost attestations.
- 1 platform-supply-chain attack simulated (adapter-layer mutation of the request): detected at attestation-reconciliation in 100% of cases.

### 3.3 Simulation fallback

For platforms without available physical access, vendor-provided simulators or community-maintained simulators run the same matrix. Simulator + physical parity is gated by a conformance test set.

### 3.4 Exit criteria

- Full matrix green on the target platform.
- p99 latency within budget.
- Zero silent-failure cases (anything not-Ok must produce a logged attestation).

---

## 4. Stage 3 — Shadow Mode

Firewall runs alongside existing lab workflows. Every real bundle the lab submits is ALSO evaluated by the firewall, but the firewall's verdict does NOT gate synthesis. Discrepancies are reviewed by human experts.

### 4.1 Deployment

- Minimum 3 partner institutions.
- Minimum 90 days per institution.
- Minimum 1000 real bundles per institution covering the institution's actual experimental distribution.
- Partner institutions' IBC/IRB has reviewed and approved the shadow arrangement.

### 4.2 Measurements

- **Approval concordance**: of bundles the lab actually synthesized, what fraction did the firewall also approve?
  - Target: ≥ 98% (high-false-positive rejection of legitimate research = un-deployable).
- **Rejection justification**: of bundles the firewall rejected, what fraction does expert review confirm should have been rejected?
  - Target: ≥ 95% (a firewall that rejects correctly is one tier more valuable than one that rejects randomly).
- **Expert-review time**: median time a bioesecurity expert spends reviewing a disputed firewall decision.
  - Target: ≤ 15 min (scalability).
- **False-negative events**: zero tolerance. Any synthesized-and-dangerous case missed by the firewall halts advancement to Guardian mode.

### 4.3 Statistical machinery

- **Clopper-Pearson confidence intervals** on every binary metric (approval rate, rejection correctness, FN rate). Advancement requires upper-bound or lower-bound (as appropriate) inside target.
- **Sample-size planning**: given target FN rate of 0.1% with 95% confidence and 80% power, n ≥ 3000 hazardous test bundles are required — dry-run corpus supplies these; shadow mode supplies the "in-distribution negative" half.
- **Bayesian update**: posterior over true FP/FN rates is updated as new data arrives. Stage-3 exit is triggered when posterior upper bound on FN falls below threshold.
- **Cross-institution consistency**: metrics broken out per-institution; statistically-significant between-institution variance triggers re-review before advancement (catches institution-specific configuration drift).

### 4.4 Exit criteria

- All three institutional deployments meeting targets simultaneously.
- 90-day window with zero false-negatives (shadow mode's highest-value measurement — does the firewall catch hazardous things that real labs submitted).
- IBC/IRB sign-off per institution.
- Partner-institution operational sign-off (the firewall added ≤ X% latency to typical workflow).

---

## 5. Stage 4 — Guardian Mode

Firewall IS the gate. Synthesis does not happen without firewall approval. Supervised by human operators.

### 5.1 Supervision

- Every firewall rejection surfaces to an on-call reviewer within minutes.
- Reviewer can either confirm the rejection (no action — bundle stays blocked) or invoke emergency override with dual-sign from L1 (override logged and audit-scored).
- Override rate is a live metric; spikes are incident-response events.

### 5.2 Anomaly detection

`monitors.rs` runs continuously:
- **Per-operator baselines**: each operator's typical submission rate, invariant-trigger distribution, time-of-day pattern.
- **Alert triggers**: significant deviation from baseline (e.g., 10x increase in rejection rate for one operator, or a surge of edge-of-threshold submissions).
- **Threat-score thresholds**: composite score per `threat.rs` crossing thresholds invokes `incident.rs` workflows.

### 5.3 Incident response

- Signed `SafeStopAction` halts affected platforms within SLA.
- IBC/IRB notified within 1 hour of critical incidents.
- Forensic bundle generated via `proof_package.rs` containing bundles + verdicts + DB snapshots + code hashes.
- Post-incident review with documented root cause + mitigation added to adversarial corpus.

### 5.4 Performance monitoring

- p50/p99 latency tracked per-institution.
- HSM operation counts per hour.
- DB freshness per installed DB.
- Audit-log growth rate, replica lag, Merkle-root witness staleness.

### 5.5 Graduated autonomy

Over time, the override rate and the FN count can support relaxation of supervision (e.g., from live-on-call review to daily-digest review) — but only per explicit policy change, documented, and reversible.

---

## 6. Continuous Testing

### 6.1 CI gates

Every PR runs:
- Full unit test suite (< 3 min target).
- Adversarial fuzz suites for 1 minute per category.
- Clippy with `-D warnings`.
- `cargo-deny` on dependency tree.
- `cargo-audit` for known CVEs.
- Format check.
- License-header check on new files.

Every nightly:
- 100K-bundle campaign on a reference profile.
- Full adversarial fuzz suites for 1 hour per category.
- Benchmark regression check (± 10% from baseline).

### 6.2 Release gates

Before tagging a minor release:
- Full Stage 1 exit criteria met.
- Adversarial suites expanded with the release's new attack scenarios.
- Migration notes for any DB-format or certificate-format changes.

Before tagging a major release:
- Stage 2 matrix re-run on all supported platforms.
- External security audit of changes to authority/ or screening/ modules.
- CHANGELOG + threat-model diff review.

### 6.3 Property-based testing

Per high-value module:
- `authority/operations.rs` — op-subset algebra: property "child is subset of parent ⇔ parent accepts child's delegation" verified with QuickCheck-style test generators.
- `audit.rs` — hash-chain property "tampering detectable ⇔ O(n) verifier returns failure" with random tamper-position generators.
- Invariant primitives — property "D1 FN rate is monotonic in similarity threshold" etc.

### 6.4 Regression testing

Every bug found in shadow or production is reduced to a failing adversarial test added to the suite. Test suite grows monotonically. We never remove tests.

### 6.5 Cross-validation

For invariants with tunable parameters (e.g., similarity thresholds), k-fold CV on the labeled corpus measures parameter sensitivity. Parameters that move FP/FN by > 10% under small perturbations are flagged for review.

---

## 7. Test Corpus Governance

### 7.1 Public corpora

- Benign corpora: public (research-reproducibility value).
- Adversarial corpora (prompt injections, malformed bundles): public (defensive value).

### 7.2 Restricted corpora

- Hazardous sequences, full-structure CWC annex entries: access-controlled. Distributed only to partner institutions with appropriate clearance.
- Tests reference these corpora by hash; CI pipelines fetch the hashed corpus via signed channel if the runner is authorized.
- Public CI skips restricted-corpus tests; partner-institution CI includes them.

### 7.3 Provenance

Every corpus entry carries a provenance note: source publication, extraction date, curator, rationale. Auditable.

### 7.4 Corpus updates

- Monthly curator review.
- New hazards (e.g., newly-published virulence factors) added within 30 days of publication.
- Retirements (compounds rescheduled or taxa removed) tracked with version history; tests against retired items are kept but flagged.

---

## 8. Implementation Plan

1. **Step 8a** — flesh out the adversarial suites. Protocol and authority suites port nearly verbatim from robotics; system suite needs DB-poisoning scenarios; cognitive suite is entirely new (§threat-model AV-1, AV-8).
2. **Step 8b** — campaign YAML schema + sim harness. Most of the work already in the sim crate from Step 0.
3. **Step 8c** — corpus libraries: start with public benign corpora; secure channel for restricted corpora.
4. **Step 8d** — statistical machinery: Clopper-Pearson, Bayesian updater, power-analysis helper. Small module.
5. **Step 8e** — HIL test harnesses per platform (co-developed with platform adapters per Step 5).
6. **Step 8f** — shadow-mode integration package: configuration, metrics dashboard, expert-review UI. The expert-review UI may be a separate minimal web app; the core firewall exposes metrics over an authenticated HTTP endpoint.

Resource estimate: 8a–8d can land in parallel with the Step 3 invariant implementations. 8e–8f are downstream of working platform adapters.
