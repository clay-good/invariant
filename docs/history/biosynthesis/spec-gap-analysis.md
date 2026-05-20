> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Specification: Gap Closure & Remediation

**Status:** Draft, 2026-04-25
**Scope:** Captures the delta between the existing specs (`spec.md`, `spec-phase1-gap-closure.md`, `spec-phase2-operational.md`, `step3`–`step10`, `threat-model.md`) and the code currently in `crates/`. Each section names the spec promise, the present implementation, and what remains. Severity tags follow `CRITICAL > HIGH > MEDIUM > LOW`.

---

## 0. Snapshot of the codebase

- `cargo build --workspace`, `cargo test --workspace`, `cargo clippy -- -D warnings` all pass.
- 547 tests pass; zero `unsafe`, zero `todo!()`/`unimplemented!()`/`panic!()` in production paths.
- All crates `#![forbid(unsafe_code)]`.
- The cryptographic spine (PCA authority chain, audit hash chain, attestation, watchdog) is feature-complete and tested. The biology, chemistry, hardware-key, and platform-integration layers are not.

---

## 1. Biological invariants (D-family) — CRITICAL

**Spec promises (step3-bio-invariants.md, D1–D10):** profile-HMM scanning at calibrated bit-score thresholds across sliding windows; codon-substituted homolog detection across 3 reading frames; host-specific codon-usage hints; cross-bundle fragmentation detection (`StatefulInvariant`).

**Code delivers ([crates/invariant-biosynthesis-core/src/invariants/dna.rs](crates/invariant-biosynthesis-core/src/invariants/dna.rs)):** D1–D6 are regex hit-class checks against a `HazardDatabase`; D7 uses a hardcoded entropy band `[2.5, 5.8]`; D8/D9 are correctly evaluated (sliding-window GC, rolling-hash hairpin); D10 is per-bundle stateless only.

**Gaps to close:**

1. **No real homology engine.** Replace regex matching with HMMER (`hmmer` C library) or k-mer alignment (`minimap2`/`rust-bio`). FN rate is currently unbounded for novel pathogen variants.
2. **No 3-frame protein-space rescreen.** `translate_dna_sequence()` exists but is not wired into a homology engine — only used to feed the same regex matcher.
3. **D7 must take host-specific bounds from `BioProfile`.** Add `codon_entropy_bounds: [f64; 2]` to the profile schema and remove the hardcoded constants in `dna.rs`.
4. **D10 needs a `StatefulInvariant` orchestrator.** Currently single-bundle; a fragmentation attack can split a hazardous gene across N bundles and pass each one. Per-operator session state (keyed on PCA chain origin) is required.
5. **Multi-source DB consensus.** `FileBackedHazardDatabase` only loads one DB; spec requires `N≥2` independent publishers for select-agent screening with explicit disagreement surfacing.

**Acceptance:** evaluate against curated HHS Select Agent reference set; FN ≤ 1e-4, FP ≤ 1e-3; published Clopper–Pearson bounds.

---

## 2. Chemical invariants (C-family) — CRITICAL

**Spec promises:** SMILES canonicalisation; SMARTS substructure matching; reaction-feasibility scoring; CWC schedule cross-reference.

**Code delivers ([crates/invariant-biosynthesis-core/src/invariants/chemical.rs](crates/invariant-biosynthesis-core/src/invariants/chemical.rs)):** SMILES strings are pattern-matched as opaque text (e.g. `[Na]`, `P(=O)(O…)(F)`). No molecule object, no canonical form, no isomer awareness.

**Gaps to close:**

1. **Integrate cheminformatics.** Bind RDKit (via FFI) or wrap a Rust port; add a `Molecule` type to replace raw `&str` SMILES.
2. **SMARTS rule library.** Move heuristics out of regex literals into a versioned, signed SMARTS rule set, loaded the same way `HazardDatabase` is loaded.
3. **Canonicalisation before screening.** Reject any C-family bundle whose SMILES does not canonicalise.
4. **C8 reaction-feasibility.** Currently a length heuristic (`>250 chars` advisory). Replace with a real synthon/retrosynthesis scorer or downgrade to advisory in the spec.

**Acceptance:** known-positive set (CWC schedules 1/2, NTA explosives) yields Fail; structural isomers of those molecules also yield Fail; benign isosters do not.

---

## 3. Peptide invariants (P-family) — HIGH

**Spec promises:** MHC-I/II binding prediction (P6); aggregation prediction calibrated against TANGO/Zyggregator (P8); PTM site prediction with sequence context (P9).

**Code delivers ([crates/invariant-biosynthesis-core/src/invariants/peptide.rs](crates/invariant-biosynthesis-core/src/invariants/peptide.rs)):** all 10 invariants run, but P5/P6/P9 are pure regex motif matching, P3 is amphipathicity by sliding window heuristic, P8 is a 6-residue aggregation window plus polyQ.

**Gaps to close:**

1. **P6** must call a real MHC predictor (NetMHCpan via subprocess, or a bundled small model) — current 8–11mer hydrophobic window is a poor proxy.
2. **P8** must compare against a validated aggregation predictor; current heuristic is uncalibrated.
3. **P5** must distinguish active-site motifs from coincidental sequence matches (structural context) — flag as `Advisory` only until a real predictor lands.

---

## 4. Protocol invariants (PR-family) — LOW

**Code delivers:** PR1–PR4 are fully evaluated.

**Gap:** PR2's 25-verb whitelist is hardcoded in [protocol.rs](crates/invariant-biosynthesis-core/src/invariants/protocol.rs). Move the vocabulary into `BioProfile` so per-profile overrides are possible. (Already noted in `README.md` "Known gaps".)

---

## 5. Screening database — HIGH

**Spec promises (step6-screening-databases.md):** signed/versioned hazard DB, multi-source consensus, SecureDNA-style oblivious queries, 30-day fail-closed staleness window.

**Code delivers ([crates/invariant-biosynthesis-core/src/screening/mod.rs](crates/invariant-biosynthesis-core/src/screening/mod.rs)):** signed JSON, schema v1, Ed25519 verification, regex hit classification, configurable freshness window. Single DB only.

**Gaps to close:**

1. **Multi-publisher consensus** — see §1.5. Validator config must accept a list of DBs and a quorum policy.
2. **SecureDNA / oblivious-query backend.** Either implement or remove from spec scope.
3. **Staleness behaviour must always be fail-closed in production** even if `allow_unimplemented_invariants=true`. Currently can be downgraded to advisory in test mode and that path is reachable from the CLI without a guard.

---

## 6. PCA authority chain — COMPLETE

**Spec:** A1–A3 proofs from threat-model.md.

**Code ([crates/invariant-biosynthesis-core/src/authority/](crates/invariant-biosynthesis-core/src/authority/)):** Ed25519 signing/verification, COSE_Sign1 envelope, hop-by-hop validation, time-bound checks, operation algebra (subset / intersection / wildcard) — all tested.

**No gaps.** Out-of-spec opportunity: institutional reference profiles (BSL-2/3/4, pharma R&D, gov-lab) showing how to map institution-root → IBC → PI → lab-member → AI-agent. Belongs in `examples/`, not the core crate.

---

## 7. HSM and key management — CRITICAL (for production)

**Spec promises (step7-hsm-key-mgmt.md):** TPM 2.0, FIPS 140-2 L3 HSMs, YubiHSM, OS keyring; multi-party threshold root-key ceremony; secure-boot attestation; key rotation.

**Code delivers ([crates/invariant-biosynthesis-core/src/keys.rs](crates/invariant-biosynthesis-core/src/keys.rs)):** file-backed Ed25519 keys with mode-0o600 enforcement. `OsKeyringStore`, `TpmKeyStore`, `YubiHsmKeyStore` all return `Unavailable`.

**Gaps to close:**

1. **Real backend implementations.** Suggested crates: `tss-esapi` (TPM 2.0), `yubihsm` (YubiHSM 2), `keyring` (OS keychain).
2. **Provisioning ceremony.** No interface exists for multi-party threshold key generation. Spec or CLI subcommand needed (`invariant-bio keygen ceremony …`).
3. **Key rotation.** No rotation API on `KeyStore`; production deployments will need overlap-key support.
4. **Attestation of firewall host.** TPM/SGX remote attestation is unimplemented; firewall cannot prove to a synthesiser that it is running on trusted hardware.

---

## 8. Audit, replication, witnessing — HIGH

**Spec promises (step8-testing-validation.md, step9-regulatory-compliance.md):** L1–L4 (completeness, ordering, authenticity, immutability); off-site replication; Merkle-root witnessing for external notarisation.

**Code delivers:**
- [audit.rs](crates/invariant-biosynthesis-core/src/audit.rs): append-only JSONL, SHA-256 hash chain, per-entry Ed25519 signatures, tamper detection, rotation guards. Complete.
- [replication.rs](crates/invariant-biosynthesis-core/src/replication.rs): `FileReplicator` real; `S3Replicator` and `WebhookWitness` are stubs returning `not yet implemented`.
- [proof_package.rs](crates/invariant-biosynthesis-core/src/proof_package.rs): bundles (request, verdict, PCA chain, audit entry, witness) for archival.

**Gaps to close:**

1. **`S3Replicator`** — wire to `aws-sdk-s3`; add cross-region replication and recovery-on-restart paths.
2. **`WebhookWitness`** — POST Merkle roots to an external notary (RFC 9162 transparency-log style). Add a verifier client.
3. **Cross-instance Merkle reconciliation.** Multiple firewalls keep independent logs today; need a periodic root-exchange protocol so divergence is detectable.

---

## 9. Synthesis-platform integration — CRITICAL

**Spec promises (step5-platform-integration.md):** integrations with Twist, IDT, Ansa, Kilobaser (DNA), CEM Liberty / Biotage / CSBio / Gyros (peptide), Chemspeed / Hamilton / Tecan (chemical), Emerald / Strateos / Transcriptic (cloud labs); execution-token verification at endpoints; post-execution attestation.

**Code delivers:** envelope types (`ExecutionToken`, `AttestedReading`, `AttestedInput`) and verifier in [attestation.rs](crates/invariant-biosynthesis-core/src/attestation.rs). No vendor API clients exist; no HTTP transport.

**Gaps to close:**

1. **New crate `invariant-biosynthesis-platform`** with a `Platform` trait and reference implementation against one vendor (suggest Twist or Emerald, since both have public APIs).
2. **Execution-token issuance command.** Today the validator produces a verdict; the firewall does not separately produce signed execution tokens that synthesisers can verify offline. Add `invariant-bio issue-token …` and document the verification protocol.
3. **Attestation issuance on the platform side.** Code can verify attested readings; there is no reference implementation that *produces* them. Provide a small "instrument-side" library or example.
4. **Instrument key provisioning.** Documented ceremony required; ties to §7.

---

## 10. Differential validation — MEDIUM

**Code ([differential.rs](crates/invariant-biosynthesis-core/src/differential.rs)):** dual-instance verdict comparison with check-level disagreement detection, fully tested.

**Gap:** not invoked by the standard validate flow. Either (a) wire it as an optional CLI flag (`--differential`) executed by default in production profiles, or (b) drop the IEC 61508 SIL 2 framing from the spec.

---

## 11. Testing, simulation, fuzzing — MEDIUM

**Code:**
- `invariant-biosynthesis-sim`: dry-run campaign harness (5 tests, sample campaigns in `examples/`).
- `invariant-biosynthesis-eval`: rubric scoring (12 lib + 3 integration tests).
- `invariant-biosynthesis-fuzz`: protocol/authority/system/cognitive suites (7 tests).

**Gaps to close:**

1. **Synthetic sequence corpora.** Sim runs against hardcoded bundles. Generate sequences covering legitimate research distributions and known hazard variants for FP/FN measurement.
2. **Statistical validation framework.** Spec calls for Clopper–Pearson bounds, power analysis, Bayesian updating; none of this exists in code. Add a stats module to `eval`.
3. **Shadow-mode evaluation.** No infrastructure for parallel verdict generation against expert human review (spec stage 3). Required before production. Target: >99% agreement on borderline cases.
4. **Hardware-in-the-loop tests.** Stage 2 of step8 requires real-platform-without-real-synthesis tests; cannot exist until §9 lands.

---

## 12. Regulatory compliance — CRITICAL (for production)

**Spec promises (step9-regulatory-compliance.md):** automated compliance reports for CDC Select Agent, NIH rDNA, FDA, USDA APHIS, EPA TSCA, CWC/ITAR/Australia Group/Wassenaar; NIST AI RMF and ISO/IEC AI safety mappings; audit-trail RBAC for regulatory accessors.

**Code delivers:** raw `proof_package` JSON export. No structured reports, no per-jurisdiction profiles, no auditor RBAC.

**Gaps to close:**

1. **`invariant-biosynthesis-compliance` crate** (new) with per-jurisdiction report generators that map verdicts and audit entries onto the agency-required schemas.
2. **Auditor RBAC.** A read-only audit-accessor role authenticated against a separate keypair; today any reader of the JSONL file sees everything.
3. **Per-jurisdiction invariant variants.** No mechanism today to say "this profile is FDA-pharma" vs "USDA-agriculture"; both run identical invariants.

---

## 13. Ecosystem and governance — LOW

**Documents:** `SECURITY.md`, `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md`, `LICENSE` are present (mostly inherited from the robotics sister project; identifiers updated).

**Gaps:** no documented RFC process; no responsible-disclosure SLA; no export-control CI check (`deny.toml` covers licensing, not EAR/ITAR). All low priority but worth a follow-on doc PR.

---

## 14. Code-quality observations

- `unwrap()`/`expect()`: ~406 occurrences, all in tests/examples — clean for production.
- Error enums are well-shaped, but invariant evaluation collapses several distinct conditions into the same variant in places. When telemetry lands (post-§9), error granularity should be revisited.
- Public API has rustdoc; module-level docs are present everywhere; no doc-test gaps.

No code-quality blockers were found. The gaps above are scope, not hygiene.

---

## 15. Phased remediation plan

**Phase A — biology and chemistry parity with spec (CRITICAL):**
- §1 HMMER/BLAST integration for D1–D5
- §1 D7 host-specific bounds; D10 stateful orchestrator
- §2 RDKit + SMARTS rule library
- §5 multi-publisher consensus

**Phase B — production trust boundary (CRITICAL):**
- §7 real HSM backends + provisioning ceremony
- §9 first-vendor platform integration + token issuance
- §12 first-jurisdiction compliance report generator
- §8 S3 replication and webhook witness

**Phase C — operational validation (HIGH/MEDIUM):**
- §3 P6/P8 real predictors
- §11 shadow-mode + statistical framework
- §10 wire differential into default validate
- §8 cross-instance Merkle reconciliation

**Phase D — polish (LOW):**
- §4 PR2 vocabulary into profile
- §13 governance docs and export-control CI

---

## 16. Acceptance gates

A future release may claim "production-ready for synthesis" only when *all* of the following hold:

1. Phase A and Phase B closed; CI green on the corresponding test suites.
2. Curated select-agent reference set: FN ≤ 1e-4, FP ≤ 1e-3, with published Clopper–Pearson bounds.
3. Shadow-mode agreement with expert review > 99% on borderline cases over a documented N.
4. At least one HSM backend in production use; file-backed keys disabled in the production config.
5. At least one synthesiser vendor verifying execution tokens end-to-end.
6. At least one jurisdiction's compliance report accepted by counsel.

Until then, the codebase is a sound reference implementation and a clean integration surface — not a deployable firewall.
