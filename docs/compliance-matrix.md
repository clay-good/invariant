# Compliance Matrix (v11-5.15.2)

Maps external safety and security standards to the Invariant Robotics
implementing code path and the test that exercises it. Cross-references
`docs/robotics/spec.md` §4 (compliance posture).

| Standard | Clause | Topic | Implementing code | Test |
|----------|--------|-------|-------------------|------|
| ISO 10218-1:2011 | §5.4.2 | Protective stop | `invariant_robotics::watchdog::Watchdog::trigger` | `crates/invariant-robotics/src/watchdog.rs` tests |
| ISO 10218-1:2011 | §5.4.3 | Safety-rated monitored stop | `validator.rs::handle_safe_stop` path | `validator::tests::safe_stop_*` |
| ISO 10218-2:2011 | §5.10 | Collaborative operation | ISO 15066 derating in `physics/proximity_velocity.rs` | `crates/invariant-robotics/src/physics/proximity_velocity.rs` tests |
| ISO/TS 15066:2016 | §5.5.5 | Power-and-force limiting | `physics/p7_collision_force.rs` (P7) | A-05 / scenario_coverage |
| ISO/TS 15066:2016 | §5.5.4 | Speed-and-separation monitoring | `coordinator::monitor::CoordinationMonitor::check` | `crates/invariant-coordinator/tests/partition_merge_soundness.rs` |
| ISO 13482:2014 | §5.7 | Personal-care robot stability | `physics/p9_stability.rs` (P9) | LocomotionFall scenario |
| IEC 61508-3:2010 | §7.4 | Software safety lifecycle | Lean 4 proofs under `formal/` | `formal/Invariant/Authority.lean` |
| IEC 62443-3-3 | SR 1.1 | Identification and authentication | `authority::chain::verify_chain` | `authority_root_zero_digest` |
| IEC 62443-3-3 | SR 2.1 | Authorization enforcement | A2 monotonicity check | `authority_g09_splice` |
| IEC 62443-3-3 | SR 6.1 | Audit log integrity | `audit::AuditLogger` + Merkle (v11 1.3) | `audit::tests::*` |
| NIST SP 800-218 (SSDF) | PW.4 | Source-code review | GitHub PR review + `ultrareview` | — |
| NIST SP 800-218 (SSDF) | PS.3 | Component archive | release.yml SBOM job | CI |
| NIST SP 800-53 Rev.5 | AU-9 | Audit-log protection | Ed25519-signed append-only chain | `audit_clock_regression` |
| NIST SP 800-53 Rev.5 | SC-12 | Cryptographic key management | `keys::FileKeyStore` + HSM stubs | `keys::tests::*` |
| NIST CSF 2.0 | PR.DS-1 | Data at rest | Audit log file mode 0600 (P3-8) | CLI keygen `force` tests |
| GDPR | Art. 32 | Pseudonymisation in logs | `<redacted>` principals in `AuthorityError` | `error_stability` |
| EU AI Act | Art. 15 | Robustness and cybersecurity | Property + fuzz tests; intent round-trip | `intent_pca_round_trip_property_256_cases`, `fuzz/` |
| RFC 6962 | §2 | Merkle audit trees | `audit/merkle.rs` (v11 1.3) | `merkle_known_vectors` |
| RFC 8032 | — | Ed25519 signatures | `ed25519-dalek` 2.x | upstream test vectors |
| RFC 8785 (JCS) | §3 | JSON canonicalisation | `proof_package::canonical_json` (v11 1.4) | `manifest_jcs_golden` |

## Notes

- Rows tagged `(v11 …)` are pending the cryptographic Phase 1 prompts;
  the table tracks the intended landing site.
- The Lean 4 proofs cover the A1–A4 authority invariants only. Physics
  invariants P1–P25 carry `sorry` placeholders pending floating-point
  verification work (out of scope for v11).
- "—" in the test column means the standard's expectations are met by
  process or external CI rather than an in-tree test.
- For the operator-facing audit-log policy that backs AU-9, see also
  [docs/shadow-deployment.md](shadow-deployment.md) §4.
