# Threat Model (v11-5.15.1)

STRIDE coverage over the five Invariant Robotics threat tiers. Each row maps
a concrete threat to the invariant ID that defends it and the campaign
scenario ID that exercises the defence under simulation.

Cross-references: `docs/robotics/spec.md` §3 (invariants), §6 (campaign);
`docs/robotics/spec-15m-campaign.md` §3 (scenarios A–N).

## Tier 1 — Protocol

| STRIDE | Threat | Invariant | Scenario |
|--------|--------|-----------|----------|
| S | Spoofed PCA hop signed with attacker key | A3 (signature continuity) | G-01 |
| T | Tampered PCA payload after signing | A3 | G-02 |
| R | Replayed PCA across sessions | B1 (session binding) | G-05 |
| I | Information disclosure via verbose error | redaction policy (`AuthorityError::UnknownKeyId`) | G-08 |
| D | DoS via 10⁶-hop chain | A4 (chain length cap) | G-04 |
| E | Privilege escalation by appending ops | A2 (monotonicity) | G-07 |
| —  | Cross-chain hop splice | A3 + predecessor digest | G-09 |

## Tier 2 — System

| STRIDE | Threat | Invariant | Scenario |
|--------|--------|-----------|----------|
| S | Forged executor identity | B4 (executor binding) | G-06 |
| T | Tampered audit JSONL on disk | L1 (signed audit chain) | K-04 |
| R | Reused sequence number after process restart | B2 (sequence monotonicity) | K-01 |
| I | Leaked private key via core dump | OS file mode 0600 (P3-8) | — |
| D | DoS via oversized command JSON | 4 KiB framing cap | I-09 |
| E | Privilege escalation via watchdog bypass | watchdog isolation | K-01 |

## Tier 3 — Cognitive

| STRIDE | Threat | Invariant | Scenario |
|--------|--------|-----------|----------|
| S | LLM impersonates trusted controller | A1 (provenance) | I-01 |
| T | LLM-generated command outside intent | intent narrowing | I-04 |
| R | LLM replays prior approved command | B2 / B3 | I-06 |
| I | Prompt-injection leaks PCA chain | redaction policy | I-02 |
| D | LLM stalls validator with NaN/Inf | P1–P25 fail-closed on non-finite | B-07 |
| E | LLM coaxes operator into expanding ops | template review gate | I-08 |

## Tier 4 — Supply chain

| STRIDE | Threat | Invariant | Scenario |
|--------|--------|-----------|----------|
| S | Trojaned `invariant` binary | reproducible build + cyclonedx SBOM (CI) | — |
| T | Patched profile JSON | profile hash in verdict (`profile_hash`) | A-06 |
| R | Replayed proof package | manifest signature + Merkle root (v11 1.3 / 1.4) | K-04 |
| I | Leaked dev key in committed test fixture | secret-detection hook + key-redaction in audit | — |
| D | Dependency CVE in `serde_json` | `cargo deny` + supply-chain monitoring | — |
| E | Privileged crate substituted via lockfile | `Cargo.lock` checked + `cargo deny advisories` | — |

## Tier 5 — Physical / side-channel

| STRIDE | Threat | Invariant | Scenario |
|--------|--------|-----------|----------|
| S | Cloned HSM token | per-key serial pinned in audit | — |
| T | Glitched sensor reading bypasses derate | SR1/SR2 sensor-range split (v11 5.1) | E-03 |
| R | Replayed sensor packet across runs | signed sensor attestation | E-04 |
| I | Power-analysis on Ed25519 sign | constant-time `ed25519-dalek` | — |
| D | RF jamming of bridge socket | bridge framing timeout + watchdog | K-01 |
| E | Manual override of e-stop wiring | hardware-level (out of scope) | — |

## Notes

- Scenario IDs trace to [docs/scenario-id-map.md](scenario-id-map.md). Rows
  with `—` correspond to defences validated outside the simulation
  campaign (cargo-deny CI, hardware fixtures, manual review).
- Cross-chain hop splice is called out separately because it spans both
  A3 and the predecessor-digest contract added by v11 1.2.
- Tier 5 entries marked `—` for invariant are physical / electrical
  defences that have no software equivalent in the validator; they are
  documented for completeness.
