# Step 1 — Reuse Map (executed)

Step 1 of `spec.md` asks for a structured reuse-mapping document against `invariant-robotics`. That analysis was performed during Step 0 and the resulting mapping is the three tables (Category A verbatim, Category B template, Category C skip) in `spec.md` itself, plus the file manifest produced by the Step 0 bootstrap.

This file exists to satisfy the Step 1 deliverable without duplicating content. For the authoritative mapping, read:

- `spec.md` → section **"Step 0: Copy/Paste Reuse Manifest from invariant-robotics"** — the Category A / B / C tables with source→destination paths and modification strategy.
- `CHANGELOG.md` entry `0.0.1` — the concrete list of what actually landed.
- `crates/invariant-biosynthesis-core/src/lib.rs` — the current module list (anything referenced there was copied; anything missing relative to robotics was either skipped or deferred to Step 3).

### Deferred ports — landed in 0.0.3

The Step 0 bootstrap deferred seven Category-A files because they transitively reference the robotics `Command` / `RobotProfile` / `models::trace` types. They were ported in the 0.0.3 release alongside the Step 3a invariant skeleton:

| File in `invariant-robotics/crates/invariant-core/src/` | Target module in bio core | Port style |
|---|---|---|
| `replication.rs` | `replication.rs` | Verbatim copy + crate rename. |
| `intent.rs` | `intent.rs` | Verbatim narrowing algebra; templates rewritten to bio (`synthesize_dna_fragment`, `run_peptide_coupling`, `dispense_reagent`, `synthesize_chemical`, `execute_protocol`). |
| `differential.rs` | `differential.rs` | Verbatim comparison logic; `Command` → `SynthesisBundle`; previous-state argument dropped. |
| `threat.rs` | `threat.rs` | Engine framework verbatim (sliding window, weighted composite, alert threshold). Five detector heuristics rewritten with bio signals: per-bundle volume vs. cap, per-principal authority-rejection rate, k-mer Jaccard replay similarity, per-principal cumulative-volume drift, payload-size z-score plus k-mer-overlap fragmentation detection (threat-model §3.1). |
| `monitors.rs` | `monitors.rs` | Verbatim copy + crate rename. |
| `incident.rs` | `incident.rs` | Verbatim copy + crate rename; `tracing::warn!` → `eprintln!` (no `tracing` dep in bio core); added bio-specific incident kinds `BioIncidentKind::{DbStale, FragmentationDetected, ScheduleOneAttempt}` plus a `bio_trigger` constructor. |
| `proof_package.rs` | `proof_package.rs` | Verbatim copy + crate rename; `test_robot` → `test_bio_lab` in fixtures. |

`invariant-robotics/` can now be deleted without losing any information that landed in `invariant-biosynthesis`.
