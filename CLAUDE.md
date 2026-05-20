# Invariant

Unified Cargo workspace covering two products: **Invariant Robotics** and
**Invariant Biosynthesis**. Single binary `invariant` (from `invariant-cli`).

## Build & Test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Project Layout

- `crates/invariant-core` — domain-agnostic protocol core: PIC/PCA chain,
  audit, keys, intent, monitors, replication, proof packages, incident,
  and the keystone `ValidationInput` / `DomainCheck` / `DomainProfile`
  trait surface (in `traits.rs`).
- `crates/invariant-robotics` — robotics domain: 25 physics checks
  (P1–P25), URDF kinematics, robot profiles, sensor attestation, the
  domain-specific audit/threat/watchdog/differential/validator. Re-exports
  the shared protocol modules from `invariant-core`. `Command` impls
  `ValidationInput`; `RobotProfile` impls `DomainProfile`.
- `crates/invariant-biosynthesis` — biosynthesis domain: D/P/C invariants,
  hazard screening, attestation, bio profiles. Mirrors the robotics
  layout. `SynthesisBundle` impls `ValidationInput`; `BioProfile` impls
  `DomainProfile`. Carries its own bio-specific `intent` templates and
  `ValidationError` taxonomy.
- `crates/invariant-cli` — single binary `invariant`. Top-level dispatch
  is `invariant <domain> <subcommand>` —
  e.g. `invariant robotics validate ...`, `invariant biosynthesis validate ...`,
  `invariant keys generate ...`.
- `crates/invariant-sim`, `crates/invariant-eval`, `crates/invariant-fuzz`
  — merged crates with `pub mod robotics;` + `pub mod biosynthesis;` per
  domain.
- `crates/invariant-coordinator` — robotics-only multi-robot coordination
  (separation, partitioning).
- `profiles/{robotics,biosynthesis}/` — built-in profile JSON.
- `examples/{robotics,biosynthesis}/` — sample inputs and demo scripts.
- `docs/{protocol,robotics,biosynthesis}/` — specs and design docs.
- `formal/` — Lean 4 proofs of authority chain invariants.
- `campaigns/` — robotics simulation campaigns.
- `isaac/` — robotics Isaac Lab integration.
- `invariant-ros2/` — robotics ROS2 bridge.
- `fuzz/` — cargo-fuzz harness.
- `scripts/` — operational scripts.

## Conventions

- Read existing files before modifying them.
- Run `cargo test` and `cargo clippy` after changes.
- One commit per logical unit of work.
- `#![forbid(unsafe_code)]` is required in every crate.
- Never push directly to main.

## Migration history

The migration from the two source repos
(`invariant-robotics`, `invariant-biosynthesis`) into this unified
workspace is documented in [PROGRESS.md](PROGRESS.md) and specified in
[INVARIANT_UNIFICATION_SPEC.md](INVARIANT_UNIFICATION_SPEC.md).
