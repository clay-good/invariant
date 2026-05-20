# Invariant

A cryptographic command-validation firewall for AI-controlled physical systems.
Two product surfaces, one Rust workspace:

- **Invariant Robotics** — motion-command validation for industrial robots,
  humanoids, quadrupeds, manipulators, and end-effectors. 25 deterministic
  physics checks (P1–P25), URDF kinematics, ISO 15066 collaborative-robot
  guards, sensor attestation, multi-robot coordination.
- **Invariant Biosynthesis** — synthesis-bundle validation for AI-controlled
  DNA / peptide / chemical / lab-protocol synthesizers. D1–D10 / P1–P10 /
  C1–C10 invariants, hazard screening, BSL2/3/4 profile gating,
  HSM-friendly attestation.

Both products share a single Rust core (`invariant-core`) implementing the
PIC/PCA authority chain, append-only signed audit log, key management,
intent narrowing, threat scoring, and the cross-domain `ValidationInput`
trait. Domain code lives in `invariant-robotics` and `invariant-biosynthesis`,
which both implement the same trait surface.

## Install

```sh
cargo install --path crates/invariant-cli
```

This installs a single binary `invariant` that dispatches by domain:

```sh
invariant robotics validate cmd.json --profile ur10e --chain chain.cose
invariant biosynthesis validate bundle.json --profile dna-synth-v1 --chain chain.cose
invariant keys generate --kid alice --output alice.key
```

`invariant <domain> --help` lists every subcommand for that surface.

## Build & Test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Workspace Layout

```
invariant/
├── Cargo.toml                          # workspace root
├── crates/
│   ├── invariant-core/                 # shared protocol + infra (PCA chain, audit, keys, traits)
│   ├── invariant-robotics/             # robotics domain (physics, URDF, profiles, sensor)
│   ├── invariant-biosynthesis/         # biosynthesis domain (D/P/C invariants, screening)
│   ├── invariant-cli/                  # single binary `invariant`
│   ├── invariant-sim/                  # simulation harness (per-domain modules)
│   ├── invariant-eval/                 # trace evaluation (per-domain modules)
│   ├── invariant-fuzz/                 # adversarial testing (per-domain modules)
│   └── invariant-coordinator/          # robotics-only multi-robot coordination
├── profiles/{robotics,biosynthesis}/   # built-in profile JSON
├── examples/{robotics,biosynthesis}/   # sample inputs and demo scripts
├── docs/{protocol,robotics,biosynthesis}/  # specs and design docs
├── formal/                             # Lean 4 proofs of authority chain invariants
├── campaigns/                          # robotics simulation campaigns
├── isaac/                              # robotics Isaac Lab integration
├── invariant-ros2/                     # robotics ROS2 bridge (see docs/ros2.md)
├── fuzz/                               # cargo-fuzz harness
└── scripts/                            # operational scripts
```

## Per-Domain Documentation

- Robotics: [docs/robotics/spec.md](docs/robotics/spec.md) (and the
  spec-v1.md … spec-v12.md history files alongside it).
- Biosynthesis: [docs/biosynthesis/spec.md](docs/biosynthesis/spec.md).
- Shared protocol: [docs/protocol/](docs/protocol/) (extracted from the
  cross-cutting sections of the per-domain specs).
- Unification spec: [INVARIANT_UNIFICATION_SPEC.md](INVARIANT_UNIFICATION_SPEC.md).
- Migration progress: [PROGRESS.md](PROGRESS.md).

## Architecture

The keystone is the `ValidationInput` trait in
[crates/invariant-core/src/traits.rs](crates/invariant-core/src/traits.rs):

```rust
pub trait ValidationInput: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    fn domain(&self) -> &'static str;
    fn operations(&self) -> Vec<Operation>;
    fn content_hash(&self) -> [u8; 32];
    fn summary(&self) -> String { /* default */ }
}
```

`Command` (robotics) and `SynthesisBundle` (biosynthesis) both implement
this trait. The shared PCA chain verifier, audit logger, and key
infrastructure work against the trait, not against either concrete type.
Adding a third domain is a matter of implementing the trait on a new
input type — no protocol changes required.

## Roadmap

- **Shadow deployment.** The operational protocol for the first 100-robot-hour
  observe-only trial on a UR10e CNC cell is documented in
  [docs/shadow-deployment.md](docs/shadow-deployment.md). Promotion from shadow
  to enforcement is a separate sign-off.
- **Closure reports.** The v11 + v12 spec-gap-closure passes are documented
  at [docs/spec-v11-verification.md](docs/spec-v11-verification.md) and
  [docs/spec-v12-verification.md](docs/spec-v12-verification.md). The
  iterative spec lineage (`spec-v1.md` … `spec-v12.md`) is archived under
  [docs/history/](docs/history/); the authoritative current spec is
  [docs/robotics/spec.md](docs/robotics/spec.md).

## License

MIT — see [LICENSE](LICENSE).

## Security

Reporting policy in [SECURITY.md](SECURITY.md). Threat model and incident
runbooks live alongside the per-domain specs in [docs/](docs/).
