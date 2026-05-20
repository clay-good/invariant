# Invariant

**A cryptographic command-validation firewall for AI-controlled physical systems.**

Invariant is AI safety infrastructure for the physical world. Wherever a
neural-network policy can move a motor, dose a reagent, or open a valve,
Invariant sits between the model and the actuator and refuses any command
that violates a deterministic safety profile — signed, audited, and
provable end-to-end.

The same protocol generalises across physical domains. The workspace
ships two production surfaces today:

- **Invariant Robotics** — motion-command validation for industrial
  arms, humanoids, quadrupeds, mobile manipulators, and end-effector
  hands. 25 deterministic physics checks (P1–P25), URDF kinematics,
  ISO 15066 collaborative-robot guards, sensor attestation, and
  multi-robot coordination. Primary use case: manufacturing cells (CNC
  tending, pick-and-place, bimanual assembly).
- **Invariant Biosynthesis** — synthesis-bundle validation for
  AI-controlled DNA / peptide / chemical / lab-protocol synthesizers.
  D1–D10 / P1–P10 / C1–C10 invariants, hazard screening (CWC,
  controlled-substance, virulence-homology), BSL2/3/4 profile gating,
  HSM-friendly attestation. Primary use case: biomedical labs and
  industrial biosynthesis lines.

A third domain — e.g. autonomous vehicles, surgical robotics,
energy-grid actuation — is a matter of implementing a single
`ValidationInput` trait against the existing protocol core. The
cryptographic substrate, audit log, and policy engine do not change.

## Why this exists

A model-output check inside the same process as the model is not a
safety boundary. Invariant treats every command as a signed payload
crossing an authority chain (PIC → PCA → enforcement), validates it
against a domain profile that was itself signed by the authorising
party, and emits a verdict that is itself signed and appended to a
tamper-evident audit log. Even when the policy model is compromised,
the firewall's refusals are independently verifiable.

Concretely, Invariant gives operators:

- **A bright line.** Physics, kinematics, and operating-envelope
  guarantees that hold regardless of model behaviour.
- **An audit log that survives the model.** Append-only, COSE-signed,
  externally verifiable.
- **A profile language.** Robot-class or lab-class operating envelopes
  expressed as signed JSON. Reviewable, diffable, attestable.
- **A simulator + adversarial harness.** 15M-episode campaigns with
  fault injection, watchdog timing, and differential dual-channel
  validation (IEC 61508-style).
- **A formal core.** Authority-chain invariants proven in Lean 4
  under `formal/`.

## Quickstart

Install the unified CLI from crates.io:

```sh
cargo install invariant-firewall
```

This installs an executable named `invariant` (the package on
crates.io is `invariant-firewall` because the bare `invariant` and
`invariant-cli` names were already owned by other crates.io users;
the binary itself is unaffected). All examples below invoke the
binary as `invariant`.

The underlying library crate publishes as `invariant-protocol` for
the same reason — in Rust code you keep using `invariant_core::*`
because the workspace ships an alias.

Robotics:

```sh
# Generate an operator keypair.
invariant keys generate --kid alice --output alice.key

# Validate a single motion command against a robot profile.
invariant robotics validate \
    --profile profiles/robotics/ur10e_cnc_tending.json \
    --command cmd.json \
    --key alice.key

# Run the embedded Trust Plane server with the Isaac Sim bridge.
invariant robotics serve \
    --profile profiles/robotics/ur10e_cnc_tending.json \
    --key alice.key \
    --bridge
```

Biosynthesis:

```sh
# Validate a synthesis bundle against a BSL2 DNA-synth profile.
invariant biosynthesis validate \
    --bundle bundle.json \
    --profile profiles/biosynthesis/university_bsl2_dna.json \
    --hazard-db hazards.json \
    --hazard-db-issuer-pub issuer.pub

# Inspect what a profile authorises.
invariant biosynthesis inspect \
    --profile profiles/biosynthesis/industry_peptide.json
```

`invariant <domain> --help` lists every subcommand. Built-in profiles
ship in `profiles/{robotics,biosynthesis}/` and on disk inside each
domain crate.

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
infrastructure work against the trait — not against either concrete
type. Adding a third domain is a matter of implementing the trait on a
new input type. No protocol changes required.

## Workspace layout

```
invariant/
├── crates/
│   ├── invariant-core/          # shared protocol core (published as `invariant-protocol`)
│   │                            #   PCA authority chain, COSE-signed audit log,
│   │                            #   keys, intent narrowing, ValidationInput trait
│   ├── invariant-robotics/      # robotics domain: 25 physics checks (P1–P25),
│   │                            #   URDF kinematics, profiles, sensor attestation
│   ├── invariant-biosynthesis/  # biosynthesis domain: D/P/C invariants,
│   │                            #   hazard screening, BSL gating, attestation
│   ├── invariant-cli/           # single binary `invariant` (published as `invariant`)
│   ├── invariant-sim/           # simulation harness (per-domain modules)
│   ├── invariant-eval/          # trace evaluation (per-domain modules)
│   ├── invariant-fuzz/          # adversarial testing (per-domain modules)
│   └── invariant-coordinator/   # robotics multi-robot coordination
├── profiles/{robotics,biosynthesis}/   # built-in profile JSON
├── examples/{robotics,biosynthesis}/   # sample inputs and demo scripts
├── docs/{protocol,robotics,biosynthesis}/   # specs and design docs
├── formal/                      # Lean 4 proofs of authority-chain invariants
├── campaigns/                   # robotics simulation campaigns (YAML)
├── isaac/                       # Isaac Lab integration
├── invariant-ros2/              # ROS 2 bridge (see docs/ros2.md)
└── fuzz/                        # cargo-fuzz harness
```

## Published crates

All eight workspace crates ship to crates.io at the same workspace
version. Two crates publish under renamed packages because the natural
names were already taken by another owner:

| Workspace alias | crates.io name | Purpose |
|---|---|---|
| `invariant-core` | `invariant-protocol` | shared protocol core, validation trait |
| `invariant-robotics` | `invariant-robotics` | robotics domain |
| `invariant-biosynthesis` | `invariant-biosynthesis` | biosynthesis domain |
| `invariant-cli` | `invariant-firewall` | unified binary (`cargo install invariant-firewall` installs the `invariant` executable) |
| `invariant-eval` | `invariant-eval` | trace evaluation |
| `invariant-sim` | `invariant-sim` | simulation harness |
| `invariant-fuzz` | `invariant-fuzz` | adversarial testing |
| `invariant-coordinator` | `invariant-coordinator` | multi-robot coordination |

Source code keeps using `invariant_core::*` and `invariant_cli::*` via
the workspace aliases; the executable produced by `invariant-firewall`
is just `invariant`.

## Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

## Documentation

- Per-domain specs: [docs/robotics/spec.md](docs/robotics/spec.md),
  [docs/biosynthesis/spec.md](docs/biosynthesis/spec.md).
- Shared protocol:
  [docs/protocol/](docs/protocol/),
  [docs/pca-chain-envelope.md](docs/pca-chain-envelope.md).
- Operational: [docs/threat-model.md](docs/threat-model.md),
  [docs/shadow-deployment.md](docs/shadow-deployment.md),
  [docs/compliance-matrix.md](docs/compliance-matrix.md).
- Cross-domain trace evaluation: [docs/eval.md](docs/eval.md).
- ROS 2 bridge: [docs/ros2.md](docs/ros2.md).
- Migration history (two source repos → this workspace):
  [docs/INVARIANT_UNIFICATION_SPEC.md](docs/INVARIANT_UNIFICATION_SPEC.md)
  and [PROGRESS.md](PROGRESS.md).

## Status & roadmap

- v0.0.3 (this release) — first publish from the unified workspace.
  Robotics + biosynthesis surfaces are feature-complete against their
  v12 specs; the protocol core's authority-chain invariants are
  Lean-verified.
- The operational protocol for the first 100-robot-hour shadow trial on
  a UR10e CNC cell is documented in
  [docs/shadow-deployment.md](docs/shadow-deployment.md). Promotion
  from shadow to enforcement is a separate sign-off.
- Verification closure reports for the v11 and v12 spec passes live at
  [docs/spec-v11-verification.md](docs/spec-v11-verification.md) and
  [docs/spec-v12-verification.md](docs/spec-v12-verification.md).
  The full spec lineage (`spec-v1.md` … `spec-v12.md`) is archived
  under [docs/history/](docs/history/).

## License

MIT — see [LICENSE](LICENSE).

## Security

Reporting policy in [SECURITY.md](SECURITY.md). Threat model and
incident runbooks live alongside the per-domain specs under
[docs/](docs/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New domains are welcome —
implement `ValidationInput` for your input type, add a profile schema,
and you inherit the entire protocol substrate (chain, audit, keys,
attestation, simulation, eval, fuzz) for free.
