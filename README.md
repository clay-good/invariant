# Invariant

**A cryptographic command-validation firewall for AI-controlled physical systems.**

Invariant sits between an AI policy and physical actuators. It rejects commands
that violate a signed, deterministic safety profile and records signed verdicts
in a tamper-evident audit log.

The workspace currently supports:

- **Robotics:** motion validation, URDF kinematics, collaborative-robot guards,
  sensor attestation, and multi-robot coordination.
- **Biosynthesis:** validation for DNA, peptide, chemical, and lab-protocol
  synthesis, including hazard screening and biosafety-level profile gates.

Shared protocol, key, audit, simulation, evaluation, and fuzzing components live
in the Rust workspace. Authority-chain invariants are proved in Lean under
[`formal/`](formal/).

## Install

```sh
cargo install invariant-firewall
```

This installs the `invariant` executable. Run `invariant --help` or
`invariant <domain> --help` to see all commands.

## Examples

Generate an operator key and validate a robotics command:

```sh
invariant keys generate --kid alice --output alice.key

invariant robotics validate \
  --profile profiles/robotics/ur10e_cnc_tending.json \
  --command cmd.json \
  --key alice.key
```

Validate a biosynthesis bundle:

```sh
invariant biosynthesis validate \
  --bundle bundle.json \
  --profile profiles/biosynthesis/university_bsl2_dna.json \
  --hazard-db hazards.json \
  --hazard-db-issuer-pub issuer.pub
```

Inspect a biosynthesis profile:

```sh
invariant biosynthesis inspect \
  --profile profiles/biosynthesis/industry_peptide.json
```

Built-in profiles and sample inputs are in [`profiles/`](profiles/) and
[`examples/`](examples/).

## Develop

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The main crates are:

- `invariant-protocol`: shared protocol core and validation traits
- `invariant-robotics`: robotics validation
- `invariant-biosynthesis`: biosynthesis validation
- `invariant-firewall`: unified CLI

See the [robotics spec](docs/robotics/spec.md),
[biosynthesis spec](docs/biosynthesis/spec.md),
[protocol documentation](docs/pca-chain-envelope.md), and
[threat model](docs/threat-model.md) for design details.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Report
security issues as described in [SECURITY.md](SECURITY.md).

Invariant is licensed under the [MIT License](LICENSE).
