# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.0.2] - 2026-04-13

### Added
- 128 comprehensive doc-tests across all 6 crates
- Crate-level `//!` documentation for docs.rs rendering
- `#![forbid(unsafe_code)]` enforced in all crates
- 8 new robot profiles: ABB GoFa, Kinova Gen3, KUKA iiwa14, Shadow Hand, Boston Dynamics Spot, Unitree G1, Unitree H1, and 4 adversarial test profiles
- Environmental awareness checks (P21-P25): terrain incline, actuator temperature, battery state, communication latency, emergency stop
- Manipulation safety checks (P11-P14): end-effector force, grasp force, payload, force rate
- Locomotion safety checks (P15-P20): velocity, foot clearance, step length, heading rate, ground reaction, friction cone
- ISO 15066 human-robot force limit checking
- URDF parser with forward kinematics for zero-trust self-collision
- Signed sensor data module for cryptographic sensor attestation
- Runtime threat scoring engine (5 behavioral detectors)
- Digital twin divergence detection
- Incident response automation pipeline
- Intent-to-operations pipeline with templates
- Proof package generation with Clopper-Pearson confidence bounds
- Audit log replication with Merkle root witnesses
- Multi-robot coordination monitor with workspace partitioning
- Simulation campaign reporter with SIL rating estimation
- CNC tending cycle state machine
- `invariant serve` embedded Trust Plane server with HTTP + Unix socket modes
- `invariant adversarial` comprehensive adversarial test suite
- `invariant compliance` standards mapping report generator
- `invariant transfer` sim-to-real transfer validation
- `invariant verify-self` binary integrity verification
- `invariant verify-package` proof package verification
- `invariant audit-gaps` sequence gap detection
- `invariant intent` signed PCA generation from templates
- `invariant bench` WCET latency benchmarking
- `invariant profile` management subcommands
- GitHub Actions CI (test + clippy + fmt) and release pipeline

### Changed
- Workspace metadata now includes keywords, categories, homepage, and documentation for crates.io

### Fixed
- Removed crate-wide `#[allow(dead_code)]` in favor of targeted annotations
- Removed single `unsafe` block (volatile write in zeroizing wrapper)

## [0.0.1] - 2026-04-04

### Added
- Initial release: cryptographic command-validation firewall for AI-controlled robots
- 6 physics checks (P1-P10), PIC authority chain, Ed25519 signing
- Validator pipeline producing signed verdicts and actuation commands
- Watchdog heartbeat monitor with safe-stop generation
- Append-only signed JSONL audit logger with hash chain integrity
- Differential validation (IEC 61508 dual-channel pattern)
- CLI with validate, audit, verify, inspect, eval, diff, campaign, keygen subcommands
- Simulation harness with dry-run campaigns and Isaac Lab bridge
- Trace evaluation engine with safety/completeness/regression presets
- Adversarial testing framework (protocol, system, cognitive attacks)
- 4 built-in robot profiles (humanoid, Franka Panda, quadruped, UR10)
- MIT license
