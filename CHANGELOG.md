# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.0.3] - 2026-04-16

### Added
- 21 new robot profiles: Fourier GR-1, Tesla Optimus, Figure 02, BD Atlas, Agility Digit, Sanctuary Phoenix, 1X NEO, Apptronik Apollo, Unitree Go2, ANYbotics ANYmal, Unitree A1, Allegro Hand, LEAP Hand, PSYONIC Ability Hand, Spot+Arm, Hello Stretch, PAL TIAGo, and 4 adversarial test profiles (total: 34)
- Dry-run validation coverage for all 34 profiles across all scenario types
- 15M campaign config generator updated for 34 profiles (272 configs)
- Cross-profile dry-run test suites for hands, mobile manipulators, and new humanoids
- ExclusionZone geometry validation at profile load time
- EnvironmentConfig warning_temperature_c validation
- Per-connection joint state tracking in Unix socket bridge (enables P4 acceleration checks)
- Environment configs for 9 profiles (franka_panda, humanoid_28dof, quadruped_12dof, ur10, ur10e_haas_cell, shadow_hand, allegro_hand, leap_hand, psyonic_ability)
- End-effector configs for 5 profiles (franka_panda, humanoid_28dof, unitree_g1, unitree_h1, ur10)
- Per-IP rate limiting for `invariant serve` (`--rate-limit` flag) with automatic stale-entry cleanup
- Audit log size limit (`AuditError::LogFull`) to prevent silent disk exhaustion
- Bridge connection limits via tokio Semaphore (default: 256 max connections)
- Bridge per-message read timeout (30s) and per-response write timeout (10s)
- `--fail-on-audit-error` flag for L1 audit completeness enforcement (HTTP 503 on write failure)
- Audit error counter exposed on `/health` endpoint for monitoring audit trail degradation
- Python test job in CI workflow
- Cross-platform binary builds (x86_64/aarch64, Linux/macOS) attached to GitHub Releases
- CycloneDX SBOM generation in release workflow
- 5 new per-profile campaign configs (humanoid, quadruped, hand, mobile manipulator, smoke test)
- Streaming SHA-256 command hash (`sha256_hex_json`) to eliminate intermediate Vec allocation
- Bridge P4 acceleration check integration test

### Fixed
- Bridge always passed None for previous_joints, permanently disabling P4 acceleration check on Unix socket path
- Serve handler sequence counter stored before validation succeeded (TOCTOU race); replaced with compare-exchange loop
- Serve handler previous_joints not updated on validation error, causing state drift
- EnvironmentConfig warning_temperature_c never validated (NaN caused division-by-zero)
- EnvironmentConfig critical_battery_pct NaN slipped through ordering check
- EnvironmentConfig max_latency_ms finiteness checked after use in comparison
- Bridge stats.lock().unwrap() without poison recovery
- All clippy warnings resolved across all 6 crates
- Bridge OOM via unbounded read_line (P0: malicious client could send gigabytes without newline)
- Constant-time token comparison leaked token length via timing side channel (P1)
- Digital twin mutex poisoning silently ignored in health endpoint and validate handler
- Audit logger open_file missing O_APPEND, breaking L4 immutability invariant under concurrent writes
- `read_last_line` performed O(n) syscalls scanning backward byte-by-byte; now reads last 128 KiB in one read
- `--no-verify` removed from all `cargo publish` commands to catch packaging misconfigurations

### Changed
- Campaign runner BUILTIN_PROFILES expanded from 13 to 34
- run_15m_campaign.sh episode distribution updated for 34 profiles
- README reorganized with table of contents and collapsible sections
- CI workflow: added fail-fast: false, --workspace flags, RUSTFLAGS
- Release workflow: added latest tag automation, preflight gate, binary builds, and SBOM
- ValidatorConfig stores profile_name, profile_hash, and signer_kid as Arc<str> to reduce hot-path allocations
- Dockerfile runs as non-root user (UID 1000), pins huggingface_hub version
- `--auth-token` CLI argument hidden from --help output (prefer --auth-token-file or env var)
- Production serve router uses `into_make_service_with_connect_info` for real client IP extraction

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
