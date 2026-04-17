# Invariant v3 — Hardening & Improvement Specification

## Document Purpose

This specification identifies every gap, weakness, and improvement opportunity in the Invariant codebase as of 2026-04-16 (34 profiles, 2,023 tests, 6 crates, ~64,000 lines Rust + ~3,000 lines Python). It is organized into actionable tasks, each with a severity rating and a self-contained prompt for Claude Code.

Supersedes nothing — this is an additive improvement plan on top of spec-v2.md.

### Severity Ratings

| Rating | Meaning |
|--------|---------|
| **P0** | Safety/security bug that could allow an unsafe command to reach actuators |
| **P1** | Security issue that weakens a stated guarantee (audit integrity, replay protection, DoS resistance) |
| **P2** | Correctness or robustness issue that affects production reliability |
| **P3** | Quality, UX, or maintainability improvement |
| **P4** | Polish, documentation, or nice-to-have |

---

## 1. Security Hardening

### 1.1 Bridge OOM via Unbounded `read_line` (P0)

**Problem:** `crates/invariant-sim/src/isaac/bridge.rs` line 196 calls `buf_reader.read_line(&mut line)` which reads until `\n` or EOF with no byte limit. A malicious client can send gigabytes of data with no newline, causing the process to OOM. The `max_msg` check on line 204 fires only AFTER the entire line is buffered in memory.

**Prompt:**
```
In crates/invariant-sim/src/isaac/bridge.rs, the read_line call on the Unix socket has no byte limit — a malicious client can OOM the process by sending data with no newline. Fix this by wrapping the reader with AsyncReadExt::take(max_msg as u64) before calling read_line, so that at most max_msg bytes are ever buffered. If the line is truncated (doesn't end with \n), send an error response and close the connection. Add a test that sends a message larger than max_msg without a newline and verifies the connection is closed without OOM. Run cargo test and cargo clippy after.
```

### 1.2 Serve Sequence Counter Race Condition (P1)

**Problem:** `crates/invariant-cli/src/commands/serve.rs` — the sequence replay check uses `AtomicU64::load` followed by a later `fetch_max`, but these are not atomic together. With 64 concurrent requests, up to 64 copies of the same sequence number can pass the check simultaneously before any advances the counter.

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, the replay protection has a TOCTOU race: last_sequence.load() and fetch_max() are not atomic with respect to each other. Two concurrent requests with the same sequence can both pass the check. Fix this by replacing the load-check pattern with a compare_exchange loop: atomically attempt to set last_sequence from prev to cmd.sequence, and reject if another request already advanced it. Only the winner of the CAS should proceed to validation. Add a test that demonstrates the fix by spawning concurrent requests with the same sequence number. Run cargo test after.
```

### 1.3 Audit Failure Silently Dropped (P1)

**Problem:** `serve.rs` line 430-435 — when audit log write fails (disk full, permissions), the error is logged to stderr but the verdict is returned successfully. This violates the L1 completeness invariant: an approved command reaches the motor without an audit record.

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, audit log write failure is silently swallowed — the verdict is returned to the client even though the audit entry was not written. This violates the L1 audit completeness invariant. Fix this by: (1) adding an audit_errors: AtomicU64 counter to AppState, (2) incrementing it on audit write failure, (3) exposing it in the /health endpoint response, (4) adding a --fail-on-audit-error flag that, when set, returns HTTP 503 instead of the verdict when audit write fails. The default behavior (log + continue) is kept for backwards compatibility, but production deployments should use the flag. Add tests for both modes. Run cargo test after.
```

### 1.4 `constant_time_eq` Leaks Token Length (P1)

**Problem:** `serve.rs` line 237-244 — the constant-time comparison returns early when lengths differ, leaking whether the submitted token has the correct length via timing.

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, the constant_time_eq function returns false immediately when a.len() != b.len(), leaking the token length via timing side channel. Fix this by computing the HMAC-SHA256 of both values with a fixed key (derived from the token itself at startup) and comparing the fixed-length digests in constant time. This eliminates the length leak. Use the sha2 crate (already a dependency) for HMAC. Add a comment explaining why this approach is used. Run cargo test after.
```

### 1.5 Auth Token Exposed in Process Table (P2)

**Problem:** `serve.rs` accepts `--auth-token` as a CLI argument, which is visible via `ps aux` and `/proc/PID/cmdline` to all users on the system.

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, the --auth-token CLI argument exposes the token in the process table. Add a warning message printed to stderr when --auth-token is used: "WARNING: --auth-token exposes the token in the process table. Use --auth-token-file or INVARIANT_AUTH_TOKEN instead." Also add #[arg(hide = true)] to the --auth-token argument so it doesn't appear in --help output (the safer alternatives are already documented). Run cargo test after.
```

### 1.6 Dockerfile Runs as Root (P2)

**Prompt:**
```
In the Dockerfile, the final stage runs as root. Add a non-root user before the ENTRYPOINT:

RUN groupadd -r invariant && useradd -r -g invariant -u 1000 invariant
USER 1000

Also pin the huggingface_hub version: change "pip install --no-cache-dir huggingface_hub" to "pip install --no-cache-dir huggingface_hub==0.23.4". Run docker build to verify the image still builds.
```

---

## 2. Correctness Fixes

### 2.1 Audit Logger `open_file` Missing O_APPEND (P2)

**Problem:** `crates/invariant-core/src/audit.rs` line 405 — `open_file` opens without `.append(true)`, relying on a manual seek-to-EOF. This is not atomic and breaks if a fork or concurrent writer exists.

**Prompt:**
```
In crates/invariant-core/src/audit.rs, the open_file function opens the audit log file with .read(true).write(true) but NOT .append(true). The manual seek-to-EOF is not atomic. Fix this by adding .append(true) to the OpenOptions chain. The read-backward logic for read_last_line still works because SeekFrom::End is valid on append-mode files. Add a comment explaining why O_APPEND is required for the L4 immutability invariant. Run cargo test after.
```

### 2.2 Digital Twin Mutex Poison Silently Ignored in Health (P2)

**Problem:** `serve.rs` line 574 — `if let Ok(dt) = dt_mutex.lock()` silently drops data when the mutex is poisoned, unlike every other mutex in the file which uses `unwrap_or_else`.

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, the health endpoint at line 574 uses "if let Ok(dt) = dt_mutex.lock()" which silently ignores a poisoned mutex. Every other mutex in this file uses .unwrap_or_else(|p| p.into_inner()) for poison recovery. Change this to match the established pattern and add an eprintln warning when poison recovery occurs. Run cargo test after.
```

### 2.3 Profile Validation: 13 Profiles Missing `environment` Config (P3)

**Problem:** 13 of 34 profiles have no `environment` config, meaning P21-P25 checks are silently skipped for those profiles. While this is by design for adversarial profiles (4), the 9 real-world profiles (allegro_hand, franka_panda, humanoid_28dof, kinova_gen3, leap_hand, psyonic_ability, quadruped_12dof, shadow_hand, ur10, ur10e_haas_cell) should have environment configs.

**Prompt:**
```
Add environment configs to these 9 profiles that are currently missing them: franka_panda, humanoid_28dof, quadruped_12dof, ur10, ur10e_haas_cell, shadow_hand, allegro_hand, leap_hand, psyonic_ability. Use conservative values appropriate to each robot type:
- Arms (franka, ur10, ur10e): max_safe_pitch_rad 0.087 (5 deg, table-mounted), max_temp 70C, warning_temp 55C, battery 5/15%, latency 100/50ms
- Humanoid: max_safe_pitch 0.2618 (15 deg), max_temp 75C, warning_temp 60C, battery 5/15%, latency 50/25ms  
- Quadruped: max_safe_pitch 0.5236 (30 deg), max_temp 50C, warning_temp 40C, battery 5/15%, latency 50/25ms
- Hands (shadow, allegro, leap, psyonic): max_safe_pitch 0.087, max_temp 55C, warning_temp 40C, battery 5/15%, latency 100/50ms
Copy to both profiles/ and crates/invariant-core/profiles/. Run cargo test after.
```

### 2.4 Profile Validation: 15 Profiles Missing `end_effectors` (P3)

**Problem:** 15 profiles have no end_effectors defined, meaning P11-P14 force/grasp/payload checks are silently skipped.

**Prompt:**
```
Add end_effector configs to these real-world profiles that are missing them: franka_panda (flange: 100N, 40N grasp, 3kg), humanoid_28dof (left_hand + right_hand: 100N, 30N grasp, 5kg each), quadruped_12dof (none needed — skip), spot (none needed — skip), unitree_g1 (left_hand + right_hand: 80N, 25N grasp, 3kg each), unitree_h1 (left_hand + right_hand: 100N, 30N grasp, 5kg each), unitree_go2 (none — skip), unitree_a1 (none — skip), anybotics_anymal (none — skip), agility_digit (none — legs only, skip), ur10 (flange: 150N, 80N grasp, 10kg). For each, include max_force_n, max_grasp_force_n, min_grasp_force_n (2.0), max_force_rate_n_per_s, max_payload_kg. Copy to both profile directories. Run cargo test after.
```

---

## 3. Production Hardening

### 3.1 Bridge Connection + Message Timeouts (P2)

**Prompt:**
```
In crates/invariant-sim/src/isaac/bridge.rs, there are no timeouts on the Unix socket bridge. A slow client can hold a connection indefinitely. Add:
1. A per-message read timeout of 30 seconds using tokio::time::timeout around the read_line call. On timeout, log a warning and close the connection.
2. A per-response write timeout of 10 seconds around write_response. On timeout, close the connection.
3. A maximum connection count using a tokio::sync::Semaphore (default 256). When the limit is reached, new connections are rejected with an error message before closing.
Add the timeout and max_connections fields to BridgeConfig with the defaults above. Add tests for read timeout and connection limit behavior. Run cargo test after.
```

### 3.2 Serve Rate Limiting (P3)

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, there is no per-client rate limiting. A single client can monopolize all 64 concurrent request slots. Add a simple token-bucket rate limiter:
1. Add a --rate-limit flag (default: 0 = disabled, positive integer = max requests per second per IP).
2. When enabled, use a HashMap<IpAddr, (Instant, u64)> behind a Mutex to track per-IP request counts per second window.
3. Requests exceeding the limit get HTTP 429 with a Retry-After header.
4. The map is cleaned up every 60 seconds to prevent unbounded growth.
Keep it simple — no external crate dependency. Add tests. Run cargo test after.
```

### 3.3 Audit Log Rotation Signal (P3)

**Prompt:**
```
In crates/invariant-core/src/audit.rs, the audit log grows unboundedly. Add:
1. An optional max_file_bytes field to AuditLogger (default: None = unlimited).
2. When set, check the file size before each write. If writing the entry would exceed the limit, return a new AuditError::LogFull variant.
3. In serve.rs, when LogFull is returned, log a warning and expose it on /health (similar to the audit_errors counter from task 1.3).
This does NOT implement rotation — that is left to external tools (logrotate). This just prevents silent disk exhaustion. Add tests. Run cargo test after.
```

---

## 4. CI/CD Improvements

### 4.1 Add Python Tests to CI (P2)

**Prompt:**
```
In .github/workflows/ci.yml, Python tests are not run. Add a new job:

  python-tests:
    name: Python tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"
      - run: pip install pytest
      - run: python -m pytest isaac/tests -x -v
        env:
          INVARIANT_BINARY: target/release/invariant

This ensures the 42 Python tests run on every PR. The e2e bridge tests need the Rust binary built first.
```

### 4.2 Add Cross-Platform Binary Builds to Release (P2)

**Prompt:**
```
In .github/workflows/release.yml, add a build-binaries job that builds release binaries for 4 targets and attaches them to the GitHub Release:

  build-binaries:
    name: Build (${{ matrix.target }})
    needs: preflight
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: aarch64-apple-darwin
            os: macos-latest
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --target ${{ matrix.target }}
        # For aarch64-linux, use cross
      - name: Package binary
        run: |
          cd target/${{ matrix.target }}/release
          tar czf invariant-${{ matrix.target }}.tar.gz invariant
      - uses: softprops/action-gh-release@v2
        with:
          files: target/${{ matrix.target }}/release/invariant-*.tar.gz

For aarch64-unknown-linux-gnu, use the cross-rs/cross action instead of native cargo build. Make the github-release job depend on build-binaries so binaries are attached.
```

### 4.3 Add SBOM Generation to Release (P3)

**Prompt:**
```
In .github/workflows/release.yml, add SBOM generation after the preflight job:

  sbom:
    name: Generate SBOM
    needs: preflight
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-cyclonedx
      - run: cargo cyclonedx --all --format json
      - uses: softprops/action-gh-release@v2
        with:
          files: "*.cdx.json"

This generates a CycloneDX SBOM for each crate and attaches it to the GitHub Release.
```

### 4.4 Remove `--no-verify` from `cargo publish` (P3)

**Prompt:**
```
In .github/workflows/release.yml, remove --no-verify from all cargo publish commands. The preflight job already validates the build, and --no-verify skips the packaging check that catches include/exclude misconfigurations. There are 6 occurrences to change.
```

---

## 5. Hot-Path Performance

### 5.1 Reduce Allocations in Validator (P3)

**Problem:** `validator.rs` performs ~26 `.clone()` calls and multiple `serde_json::to_vec` allocations per command on the hot path. For a 1kHz control loop, this means ~26,000 allocations per second.

**Prompt:**
```
In crates/invariant-core/src/validator.rs, the validate() hot path performs excessive allocations. Identify and reduce allocations without changing the public API:

1. profile_name.clone() and profile_hash.clone() are called every invocation but the values never change. Store them as Arc<str> in ValidatorConfig so clone() is a reference count bump, not a heap allocation.

2. The authority summary builds two Vec<String> for operations_required and operations_granted by calling .to_string() on each Operation. Consider using Cow<str> or storing pre-formatted strings.

3. command_hash is computed by serializing the entire command to JSON first (serde_json::to_vec), then hashing. Consider hashing the command fields directly with a streaming SHA-256 hasher to avoid the intermediate Vec<u8> allocation.

Only make changes that are clearly safe and don't affect correctness. Run cargo test and cargo bench (if bench exists) after. Measure the difference.
```

### 5.2 `read_last_line` O(n) Syscalls (P3)

**Prompt:**
```
In crates/invariant-core/src/audit.rs, the read_last_line function performs one seek + one read_exact syscall per byte when scanning backward for the last newline. For a 10KB audit entry, that's 10,000 syscalls. Fix this by reading the last 128KB from EOF in a single read, then scanning backward in memory for the last newline. This reduces startup latency for large audit logs from O(line_length) syscalls to O(1). Add a benchmark test that opens a 100MB audit log and measures read_last_line time. Run cargo test after.
```

---

## 6. Campaign & Profile Completeness

### 6.1 Per-Profile Campaign YAML Configs (P3)

**Problem:** All 9 campaign YAML configs use only `ur10e_cnc_tending` or `ur10e_haas_cell`. No campaign configs exist for humanoids, quadrupeds, hands, or mobile manipulators.

**Prompt:**
```
Create 5 new campaign YAML configs in campaigns/:

1. humanoid_stress_test.yaml — humanoid_28dof profile, 50K episodes, scenarios: baseline (40%), aggressive (20%), locomotion_runaway (10%), locomotion_fall (10%), prompt_injection (10%), environment_fault (10%)

2. quadruped_stress_test.yaml — spot profile, 50K episodes, scenarios: baseline (40%), aggressive (20%), locomotion_slip (10%), locomotion_trip (10%), locomotion_stomp (10%), environment_fault (10%)

3. hand_stress_test.yaml — shadow_hand profile, 20K episodes, scenarios: baseline (50%), aggressive (30%), prompt_injection (10%), authority_escalation (10%)

4. mobile_manipulator_test.yaml — spot_with_arm profile, 30K episodes, scenarios: baseline (30%), aggressive (20%), locomotion_runaway (10%), exclusion_zone (10%), environment_fault (10%), compound_authority_physics (10%), long_running_stability (10%)

5. all_profiles_smoke_test.yaml — needs custom handling: describe in a comment that this should be run with "invariant campaign" using generate_15m_configs with total_episodes=34000 shards=1 to exercise every profile with 1000 episodes each.

Each config should have max_violation_escape_rate: 0.0 in success criteria. Run a dry-run on each to verify they work:
  cargo run --release -- campaign --config campaigns/humanoid_stress_test.yaml --dry-run --key keys.json
```

---

## 7. Documentation & Polish

### 7.1 CHANGELOG for v0.0.3 (P3)

**Prompt:**
```
Update CHANGELOG.md with a new [0.0.3] entry dated 2026-04-16. Include all changes made since 0.0.2:

### Added
- 21 new robot profiles: Fourier GR-1, Tesla Optimus, Figure 02, BD Atlas, Agility Digit, Sanctuary Phoenix, 1X NEO, Apptronik Apollo, Unitree Go2, ANYbotics ANYmal, Unitree A1, Allegro Hand, LEAP Hand, PSYONIC Ability Hand, Spot+Arm, Hello Stretch, PAL TIAGo, and 4 adversarial test profiles (total: 34)
- Dry-run validation coverage for all 34 profiles across all scenario types
- 15M campaign config generator updated for 34 profiles (272 configs)
- Cross-profile dry-run test suites for hands, mobile manipulators, and new humanoids
- ExclusionZone geometry validation at profile load time
- EnvironmentConfig warning_temperature_c validation
- Per-connection joint state tracking in Unix socket bridge (enables P4 acceleration checks)

### Fixed
- Bridge always passed None for previous_joints, permanently disabling P4 acceleration check on Unix socket path
- Serve handler sequence counter stored before validation succeeded (TOCTOU race)
- Serve handler previous_joints not updated on validation error, causing state drift
- EnvironmentConfig warning_temperature_c never validated (NaN caused division-by-zero)
- EnvironmentConfig critical_battery_pct NaN slipped through ordering check
- EnvironmentConfig max_latency_ms finiteness checked after use in comparison
- Bridge stats.lock().unwrap() without poison recovery
- All clippy warnings resolved across all 6 crates

### Changed
- Campaign runner BUILTIN_PROFILES expanded from 13 to 34
- run_15m_campaign.sh episode distribution updated for 34 profiles
- README reorganized with table of contents and collapsible sections
- CI workflow: added fail-fast: false, --workspace flags, RUSTFLAGS
- Release workflow: added latest tag automation and preflight gate
```

### 7.2 Update README Test Count and Badges (P4)

**Prompt:**
```
In README.md, find and update all stale test counts. The current count is 2,023 Rust tests. Also update:
- The "~2000 tests" line in the Building section to "~2,023 tests"
- Verify the badges at the top still render correctly
- Verify all profile tables match the current 34 profiles (they should from previous work)
Run cargo test to confirm the exact count.
```

### 7.3 Fix `cargo doc` Warning (P4)

**Prompt:**
```
cargo doc --workspace --no-deps produces 1 warning: "public documentation for update_state links to private item MAX_EE_PER_ROBOT" in invariant-robotics-coordinator. Fix this by either making MAX_EE_PER_ROBOT pub(crate) and using the actual value in the doc comment, or by removing the link and writing the constant value inline in the doc string. Run cargo doc --workspace --no-deps and verify zero warnings.
```

### 7.4 Bump Version to 0.0.3 (P4)

**Prompt:**
```
Update the workspace version from 0.0.2 to 0.0.3 in the root Cargo.toml (workspace.package.version). Also update all inter-crate dependency version pins from "0.0.2" to "0.0.3" in each crate's Cargo.toml (there are 5 crates that depend on invariant-core, and invariant-cli depends on 4 other crates). Run cargo build to verify all version references are consistent.
```

---

## 8. Testing Gaps

### 8.1 Serve Handler Integration Tests for New Fixes (P2)

**Prompt:**
```
In crates/invariant-cli/src/commands/serve.rs, add integration tests for:

1. test_audit_write_failure_increments_counter — mock an audit logger that returns Err, verify the health endpoint shows audit_errors > 0.

2. test_concurrent_same_sequence_rejected — spawn 10 concurrent requests with sequence=1, verify exactly 1 succeeds and 9 get HTTP 400.

3. test_previous_joints_updated_on_rejection — send a command that gets rejected (e.g., bad authority), then send a valid command. Verify that P4 acceleration check uses the rejected command's joints as the baseline (not None).

Run cargo test after.
```

### 8.2 Bridge Previous Joints Test (P2)

**Prompt:**
```
In crates/invariant-sim/src/isaac/bridge.rs, add a test that verifies P4 acceleration checking works through the bridge:

1. Start a bridge with a profile that has low max_acceleration (e.g., 10.0 rad/s²).
2. Send a first command with joint velocity 0.0.
3. Send a second command 10ms later with joint velocity 50.0 (which implies acceleration of 5000 rad/s², far exceeding the limit).
4. Verify the second command is rejected with a check containing "acceleration".

This proves the per-connection previous_joints tracking is working correctly. Run cargo test after.
```

---

## Priority Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P0 | 1 | Bridge OOM via unbounded read_line |
| P1 | 3 | Sequence race, audit completeness, token length leak |
| P2 | 8 | O_APPEND, mutex poison, Dockerfile root, Python CI, binary builds, connection timeouts, serve tests, bridge tests |
| P3 | 9 | Rate limiting, audit rotation, SBOM, allocations, profiles, campaigns, changelog, read_last_line, no-verify |
| P4 | 3 | README, doc warning, version bump |
| **Total** | **24** | |

### Recommended Execution Order

1. **P0**: 1.1 (bridge OOM)
2. **P1**: 1.2, 1.3, 1.4 (sequence race, audit completeness, token leak)
3. **P2 security**: 1.5, 1.6 (auth token, Dockerfile)
4. **P2 correctness**: 2.1, 2.2 (O_APPEND, mutex poison)
5. **P2 CI**: 4.1, 4.2 (Python tests, binary builds)
6. **P2 robustness**: 3.1 (bridge timeouts)
7. **P2 testing**: 8.1, 8.2 (serve + bridge tests)
8. **P3 profiles**: 2.3, 2.4 (environment + end_effectors)
9. **P3 production**: 3.2, 3.3 (rate limiting, audit rotation)
10. **P3 CI/CD**: 4.3, 4.4 (SBOM, no-verify)
11. **P3 performance**: 5.1, 5.2 (allocations, read_last_line)
12. **P3 campaigns**: 6.1 (per-profile YAML)
13. **P4 polish**: 7.1, 7.2, 7.3, 7.4 (changelog, README, docs, version)
