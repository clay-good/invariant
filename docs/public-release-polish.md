# Public Release Polish Spec

Checklist of items to fix before the repo is ready for public use.

## Must Fix

- [x] **MF-1: Remove `#![allow(dead_code)]` from invariant-core**
  - Removed crate-wide suppression. Added targeted `#[allow(dead_code)]` with justification comments on 4 internal items (crypto helper, observation fields, fingerprint field, similarity function).

- [x] **MF-2: Add `#![forbid(unsafe_code)]` to all crates**
  - Added to all 6 `lib.rs` files + `main.rs` for the CLI.
  - Replaced the one `unsafe` block (volatile write in zeroizing wrapper) with safe `fill(0)`.

- [x] **MF-3: Fix stale test counts in README**
  - Updated badge and body text. Actual count: ~1,998 tests.

- [x] **MF-4: Fix README references to nonexistent crates/dirs**
  - Removed `invariant-ros2` row. Annotated `formal/` as separate build.
  - Fixed library embedding example: `invariant_core` -> `invariant_robotics_core`.

- [x] **MF-5: Add `keywords` and `categories` to workspace Cargo.toml**
  - Added: `["robotics", "safety", "cryptography", "ed25519", "real-time"]`
  - Categories: `["aerospace::drones", "cryptography", "science::robotics", "command-line-utilities"]`

- [x] **MF-6: Add `homepage` and `documentation` to workspace Cargo.toml**
  - `homepage` -> GitHub repo. `documentation` -> docs.rs.

- [x] **MF-7: Add crate-level `//!` docs to all lib.rs files**
  - Added to invariant-core, invariant-sim, invariant-eval, invariant-coordinator.
  - Updated invariant-fuzz (expanded existing docs).
  - Fixed rustdoc link errors (`<hex>` HTML tag, `[x,y,z]` brackets, private item links).

- [x] **MF-8: Create CHANGELOG.md**
  - Covers v0.0.1 and v0.0.2 with categorized changes.

- [x] **MF-9: Create CONTRIBUTING.md**
  - Development setup, conventions, adding checks/profiles, PR process.

- [x] **MF-10: Create SECURITY.md**
  - Responsible disclosure policy, scope, recognition.

- [x] **MF-11: Replace static README badges with live CI badges**
  - CI status badge, crates.io version, docs.rs, license, unsafe-forbidden.

- [x] **MF-12: Add `.env` to .gitignore**
  - Added `.env` and `.env.*` patterns.

- [x] **MF-13: Add `rust-toolchain.toml`**
  - Pins `stable` channel with `rustfmt` + `clippy` components. MSRV 1.75 in Cargo.toml.

- [x] **MF-14: Add doc-test and rustdoc build to CI**
  - Added `doc` job with `RUSTDOCFLAGS: -D warnings`.

## Verification

All checks pass with zero warnings:

```
cargo build --release    # OK
cargo test               # 1,998 passed, 0 failed, 13 ignored
cargo clippy -D warnings # zero warnings
cargo fmt --check        # OK
cargo doc --no-deps      # OK (RUSTDOCFLAGS=-D warnings)
```
