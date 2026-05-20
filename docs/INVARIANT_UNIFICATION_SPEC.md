# Invariant Unification Spec

**Goal:** Merge `invariant-robotics` and `invariant-biosynthesis` into a single repo `invariant/`, with a shared core crate and two domain modules (`robotics`, `biosynthesis`). Preserve product-level naming where it matters (CLI subcommands, marketing surface), but eliminate code duplication of the PIC/PCA protocol, audit log, watchdog, differential validation, intent narrowing, and CLI scaffolding.

**Audience:** You (Clay), or whoever picks this up. Written to be executable step-by-step without re-deriving decisions.

**Pre-flight state assumed:** You have copied both source folders into a working directory:
```
/Users/user/Documents/development/public/invariant/
  ├── _from-robotics/        ← copy of invariant-robotics
  └── _from-biosynthesis/    ← copy of invariant-biosynthesis
```
The old folders remain in place until this spec is fully executed and verified. Do NOT delete them until Phase 9.

---

## Section 1 — Final target layout

```
invariant/
├── Cargo.toml                          # workspace root
├── Cargo.lock
├── README.md                           # product overview, links to domain READMEs
├── CHANGELOG.md                        # unified from robotics CHANGELOG + biosynthesis history
├── CLAUDE.md                           # merged guidance
├── CONTRIBUTING.md
├── LICENSE                             # MIT (both repos already MIT)
├── SECURITY.md                         # merged threat model
├── deny.toml
├── rust-toolchain.toml                 # rust 1.75 from both
├── Dockerfile                          # multi-stage, supports both domain CLIs
├── .github/                            # CI workflows (merged)
│
├── crates/
│   ├── invariant-core/                 # NEW — shared protocol + infra
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── authority/              # PCA chain (lifted from either repo, identical)
│   │       ├── models/                 # authority, audit, common types
│   │       ├── audit.rs                # hash-chained JSONL log
│   │       ├── watchdog.rs             # heartbeat / safe-stop
│   │       ├── differential.rs         # dual-instance verdict comparison
│   │       ├── intent.rs               # operation narrowing pipeline
│   │       ├── threat.rs               # threat scoring
│   │       ├── keys.rs                 # Ed25519 key mgmt
│   │       ├── envelopes.rs            # COSE_Sign1 wrappers
│   │       ├── incident.rs
│   │       ├── monitors.rs
│   │       ├── profiles.rs             # generic profile loading trait
│   │       ├── proof_package.rs
│   │       ├── replication.rs
│   │       ├── util.rs
│   │       ├── validator.rs            # generic pipeline; ValidationInput trait
│   │       └── traits.rs               # NEW: ValidationInput, DomainProfile, DomainCheck
│   │
│   ├── invariant-robotics/             # domain crate (was invariant-core in robotics repo)
│   │   ├── Cargo.toml                  # depends on invariant-core
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── command.rs              # Command input type (impl ValidationInput)
│   │       ├── physics/                # 25 physics modules, unchanged
│   │       ├── actuator.rs
│   │       ├── cycle.rs
│   │       ├── digital_twin.rs
│   │       ├── sensor.rs
│   │       ├── urdf.rs
│   │       └── profiles/               # robot JSON profiles loader
│   │
│   ├── invariant-biosynthesis/         # domain crate
│   │   ├── Cargo.toml                  # depends on invariant-core
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── bundle/                 # SynthesisBundle (impl ValidationInput)
│   │       ├── invariants/             # dna, peptide, chemical, homology, molecule, protocol, stateful
│   │       ├── screening/              # hazard database trait + impls
│   │       ├── attestation.rs
│   │       └── profiles/               # synthesizer JSON profiles loader
│   │
│   ├── invariant-cli/                  # single binary `invariant`
│   │   ├── Cargo.toml                  # depends on core + both domain crates (feature-gated)
│   │   └── src/
│   │       ├── main.rs                 # top-level: `invariant <domain> <subcommand>`
│   │       ├── shared/                 # validate, audit, inspect, keygen, intent, campaign, eval, differential
│   │       ├── robotics/               # serve, bench, compliance, transfer, verify-package, forge
│   │       └── biosynthesis/           # any bio-only subcommands
│   │
│   ├── invariant-sim/                  # merged sim crate, feature-gated per domain
│   ├── invariant-eval/                 # merged eval crate
│   ├── invariant-fuzz/                 # merged fuzz crate
│   └── invariant-coordinator/          # robotics-only for now; keep as-is
│
├── profiles/
│   ├── robotics/                       # 34 robot JSONs
│   └── biosynthesis/                   # 6 synthesizer JSONs
│
├── examples/
│   ├── robotics/
│   └── biosynthesis/
│
├── docs/
│   ├── README.md
│   ├── protocol/                       # PIC/PCA spec (shared)
│   ├── robotics/                       # physics invariants, ISO 15066 notes
│   └── biosynthesis/                   # D/P/C invariants, screening notes
│
├── formal/                             # Lean 4 proofs (robotics-only currently)
├── campaigns/                          # robotics campaigns
├── isaac/                              # robotics Isaac sim integration
├── invariant-ros2/                     # robotics ROS2 bridge
└── scripts/                            # merged scripts
```

**Why this shape:**
- `invariant-core` has zero domain knowledge. It exposes traits (`ValidationInput`, `DomainProfile`, `DomainCheck`) that domain crates implement.
- Domain crates own their input types and checks. They do NOT re-implement PCA, audit, watchdog.
- One CLI binary, with domain as the first positional argument: `invariant robotics validate cmd.json` / `invariant biosynthesis validate bundle.json`. Shared subcommands live in `crates/invariant-cli/src/shared/` and dispatch on domain.
- Product naming is preserved on the marketing side (you can still call the products "Invariant Robotics" and "Invariant Biosynthesis"), while the code is unified.

---

## Section 2 — The `ValidationInput` trait (load-bearing decision)

This trait is the keystone. Get it right or the rest of the refactor leaks domain assumptions into core.

Create [crates/invariant-core/src/traits.rs](crates/invariant-core/src/traits.rs):

```rust
use crate::audit::AuditEntry;
use crate::authority::AuthorityChain;
use crate::models::authority::Operation;
use serde::{Deserialize, Serialize};

/// Input that can be validated through the PIC/PCA pipeline.
/// Implemented by `robotics::Command` and `biosynthesis::SynthesisBundle`.
pub trait ValidationInput: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Stable string identifying the domain (e.g. "robotics", "biosynthesis").
    /// Used in audit log entries and CLI dispatch.
    fn domain(&self) -> &'static str;

    /// The PCA-protected operation(s) this input claims authority for.
    /// Must match against the AuthorityChain's narrowed operation set.
    fn operations(&self) -> Vec<Operation>;

    /// Stable hash of the input payload for audit chaining and replay detection.
    fn content_hash(&self) -> [u8; 32];

    /// Optional: a short human-readable summary for audit log / CLI output.
    fn summary(&self) -> String {
        format!("{} input ({} ops)", self.domain(), self.operations().len())
    }
}

/// A domain-specific check that runs after PCA validation succeeds.
/// Robotics impls: P1..P25 physics checks. Biosynthesis impls: D1..D10, P1..P10, C1..C10.
pub trait DomainCheck<I: ValidationInput>: Send + Sync {
    /// Stable identifier (e.g. "P1", "D3", "C7").
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn run(&self, input: &I, ctx: &CheckContext) -> CheckResult;
}

pub struct CheckContext<'a> {
    pub chain: &'a AuthorityChain,
    pub profile: &'a dyn DomainProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckResult {
    Pass,
    Fail { reason: String, evidence: serde_json::Value },
    Skip { reason: String },
}

/// Domain-specific profile (robot URDF + limits, synthesizer capabilities).
pub trait DomainProfile: Send + Sync {
    fn id(&self) -> &str;
    fn domain(&self) -> &'static str;
    fn as_any(&self) -> &dyn std::any::Any; // for downcasting in domain checks
}
```

The generic validator in `crates/invariant-core/src/validator.rs` then becomes:

```rust
pub struct Validator<I: ValidationInput> {
    profile: Box<dyn DomainProfile>,
    checks: Vec<Box<dyn DomainCheck<I>>>,
    audit: AuditLog,
}

impl<I: ValidationInput> Validator<I> {
    pub fn validate(&mut self, signed_input: SignedEnvelope<I>) -> ValidationVerdict {
        // 1. Verify COSE_Sign1 envelope, extract chain + input
        // 2. Verify AuthorityChain monotonicity (A1-A3)
        // 3. Verify input.operations() ⊆ chain.terminal_operations()
        // 4. Run all self.checks in order, collect results
        // 5. Append to audit log (hash-chained)
        // 6. Return verdict
    }
}
```

Notes:
- `as_any()` downcast in `DomainProfile` is the pragmatic escape hatch. The alternative (associated type on the trait) propagates type parameters everywhere and breaks dyn-compat. Downcast at the boundary inside each domain check.
- Keep `Operation` and `AuthorityChain` in `invariant-core::models`. They are domain-agnostic.

---

## Section 3 — Phased migration plan

Execute phases in order. After each phase, run `cargo check --workspace` from `invariant/`. Do not move on until clean.

### Phase 0 — Set up the empty workspace shell (30 min)

1. `cd /Users/user/Documents/development/public/invariant`
2. Create the directory tree from Section 1 (empty `crates/*/src/` directories with placeholder `lib.rs` files containing only `// placeholder`).
3. Create root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/invariant-core",
    "crates/invariant-robotics",
    "crates/invariant-biosynthesis",
    "crates/invariant-cli",
    "crates/invariant-sim",
    "crates/invariant-eval",
    "crates/invariant-fuzz",
    "crates/invariant-coordinator",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
authors = ["Clay Good <hi@claygood.com>"]
edition = "2021"
rust-version = "1.75"
license = "MIT"
repository = "https://github.com/clay-good/invariant"
homepage = "https://github.com/clay-good/invariant"

[workspace.dependencies]
# Crypto — use coset 0.4 (robotics is newer; biosynthesis on 0.3 must upgrade)
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
coset = "0.4"
sha2 = "0.10"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
chrono = { version = "0.4", features = ["serde"] }
base64 = "0.22"

# Core utilities
rand = "0.8"
regex = "1.11"
thiserror = "2.0"
quick-xml = "0.39"

# CLI & server
clap = { version = "4.6", features = ["derive"] }
tokio = { version = "1.52" }
axum = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Internal
invariant-core = { path = "crates/invariant-core", version = "0.1.0" }
invariant-robotics = { path = "crates/invariant-robotics", version = "0.1.0" }
invariant-biosynthesis = { path = "crates/invariant-biosynthesis", version = "0.1.0" }
```

4. Copy `rust-toolchain.toml`, `deny.toml`, `LICENSE` from `_from-robotics/` (newer).
5. Initialize git: `git init && git add -A && git commit -m "scaffold workspace"`.

**Verify:** `cargo check --workspace` should succeed (all crates compile empty stubs).

### Phase 1 — Move shared protocol code into `invariant-core` (2–3 hrs)

The robotics and biosynthesis copies of these files are byte-identical or near-identical. Use the **robotics** version as the source of truth (it's more recent — v0.0.3 vs v0.0.1 — and uses coset 0.4).

Files to copy from `_from-robotics/crates/invariant-core/src/` into `invariant/crates/invariant-core/src/`:

| Source file | Destination | Notes |
|---|---|---|
| `authority/` (whole dir) | `authority/` | Unchanged |
| `models/authority.rs` | `models/authority.rs` | Strip docstring examples mentioning robotics-specific ops; replace with generic `op:resource:*` |
| `models/audit.rs` | `models/audit.rs` | Unchanged |
| `models/mod.rs` | `models/mod.rs` | Keep only authority + audit; remove `Command`-specific exports |
| `audit.rs` | `audit.rs` | Unchanged |
| `watchdog.rs` | `watchdog.rs` | Unchanged |
| `differential.rs` | `differential.rs` | Make generic over `I: ValidationInput` |
| `intent.rs` | `intent.rs` | Unchanged |
| `threat.rs` | `threat.rs` | Unchanged |
| `keys.rs` | `keys.rs` | Unchanged |
| `envelopes.rs` | `envelopes.rs` | Make generic over `I: ValidationInput` |
| `incident.rs` | `incident.rs` | Unchanged |
| `monitors.rs` | `monitors.rs` | Audit which fields are robotics-specific; strip if any |
| `proof_package.rs` | `proof_package.rs` | Unchanged |
| `replication.rs` | `replication.rs` | Unchanged |
| `util.rs` | `util.rs` | Unchanged |

NEW files to create:
- `traits.rs` (content from Section 2)
- `validator.rs` (generic version, content sketched in Section 2)
- `profiles.rs` (trait-based; concrete profile loading moves to domain crates)

DO NOT copy these robotics files into core (they're domain-specific):
- `actuator.rs`, `cycle.rs`, `digital_twin.rs`, `sensor.rs`, `urdf.rs`, `physics/`

DO NOT copy these biosynthesis files into core:
- `bundle/`, `invariants/`, `screening/`, `attestation.rs`

Write `crates/invariant-core/Cargo.toml`:

```toml
[package]
name = "invariant-core"
version.workspace = true
authors.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
ed25519-dalek.workspace = true
coset.workspace = true
sha2.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
base64.workspace = true
rand.workspace = true
regex.workspace = true
thiserror.workspace = true
tracing.workspace = true
```

Update `crates/invariant-core/src/lib.rs` to re-export the public API:

```rust
pub mod audit;
pub mod authority;
pub mod differential;
pub mod envelopes;
pub mod incident;
pub mod intent;
pub mod keys;
pub mod models;
pub mod monitors;
pub mod profiles;
pub mod proof_package;
pub mod replication;
pub mod threat;
pub mod traits;
pub mod util;
pub mod validator;
pub mod watchdog;

pub use traits::{CheckContext, CheckResult, DomainCheck, DomainProfile, ValidationInput};
pub use validator::Validator;
```

**Verify:** `cargo check -p invariant-core` clean. Run any pre-existing core tests (copy `tests/` for the authority/audit/watchdog suites from robotics).

### Phase 2 — Extract `invariant-robotics` domain crate (2–3 hrs)

Move from `_from-robotics/crates/invariant-core/src/`:
- `physics/` → `invariant/crates/invariant-robotics/src/physics/`
- `actuator.rs`, `cycle.rs`, `digital_twin.rs`, `sensor.rs`, `urdf.rs` → same names in `invariant-robotics/src/`
- Locate the `Command` type (search robotics core for `struct Command`) → move to `invariant-robotics/src/command.rs`

Move profile loading:
- `_from-robotics/profiles/` → `invariant/profiles/robotics/`
- `_from-robotics/crates/invariant-core/src/profiles.rs` → split: keep generic trait in core, move robotics-specific loader to `invariant-robotics/src/profiles.rs`

Implement traits:
1. `impl ValidationInput for Command` in `command.rs`:
   - `domain()` returns `"robotics"`
   - `operations()` extracts the op string(s) from the command
   - `content_hash()` SHA-256 of canonical JSON serialization
2. `impl DomainProfile for RobotProfile` in `profiles.rs`
3. For each physics check P1..P25, refactor into `struct PXCheck` implementing `DomainCheck<Command>`

Cargo.toml:

```toml
[package]
name = "invariant-robotics"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
invariant-core.workspace = true
serde.workspace = true
serde_json.workspace = true
quick-xml.workspace = true  # for URDF parsing
thiserror.workspace = true
# ... rest from robotics core's Cargo.toml
```

Update all `use crate::audit::...` etc. in physics modules to `use invariant_core::audit::...`.

**Verify:** `cargo check -p invariant-robotics` clean. Port the robotics physics test suite — it should run unchanged after import path updates.

### Phase 3 — Extract `invariant-biosynthesis` domain crate (2–3 hrs)

Same approach as Phase 2. Move from `_from-biosynthesis/crates/invariant-biosynthesis-core/src/`:
- `bundle/` → `invariant/crates/invariant-biosynthesis/src/bundle/`
- `invariants/` → same
- `screening/` → same
- `attestation.rs` → same

Implement:
1. `impl ValidationInput for SynthesisBundle` in `bundle/mod.rs`
2. `impl DomainProfile for BiosynthesisProfile`
3. Each invariant (D1..D10, P1..P10, C1..C10) becomes `DomainCheck<SynthesisBundle>`

**Note on coset version bump:** biosynthesis was on coset 0.3; this phase upgrades it to 0.4 via the workspace dep. Test envelope encode/decode against fixtures from `_from-biosynthesis/` to catch any wire-format regressions. The COSE_Sign1 format is stable across these versions but the API surface changed slightly.

Move profiles:
- `_from-biosynthesis/profiles/` → `invariant/profiles/biosynthesis/`

**Verify:** `cargo check -p invariant-biosynthesis` clean. Run the biosynthesis invariant tests.

### Phase 4 — Build unified CLI (2 hrs)

Top-level structure (`crates/invariant-cli/src/main.rs`):

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "invariant", version)]
struct Cli {
    #[command(subcommand)]
    domain: Domain,
}

#[derive(Subcommand)]
enum Domain {
    Robotics(robotics::RoboticsArgs),
    Biosynthesis(biosynthesis::BiosynthesisArgs),
    /// Domain-agnostic operations (keygen, etc.)
    Keys(shared::KeysArgs),
}
```

Each domain module re-exposes shared subcommands templated on its input type:

```rust
// crates/invariant-cli/src/robotics/mod.rs
#[derive(Subcommand)]
pub enum RoboticsSubcommand {
    Validate(shared::ValidateArgs),    // uses Validator<Command>
    Audit(shared::AuditArgs),
    Inspect(shared::InspectArgs),
    Intent(shared::IntentArgs),
    Campaign(shared::CampaignArgs),
    Eval(shared::EvalArgs),
    Differential(shared::DifferentialArgs),
    // Robotics-only:
    Serve(ServeArgs),
    Bench(BenchArgs),
    Compliance(ComplianceArgs),
    Transfer(TransferArgs),
    VerifyPackage(VerifyPackageArgs),
    Forge(ForgeArgs),
}
```

Shared subcommand impls live in `crates/invariant-cli/src/shared/` and are generic over `I: ValidationInput`.

CLI invocations the spec must support:
- `invariant robotics validate cmd.json --profile ur10e --chain chain.cose`
- `invariant biosynthesis validate bundle.json --profile dna-synth-v1 --chain chain.cose`
- `invariant keys generate --out alice.key`
- `invariant robotics serve --port 8080 --profile ur10e`
- `invariant biosynthesis differential --bundle x.json --primary url1 --secondary url2`

**Backward-compatibility note:** Old scripts will invoke `invariant-robotics-cli validate ...` and `invariant-biosynthesis-cli validate ...`. Ship thin shim binaries (`invariant-robotics`, `invariant-biosynthesis`) that forward to `invariant robotics ...` and `invariant biosynthesis ...` respectively, for at least one minor version.

**Verify:** `cargo build --release -p invariant-cli`. Run all the example invocations against fixtures copied from both source repos' `examples/`.

### Phase 5 — Migrate sim / eval / fuzz / coordinator (1–2 hrs each)

For each of `invariant-sim`, `invariant-eval`, `invariant-fuzz`:
- Merge code from both source repos
- Feature-gate per domain: `cargo features = ["robotics", "biosynthesis"]`, both default-on
- Code that branches on domain dispatches through the `ValidationInput::domain()` string

`invariant-coordinator` is robotics-only; copy as-is from robotics, depend on `invariant-robotics` + `invariant-core`. If biosynthesis ever needs a coordinator, generalize then.

### Phase 6 — Move ancillary assets (1 hr)

| Source | Destination |
|---|---|
| `_from-robotics/formal/` | `invariant/formal/` |
| `_from-robotics/campaigns/` | `invariant/campaigns/` |
| `_from-robotics/isaac/` | `invariant/isaac/` |
| `_from-robotics/invariant-ros2/` | `invariant/invariant-ros2/` |
| `_from-robotics/scripts/` | `invariant/scripts/` |
| `_from-robotics/fuzz/` | merge into `crates/invariant-fuzz/` |
| `_from-robotics/docs/` | `invariant/docs/robotics/` + extract protocol-level docs to `invariant/docs/protocol/` |
| `_from-biosynthesis/docs/` | `invariant/docs/biosynthesis/` |
| `_from-robotics/examples/` | `invariant/examples/robotics/` |
| `_from-biosynthesis/examples/` | `invariant/examples/biosynthesis/` |

**Formal proofs caveat:** The Lean 4 proofs in `formal/` reference the old crate boundary (`invariant_core::authority::...`). After the move, the proofs will need import path updates and the trait abstractions in core may require new lemmas. Budget a day for this; don't block Phase 6 on it — track as a Phase 6b task.

### Phase 7 — Merge top-level docs (1 hr)

- **README.md:** Product overview. Brief intro to PIC protocol. Two prominent links: "Robotics →" and "Biosynthesis →" to per-domain READMEs in `docs/robotics/` and `docs/biosynthesis/`.
- **SECURITY.md:** Merge threat models. Both already cover: prompt injection, privilege escalation, replay, audit tampering. Add a section per domain for domain-specific threats (physical harm vs. biological/chemical hazard).
- **CHANGELOG.md:** New `0.1.0` entry: "Unified invariant-robotics and invariant-biosynthesis into single workspace. Extracted shared `invariant-core` crate. CLI now uses `invariant <domain> <subcommand>` form." Preserve prior entries under "Pre-unification history (robotics)" and "Pre-unification history (biosynthesis)" subheadings.
- **CLAUDE.md:** Merge both. New top section explaining the workspace layout and trait architecture.
- **CONTRIBUTING.md:** From robotics (biosynthesis didn't have one).

### Phase 8 — CI / Docker / release tooling (1 hr)

- Merge `.github/workflows/` from both. Workflow names: `ci.yml` (test + clippy + fmt for whole workspace), `release.yml` (build CLI binaries), `security.yml` (cargo-deny, cargo-audit).
- `Dockerfile`: multi-stage, builds the unified `invariant` CLI. Image tag `invariant:latest`. Document `docker run invariant robotics validate ...` and `docker run invariant biosynthesis validate ...`.
- `deny.toml`: union of both repos' deny lists; tighten to the stricter of the two on overlaps.

### Phase 9 — Verification and cleanup (1–2 hrs)

Run, in order, from `invariant/`:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `cargo deny check`
5. Manual smoke tests:
   - `cargo run --release -- robotics validate examples/robotics/ur10e-valid-command.json --profile ur10e`
   - `cargo run --release -- biosynthesis validate examples/biosynthesis/safe-dna-bundle.json --profile dna-synth-v1`
   - `cargo run --release -- keys generate --out /tmp/test.key`
   - Verify the audit log produced is hash-chained correctly.
6. Differential parity check: take a robotics command that the old `invariant-robotics` validator accepted; confirm the new `invariant robotics validate` accepts it with byte-identical verdict (modulo timestamps). Same for biosynthesis.
7. Only after all of the above pass: delete `_from-robotics/` and `_from-biosynthesis/`. Delete the sibling folders `invariant-robotics/` and `invariant-biosynthesis/` from `/Users/user/Documents/development/public/` (after confirming git is clean and pushed).

**Do not delete the old folders before this step.** If any test regression appears post-deletion, recovery requires git history from the old repos.

---

## Section 4 — Decisions to make before starting

These are deliberate choices left to you; the spec assumes defaults but flag them:

1. **Repo strategy (single repo vs. split publish):** ✅ RESOLVED (2026-05-18)
   - Decision: single monorepo `clay-good/invariant`. Publish all 8 workspace crates separately to crates.io under their unified names. See Section 8 for the full crates.io migration plan.
   - The two source GitHub repos (`clay-good/invariant-robotics`, `clay-good/invariant-biosynthesis`) will be deleted manually after the unification is verified.

2. **Versioning:**
   - Default: start unified at `0.1.0`. Robotics jumps from 0.0.3 → 0.1.0; biosynthesis from 0.0.1 → 0.1.0. Document the version reset in CHANGELOG.
   - Alternative: independent per-crate versioning (workspace-inherited but bumped separately). More flexible long-term.

3. **CLI binary name strategy:**
   - Default: one binary `invariant` with shim binaries `invariant-robotics` and `invariant-biosynthesis` for back-compat (one minor version).
   - Alternative: keep two binaries permanently, share code via the library crates. Less elegant but zero migration cost for users.

4. **Release blast radius:**
   - If a bug in `invariant-core` is found, both products ship a patch simultaneously. Acceptable? If not, consider pinning `invariant-biosynthesis` to a specific `invariant-core` version range and managing the SemVer surface carefully.

5. **Formal proofs scope:**
   - The Lean 4 proofs in `formal/` were written against robotics core. After unification, the proofs apply to `invariant-core`. Decide whether to extend the proofs to also cover the `ValidationInput` trait abstraction. Default: yes, treat as a Phase 6b deliverable, not a Phase 1–5 blocker.

---

## Section 5 — Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `coset` 0.3 → 0.4 breaks biosynthesis envelope decoding for existing signed artifacts | Medium | High | Test against fixture envelopes from `_from-biosynthesis/examples/`. If breakage: write a one-time migration tool to re-sign with 0.4. |
| `ValidationInput` trait surface is wrong (need to add methods later) | Medium | Medium | Start narrow (the 4 methods in Section 2). Adding methods later is backward-compatible if defaulted. |
| Formal proofs require non-trivial rework | High | Low (not blocking) | Schedule as Phase 6b. Keep old proofs in `formal/` for reference until reworked. |
| External users on `invariant-robotics-cli` script integrations break | Medium | Medium | Ship shim binary; document migration in CHANGELOG and README. |
| Tests pass but runtime behavior differs (silent verdict drift) | Low | High | Phase 9 differential parity check against old binaries with archived fixtures. |
| Audit log format changes inadvertently | Low | High | Pin `audit.rs` to byte-identical port from robotics. Add a golden-file test that hashes a known input + chain and asserts the audit entry bytes. |

---

## Section 6 — Estimated effort

| Phase | Hours |
|---|---|
| 0. Workspace shell | 0.5 |
| 1. invariant-core | 3 |
| 2. invariant-robotics | 3 |
| 3. invariant-biosynthesis | 3 |
| 4. invariant-cli | 2 |
| 5. sim / eval / fuzz / coordinator | 4 |
| 6. Ancillary assets | 1 |
| 6b. Formal proofs rework | 8 (deferred) |
| 7. Docs merge | 1 |
| 8. CI / Docker | 1 |
| 9. Verification + cleanup | 2 |
| **Total (Phases 0–9, excluding 6b)** | **~20.5 hrs** |

Single focused week, or two part-time weeks. The trait extraction (Phase 1 + the impls in Phases 2–3) is the hard part; everything else is mechanical.

---

## Section 8 — crates.io publishing & release plan

**Decision date:** 2026-05-18.
**Owner:** Clay (sole crates.io owner of all affected crates).

### 8.1 The naming problem

The pre-unification crates.io footprint was robotics-prefixed:

| Old (crates.io) | Status |
|---|---|
| `invariant-robotics` | published |
| `invariant-robotics-core` | published |
| `invariant-robotics-coordinator` | published |
| `invariant-robotics-eval` | published |
| `invariant-robotics-fuzz` | published |
| `invariant-robotics-sim` | published |

The unified workspace publishes under domain-neutral names because the merged crates (`invariant-core`, `invariant-sim`, `invariant-eval`, `invariant-fuzz`, `invariant-coordinator`) now contain or support both the robotics AND biosynthesis domains. Keeping the `invariant-robotics-*` prefix would be semantically wrong — these crates are no longer robotics-specific.

| New (crates.io target) | Source workspace crate |
|---|---|
| `invariant-core` | `crates/invariant-core` |
| `invariant-robotics` | `crates/invariant-robotics` |
| `invariant-biosynthesis` | `crates/invariant-biosynthesis` |
| `invariant-coordinator` | `crates/invariant-coordinator` |
| `invariant-sim` | `crates/invariant-sim` |
| `invariant-eval` | `crates/invariant-eval` |
| `invariant-fuzz` | `crates/invariant-fuzz` |
| `invariant-cli` | `crates/invariant-cli` (binary) |

### 8.2 Deletion strategy

crates.io permits deletion when **all** of:
- No other crate on crates.io depends on it.
- Single owner.
- Either published <72 hours ago, OR <1000 downloads per month of life.

All 6 of Clay's old `invariant-robotics-*` crates qualify (sole owner, low download counts, no reverse-deps).

**Plan:** delete all 6 old crates outright. No yanking, no tombstone crates, no facade re-exports. Clean slate.

After deletion, crates.io blocks republishing the same name for **24 hours**. Plan the deletion timing accordingly — in particular `invariant-robotics`, which we want to reuse, must be deleted ≥24 hours before the unified `invariant-robotics` is published.

### 8.3 Recommended sequence

1. **T-minus 24h+ (or earlier):** Delete all 6 old crates from crates.io via the per-crate `/delete` UI:
   - `invariant-robotics`
   - `invariant-robotics-core`
   - `invariant-robotics-coordinator`
   - `invariant-robotics-eval`
   - `invariant-robotics-fuzz`
   - `invariant-robotics-sim`
2. **T-zero:** Once the 24-hour republish block has cleared, run the unified release workflow (Section 8.4), which publishes all 8 new crates in dependency order.
3. **After publish succeeds:** Delete the two source GitHub repos:
   - https://github.com/clay-good/invariant-robotics
   - https://github.com/clay-good/invariant-biosynthesis

### 8.4 GitHub Actions release workflow

The `.github/workflows/release.yml` workflow publishes the 8 crates in dependency order on a version tag push (e.g. `v0.2.0`):

```
1. invariant-core
2. invariant-robotics            ┐
3. invariant-biosynthesis        ┤  (both depend on invariant-core)
4. invariant-coordinator         ┤  (depends on invariant-robotics + invariant-core)
5. invariant-eval                ┤
6. invariant-sim                 ┤
7. invariant-fuzz                ┤
8. invariant-cli                 ┘  (depends on all of the above)
```

Workflow requirements:
- Triggered on `v*` tag push.
- Uses `CARGO_REGISTRY_TOKEN` secret (Clay's crates.io token).
- Each `cargo publish` step must succeed before the next runs (sequential, not parallel — crates.io indexing has lag and dependent publishes will fail if the index hasn't propagated).
- `cargo publish --dry-run` for each crate in CI on every PR to catch packaging regressions before tag time.
- GitHub Release notes generated from `CHANGELOG.md` for the tagged version.

### 8.5 What this means for CHANGELOG.md

The `0.2.0` release notes (or whatever version unification ships under) must call out:
- All 6 `invariant-robotics-*` crates were deleted from crates.io and replaced with 7 new crate names plus the renamed `invariant-robotics`.
- No upgrade path from old crate names exists — downstream users (none known at time of unification) must update their `Cargo.toml` to the new names.
- Wire protocol, audit format, and signed-envelope compatibility are preserved (per Section 7).

### 8.6 Risk

| Risk | Mitigation |
|---|---|
| Deletion of `invariant-robotics` and then the 24-hour republish block expires before unified release is ready | Don't delete `invariant-robotics` until the unified workspace is verified green and ready to publish. Other 5 names can be deleted at any time since none are being reused. |
| Someone else squats `invariant-robotics` in the 24-hour window | Extremely unlikely (niche name) but possible. If it happens, contact crates.io support — name-squatting of a recently-deleted crate by the original owner has a manual remediation path. |
| `cargo publish` for a dependent crate fails because the index hasn't updated | Workflow waits 30s between publishes; if indexing is slow, manual re-run picks up where it left off. |

---

## Section 9 — What this spec does NOT do

- Does not change the wire protocol. Signed envelopes from before unification remain valid after, modulo the coset bump.
- Does not change the audit log format. Entries from old logs can be appended to by new binaries.
- Does not unify the product names or marketing. "Invariant Robotics" and "Invariant Biosynthesis" remain distinct product surfaces; only the codebase is unified.
- Does not introduce new domain checks. Every P/D/C invariant present in the old repos is preserved with identical semantics.
- Does not add a third domain. The trait design admits one in the future, but adding e.g. "invariant-autonomous-vehicles" is out of scope here.

---

End of spec.
