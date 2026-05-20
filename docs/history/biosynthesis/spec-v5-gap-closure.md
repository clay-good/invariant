> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Specification: Gap Closure & Remediation — Part 5

**Date:** 2026-04-29
**Branch:** `codelicious/spec-spec-gap-analysis-part-3-part-5`
**Baseline:** 639 tests passing, `cargo build --workspace` + `cargo clippy -- -D warnings` clean.
**Predecessors:** `docs/spec-gap-analysis.md` · `docs/spec-gap-analysis-part-3.md` · `docs/spec-gap-analysis-part-4.md`

This document is a full re-audit of the codebase against all prior specs. It supersedes the open-items lists in parts 3 and 4. Each section describes a gap, its severity, the file evidence, and a **self-contained Claude Code implementation prompt** — paste the prompt directly into a Claude Code session to execute that step.

---

## 0. Baseline snapshot

| Metric | Value |
|--------|-------|
| Tests | 639 passing, 0 failing |
| Build | Clean |
| Clippy | Clean (`-D warnings`) |
| Unsafe | 0 (`#![forbid(unsafe_code)]` in all 5 crates) |
| `todo!()` / `unimplemented!()` in prod paths | 0 |

**What closed since part-4 (2026-04-27):**

| Part-4 gap | Status | Evidence |
|---|---|---|
| H-1 CLI surface for library features | CLOSED | `validate.rs` has `--hazard-db`, `--quorum`, `--no-stateful`, `--threat-threshold`, `--nonce-log` |
| M-7 PCA chain depth unbounded | CLOSED | `BioProfile.max_authority_chain_depth` present and validated |
| L-1 PR2 vocabulary in profile | CLOSED | `BioProfile.allowed_protocol_steps` validated against built-in verb list |
| C-5 Stateful detector opt-in | CLOSED | `ValidatorConfig::new` wires stateful detector by default; `--no-stateful` to disable |
| C-6 Split allow knob (partial) | PARTIAL | `allow_stale_screening` split from `allow_unimplemented_invariants`; BSL ≥ 3 guard added; but **`stale_screening_max_days` field was never added** |

**Severity legend:**

| Tag | Meaning |
|-----|---------|
| CRITICAL | Production-blocking security or correctness hole |
| HIGH | Major capability gap; library has the feature but it is unreachable, unvalidated, or misconfigured by default |
| MEDIUM | Operational / observability gap; required for serious deployments |
| LOW | Polish; governance or documentation |
| NEW | Newly identified; not in any prior gap analysis |

Open counts: **5 CRITICAL · 5 HIGH · 6 MEDIUM · 2 LOW · 4 NEW**

---

## 1. Critical gaps

### GAP-C1 — Chemical invariants have no real cheminformatics

**Severity:** CRITICAL
**Files:** `crates/invariant-biosynthesis-core/src/invariants/chemical.rs`
**Symptom:** C1–C10 treat SMILES as opaque strings. All matching is regex tokens on the raw SMILES text (e.g. `P(=O)(OC`, `[Na]`, `N=N=N`). There is no `Molecule` type, no canonicalisation, no isomer detection, no SMARTS engine. CWC Schedule-1 analogs with non-canonical atom ordering, stereochemistry differences, or ionic encodings evade every C-invariant. C8 reaction feasibility is a `>250-char SMILES` advisory.
**Prior refs:** spec-gap-analysis.md §2, part-3 §2, part-4 C-1.

---

**Step C1-a — Introduce a `cheminformatics` feature flag and a minimal SMILES normaliser**

```
Read crates/invariant-biosynthesis-core/Cargo.toml and src/invariants/chemical.rs in full.

Add a Cargo feature named "cheminformatics" to invariant-biosynthesis-core/Cargo.toml. Under that feature, add a dependency on the `smiles_parser` crate (pure-Rust, no unsafe) at a recent semver. Do NOT add rdkit or any C FFI dependency yet — those land in a later step.

In src/invariants/chemical.rs, add a new module-level function:

    fn normalise_smiles(smiles: &str) -> String

When the "cheminformatics" feature is active, this function must:
1. Parse the SMILES using smiles_parser.
2. Re-emit canonical SMILES (alphabetically sorted heavy atoms at the same ring-closure label).
3. Return the canonical string.
When the feature is NOT active, return the input unchanged (identity function).

Wire `normalise_smiles` into every C-invariant's `evaluate_with` method: normalise the SMILES before any regex or DB lookup. Add a test that shows two SMILES encoding the same molecule but in different atom order produce the same canonical string and both trip C1 on a Schedule-1 DB hit.

Verify with `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`. Ensure the feature-off path still compiles and all 639 existing tests pass.
```

---

**Step C1-b — Add a signed SMARTS rule library for C-invariants**

```
Read docs/spec-gap-analysis.md §2 (the spec promise for chemical invariants), crates/invariant-biosynthesis-core/src/screening/mod.rs (the existing signed hazard-DB format), and crates/invariant-biosynthesis-core/src/invariants/chemical.rs.

Design and implement a `SmartsRuleFile` that follows the same signed-JSON format as `SignedHazardFile` in screening/mod.rs — same Ed25519 signature over a SHA-256 digest of the body, same schema-version field. The body should be:

    {
      "schema_version": 1,
      "rules_version": <u64>,
      "rules": [
        { "id": "cwc-s1-gb", "label": "GB nerve agent scaffold", "invariant": "C1",
          "severity": "fail", "smarts": "P(=O)(F)(OCC)" },
        ...
      ]
    }

Add a `SmartsRuleDatabase` struct in a new file `crates/invariant-biosynthesis-core/src/screening/smarts.rs`. It must:
- Load and verify a `SmartsRuleFile` from bytes (same signature flow as `FileBackedHazardDatabase`).
- Expose a `check(smiles: &str) -> Vec<SmartsHit>` method. Behind the "cheminformatics" feature flag this should use the smiles_parser library. Without the flag, it falls back to the existing regex-on-raw-SMILES approach.
- Report `rule_id`, `label`, `invariant` (which C-invariant triggered it), and `severity` ("fail" or "advisory") for each hit.

Wire `SmartsRuleDatabase` into `ValidatorConfig` similarly to `hazard_db`: an optional `Arc<SmartsRuleDatabase>` that, when set, is consulted in every C-invariant's `evaluate_with`. Each C-invariant should prefer SMARTS hits over its existing regex heuristic when a `SmartsRuleDatabase` is present.

Add the `--smarts-db` and `--smarts-db-issuer-pub` flags to the `validate` subcommand in crates/invariant-biosynthesis-cli/src/commands/validate.rs. Wire them to `ValidatorConfig::with_smarts_db`.

Write at least 8 tests: schema parse, signature verification, signature rejection, a known CWC-S1 SMILES triggers fail, a benign phosphate does not, a narcotic triggers C4, round-trip JSON serialisation of a rule file, and the CLI flag integration test.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-C2 — D-family protein k-mer screener is uncalibrated

**Severity:** CRITICAL
**Files:** `crates/invariant-biosynthesis-core/src/invariants/dna.rs:63-68` (constants `DEFAULT_PROTEIN_KMER_K = 5`, `DEFAULT_PROTEIN_KMER_THRESHOLD = 0.30`)
**Symptom:** The 3-frame + reverse-complement protein k-mer Jaccard screener added in chunk-03 has hardcoded constants chosen without reference to any published corpus. The spec requires FN ≤ 1×10⁻⁴ and FP ≤ 1×10⁻³ with Clopper–Pearson 95% confidence intervals against the HHS Select-Agent reference set. Neither the reference set nor any calibration exists.
**Prior refs:** part-3 §1 remaining gap #1, part-4 C-2.

---

**Step C2-a — Add a calibration corpus and parameter sweep harness to the sim crate**

```
Read crates/invariant-biosynthesis-sim/src/lib.rs in full, then read crates/invariant-biosynthesis-core/src/invariants/dna.rs lines 59–173 (the protein_space_rescreen function and translate_dna_sequence).

In crates/invariant-biosynthesis-sim/src/lib.rs, add a new public module `calibration` (or a separate file `crates/invariant-biosynthesis-sim/src/calibration.rs`). Implement:

1. A `CalibrationCorpus` struct that holds:
   - `true_positives: Vec<SynthesisBundle>` — bundles containing known-hazardous DNA sequences (add 5 hard-coded representative synthetic sequences for select agents: partial toxin genes with stop codons so they are not actually dangerous, but with enough sequence similarity to trigger a properly calibrated screener).
   - `true_negatives: Vec<SynthesisBundle>` — bundles of clearly benign housekeeping genes (add 5 hard-coded sequences: GAPDH, beta-actin, GFP, kanamycin resistance without promoter context, T7 terminator hairpin).

2. A `sweep` function:
   fn sweep(corpus: &CalibrationCorpus, hazard_db: &Arc<dyn HazardScreener>, k_range: RangeInclusive<usize>, threshold_range: Vec<f64>) -> Vec<SweepPoint>
   where SweepPoint is { k: usize, threshold: f64, tp: u32, fp: u32, tn: u32, fn_: u32, sensitivity: f64, specificity: f64, f1: f64 }.
   For each (k, threshold) pair, run every corpus bundle through SelectAgentScreen::evaluate_with using an InvariantContext constructed with the given hazard_db and a profile that has protein_kmer_k = Some(k) and protein_kmer_threshold = Some(threshold). Count TP/FP/TN/FN.

3. A `clopper_pearson_interval` function that computes the exact 95% CI for a binomial proportion given observed successes and total trials.

4. A `calibration_report` function that formats the sweep results as a Markdown table with sensitivity, specificity, F1, and CI columns.

Add a test that runs `sweep` over k ∈ {4, 5, 6} and threshold ∈ {0.20, 0.25, 0.30, 0.35} and asserts that at k=5, threshold=0.30, sensitivity is ≥ 0.8 on the synthetic TP corpus (this is a lower bound before a real reference set; it will tighten when real data arrives). Also assert that the Clopper–Pearson CI for 5/5 TP hits at 95% level has a lower bound > 0.48 (the exact value for 5 successes out of 5 trials).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

**Step C2-b — Lock calibration constants and document them**

```
Read the output of the calibration sweep added in step C2-a (or read the test assertions) and crates/invariant-biosynthesis-core/src/invariants/dna.rs lines 63–68.

Add a new file `docs/CALIBRATION.md` with the following structure:
- Section "Protein k-mer screener (D1–D6)": document that k=5 and Jaccard threshold=0.30 are the default values, why they were chosen, what the synthetic-corpus sensitivity/specificity numbers are, and what additional calibration is needed before a production claim can be made.
- Section "Known limitations": explicitly state that the current corpus is synthetic and does not constitute a validated reference set; real calibration requires the HHS Select Agent FASTA sequences.
- Section "Roadmap": describe the path to achieving FN ≤ 1e-4 and FP ≤ 1e-3.

Also update the doc comments on `DEFAULT_PROTEIN_KMER_K` and `DEFAULT_PROTEIN_KMER_THRESHOLD` in dna.rs to reference `docs/CALIBRATION.md` and state the current empirical bounds.

Add a test in crates/invariant-biosynthesis-core/src/invariants/dna.rs that constructs a BioProfile with protein_kmer_k = Some(5) and protein_kmer_threshold = Some(0.30) and asserts these are accepted by BioProfile::validate (regression guard against accidental range tightening).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-C3 — HSM backends are stubs

**Severity:** CRITICAL (for production)
**Files:** `crates/invariant-biosynthesis-core/src/keys.rs:289–539`
**Symptom:** `OsKeyringStore`, `TpmKeyStore`, and `YubiHsmKeyStore` all return `KeyStoreError::Unavailable("…not yet implemented")`. File-backed Ed25519 keys are the only working path. No multi-party ceremony, no rotation, no host attestation.
**Prior refs:** spec-gap-analysis.md §7, part-3 §7, part-4 C-3.

---

**Step C3-a — Implement OS keyring backend**

```
Read crates/invariant-biosynthesis-core/src/keys.rs in full. Pay careful attention to the KeyStore trait signature, how FileBackedKeyStore works, and the OsKeyringStore stub.

Add a dependency on the `keyring` crate (version 2.x, cross-platform OS keyring: macOS Keychain, Linux Secret Service, Windows Credential Manager) to Cargo.toml under a feature flag named "os-keyring". This dependency must be optional.

Implement `OsKeyringStore` for the feature-on case in keys.rs:
- `store_key(kid, signing_key)`: serialize the signing key bytes as base64 and store in the OS keyring under service name "invariant-bio" and username = kid. Return an Err if the OS keyring is unavailable (e.g. headless server with no Secret Service), NOT a panic.
- `load_key(kid)`: retrieve and deserialize. Return KeyStoreError::NotFound if the kid is absent, KeyStoreError::Unavailable if the OS keyring service is unavailable.
- `delete_key(kid)`: remove the entry.

For the feature-off case, keep the existing `Unavailable` stub. Do not change the Unavailable stub for TpmKeyStore or YubiHsmKeyStore.

Add the `--key-backend os-keyring` option to the `keygen` subcommand (crates/invariant-biosynthesis-cli/src/commands/keygen.rs). When chosen, use `OsKeyringStore` instead of `FileBackedKeyStore`. Guard the option behind a `#[cfg(feature = "os-keyring")]` compile gate with a descriptive error message for the feature-off case.

Write 4 tests gated with `#[cfg(feature = "os-keyring")]`:
1. Store a key and load it back.
2. Load an absent key returns NotFound.
3. Delete a stored key and confirm it is gone.
4. Round-trip signing: store key, load key, sign a message, verify with the original verifying key.

Verify `cargo test --workspace --features invariant-biosynthesis-core/os-keyring` and `cargo clippy --workspace -- -D warnings`.
```

---

**Step C3-b — Implement TPM 2.0 backend and keygen ceremony command**

```
Read crates/invariant-biosynthesis-core/src/keys.rs (the TpmKeyStore stub and KeyStore trait), and crates/invariant-biosynthesis-cli/src/commands/keygen.rs.

Add a dependency on `tss-esapi` (version 7.x) to Cargo.toml under an optional feature named "tpm2". This is a Linux-only TPM 2.0 library; gate all TPM code with `#[cfg(all(feature = "tpm2", target_os = "linux"))]`.

Implement `TpmKeyStore`:
- `store_key(kid, signing_key)`: create a TPM2B_DATA blob by sealing the raw signing-key bytes under the TPM's Storage Root Key (SRK) using `tss_esapi::Context::create` with `ObjectAttributes::FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN`. Store the sealed blob as a file at `~/.local/share/invariant-bio/tpm/<kid>.blob`.
- `load_key(kid)`: unseal the blob via `tss_esapi::Context::unseal`. Return `KeyStoreError::Unavailable` if the TPM device is not present (`/dev/tpm0` missing), `KeyStoreError::NotFound` if the blob file does not exist.
- `delete_key(kid)`: remove the blob file and call `FlushContext` on any loaded transient objects.

Add a `keygen ceremony --threshold N --quorum M` subcommand to the CLI. This command:
1. Generates a fresh Ed25519 signing key locally.
2. Splits it into N Shamir shares using the `vsss-rs` crate (feature-gated as "shamir").
3. Prints each share as a hex string, labeled "Share 1 of N", "Share 2 of N", etc.
4. Stores the full key in the chosen backend (--key-backend flag).
5. Prints the verifying key public bytes as hex for distribution.
Ceremony mode must NEVER persist the private key to disk in cleartext; it must go directly to the backend or be split immediately.

Write 3 tests (not requiring a real TPM — mock the tss_esapi context using the TPM simulator if available, otherwise gate them as `#[cfg(feature = "tpm2")]` and mark `#[ignore]` with a comment explaining the TPM device requirement):
1. Store and load round-trip.
2. Missing TPM device returns Unavailable.
3. Shamir split: reconstruct the key from M-of-N shares and verify it matches the original.

Verify `cargo build --workspace` (without tpm2 feature) and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-C4 — Replication backends are stubs

**Severity:** CRITICAL (for production)
**Files:** `crates/invariant-biosynthesis-core/src/replication.rs:239–294`
**Symptom:** `S3Replicator::replicate_entry` and `WebhookWitness::publish` both return `ReplicationError::Unavailable`. Audit log is local-disk only; disk loss = audit trail loss. No Merkle-root witnessing for external notarisation.
**Prior refs:** spec-gap-analysis.md §8, part-3 §8, part-4 C-4.

---

**Step C4-a — Implement S3 audit-log replication**

```
Read crates/invariant-biosynthesis-core/src/replication.rs in full, paying careful attention to the AuditReplicator trait, FileReplicator, and the S3Replicator stub. Also read crates/invariant-biosynthesis-core/src/audit.rs to understand the AuditEntry and signed-entry format.

Add optional dependencies to Cargo.toml under a feature named "s3-replication":
- `aws-sdk-s3` version 1.x
- `aws-config` version 1.x
- `tokio` version 1.x with features ["rt-multi-thread", "macros"]

Implement `S3Replicator`:
- `new(bucket: String, prefix: String)`: constructor. The bucket and prefix are the S3 path root for replicated entries.
- `replicate_entry(entry: &SignedAuditEntry) -> Result<(), ReplicationError>`: serialise the entry to JSON, compute the SHA-256 of the bytes, and PUT to `s3://<bucket>/<prefix>/<entry.sequence>/<sha256_hex>.json`. Use the AWS SDK's default credential chain (environment variables, instance role, ~/.aws/credentials). On network error, return `ReplicationError::NetworkError { reason }`. On credential error, return `ReplicationError::Unavailable { reason }`.
- `verify_replicated(entry: &SignedAuditEntry) -> Result<bool, ReplicationError>`: GET the object at the expected key and verify the SHA-256 matches. Return `Ok(false)` if the object is missing, `Ok(true)` if hash matches.

Add a `with_s3_replicator(bucket, prefix)` builder method on the audit logger (in audit.rs) that wires a `S3Replicator` as a background replication target. Replication should be best-effort (failures log a warning but do not fail the audit write).

Write 4 tests gated with `#[cfg(feature = "s3-replication")]`:
1. A mock S3 client (using the `aws-sdk-s3`'s test utilities or `mockall`) that asserts the PUT is called with the correct key.
2. Network error returns `ReplicationError::NetworkError`.
3. `verify_replicated` on a missing object returns `Ok(false)`.
4. Round-trip: replicate then verify.

Verify `cargo build --workspace` (without s3-replication feature) and `cargo clippy --workspace -- -D warnings`.
```

---

**Step C4-b — Implement WebhookWitness for Merkle-root publication**

```
Read crates/invariant-biosynthesis-core/src/replication.rs, specifically the WebhookWitness stub and the WitnessRecord type. Also read src/audit.rs to understand how Merkle roots are computed and how the audit log tail is structured.

Add optional dependencies under a feature named "webhook-witness":
- `reqwest` version 0.12.x with features ["json", "blocking"] (NOT async — keep replication synchronous to avoid Tokio dependency in the core crate)
- `backoff` version 0.4.x for retry logic

Implement `WebhookWitness`:
- `new(url: String, max_retries: u32, timeout_secs: u64)`: constructor.
- `publish(record: &WitnessRecord) -> Result<(), ReplicationError>`: POST `record` as JSON to `self.url`. Use exponential backoff with jitter (initial interval 100ms, max 30s, up to `max_retries` attempts). The POST must set `Content-Type: application/json` and a `User-Agent: invariant-bio/<version>` header. On all retries exhausted, return `ReplicationError::NetworkError`. On 4xx response, return `ReplicationError::PublishRejected { status_code, body }` (add this variant to the error enum).

Add a `WitnessRecord` type to replication.rs if not already present:
    pub struct WitnessRecord {
        pub firewall_kid: String,
        pub merkle_root: String,   // hex SHA-256
        pub entry_count: u64,
        pub timestamp: DateTime<Utc>,
        pub signature: String,     // base64 Ed25519 over sha256_hex_json(body fields above)
    }

Add a `publish_root(signing_key, kid) -> Result<WitnessRecord, ReplicationError>` method on `AuditLogger` that computes the current Merkle root from all stored entries, constructs a `WitnessRecord`, signs it, and calls `WebhookWitness::publish`.

Write 5 tests:
1. A mock HTTP server (use `wiremock` or `httpmock` crate, feature-gated) that asserts the correct Content-Type and JSON body.
2. Retry on 503 eventually succeeds.
3. 401 response returns PublishRejected with the status code.
4. `WitnessRecord` signature is valid (verify with the signing key's verifying key).
5. Merkle root changes after appending a new audit entry.

Verify `cargo build --workspace` (without webhook-witness feature) and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-C5 — `allow_stale_screening` has no staleness-window companion

**Severity:** CRITICAL (security gap)
**Files:** `crates/invariant-biosynthesis-core/src/models/profile.rs:64–75`
**Symptom:** `BioProfile.allow_stale_screening: bool` exists and is validated (rejected at BSL ≥ 3). However, there is no `stale_screening_max_days: Option<u32>` companion field. When `allow_stale_screening = true` and `bsl_level < 3`, the profile accepts a screening database of any age — days, months, or years old — with no bound. `BioProfile::validate` does not require a window to be present. This was called out as part of the C-6 remediation in part-4 but the `stale_screening_max_days` field was never added.
**Prior refs:** part-4 C-6 (partial).

---

**Step C5 — Add and enforce `stale_screening_max_days`**

```
Read crates/invariant-biosynthesis-core/src/models/profile.rs in full, then read crates/invariant-biosynthesis-core/src/validator.rs lines 440–480 (the staleness-check logic) to understand how `allow_stale_screening` is currently used.

1. Add the field `stale_screening_max_days: Option<u32>` to `BioProfile` with serde attributes `#[serde(default, skip_serializing_if = "Option::is_none")]`. Place it immediately after `allow_stale_screening`. Add a doc comment explaining that this field is required when `allow_stale_screening = true` and is silently ignored otherwise.

2. Add validation logic to `BioProfile::validate`:
   - If `allow_stale_screening && stale_screening_max_days.is_none()` → return `ValidationError::ProfileFieldInvalid { field: "stale_screening_max_days", reason: "must be set when allow_stale_screening is true" }`.
   - If `stale_screening_max_days` is `Some(0)` → return an error: "stale_screening_max_days must be at least 1".
   - If `stale_screening_max_days` is `Some(n)` where n > 365 → return an advisory warning (not an error): "stale_screening_max_days > 365 is unusually permissive; confirm this is intentional". Actually, make this a hard error if bsl_level >= 2 and n > 90.

3. In validator.rs, update the staleness check: when `profile.allow_stale_screening` is true, compare the DB's age against `profile.stale_screening_max_days.unwrap_or(30)` days (the unwrap_or is a safe fallback since validate() guarantees the field is present if allow_stale_screening is true, but this guards against programmatic construction that bypasses validate).

4. Update every BioProfile struct literal in test fixtures that sets `allow_stale_screening: true` to also set `stale_screening_max_days: Some(<reasonable value>)`. Search for `allow_stale_screening: true` across all crates and fix each site.

5. Update the JSON profile files in profiles/ that set `allow_stale_screening: true` (if any) to add the companion field.

Write 5 tests for `BioProfile::validate`:
1. allow_stale_screening=true without stale_screening_max_days → validation error.
2. allow_stale_screening=true with stale_screening_max_days=Some(30) → valid.
3. allow_stale_screening=true with stale_screening_max_days=Some(0) → error.
4. allow_stale_screening=false with stale_screening_max_days=None → valid (field not required).
5. BSL-2 profile with stale_screening_max_days=Some(91) → hard error.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`. Confirm no existing tests were broken.
```

---

### GAP-C6 — Platform adapters do not exist

**Severity:** CRITICAL (for production)
**Files:** `crates/invariant-biosynthesis-core/src/attestation.rs` (envelope types only)
**Symptom:** Zero vendor adapters (Twist, IDT, Ansa, Kilobaser, CEM, Biotage, Chemspeed, Hamilton, Tecan, Emerald, Strateos, Transcriptic). No HTTP transport. No instrument-side library to produce attested readings. No `invariant-bio issue-token` command. The `validate_with_attested_inputs` path in the validator can only verify attested readings; nothing in the repo produces them.
**Prior refs:** spec-gap-analysis.md §9, part-3 §9, part-4 C-7.

---

**Step C6-a — Create `invariant-biosynthesis-platform` crate with `Platform` trait**

```
Read crates/invariant-biosynthesis-core/src/attestation.rs in full to understand ExecutionToken, AttestedReading, and AttestedInput types. Also read the workspace Cargo.toml.

Create a new crate crates/invariant-biosynthesis-platform/:
- Add it to the workspace in the root Cargo.toml.
- Add Cargo.toml with edition = "2021", #![forbid(unsafe_code)] in lib.rs.
- Depend on invariant-biosynthesis-core (workspace path), serde, serde_json, thiserror, ed25519-dalek, base64.

In src/lib.rs, define:

    pub trait Platform: Send + Sync {
        fn name(&self) -> &str;
        fn issue_token(&self, verdict: &SignedVerdict, kid: &str, signing_key: &SigningKey)
            -> Result<ExecutionToken, PlatformError>;
        fn submit_job(&self, token: &ExecutionToken) -> Result<JobHandle, PlatformError>;
        fn poll_job(&self, handle: &JobHandle) -> Result<JobStatus, PlatformError>;
        fn fetch_attested_reading(&self, handle: &JobHandle)
            -> Result<AttestedReading, PlatformError>;
    }

    pub struct JobHandle { pub job_id: String, pub platform: String }
    pub enum JobStatus { Pending, Running, Complete, Failed { reason: String } }

    #[derive(thiserror::Error, Debug)]
    pub enum PlatformError {
        #[error("HTTP error: {0}")] Http(String),
        #[error("auth error: {0}")] Auth(String),
        #[error("job failed: {0}")] JobFailed(String),
        #[error("platform unavailable: {0}")] Unavailable(String),
    }

Add a `MockPlatform` struct that implements `Platform` for testing, holding a pre-loaded `AttestedReading` it returns from `fetch_attested_reading`. MockPlatform::submit_job always succeeds, poll_job always returns Complete.

Write 4 tests on MockPlatform:
1. issue_token constructs a token with the correct verdict hash.
2. submit_job returns a JobHandle with the platform name set.
3. poll_job returns Complete.
4. fetch_attested_reading returns the pre-loaded reading and it passes attestation verification.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

**Step C6-b — Add `invariant-bio issue-token` CLI command**

```
Read crates/invariant-biosynthesis-cli/src/commands/mod.rs and crates/invariant-biosynthesis-cli/src/main.rs to understand the subcommand wiring pattern. Read crates/invariant-biosynthesis-core/src/attestation.rs to understand ExecutionToken construction.

Add a new file crates/invariant-biosynthesis-cli/src/commands/issue_token.rs.

Implement `IssueTokenArgs`:
- `--verdict <PATH>`: path to a signed verdict JSON.
- `--signing-key <PATH>`: path to the validator's private key file (same format as keygen output).
- `--kid <STRING>`: key identifier of the signer.
- `--output <PATH>`: where to write the signed ExecutionToken JSON (stdout if omitted).
- `--ttl-seconds <u64>`: how long the token is valid (default 3600).

The command must:
1. Load and deserialize the SignedVerdict.
2. Reject if the verdict's overall decision is not Approved.
3. Construct an ExecutionToken: { verdict_hash: sha256_hex_json(&verdict), issued_at: now, expires_at: now + ttl, kid, signature }.
4. Sign using Ed25519: signature = base64(signing_key.sign(sha256_hex_json(&token_body).as_bytes())).
5. Write the token JSON to the output sink.

Wire the subcommand into main.rs and commands/mod.rs.

Write 3 tests:
1. Happy path: valid Approved verdict → produces a well-formed token.
2. Rejected verdict → exits with code 1 and error message.
3. Missing signing key file → exits with code 3.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

## 2. High-priority gaps

### GAP-H1 — D7 codon-usage organism check has no CUTG statistical test

**Severity:** HIGH
**Files:** `crates/invariant-biosynthesis-core/src/invariants/dna.rs:716–783`
**Symptom:** `codon_usage_organism` in `BioProfile` is validated against a whitelist (`e_coli`, `s_cerevisiae`, `h_sapiens`, `cho_k1`) but the validator only uses Shannon entropy. No codon-usage table (CUTG) is loaded; no chi-squared goodness-of-fit test is performed against the host distribution. Codon-shuffled hazard genes in a benign exotic-host carrier sequence produce normal Shannon entropy and pass D7.
**Prior refs:** part-4 H-4.

---

**Step H1 — Add embedded CUTG tables and chi-squared D7 test**

```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs lines 700–850 (the D7 CodonEntropyScreen implementation) and crates/invariant-biosynthesis-core/src/models/profile.rs (the codon_usage_organism field).

1. Create a new file crates/invariant-biosynthesis-core/src/codon_tables.rs. This file embeds CUTG-derived codon frequencies as compile-time static arrays using `include_str!` on small JSON data files you will also create in crates/invariant-biosynthesis-core/data/codon_tables/.

   Create 4 JSON files: e_coli.json, s_cerevisiae.json, h_sapiens.json, cho_k1.json. Each file is a JSON object mapping each of the 64 codons (AAA, AAC, ..., TTT) to its relative frequency (summing to 1.0 within each amino acid's synonymous family). Use publicly available CUTG 2022 average frequencies for each organism. You may embed approximate values — the important thing is the structure is correct and the frequencies are plausible.

   Example e_coli.json structure:
   { "AAA": 0.74, "AAG": 0.26, "AAC": 0.43, "AAT": 0.57, ... }
   (These are relative frequencies within Lys codons for E. coli; include all 64.)

2. In codon_tables.rs, implement:
   - `pub fn get_table(organism: &str) -> Option<&'static CodonTable>`
   - `pub struct CodonTable { pub organism: &'static str, pub freqs: HashMap<&'static str, f64> }`
   - `pub fn chi_squared(sequence: &str, table: &CodonTable) -> f64` — counts observed codon frequencies in sequence, computes chi-squared against the expected frequencies from table, returns the test statistic. Codons with expected frequency = 0 are excluded from the sum.
   - `pub fn p_value_conservative(chi_sq: f64, df: u32) -> f64` — use a Poisson approximation (chi-sq distribution) or a lookup table for the 63 degrees of freedom case. A conservative approximation is acceptable; document the method.

3. Update the D7 `CodonEntropyScreen::evaluate_with` to:
   - If profile.codon_usage_organism is set and a CUTG table exists for that organism, run chi_squared on the bundle's DNA sequence.
   - p_value < 0.001 → Fail("codon usage inconsistent with declared host organism at p<0.001").
   - 0.001 ≤ p_value < 0.05 → Advisory("codon usage marginally inconsistent with declared host organism at p<0.05").
   - p_value ≥ 0.05 → Pass (combine with existing entropy check; worst result wins).
   - If no organism is declared or no table is available, fall back to the existing entropy-only path.

4. Add the new module to lib.rs: `pub mod codon_tables;`

Write 6 tests:
1. A known E. coli gene (e.g. the lacZ fragment) passes D7 with organism="e_coli".
2. A randomly shuffled codon sequence produces high chi-squared (p < 0.001) and triggers Fail.
3. organism="s_cerevisiae" with an E. coli-biased sequence triggers Advisory.
4. No organism set → entropy-only path still works.
5. chi_squared function: verify the statistic is 0.0 for a sequence with exactly the expected codon distribution.
6. p_value_conservative: verify p(0.0, 63) ≈ 1.0 and p(100.0, 63) < 0.01.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-H2 — Threat scorer is not default-on for high-BSL profiles

**Severity:** HIGH
**Files:** `crates/invariant-biosynthesis-core/src/validator.rs:85–137`
**Symptom:** `ValidatorConfig` has `threat_scorer: Option<ThreatScorer>` and `threat_alert_threshold: Option<f64>`, both defaulting to `None`. The threat scorer is only active when the caller explicitly provides it via `with_threat_scorer`. For BSL ≥ 3 profiles, disabling the threat scorer silently removes a defence layer. The CLI enables it only with `--threat-threshold`.
**Prior refs:** part-4 H-2, X-1.

---

**Step H2 — Default-on threat scorer for high-BSL profiles**

```
Read crates/invariant-biosynthesis-core/src/validator.rs lines 70–220 (ValidatorConfig fields and builder methods) and crates/invariant-biosynthesis-core/src/models/profile.rs (bsl_level field).

1. Change the default in `ValidatorConfig::default()` (or wherever `threat_scorer: None` is set in `new()`) so that when the provided `BioProfile` has `bsl_level >= 3`, a `ThreatScorer::with_defaults()` is created automatically and stored in `threat_scorer`. For BSL ≤ 2 profiles, keep the existing None default (threat scoring is opt-in at lower BSL).

2. Add a builder method `without_threat_scorer(mut self) -> Self` that sets `threat_scorer = None` regardless of BSL level, for use in testing.

3. Update the `validate` CLI command: remove the requirement to pass `--threat-threshold` before the threat scorer activates. The new behaviour is:
   - If the profile has BSL ≥ 3 and no `--threat-threshold` is given, use the default threshold from `ThreatScorerConfig` (0.7).
   - `--threat-threshold` overrides the default for any BSL level.
   - BSL ≤ 2 profiles still require `--threat-threshold` to activate the scorer.

4. Add a note in the `--threat-threshold` help text explaining this difference.

Write 4 tests:
1. ValidatorConfig::new with BSL-3 profile → threat_scorer is Some.
2. ValidatorConfig::new with BSL-2 profile → threat_scorer is None.
3. .without_threat_scorer() on a BSL-3 config → threat_scorer becomes None.
4. Validate CLI with a BSL-3 profile and no --threat-threshold → threat scorer active at default threshold (integration test asserting the validator runs without error).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-H3 — Attestation nonce log grows unbounded

**Severity:** HIGH
**Files:** `crates/invariant-biosynthesis-core/src/attestation.rs:188–239`
**Symptom:** `AttestationVerifier::with_persistent_log` reads and writes a JSONL nonce log to survive restarts. There is no rotation policy. A long-running firewall will accumulate every nonce ever seen; on a high-throughput installation this exhausts disk.
**Prior refs:** part-4 H-6.

---

**Step H3 — Add time-windowed nonce log rotation**

```
Read crates/invariant-biosynthesis-core/src/attestation.rs lines 188–239 (AttestationVerifier and its nonce-log persistence methods) in full.

1. Add a `nonce_ttl_days: u32` field to `AttestationVerifier` (default: 90). This is the window within which a nonce is remembered for replay protection. Nonces older than this window are automatically considered expired (a replay attack with a nonce from 91 days ago is not a threat if the token's issued-at timestamp itself would be too old to be valid).

2. Change the log format: each JSONL line must include an `expires_at: DateTime<Utc>` field set to `issued_at + nonce_ttl_days`. On load, skip (and rewrite without) any entries whose `expires_at` is before now.

3. Add a `rotate(&self) -> Result<usize, AttestationError>` method that:
   - Reads the current log.
   - Drops all entries where `expires_at < now`.
   - Rewrites the log atomically (write to a temp file, then rename).
   - Returns the number of entries dropped.

4. Call `rotate()` automatically inside `with_persistent_log` after loading, and again periodically: add an internal counter that triggers a rotation after every 1000 `verify()` calls (to avoid calling `rotate` on every request in high-throughput deployments).

5. Add a `nonce_count() -> usize` method for observability.

Write 5 tests:
1. Expired nonces are removed on load.
2. Fresh nonces are retained on load.
3. Rotation drops the right entries and returns the correct count.
4. Nonce count reflects only non-expired entries.
5. After 1001 verify calls (using a helper that fast-forwards the clock), rotation fires automatically.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-H4 — Incident responder is not wired into the validator

**Severity:** HIGH
**Files:** `crates/invariant-biosynthesis-core/src/incident.rs`, `crates/invariant-biosynthesis-core/src/validator.rs`
**Symptom:** `IncidentResponder`, `IncidentRecord`, and `IncidentTrigger` are fully implemented and tested in isolation. The validator pipeline does not call them. AlertSink::Webhook and AlertSink::Syslog return `AlertError::Unavailable`.
**Prior refs:** spec-gap-analysis.md M-6, part-3 §M-6, part-4 M-6.

---

**Step H4-a — Wire incident responder into the validator post-verdict path**

```
Read crates/invariant-biosynthesis-core/src/incident.rs in full, then read crates/invariant-biosynthesis-core/src/validator.rs lines 380–600 (the validate() and validate_with_attested_inputs() methods).

1. Add an optional `incident_responder: Option<Arc<Mutex<IncidentResponder>>>` field to `ValidatorConfig`. Default: None. Add a builder method `with_incident_responder(r: Arc<Mutex<IncidentResponder>>) -> Self`.

2. After the validator produces a final verdict, if an `incident_responder` is present, call it in these cases:
   - The overall verdict is Rejected AND the composite threat score (from ThreatAnalysis) exceeds 0.85 → trigger with `IncidentTrigger::HighThreatScore { score }`.
   - Any invariant result is `InvariantStatus::Fail` for a CRITICAL invariant (D1, D2, D3, D4, D5, C1) → trigger with `IncidentTrigger::CriticalInvariantFail { invariant_id }`.
   - The PCA authority check fails (authority_passed = false) more than 3 times within the validator's session (track a failure counter in ValidatorConfig) → trigger with `IncidentTrigger::RepeatedAuthorizationFailure { count }`.
   Add these IncidentTrigger variants to the enum in incident.rs if they are not already present.

3. If the incident responder is in Lockdown state, the validator must immediately return a Rejected verdict with reason "system in lockdown; manual reset required" without running any invariants.

Write 4 tests:
1. High threat score above 0.85 triggers the incident responder.
2. Critical invariant fail triggers the incident responder.
3. Lockdown state causes the validator to reject immediately.
4. Non-critical invariant fail does NOT trigger the incident responder.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

**Step H4-b — Implement webhook and syslog alert sinks**

```
Read crates/invariant-biosynthesis-core/src/incident.rs focusing on AlertSink, AlertError, and the existing Unavailable stub returns.

1. Under a feature flag "webhook-alerts" (add to Cargo.toml), implement AlertSink::Webhook using the same reqwest-based approach as Step C4-b (reuse the dependency). The POST body is JSON: { "incident_id": ..., "trigger": ..., "timestamp": ..., "firewall_kid": ... }. On network failure, return AlertError::NetworkError { reason }.

2. Under a feature flag "syslog-alerts" (add to Cargo.toml), implement AlertSink::Syslog using the `syslog` crate (version 6.x). Format: "invariant-bio[INCIDENT]: <trigger_description>". Map severity to syslog level: CriticalInvariantFail → LOG_CRIT, HighThreatScore → LOG_ALERT, RepeatedAuthorizationFailure → LOG_WARNING.

3. Both feature-off paths must still compile and return AlertError::Unavailable (keep the existing stubs as the non-feature implementation).

Write 4 tests:
1. Webhook alert (feature-gated): mock HTTP server asserts correct JSON body and content-type.
2. Webhook alert on network error returns NetworkError.
3. Syslog alert (feature-gated): verify the syslog crate's `send` method is called with the expected priority.
4. Feature-off: both sinks return Unavailable without panicking.

Verify `cargo build --workspace` (without alert features) and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-H5 — AUDIT-READINESS.md is absent

**Severity:** HIGH
**Files:** (missing — `docs/AUDIT-READINESS.md` does not exist)
**Symptom:** Phase-2 §20 requires a document that walks auditors through build steps, test inventory, supported features, known limitations, crypto primitives, library versions, and supply-chain (SBOM). Absent. The existing `docs/threat-model.md` pre-dates the stateful detector and k-mer screener.
**Prior refs:** part-4 H-7.

---

**Step H5 — Author AUDIT-READINESS.md and refresh threat-model.md**

```
Read docs/threat-model.md in full. Read SECURITY.md, README.md, Cargo.toml for each crate, and crates/invariant-biosynthesis-core/src/invariants/dna.rs lines 1–30 and 59–68 (D-family screener overview and calibration constants). Read crates/invariant-biosynthesis-core/src/authority/mod.rs and src/audit.rs module-level docs.

Create docs/AUDIT-READINESS.md with the following sections:

1. **Build and test reproduction**: exact commands to reproduce a clean build and test run from source, including toolchain version (Rust 1.78+), feature flags, and expected test count.

2. **Supported features and capability matrix**: for each invariant family (D, P, C, PR, S) state: implemented, heuristic-quality (not calibrated), calibrated, or production-ready. Be honest — today D/P/C are heuristic. Mark cheminformatics as "pending feature flag".

3. **Known limitations** (mandatory for auditors):
   - Protein k-mer screener is uncalibrated (reference corpus pending).
   - Chemical invariants are regex-based (SMARTS engine pending).
   - HSM backends other than file-backed are stubs.
   - Replication backends (S3, webhook) are stubs.
   - Platform adapters do not exist.
   - Attestation nonce log rotation policy is time-windowed (90 days default).

4. **Cryptographic primitives**: document each crypto usage: Ed25519 (ed25519-dalek 2.x, libsodium-compatible), SHA-256 (sha2 via ring), COSE_Sign1 (coset crate), base64-STANDARD encoding. State that all keys are 32-byte Ed25519 scalar; no RSA, no ECDSA.

5. **Dependency audit**: list the commands `cargo deny check` and `cargo audit` (requires cargo-audit); note which ones must be clean for a production build. State that `cargo deny.toml` enforces MIT/Apache-2.0 license compliance.

6. **SBOM**: document that `cargo cyclonedx` (or `cargo-sbom`) generates the SBOM; provide the command. Note this is not automated in CI yet (see roadmap).

7. **Acceptance gates status table** (replicate and update the table from part-4 §X-3 with current status):
   | Gate | Status |
   |------|--------|
   | Phase 2 closed | ❌ in progress |
   | Reference set FN/FP validated | ❌ corpus pending |
   | Shadow-mode > 99% agreement | ❌ no infrastructure |
   | At least one HSM backend in production | ❌ stubs |
   | At least one synthesizer end-to-end | ❌ no adapters |
   | Compliance report accepted by counsel | ❌ no compliance crate |
   | Stateful + consensus reachable from CLI, default in prod profiles | ✅ done |

Then update docs/threat-model.md:
- Add a section "§3.5 Cross-bundle fragmentation bypass" documenting the S1 `FragmentationBypassDetector`, its k=24 DNA k-mer window, the Jaccard ≥ 0.4 threshold, and its opt-out mechanism (--no-stateful).
- Add "§3.6 Codon-substituted homolog bypass" documenting the D1–D6 3-frame + reverse-complement protein k-mer screen (k=5, Jaccard ≥ 0.30), its calibration status, and known FN risk with exotic organisms.
- Update the "Coverage summary" table to include D10/S1 and the new D-family protein-space screen.

No new code is required. Verify by running `cargo test --workspace` (no regressions) and reading the newly created documents for consistency.
```

---

## 3. Medium-priority gaps

### GAP-M1 — Consensus disagreement is not structured

**Severity:** MEDIUM
**Files:** `crates/invariant-biosynthesis-core/src/screening/mod.rs:397–406`
**Symptom:** When `ConsensusHazardScreener` sources disagree on a hit, the disagreement is surfaced only as a string label appended to `HazardHit.matched_text`. Compliance auditing requires a structured record of which sources agreed, which disagreed, and the quorum result.

---

**Step M1 — Add structured consensus report to HazardHit and verdict**

```
Read crates/invariant-biosynthesis-core/src/screening/mod.rs in full, paying attention to ConsensusHazardScreener, HazardHit, and QuorumPolicy. Read crates/invariant-biosynthesis-core/src/models/verdict.rs to understand how hits are embedded in the verdict.

1. Add a new type to screening/mod.rs:
   pub struct SourceVerdict { pub source_index: usize, pub source_kid: String, pub hit: bool, pub matched_text: Option<String> }
   pub struct ConsensusReport { pub entry_id: String, pub policy: QuorumPolicy, pub sources: Vec<SourceVerdict>, pub quorum_met: bool }

2. Add `consensus_report: Option<ConsensusReport>` to `HazardHit`. Set it to `None` for single-source hits; populate it for hits from `ConsensusHazardScreener`.

3. In `ConsensusHazardScreener::check`, for each pattern that is evaluated, build a `SourceVerdict` per source. After applying the quorum policy, attach the `ConsensusReport` to any emitted `HazardHit`.

4. In `models/verdict.rs`, add a `consensus_reports: Vec<ConsensusReport>` field to `Verdict`. After running screening, extract all `HazardHit.consensus_report` values and collect them into the verdict field.

5. Update serde derives so ConsensusReport serialises as a nested JSON object inside the HazardHit and verdict JSON.

Write 4 tests:
1. Single-source screener → consensus_report is None in every HazardHit.
2. Two-source consensus with "all" policy where both agree → quorum_met = true, sources has 2 entries.
3. Two-source consensus where sources disagree and policy is "any" → quorum_met = true, one source.hit = true, one = false.
4. Two-source consensus where sources disagree and policy is "all" → quorum_met = false, hit is not emitted (or emitted as Advisory with explanation).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-M2 — Differential validation not in standard validate flow

**Severity:** MEDIUM
**Files:** `crates/invariant-biosynthesis-core/src/differential.rs`, `crates/invariant-biosynthesis-cli/src/commands/differential.rs`
**Symptom:** The `differential` subcommand accepts two pre-computed verdict JSON files. There is no `validate --differential <secondary-config>` mode that runs both validators live and blocks on disagreement.

---

**Step M2 — Add `--differential` to the validate subcommand**

```
Read crates/invariant-biosynthesis-cli/src/commands/validate.rs in full, then read crates/invariant-biosynthesis-core/src/differential.rs and crates/invariant-biosynthesis-cli/src/commands/differential.rs.

1. Add the following args to ValidateArgs:
   `--differential <PATH>`: path to a second validator config JSON (profile + hazard DB). When provided, the validate command runs the same bundle through both the primary and secondary validator configs and compares verdicts using DifferentialChecker.

2. Define a simple `SecondaryValidatorConfig` type that is deserialisable from JSON and carries: profile_path, hazard_db_path, hazard_db_issuer_pub_path. Load this in run_inner before the main validation.

3. After both verdicts are produced, call `DifferentialChecker::compare(primary, secondary)`. If the result has any `DifferentialResult::Diverge` entries:
   - Log each divergence to stderr.
   - Override the final exit code to 1 (rejection) regardless of the primary verdict.
   - Embed the divergence records in the output verdict JSON under a new field `differential_divergences`.

4. If `--differential` is not provided, behaviour is identical to current.

Write 3 tests in cli_integration.rs (or commands/differential.rs):
1. Two identical configs agree → exit code reflects primary verdict only.
2. Configs disagree on one check → exit code 1 and divergence records in output.
3. Secondary config file not found → exit code 3, descriptive error.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-M3 — No statistical validation framework

**Severity:** MEDIUM
**Files:** `crates/invariant-biosynthesis-eval/src/lib.rs`
**Symptom:** Spec demands Clopper–Pearson confidence intervals, power analysis, and Bayesian updating for FP/FN estimation. None of this exists. The `eval` crate has rubric scoring but no statistical framework.

---

**Step M3 — Add `stats` module to the eval crate**

```
Read crates/invariant-biosynthesis-eval/src/lib.rs and its tests in full.

Add a new file crates/invariant-biosynthesis-eval/src/stats.rs and expose it as `pub mod stats` in lib.rs.

Implement:

1. `pub fn clopper_pearson(successes: u32, trials: u32, confidence: f64) -> (f64, f64)` — the exact Clopper–Pearson interval for a binomial proportion. Use the beta distribution CDF: lower = Beta::quantile(alpha/2, successes, trials - successes + 1), upper = Beta::quantile(1 - alpha/2, successes + 1, trials - successes). Implement the regularised incomplete beta function via the continued-fraction algorithm (no external stats crate required — implement it from scratch). alpha = 1 - confidence.

2. `pub fn minimum_detectable_effect(baseline: f64, power: f64, alpha: f64, n: u32) -> f64` — returns the minimum effect size detectable at given power and significance level for a two-proportion z-test of sample size n.

3. `pub struct BinaryClassifierMetrics { pub tp: u32, pub fp: u32, pub tn: u32, pub fn_: u32 }` with methods:
   - `sensitivity(&self) -> f64`
   - `specificity(&self) -> f64`
   - `precision(&self) -> f64`
   - `f1(&self) -> f64`
   - `sensitivity_ci(&self, confidence: f64) -> (f64, f64)` — Clopper–Pearson on TP/(TP+FN)
   - `specificity_ci(&self, confidence: f64) -> (f64, f64)` — Clopper–Pearson on TN/(TN+FP)

4. `pub fn bayesian_update(prior: f64, likelihood_ratio: f64) -> f64` — standard Bayes rule on odds form: posterior_odds = prior_odds * likelihood_ratio; return posterior probability.

Write 10 tests:
- clopper_pearson(5, 5, 0.95) has lower bound > 0.478 and upper = 1.0.
- clopper_pearson(0, 10, 0.95) has lower = 0.0 and upper < 0.31.
- clopper_pearson(3, 10, 0.95) is roughly (0.067, 0.652).
- BinaryClassifierMetrics::sensitivity on all-positive classifier = 1.0.
- BinaryClassifierMetrics::specificity on all-negative classifier = 1.0.
- F1 is 0.0 when precision is 0.0.
- sensitivity_ci returns a valid interval (lower ≤ sensitivity ≤ upper).
- specificity_ci returns a valid interval.
- minimum_detectable_effect is positive and decreases as n increases.
- bayesian_update(0.01, 10.0) ≈ 0.0917 (approximate).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-M4 — No performance benchmarks

**Severity:** MEDIUM
**Files:** (missing — `crates/invariant-biosynthesis-core/benches/` does not exist)
**Symptom:** Phase-2 §17 requires `criterion` harnesses on hot paths. No benchmarks exist anywhere in the workspace.

---

**Step M4 — Add criterion benchmarks for hot paths**

```
Read crates/invariant-biosynthesis-core/src/validator.rs (the validate method), src/invariants/dna.rs (protein_space_rescreen and translate_dna_sequence), src/screening/mod.rs (FileBackedHazardDatabase::check), and src/audit.rs (append).

1. Add `criterion` as a dev-dependency in crates/invariant-biosynthesis-core/Cargo.toml:
   [dev-dependencies]
   criterion = { version = "0.5", features = ["html_reports"] }

   Add the bench target:
   [[bench]]
   name = "core_hot_paths"
   harness = false

2. Create crates/invariant-biosynthesis-core/benches/core_hot_paths.rs with criterion groups:

   - `bench_dna_translate`: call `translate_dna_sequence` on a 3000 nt sequence (a realistic gene fragment). Report throughput in nt/s.
   - `bench_protein_kmer_rescreen`: call `protein_space_rescreen` with k=5, threshold=0.30 on a 1500 nt sequence against 10 hazard hits. Report throughput.
   - `bench_hazard_db_check`: call `FileBackedHazardDatabase::check` on a 500 nt DNA sequence against a DB with 50 patterns. Report throughput.
   - `bench_validator_full`: run `ValidatorConfig::validate(&bundle, now, None)` end-to-end for a clean DNA bundle (no hazard hits). Report calls/s.
   - `bench_audit_append`: append 100 entries sequentially to an in-memory audit log (backed by a temp dir). Report entries/s.

3. Create crates/invariant-biosynthesis-core/docs/ (or docs/) `PERFORMANCE.md`:
   Document the intended performance targets:
   - DNA translation: ≥ 10 Mnt/s
   - Protein k-mer rescreen: ≥ 1 Mnt/s
   - Full validation (no DB): ≤ 5 ms per bundle
   - Audit append: ≥ 1000 entries/s
   State that these are aspirational baselines to be updated after first benchmark run.

Write the benchmark file (criterion benches, not tests), then also write 2 smoke tests (in the test suite, not benches) that call each benchmarked function once and assert they return a result without panicking.

Verify `cargo bench --workspace 2>&1 | head -40` produces criterion output without errors, and `cargo test --workspace` still passes.
```

---

### GAP-M5 — D9 secondary-structure check is a rolling-hash heuristic

**Severity:** MEDIUM
**Files:** `crates/invariant-biosynthesis-core/src/invariants/dna.rs:937–974`
**Symptom:** D9 uses a 20-nt sliding rolling-hash to find perfect self-complementary windows. Real hairpin/G-quadruplex detection requires free-energy minimisation (ViennaRNA/RNAfold). The heuristic has high false-positive and false-negative rates for real sequences.

---

**Step M5 — Gate ViennaRNA behind a feature flag and improve the heuristic**

```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs lines 900–1010 (D9 SynthesisFeasibilityCheck). Read crates/invariant-biosynthesis-core/Cargo.toml.

1. Add an optional feature "viennarna" to Cargo.toml. When enabled, add a dependency on the `viennarna` crate (a Rust binding to the ViennaRNA library; version 0.2.x). Gate all ViennaRNA calls behind `#[cfg(feature = "viennarna")]`.

2. Under the feature flag, replace the rolling-hash hairpin detector with:
   - A call to `viennarna::fold(sequence)` to get the MFE secondary structure and ΔG.
   - If ΔG < -10 kcal/mol → Fail("predicted secondary structure ΔG = X kcal/mol; may impair synthesis").
   - If -10 ≤ ΔG < -5 kcal/mol → Advisory("secondary structure ΔG = X kcal/mol").
   - ΔG ≥ -5 → Pass.

3. Without the feature flag, improve the existing heuristic:
   - Extend to a 12–25 nt window instead of fixed 20 nt.
   - Also detect G-quadruplex motif: ≥ 3 runs of ≥ 3 consecutive Gs within 40 nt → Advisory("G-quadruplex signature detected").
   - Preserve the existing rolling-hash perfect-complement check as the Fail path (unchanged).

4. Add a `PROTOCOL_STEP_VOCAB_VERSION` comment to document that the heuristic improvements are version-tagged in the invariant output (include "heuristic" in the advisory message so callers know it is not ViennaRNA-derived).

Write 5 tests (all without the viennarna feature, since CI may not have the library):
1. A sequence with a perfect 20-nt hairpin → Fail.
2. A sequence with no self-complementarity → Pass.
3. A sequence with G4 motif (4 G-runs) → Advisory.
4. A short (< 40 nt) sequence → Pass (too short for meaningful secondary structure).
5. D9 under feature = "viennarna" path: create a mock that returns ΔG = -12 → Fail (test the dispatch logic, not ViennaRNA itself).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`. Verify `cargo build --workspace --features invariant-biosynthesis-core/viennarna` either succeeds or produces only an expected "viennarna library not found" linker error.
```

---

### GAP-M6 — No compliance crate and no per-jurisdiction reports

**Severity:** MEDIUM
**Files:** (missing — `crates/invariant-biosynthesis-compliance/` does not exist)
**Symptom:** Phase-2 §19 and spec-gap-analysis.md §12 call for a compliance crate with per-jurisdiction report generators (CDC Select Agent, NIH rDNA, CWC, FDA). Raw `proof_package` JSON export exists, but there are no structured agency-specific report formats.

---

**Step M6 — Create `invariant-biosynthesis-compliance` skeleton**

```
Read crates/invariant-biosynthesis-core/src/proof_package.rs in full to understand ProofPackage structure. Read docs/spec.md §12 (regulatory compliance section) if it exists, or docs/spec-gap-analysis.md §12.

Create a new crate crates/invariant-biosynthesis-compliance/:
- Add to workspace Cargo.toml.
- Depend on invariant-biosynthesis-core (workspace path), serde, serde_json, chrono.

In src/lib.rs:

1. Define a `Jurisdiction` enum:
   pub enum Jurisdiction { CdcSelectAgent, NihRdna, Cwc, FdaPharmaceutical, EpaTsca }

2. Define a `ComplianceReport` struct:
   pub struct ComplianceReport {
       pub jurisdiction: Jurisdiction,
       pub generated_at: DateTime<Utc>,
       pub firewall_version: String,
       pub proof_package_hash: String,    // sha256_hex_json of the ProofPackage
       pub findings: Vec<ComplianceFinding>,
       pub overall_status: ComplianceStatus,
   }
   pub struct ComplianceFinding { pub rule_id: String, pub description: String, pub status: ComplianceStatus, pub evidence: String }
   pub enum ComplianceStatus { Pass, Advisory, Fail, NotApplicable }

3. Define a `ReportGenerator` trait:
   pub trait ReportGenerator {
       fn jurisdiction(&self) -> Jurisdiction;
       fn generate(&self, package: &ProofPackage) -> ComplianceReport;
   }

4. Implement `CdcSelectAgentReportGenerator`:
   - Maps each D-family invariant result to its CDC select-agent program rule ID (e.g. D1 → "42 CFR §73.5(a) — Possession of a select agent").
   - If any D1–D5 invariant Fail in the package's verdict → Fail finding.
   - If S1 Fail → Fail finding for "42 CFR §73.5(b) — Transfer restrictions".
   - Otherwise → Pass or Advisory.

5. Expose a `generate_report(jurisdiction: Jurisdiction, package: &ProofPackage) -> ComplianceReport` convenience function that dispatches to the right generator.

6. Implement `to_json(report: &ComplianceReport) -> String` and `to_markdown(report: &ComplianceReport) -> String` formatters.

Write 5 tests:
1. CdcSelectAgent report with a clean verdict → all Pass findings.
2. CdcSelectAgent report with a D1 Fail → Fail finding for the correct rule ID.
3. Report JSON round-trips through serde.
4. Markdown formatter includes the jurisdiction name and overall_status.
5. generate_report dispatches to the correct generator for each Jurisdiction variant.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

## 4. Low-priority gaps

### GAP-L1 — No RFC process or responsible-disclosure SLA

**Severity:** LOW
**Files:** `SECURITY.md`

---

**Step L1 — Add RFC template and SECURITY.md SLA**

```
Read SECURITY.md in full.

1. Update SECURITY.md to add a "Response SLA" section:
   - Critical (CVSS ≥ 9.0): acknowledge within 24 hours, patch within 7 days.
   - High (CVSS 7.0–8.9): acknowledge within 48 hours, patch within 30 days.
   - Medium/Low: acknowledge within 7 days, patch within 90 days.
   - State the contact method (e.g. email to hi@claygood.com with subject "SECURITY: invariant-biosynthesis").

2. Create docs/rfcs/README.md with a one-page RFC process:
   - RFC stands for "Request for Feature/Change".
   - Required for: new invariants, new protocol verbs (allowed_protocol_steps additions), breaking changes to the signed verdict schema, new hazard classes, changes to the BioProfile struct fields.
   - Format: markdown file in docs/rfcs/ named NNNN-short-title.md.
   - Required sections: Summary, Motivation, Detailed Design, Drawbacks, Alternatives, Unresolved Questions.
   - Process: open as a draft PR, label "RFC", requires sign-off from two reviewers before merge.

3. Create docs/rfcs/0001-protocol-verb-add-template.md as a worked example showing how to propose adding a new protocol verb to the allowed vocabulary.

No code changes. Verify there are no regressions with `cargo test --workspace`.
```

---

### GAP-L2 — No export-control CI check

**Severity:** LOW
**Files:** `deny.toml` (covers licensing only)

---

**Step L2 — Add export-control dependency check to CI**

```
Read deny.toml (or Cargo.deny.toml) at the project root to understand its current structure. If it does not exist, create it.

1. Add a [bans] section to deny.toml that explicitly bans any crate known to be export-controlled or whose use may trigger ITAR/EAR review. Start with an empty ban list but add a comment: "Add crate names here if they are export-controlled or have ITAR implications."

2. Add a [advisories] section with `vulnerability = "deny"` and `unmaintained = "warn"`.

3. Create docs/EXPORT-CONTROL.md with the following sections:
   - "Policy": state that this project is a U.S.-origin software project; redistribution of binaries that incorporate classified algorithms (if any) requires EAR classification review.
   - "Dependency review process": any new dependency that handles cryptography, biological databases, or controlled-substance information must be reviewed by the maintainer before merging.
   - "Known controlled items": list that Ed25519-dalek is a U.S.-export-controlled cryptographic library subject to EAR exception TSU.
   - "CI check": document the `cargo deny check` command that enforces the ban list.

4. Add a note to CLAUDE.md (the project-level instructions file) reminding contributors to run `cargo deny check` before merging PRs that add new dependencies.

No Rust code changes. Verify `cargo deny check` runs without error (install cargo-deny first if needed: `cargo install cargo-deny`).
```

---

## 5. New gaps (not in any prior analysis)

### GAP-N1 — `allowed_protocol_steps` can only restrict, not extend, the built-in vocabulary

**Severity:** NEW / MEDIUM
**Files:** `crates/invariant-biosynthesis-core/src/models/profile.rs:131–142`, `crates/invariant-biosynthesis-core/src/invariants/protocol.rs:59–61`
**Symptom:** `BioProfile::validate` calls `is_builtin_verb(step)` for every entry in `allowed_protocol_steps`. This means the profile field is validated against the built-in 25-verb global ceiling — a profile cannot declare a custom verb not in the built-in list. The spec document (L-1 in part-4) left this as a decision to be made. The current behaviour is undocumented; operators who read the field description ("restricted protocol step vocabulary") will be confused when their custom verb is rejected at profile load time.

---

**Step N1 — Document and test the built-in ceiling policy**

```
Read crates/invariant-biosynthesis-core/src/models/profile.rs lines 49–55 (allowed_protocol_steps field doc), lines 131–142 (validation), and crates/invariant-biosynthesis-core/src/invariants/protocol.rs lines 27–61 (ALLOWED_VERBS list and is_builtin_verb).

The DECISION is to keep the built-in list as a global ceiling (profiles may restrict, not extend). Document this explicitly.

1. Update the `allowed_protocol_steps` field doc comment in profile.rs to read:
   "Optional per-profile restriction of the protocol step vocabulary. When set, only verbs in this list (which must be a subset of the built-in 25-verb vocabulary) are allowed by PR2. Profiles cannot introduce new verbs outside the built-in list; new verbs require an RFC (see docs/rfcs/README.md) to update the global vocabulary and the PROTOCOL_STEP_VOCAB_VERSION constant."

2. Update the error message in BioProfile::validate for allowed_protocol_steps to read:
   "verb {verb:?} is not in the built-in allowed verb list (PROTOCOL_STEP_VOCAB_VERSION = {version}); to add new verbs, open an RFC — see docs/rfcs/README.md"
   Wire in `crate::invariants::protocol::PROTOCOL_STEP_VOCAB_VERSION` from protocol.rs.

3. Update the doc comment on `PROTOCOL_STEP_VOCAB_VERSION` in protocol.rs to state: "Increment this version whenever the built-in verb list changes; all deployed profiles must re-validate after a version bump."

4. Add a CHANGELOG entry (create CHANGELOG.md if it does not exist) noting that allowed_protocol_steps is a restriction-only field.

Write 3 tests:
1. allowed_protocol_steps containing only valid built-in verbs → BioProfile validates successfully.
2. allowed_protocol_steps containing a non-built-in verb → BioProfile::validate returns ProfileFieldInvalid with the PROTOCOL_STEP_VOCAB_VERSION in the reason.
3. PR2::evaluate_with uses the profile's restricted list when present.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-N2 — Built-in profiles do not declare `max_authority_chain_depth`

**Severity:** NEW / LOW
**Files:** `profiles/university_bsl2_dna.json`, `profiles/university_bsl3_dna.json`, `profiles/government_bsl4_restricted.json`, `profiles/industry_peptide.json`, `profiles/industry_chemical.json`, `profiles/export_controlled_chemical.json`
**Symptom:** `max_authority_chain_depth` has a `#[serde(default = "default_max_chain_depth")]` attribute so it deserialises to `5` when absent from JSON. All 6 built-in profiles omit the field. This means the profiles are implicitly relying on a default rather than making an explicit security decision. A change to `default_max_chain_depth()` would silently change all deployed profiles without a JSON diff.

---

**Step N2 — Make chain depth explicit in all built-in profiles**

```
Read profiles/university_bsl2_dna.json, profiles/university_bsl3_dna.json, profiles/government_bsl4_restricted.json, profiles/industry_peptide.json, profiles/industry_chemical.json, and profiles/export_controlled_chemical.json. Also read crates/invariant-biosynthesis-core/src/models/profile.rs lines 72–75 (max_authority_chain_depth field and default).

For each profile JSON file, add an explicit "max_authority_chain_depth" field:
- university_bsl2_dna.json: 5 (standard)
- university_bsl3_dna.json: 4 (slightly tighter for BSL-3)
- government_bsl4_restricted.json: 3 (strict — minimal delegation depth for BSL-4)
- industry_peptide.json: 5
- industry_chemical.json: 5
- export_controlled_chemical.json: 4 (tighter for export-controlled)

Also add "stale_screening_max_days" where "allow_stale_screening" is true (none of the current profiles have allow_stale_screening set, so this is a no-op, but it confirms the field exists).

Update crates/invariant-biosynthesis-core/src/profiles.rs: add tests asserting each profile's explicit `max_authority_chain_depth` matches the expected value. This is a regression guard.

Write 2 new tests in profiles.rs:
1. BSL-4 profile has max_authority_chain_depth <= 3.
2. All profiles have max_authority_chain_depth explicitly set (i.e., after round-tripping through JSON, the field serialises back out — confirm by checking the JSON string contains "max_authority_chain_depth").

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-N3 — P-family invariants have no calibration documentation

**Severity:** NEW / HIGH
**Files:** `crates/invariant-biosynthesis-core/src/invariants/peptide.rs`
**Symptom:** P1–P10 have real heuristic implementations (not stubs), but every heuristic uses constants chosen without reference to any benchmarking corpus. For example: P1 uses `charge ≥ 3 AND hydrophobic_fraction ≥ 0.35` without any published evidence these thresholds yield acceptable FP/FN rates on a curated AMP dataset (e.g. APD3 or DBAASP). P3 uses a hydrophobic fraction ≥ 0.55 over 18 residues with no calibration reference. P8 uses a 6-residue aggregation window. None of these choices are documented or tested against known-positive and known-negative peptide sets.

---

**Step N3 — Add peptide invariant calibration corpus and document thresholds**

```
Read crates/invariant-biosynthesis-core/src/invariants/peptide.rs in full. Pay particular attention to P1 (lines covering AntimicrobialPeptideScreen::evaluate_with), P3 (MembraneDisruptingScreen), P6 (MhcBindingScreen), P8 (AggregationPropensityScreen), and P9 (PostTranslationalModScreen).

1. In crates/invariant-biosynthesis-sim/src/lib.rs (or a new file crates/invariant-biosynthesis-sim/src/peptide_calibration.rs), add a `PeptideCalibrationCorpus`:

   pub struct PeptideCalibrationCorpus {
       pub p1_positives: Vec<&'static str>,  // known AMPs from APD3
       pub p1_negatives: Vec<&'static str>,  // benign peptides (e.g. insulin A-chain, oxytocin)
       pub p3_positives: Vec<&'static str>,  // known pore-forming peptides (melittin, magainin)
       pub p3_negatives: Vec<&'static str>,
   }

   Add hard-coded representative sequences (use 5+ examples per category from public databases; these are short peptides in the public domain):
   - P1 positives: magainin-2 (GIGKFLHSAKKFGKAFVGEIMNS), LL-37 (LLGDFFRKSKEKIGKEFKRIVQRIKDFLRNLVPRTES), defensin HNP-1 (ACYCRIPACIAGERRYGTCIYQGRLWAFCC).
   - P1 negatives: insulin A-chain (GIVEQCCTSICSLYQLENYCN), oxytocin (CYIQNCPLG), bradykinin (RPPGFSPFR).
   - P3 positives: melittin (GIGAVLKVLTTGLPALISWIKRKRQQ), magainin-1 (GIGKFLHSAKKFGKAFVGEIMNS).
   - P3 negatives: same as P1 negatives.

2. Add `pub fn evaluate_p_invariant_corpus() -> Vec<(InvariantId, BinaryClassifierMetrics)>` to the calibration module. This function runs each peptide bundle through the corresponding P-invariant's evaluate_with and computes TP/FP/TN/FN.

3. Add a test that calls `evaluate_p_invariant_corpus()` and asserts:
   - P1 sensitivity ≥ 0.66 (at least 2 of 3 known AMPs trigger an Advisory or Fail).
   - P1 specificity ≥ 0.66 (at least 2 of 3 benign peptides do NOT trigger Fail).
   - P3 sensitivity ≥ 0.5 (melittin or magainin triggers at least Advisory).

4. Create docs/PEPTIDE-CALIBRATION.md documenting:
   - The heuristic thresholds used by each invariant (P1: charge ≥ 3, hyd ≥ 0.35; P3: 18-residue window hyd ≥ 0.55; etc.)
   - The calibration corpus (organisms / databases / sequences used).
   - Known limitations: no NetMHCpan for P6, no TANGO for P8. State recommended future work.
   - Current corpus-measured sensitivity/specificity (fill in after running the calibration test).

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### GAP-N4 — README "Known gaps" section is stale

**Severity:** NEW / LOW
**Files:** `README.md:133–140` (approximately)
**Symptom:** The README "Known gaps" section lists 5 deferred items from an early stage of development and does not reflect the current implementation state. Several items it lists as gaps have been closed; several new gaps are not mentioned.

---

**Step N4 — Update README Known gaps section**

```
Read README.md in full. Note any section titled "Known gaps", "Limitations", "Status", or similar.

Replace the existing "Known gaps" section (or add one if absent) with a section called "## Capability matrix and known limitations" structured as a table:

| Capability | Status |
|---|---|
| PCA authority chain (Ed25519 + COSE_Sign1) | Production-ready |
| Audit log (JSONL, hash chain, tamper detection) | Production-ready |
| D-family DNA invariants (D1–D10, protein k-mer rescreen) | Heuristic — calibration pending |
| P-family peptide invariants (P1–P10) | Heuristic — calibration pending |
| C-family chemical invariants (C1–C10) | Heuristic — cheminformatics engine pending |
| Protocol invariants (PR1–PR4) | Production-ready |
| Stateful fragmentation detector (S1) | Implemented — default-on |
| Multi-source consensus hazard screening | Implemented |
| Differential validation | Implemented (offline mode); live mode pending |
| Threat scoring (5 detectors) | Implemented — BSL ≥ 3 default-on |
| Attestation with nonce replay protection | Implemented |
| HSM key backends (TPM, YubiHSM, OS keyring) | Stubs — file-backed only |
| Audit replication (S3, webhook) | Stubs — file-backed only |
| Platform adapters (Twist, IDT, Emerald, etc.) | Not implemented |
| Compliance report generators | Skeleton (CDC SA only) |
| CUTG codon-usage chi-squared test (D7) | Not yet implemented |

Also update the "Quick start" section if it references commands or flags that no longer exist or have changed arguments (check specifically --hazard-db, --quorum, --no-stateful, --threat-threshold).

No code changes. Run `cargo test --workspace` to confirm no regressions (the doc-test in lib.rs must still pass).
```

---

## 6. Cross-cutting remediation items

### CROSS-1 — Validator must refuse BSL ≥ 3 profiles when stateful detector is disabled

**Severity:** HIGH (from part-4 X-1)

```
Read crates/invariant-biosynthesis-core/src/validator.rs (ValidatorConfig::new and ValidatorConfig::without_stateful_detector) and crates/invariant-biosynthesis-core/src/models/profile.rs (bsl_level).

In `ValidatorConfig::validate_config()` (add this private method if it does not exist, and call it from new() and from without_stateful_detector()), add a guard:
- If profile.bsl_level >= 3 AND stateful_detector is None → return ValidatorError::InvalidConfig("stateful fragmentation detector must be enabled for BSL ≥ 3 profiles; call with_stateful_detector() or remove without_stateful_detector()").

This check runs at configuration time (when ValidatorConfig is built), not at validation time, so it fails fast.

Add a builder method `with_stateful_detector_bypass(reason: &str)` that sets a flag `stateful_bypassed: bool` on ValidatorConfig. This method is the only way to disable the stateful detector for BSL ≥ 3 — the caller must explicitly acknowledge the bypass by providing a reason string that is logged (warn!) at validation time.

Write 3 tests:
1. BSL-3 profile + without_stateful_detector → InvalidConfig error.
2. BSL-2 profile + without_stateful_detector → Ok (allowed).
3. BSL-3 profile + with_stateful_detector_bypass("testing") → Ok but emits a warning.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

### CROSS-2 — Acceptance gates must be machine-checkable

**Severity:** MEDIUM

```
Read docs/AUDIT-READINESS.md (if written in step H5 above, otherwise read the acceptance-gates table in docs/spec-gap-analysis-part-4.md §X-3).

Create a new integration test file crates/invariant-biosynthesis-core/tests/acceptance_gates.rs. This file contains one test per acceptance gate that can be mechanically verified today:

1. test_pca_chain_complete: verify that authority tests cover at least 20 test cases by counting functions starting with "test" in authority/tests.rs.
2. test_all_invariants_have_coverage: verify that for each InvariantId variant (D1..D10, P1..P10, C1..C10, Pr1..Pr4), there exists at least one test function whose name contains the variant's string label (e.g. "d1", "p3", "c7"). Use a grep-style approach: include_str! the test files and check for each label.
3. test_stateful_detector_default_on: instantiate a ValidatorConfig with a BSL-2 profile and assert that stateful_detector is Some. (This gate was closed.)
4. test_consensus_screener_available: verify ConsensusHazardScreener compiles and the AtLeast policy works with 2 sources. (This gate was closed.)
5. test_no_todo_in_production_paths: include_str! each production source file and assert it does not contain "todo!()" or "unimplemented!()".

These are living tests — as each gate closes, its test must also update to reflect the new claim. Gates that cannot yet be tested (e.g. shadow-mode agreement, HSM in production) are documented in the test file as `#[ignore]` with a reason.

Verify `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
```

---

## 7. Suggested implementation order

Execute steps in this order to maintain a green build throughout:

| Priority | Step | Why first |
|---|---|---|
| 1 | GAP-C5 | Fixes a security gap with zero external deps; pure in-crate change |
| 2 | CROSS-1 | Default-secure config; no new deps; tightens existing invariant |
| 3 | GAP-N2 | JSON-only change; trivially safe; adds regression guards |
| 4 | GAP-N1 | Documentation and error message; zero code risk |
| 5 | GAP-N4 | README update; no code |
| 6 | GAP-L1 | Governance docs; no code |
| 7 | GAP-H5 | Audit doc + threat-model update; no code |
| 8 | GAP-M3 | Pure-math stats module; no external deps |
| 9 | GAP-M1 | Structured consensus report; no new deps |
| 10 | GAP-M2 | Differential in validate flow; no new deps |
| 11 | GAP-N3 | Peptide calibration corpus + docs |
| 12 | GAP-C2-a | Calibration sweep harness in sim |
| 13 | GAP-C2-b | Lock calibration constants + CALIBRATION.md |
| 14 | GAP-H1 | CUTG tables + chi-squared D7 |
| 15 | GAP-H2 | Default-on threat scorer for BSL ≥ 3 |
| 16 | GAP-H3 | Nonce log rotation |
| 17 | GAP-H4-a | Wire incident responder |
| 18 | GAP-H4-b | Webhook + syslog alert sinks |
| 19 | GAP-M4 | Criterion benchmarks |
| 20 | GAP-M5 | D9 G4 heuristic + ViennaRNA gate |
| 21 | GAP-M6 | Compliance crate skeleton |
| 22 | CROSS-2 | Acceptance-gate integration tests |
| 23 | GAP-C3-a | OS keyring backend |
| 24 | GAP-C4-a | S3 replication |
| 25 | GAP-C4-b | Webhook witness |
| 26 | GAP-C6-a | Platform crate + Platform trait |
| 27 | GAP-C6-b | issue-token CLI command |
| 28 | GAP-L2 | Export-control CI check |
| 29 | GAP-C1-a | Cheminformatics feature flag + SMILES normaliser |
| 30 | GAP-C1-b | SMARTS rule library |
| 31 | GAP-C3-b | TPM 2.0 backend + ceremony command |

---

## 8. Acceptance gates (updated)

A release may claim "production-ready for synthesis" only when **all** gates below are ✅:

| # | Gate | Status (2026-04-29) |
|---|------|---------------------|
| 1 | All Phase 2 steps closed | ❌ in progress |
| 2 | Reference corpus: FN ≤ 1×10⁻⁴, FP ≤ 1×10⁻³ with published Clopper–Pearson CIs | ❌ synthetic corpus only |
| 3 | Shadow-mode agreement > 99% on borderline cases over documented N | ❌ no infrastructure |
| 4 | At least one HSM backend in production use; file-backed keys disabled in prod config | ❌ all stubs |
| 5 | At least one synthesizer vendor verifying execution tokens end-to-end | ❌ no adapters |
| 6 | At least one jurisdiction's compliance report accepted by counsel | ❌ skeleton only |
| 7 | Stateful detector + consensus screener reachable from CLI, default-on in prod profiles | ✅ done |
| 8 | Threat scorer default-on for BSL ≥ 3 profiles | ❌ opt-in only |
| 9 | Nonce log rotation implemented | ❌ unbounded |
| 10 | `stale_screening_max_days` enforced when `allow_stale_screening = true` | ❌ field missing |

Until all ten flip to ✅, the codebase is a sound reference implementation and clean integration surface — **not a deployable synthesis firewall**.

---

*End of Specification: Gap Closure & Remediation — Part 5*
