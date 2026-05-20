# Step 6 — Screening Database Integration and Management

**Status:** v0.1 design. Implements `spec.md` Step 6.
**Prereqs:** D/P/C invariant skeleton (Step 3), signed-payload utilities (Step 0), threat model constraints AV-5 and §3.1.

Invariants are only as good as the hazard data they screen against. This document specifies how that data flows into the firewall with cryptographic integrity, fails closed on staleness, and preserves operator privacy.

---

## 1. Database Taxonomy

Seven operational databases, grouped by what they screen.

### Hazard classification lists

| DB | Source | Used by | Update cadence | Size |
|---|---|---|---|---|
| `HHS_SAP` | HHS Select Agent Program | D1 | Quarterly + ad hoc | ~70 taxa |
| `AG_BIO` | Australia Group biological | D1, D4 | Semi-annual | ~100 items |
| `CWC_ANNEX` | OPCW CWC schedules 1/2/3 | C1 | Annual + ad hoc | ~80 compounds |
| `FDA_CSA` | FDA controlled substances | C3 | Quarterly | ~400 compounds |
| `EPA_TSCA` | EPA Toxic Substances Control Act | C4 | Semi-annual | ~80k compounds |
| `IATA_DG` | IATA Dangerous Goods | Shipping validator | Annual | ~3k compounds |
| `NIH_RG` | NIH Risk Group taxa | scope_tags | Annual | ~1.5k taxa |

### Sequence and structure databases

| DB | Source | Used by | Update cadence | Size |
|---|---|---|---|---|
| `SecureDNA_SIG` | SecureDNA cryptographic screening | D1, D2, D3 | Continuous | ~TB (zero-knowledge signatures) |
| `NCBI_VIRULENCE` | Curated virulence-factor sequences | D4 | Monthly | ~50MB HMM profiles |
| `CARD` | Antibiotic resistance genes | D5 | Monthly | ~100MB |
| `iGEM_PARTS` | Synthetic biology standard parts | D6 | Continuous | ~10k parts |
| `PUBCHEM_HAZ` | PubChem hazard-flagged structures | C1–C6 | Monthly | ~GB |
| `REACH_CMR` | EU REACH CMR substances | C5 | Annual | ~1k compounds |

Sizes are order-of-magnitude; exact figures track upstream publishers.

---

## 2. Signed-Update Protocol

### 2.1 Record format

Every database entry is stored in one of two forms.

**Per-entry signed** (small DBs, coarse updates):
```
{
  "db_id": "HHS_SAP",
  "version": 42,
  "previous_version_hash": "sha256-...",
  "entries": [ ... ],
  "valid_until": "2026-10-01T00:00:00Z",
  "publisher_kid": "hhs-sap-signer-2026",
  "signature": "ed25519-..."
}
```

**Merkle-tree signed** (large DBs, incremental updates):
```
{
  "db_id": "SecureDNA_SIG",
  "version": 10234,
  "previous_version_hash": "sha256-...",
  "merkle_root": "sha256-...",
  "leaf_count": 8423107,
  "valid_until": "2026-04-26T00:00:00Z",
  "publisher_kid": "securedna-signer-2026",
  "signature": "ed25519-..."
}
```

For Merkle-signed DBs, individual lookups provide an inclusion proof against the signed root, so the client never needs the full DB locally.

### 2.2 Version chaining

`previous_version_hash` commits each update to its predecessor. Rollback attacks (serving older signed content) are detected by the client comparing received version against its persisted latest-seen version — the client refuses to regress.

### 2.3 Staleness enforcement

Every DB has a `max_staleness` window in `config.toml`:

```toml
[databases.HHS_SAP]
max_staleness_days = 14

[databases.SecureDNA_SIG]
max_staleness_hours = 24

[databases.CWC_ANNEX]
max_staleness_days = 30
```

A DB older than its window is considered `DbStale`. Any invariant that depends on it returns `InvariantStatus::DbStale` → bundle rejection. Fail closed. No silent degradation.

### 2.4 Multi-source consensus (high-risk DBs)

For `HHS_SAP`, `CWC_ANNEX`, and `SecureDNA_SIG`, require ≥2 independent publishers' signatures before trusting an update. Disagreement between publishers escalates to manual review and freezes updates to the affected DB.

Configured in `config.toml`:
```toml
[databases.HHS_SAP]
required_publishers = ["hhs-sap-signer-2026", "who-ihr-signer-2026"]
quorum = 2
```

---

## 3. Screening Algorithms

The `screening/` module implements algorithmic primitives the D/P/C invariants call into. Keeping these centralized (rather than duplicated in each invariant file) is both a code-quality and audit-surface choice — algorithmic bugs live in one place.

### 3.1 Sequence screening

- **BLAST-style k-mer homology** (`screening/kmer.rs`). Rolling hash, configurable k (default 30). Used by D1 for fast pre-filter.
- **Translated-protein homology** (`screening/aa_homology.rs`). Six-frame translation → protein-level match. Used by D1, D3, D4. Implements the threat-model §3.1 "codon-substituted homologs" defense.
- **HMM profile scanning** (`screening/hmm.rs`). Uses HMMER-compatible models for functional-domain detection. Used by D4, D5. Reference models come from `NCBI_VIRULENCE` and `CARD` DBs.
- **Secondary-structure prediction** (`screening/rna_secondary.rs`). Used by D9 for synthesizability feasibility (not safety-critical; advisory).
- **Codon-usage entropy** (`screening/codon_entropy.rs`). Used by D7. Implements the threat-model §AV-8 covert-channel defense: flags sequences whose codon distribution is anomalous versus the host's codon-usage table.

### 3.2 Structure screening (small molecules)

- **Substructure match** (`screening/substructure.rs`). SMARTS-based matching. Used by C1 (CWC), C2 (explosives), C3 (controlled substances).
- **Fingerprint similarity** (`screening/fingerprint.rs`). Morgan fingerprints + Tanimoto similarity. Used by C4, C5, C6 for "similar to known hazard" screening.
- **QSAR-style property prediction** (`screening/qsar.rs`). Simple rule-based property estimators for `C5` (mutagenicity: Ashby-Tennant alerts) and `C7` (bioaccumulation: logP-based). Machine-learning predictors are explicitly out of scope — they're non-deterministic and violate the firewall's "deterministic screening" property. Use ML only upstream in the cognitive layer.

### 3.3 Protein-function classification

- **AMP prediction** (`screening/amp_classifier.rs`). Used by P1. Rule-based classifier using net charge + hydrophobic moment + length, calibrated against a held-out AMP dataset. Deterministic; published thresholds.
- **Membrane-disruption screening** (`screening/membrane.rs`). P3. Hydrophobic-face prediction + secondary-structure prediction.
- **Immunogenic epitope prediction** (`screening/mhc.rs`). P6. MHC-binding matrix scoring with published PSSMs.

---

## 4. Performance Targets

| Operation | Target p50 | Target p99 |
|---|---|---|
| D1 select-agent k-mer prefilter (3kbp sequence) | 2 ms | 10 ms |
| D1 translated-protein HMM (3kbp → proteins) | 50 ms | 250 ms |
| C1 CWC substructure match (100 compounds in annex) | 5 ms | 20 ms |
| C4 PubChem fingerprint lookup | 20 ms | 100 ms |
| Full D/P/C invariant sweep (typical bundle) | 100 ms | 500 ms |
| DB freshness check (all 13 DBs) | 1 ms | 5 ms |
| Signature verification (bundle + chain L0→L4) | 300 µs | 1 ms |

End-to-end validation (signature + chain + scope + full invariant sweep + audit write) must fit in **1 second p99** to be operationally acceptable for interactive use. Batch mode permits higher latency.

---

## 5. Caching

- **In-memory LRU** per invariant, keyed by `(db_version, payload_hash)`. Bounded by memory config; default 256MB total across all invariants.
- **Cache invalidation on DB update.** Any DB update bumps its version, which is part of the cache key — no manual invalidation needed.
- **Persistent SQLite cache** on disk for cold-start speed. Signed with the firewall's local key so cache-poisoning attacks require compromise equivalent to compromising the firewall itself.

---

## 6. Privacy-Preserving Screening

### 6.1 SecureDNA integration

For D1/D2/D3 on sensitive research (e.g., novel therapeutics, classified work), use SecureDNA's zero-knowledge screening protocol:
- Client computes an oblivious commitment over the sequence.
- Server returns a proof of non-match or a match-without-revealing-which-hazard.
- No plaintext sequence leaves the client.

Defends threat-model AV-7 (model extraction / IP inference).

### 6.2 Differential privacy for aggregate stats

Aggregate screening metrics (false-positive rates, per-org submission counts) published by institutions for coordination are released only with calibrated differential-privacy noise. `screening/dp_aggregates.rs` provides the DP mechanism.

### 6.3 Zero-knowledge compliance proofs

For regulatory reporting without disclosing research content, `screening/zk_compliance.rs` emits ZK proofs of the form "all bundles in the reporting period passed all mandatory invariants" without revealing the bundles themselves. Pragma choice: Halo2 or Groth16 depending on verifier ecosystem — pin in Step 6 implementation.

### 6.4 Oblivious queries

For hazard DBs that reveal IP by what you queried (e.g., "did you just ask about Variola?"), oblivious-RAM queries hide access patterns. Out of scope for v1 — tracked as a roadmap item.

---

## 7. Operational Procedures

### 7.1 Air-gapped update

1. External operator fetches signed DB update + previous-version-hash chain from publisher.
2. Verifies signature using publisher public key on record.
3. Loads update onto removable media.
4. Transfers to air-gapped firewall via one-way data diode or sneakernet.
5. Air-gapped firewall verifies signature again, enforces version chain, persists.

Full ceremony script in `docs/ceremonies/db-airgap-update.md` (Step 7 deliverable).

### 7.2 Key rotation

Publisher key rotation follows the same schedule as other L1-equivalent keys (§Step 4). The firewall trusts a publisher's NEW key only if the rotation is countersigned by the previous key (key-chain continuity).

### 7.3 Rollback / recovery

If a bad update is published (false positive rate spike, or content error):
- Publisher emits a signed `Retraction` for the affected version.
- Firewall marks that version as retracted and falls back to the last non-retracted version.
- If staleness window is exceeded at that earlier version, affected invariants fail closed until a corrected update arrives.

### 7.4 Audit

- Every DB update, including its signature and version-chain verification, is logged.
- Per-invariant per-bundle screening decisions are logged with `(db_id, db_version)` so a past decision can be replayed against the exact DB state that produced it.
- `proof_package.rs` can emit a "replay bundle" containing the bundle + exact DB snapshots + exact invariant code version for external verification.

---

## 8. Database Schemas

Minimal schemas shown; full schemas land in the Step 6 implementation.

### `HHS_SAP`
```
entry := { id, taxon, ncbi_taxid, common_names, added_version }
```

### `CWC_ANNEX`
```
entry := { schedule (1|2|3), cas, name, smiles, parent_schedule? }
```

### `NCBI_VIRULENCE`
```
entry := { hmm_profile_id, description, source_organism, virulence_mechanism, hmmer_file_hash }
```

### `SecureDNA_SIG` (opaque per zero-knowledge protocol)
```
entry := { commitment, metadata_zk_proof }
```

All entries serialize via serde with `#[serde(deny_unknown_fields)]` per the codebase-wide invariant from the threat model.

---

## 9. Implementation Plan

1. **Step 6a** — implement `HazardDatabase` trait + `DatabaseManager` (multi-DB coordinator with freshness + multi-source consensus + version chain).
2. **Step 6b** — implement the screening algorithmic primitives (§3). Each file is ~200–600 LoC with a benchmark and a property-test harness.
3. **Step 6c** — wire primitives into the invariants (replacing Step 3 `Unimplemented` stubs file-by-file).
4. **Step 6d** — publisher simulator for testing: spins up mock HHS_SAP / CWC / SecureDNA endpoints with known-good and known-bad update sequences.
5. **Step 6e** — ceremony docs under `docs/ceremonies/`.
6. **Step 6f** — SecureDNA protocol integration (contingent on SecureDNA spec + partnership; may land post-v1).

Third-party crate dependencies introduced in Step 6 (each justified individually):
- A HMM scanner (hmmer-rs or a pure-Rust port). Evaluate vs. vendoring.
- A SMARTS matcher (rdkit-sys bindings are the obvious choice; complicates the "minimal deps" goal — evaluate writing a minimal pure-Rust substructure matcher for the CWC annex specifically, since that list is small enough).
- A Halo2 or Groth16 crate, if §6.3 ships in v1.

Each dependency addition goes through a `cargo-deny` + review gate before merge.
