# Step 5 — Synthesis Platform Integration Architecture

**Status:** v0.1 design. Implements `spec.md` Step 5.
**Prereqs:** signed `ExecutionToken` type (Step 0), PCA chain (Step 4), attestation module (Step 0 rename of `sensor.rs`).

The firewall produces a signed `ExecutionToken`. This document describes how that token reaches — and is enforced by — real synthesis hardware and cloud-lab APIs. Scope coverage: DNA synthesis, peptide synthesis, chemical synthesis, cloud labs.

---

## 1. Integration Contract (shared across all platforms)

Every platform integration, regardless of vendor, must satisfy:

### 1.1 Key contract
- Platform holds a device Ed25519 keypair (L5 in the PCA tree). Private key is hardware-bound (TPM 2.0 minimum; FIPS 140-2 Level 3 preferred — see `docs/hsm-key-mgmt.md`).
- Public key is registered in the firewall's trusted-synthesizer list during provisioning.
- Keys rotate on a configurable cadence (default: 90 days).

### 1.2 Verification contract
The platform MUST verify, before initiating any physical action, that:
1. `ExecutionToken.signature` is a valid Ed25519 signature by a recognized firewall `kid`.
2. `ExecutionToken.synthesizer_kid` matches this platform's `kid` (platform-binding; anti-spoofing — threat model AV-4).
3. `ExecutionToken.bundle_hash` matches the SHA-256 of the bundle the platform received.
4. `ExecutionToken.valid_until > now`.
5. `ExecutionToken.nonce` has not been used in this platform's nonce cache (durable across reboots).

Failure at any step = no physical action + audit-log entry with reason.

### 1.3 Attestation contract
After execution (or attempted execution), the platform MUST emit a signed attestation back to the firewall containing:
- Original `ExecutionToken.nonce`.
- Actual action taken (sequence synthesized, reagents dispensed, protocol steps executed).
- Hardware telemetry snapshot (temperature, pressure, reagent lot IDs, timestamp).
- Completion status (`Ok`, `Aborted { reason }`, `Partial { completed_steps }`).
- Device signature.

Attestations are hash-chained into the firewall's audit log. Divergence between `ExecutionToken.requested_action` and `Attestation.actual_action` is flagged by the `monitors.rs` runtime.

### 1.4 Transport-layer
The wire format is application-neutral. Platform integration adapters translate:
- Firewall → platform: firewall emits canonical JSON `ExecutionToken`; adapter translates to platform-native format (vendor REST, GraphQL, gRPC, serial protocol).
- Platform → firewall: adapter translates vendor status/telemetry to canonical `Attestation` JSON.

All transport is authenticated (mTLS with the platform device cert as the client cert) *and* the payload is independently signed. Transport security is defense-in-depth, not the primary trust boundary.

---

## 2. Per-Platform Integration

### 2.1 DNA synthesis

#### Twist Bioscience
- Integration type: order-submission API (Twist does not run on-site).
- Bundle → Twist order translation: `SynthesisPayload::Dna { sequence }` → Twist REST API order object with PO reference = firewall-audit-log serial.
- Verification: Twist already runs IGSC-compliant screening. Firewall's D-series invariants run *in addition*, upstream.
- Attestation: Twist order-status webhook → firewall `Attestation` endpoint. Sequence delivered by physical shipment; lot arrival is attested via internal inventory update.
- Implementation path: `crates/invariant-biosynthesis-platforms/twist/` (new crate, to be added in Step 5 implementation).

#### Integrated DNA Technologies (IDT)
- Integration type: order-submission API.
- Analogous to Twist. IDT also runs gBlock-level screening; firewall adds PCA-enforced authority trail.

#### Ansa Biotechnologies
- Integration type: enzymatic synthesis, on-site platform, direct command/response.
- Bundle → command: `SynthesisPayload::Dna` → Ansa platform protocol.
- Verification: on-device signature check before first enzymatic cycle. Reference firmware patch required (§5.1).
- Attestation: per-base-addition telemetry streamed; batched into an Attestation at cycle completion.

#### Kilobaser (benchtop)
- Integration type: USB-connected benchtop synthesizer.
- Integration adapter runs on the benchtop host PC; enforces signature check before enabling the synthesizer's run-enable GPIO.
- Air-gap-friendly deployment model: firewall runs on the same host PC; no network required.

#### BioXp 3250 workstation
- Integration type: cartridge-driven bench platform.
- Integration at the workstation controller layer — signature check before cartridge load.
- Attestation: post-run fluorescence QC + sequencing confirmation (if configured).

### 2.2 Peptide synthesis

#### CEM Liberty
- Integration type: on-site automated synthesizer with vendor SCADA control.
- Vendor SCADA already supports external approval hooks; firewall plugs in there.
- Bundle → protocol: `SynthesisPayload::Peptide` + coupling parameters → CEM run file.
- Attestation: per-coupling UV-trace + final HPLC report.

#### Biotage (Syro, Initiator+)
- Analogous to CEM. Supports external scripting via Biotage API.

#### CSBio automated synthesis
- Integration type: similar SCADA model.

#### Gyros Protein Technologies
- Integration type: microfluidic peptide synthesis. API-driven.

### 2.3 Chemical synthesis

#### Chemspeed (Autoplant, Swing)
- Integration type: automated synthesis platform with Python SDK.
- Firewall emits `ExecutionToken`; adapter translates to Chemspeed task sequence.
- Critical constraint: exothermic-reaction safety interlocks remain on the Chemspeed controller, not the firewall. Firewall blocks unauthorized *requests*; vendor controller blocks unsafe *execution*. Defense in depth (threat model §defense-in-depth).

#### Unchained Labs
- Analogous. Protein/nanoparticle synthesis platforms with documented APIs.

#### Hamilton (STAR, VANTAGE)
- Integration type: automated liquid handler. Firewall validates dispense schedules.
- Hazard: reagent-misassignment attacks — an attacker changes the reagent → deck-position mapping. Mitigation: deck-layout hashing included in the bundle; reagent lot barcodes attested by the instrument and matched against the bundle.

#### Tecan (Fluent, Freedom EVO)
- Analogous to Hamilton. Deck-layout attestation is the key requirement.

### 2.4 Cloud labs

#### Emerald Cloud Lab
- Integration type: remote API; physical execution in Emerald facility.
- Bundle → Symbolic Lab Language (SLL) script. Firewall verifies the SLL translation matches the bundle intent before submission.
- Attestation: post-run experimental record signed by Emerald's service key. Emerald is treated as a delegated execution authority under its own L5 key.

#### Strateos / Transcriptic
- Integration type: remote API; Autoprotocol JSON.
- Analogous to Emerald. Additional requirement: Strateos provides per-instrument device-level attestations which the firewall correlates with the service-level attestation.

#### Academic core facilities
- Heterogeneous. Default integration: firewall signs an order slip (human-readable + signed metadata); core facility staff scan the metadata QR on accept and the firewall logs an acknowledgement. Not fully-automated but crypto-auditable.

---

## 3. Command-Bundle Format Translation

The firewall's `SynthesisBundle` type is domain-canonical. Per-platform adapters are pure functions:

```
fn translate(bundle: &SynthesisBundle, token: &ExecutionToken) -> VendorRequest
fn translate_back(vendor_response: &VendorResponse) -> Attestation
```

Adapter tests verify round-trip fidelity on a corpus of golden bundles per platform. Any translation that loses information (e.g., a platform that can't represent a particular oligo modification) must return `TranslationError::UnsupportedPayload` rather than silently synthesize a different thing.

---

## 4. Batch and Queue Management

Synthesis is not instantaneous. A single bundle may correspond to an hour-long peptide synthesis or a week-long chemical campaign. The firewall does not manage queues itself (avoids duplicating vendor logic) but imposes:

- **Queue-admission check.** Adding a bundle to a vendor queue triggers the signature verification; no queue-admission without a valid token.
- **Nonce reservation.** The nonce is reserved at queue admission, released on completion or abort. Prevents nonce-replay across queue abort/resubmit cycles.
- **Stale-queue detection.** Bundles sitting in queue past `ExecutionToken.valid_until` are auto-aborted and require re-signing.

---

## 5. Hardware Integration Security

### 5.1 Vendor firmware requirements

Synthesis vendors integrating with invariant-biosynthesis must meet a reference set of firmware requirements (documented in `docs/platform-certification.md`, future deliverable):

1. Signature verification in the execution path, not in a sidecar.
2. Hardware-bound private key (TPM or equivalent).
3. Tamper-evident logging of all commands executed.
4. Secure boot with attested firmware version.
5. Kill-switch response: signed `SafeStopAction::HaltSynthesis` halts in ≤1 second.

Vendors passing all five get a certification badge; integrations with uncertified vendors are permitted but emit a runtime warning and raise the threat score.

### 5.2 Air-gapped operation

For BSL-3+, Schedule 1 CWC, or select-agent work, the firewall and synthesizer run on an isolated network:
- No firewall egress to the internet during signing.
- Audit log exported via one-way diode to an external witness.
- Manual key-rotation ceremonies.

`docs/air-gap-deployment.md` (Step 7 deliverable) specifies the operational procedure.

### 5.3 Emergency shutdown

A signed `SafeStopAction::HaltSynthesis` token, countersigned by L1 or L0, causes:
- Immediate abort of in-progress operations (vendor must support).
- Refusal of all new tokens until an L1 signs a `ResumeAuthorization`.
- Audit-log entry with the triggering condition.

---

## 6. Operational Workflows

### 6.1 Validation pipeline (per bundle)

```
1. AI agent signs a SynthesisBundle with L4 key.
2. Firewall receives bundle.
3. PCA chain verification (L0→L4).
4. Scope-tags policy check.
5. Invariant screening (D/P/C series).
6. Multi-sig check if triggered (§Step 4 §5).
7. Threat-score accumulation.
8. Firewall signs ExecutionToken referencing bundle hash.
9. Platform receives token + bundle.
10. Platform verifies token (§1.2).
11. Platform executes.
12. Platform emits Attestation.
13. Firewall audits Attestation vs bundle.
```

### 6.2 Multi-platform coordination

When a single research protocol spans platforms (e.g., DNA synthesized at Twist, then expressed at cloud lab, then peptide work at in-house CEM):
- Each platform's ExecutionToken is separately signed.
- The bundles share a `protocol_id` for correlation in the audit log.
- Cross-platform invariants (e.g., total cumulative volume) are evaluated at firewall validation time, not at platform time.

### 6.3 Inventory and reagent tracking

Out of scope for the firewall core. Firewall consumes reagent-lot telemetry (as attested inputs, §AV-2 mitigation) but does not maintain inventory state. Institutional LIMS is the source of truth; firewall hashes LIMS snapshots into the audit log for tamper-evidence.

### 6.4 Incident response

On any invariant failure, attestation mismatch, or scope violation:
1. Incident is logged (`incident.rs`).
2. `SafeStopAction::HaltSynthesis` emitted to affected platforms.
3. IBC/IRB notified via configured webhook.
4. Threat score incremented on the originating PCA subtree.
5. Incident forensic bundle auto-generated via `proof_package.rs`.

---

## 7. Implementation Path

Not all platforms need to ship in v1. Recommended prioritization:

**Tier 1 (ship first):**
- Twist Bioscience — largest DNA vendor, well-documented API.
- Emerald Cloud Lab — flagship cloud-lab integration, drives design for the general remote-execution case.
- Kilobaser — benchtop proves the air-gapped deployment model.

**Tier 2:**
- IDT, Chemspeed, CEM, Hamilton.

**Tier 3:**
- Remaining vendors as community contributions or customer-driven.

Each platform integration is an independent Rust crate under `crates/invariant-biosynthesis-platforms/`. A platform adapter is about 300–800 LoC plus tests and is well-suited as an open-source contribution surface.

---

## 8. Reference Implementation Checklist

A new platform integration must ship with:
- [ ] Device-key provisioning doc.
- [ ] `translate` and `translate_back` functions with 20+ golden test cases.
- [ ] Signature-verification integration tested on real hardware (or vendor-provided simulator).
- [ ] Attestation round-trip tested.
- [ ] Emergency-halt path tested (actual hardware or simulator).
- [ ] Documented latency and throughput characteristics.
- [ ] Vendor-signed MoU that firmware requirements (§5.1) are met or tracked.
- [ ] Certification badge status recorded in the integration's README.
