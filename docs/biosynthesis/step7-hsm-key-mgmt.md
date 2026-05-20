# Step 7 — HSM Integration and Cryptographic Key Management

**Status:** v0.1 design. Implements `spec.md` Step 7.
**Prereqs:** PCA chain (Step 4); Ed25519 primitives in `authority/crypto.rs` (Step 0).

This document specifies how keys are generated, stored, used, rotated, and retired across the six PCA levels (L0–L5). The goal is to push as much risk as possible into hardware roots while keeping the firewall's code path Ed25519-only.

---

## 1. Hardware Support Matrix

Each PCA level has a baseline HSM requirement and a preferred upgrade path. Lower levels can run software-only; higher levels cannot.

| Level | Baseline | Preferred | Rationale |
|---|---|---|---|
| L0 Institution root | FIPS 140-2 Level 3 HSM | FIPS 140-2 Level 4 + MofN key custodians | Catastrophic if compromised |
| L1 IBC/IRB | TPM 2.0 or YubiHSM 2 | Same HSM family as L0 (separate slot) | Organizational-level key |
| L2 PI | TPM 2.0 or YubiKey 5 | YubiHSM 2 | Per-protocol, longish-lived |
| L3 Lab member | YubiKey 5 + OS keychain | YubiKey 5 dedicated-slot | Human-held, routinely present |
| L4 AI agent | OS keychain | Confidential Compute enclave (SGX, SEV-SNP) | Ephemeral, high-volume |
| L5 Synthesis platform | TPM 2.0 (vendor) | FIPS 140-2 L3 vendor HSM | Device-attested |

Three niche platform families worth enumerating because specific user deployments demand them:

- **ARM TrustZone** — embedded synthesizer controllers where TPM footprint is infeasible. Fulfills "hardware-bound private key" but at lower assurance than TPM 2.0.
- **Intel SGX / AMD SEV-SNP** — cloud deployments where the firewall itself runs in a confidential VM. The firewall's signing key is sealed to the enclave.
- **Custom FPGA security processor** — air-gapped nuclear/select-agent contexts where commercial HSMs are not acceptable. Treated as "FIPS 140-2 L3 equivalent" when third-party evaluated.

The crypto crate in `authority/crypto.rs` abstracts over the key-source; a new `KeyHandle` trait added in Step 7 implementation lets signing code be agnostic to whether the key lives in SoftHSM, YubiHSM, TPM, SGX, or an HSM via PKCS#11.

---

## 2. Key Lifecycle

### 2.1 Generation

**L0 ceremony** (institution root, one-time):
1. Minimum 3 witnesses from IBC + IT-security + institutional compliance.
2. HSM entropy source tested to NIST SP 800-90B standards immediately before generation.
3. Key generated in HSM; private key never leaves HSM.
4. Public key fingerprinted; fingerprint recorded in paper form signed by all witnesses.
5. A genesis entry is written to the audit log bootstrap containing the public key + ceremony minutes.
6. Backup: either M-of-N Shamir share distribution across geographic sites, or threshold-signature setup (see §4.3).

**L1–L2 issuance**:
1. Human approver sits at an HSM-connected workstation.
2. Two-person integrity (signer + witness) for every issuance.
3. Issuance is batched quarterly for routine work; urgent issuance available with elevated two-person review.
4. Every issuance logged to audit with both humans' signatures.

**L3 provisioning**:
1. PI delegates to lab member using L2 key at PI workstation.
2. Lab member's YubiKey generates a keypair on-device; public key sent to PI.
3. PI signs L3 certificate.
4. L3 installed on lab member's authenticated workstation + YubiKey.

**L4 agent key**:
1. Agent runtime generates a keypair in memory at session start.
2. Signed request sent to lab member's L3 for delegation.
3. Lab member approves via local HSM touch.
4. L4 certificate returned; agent holds private key in RAM only for session duration.
5. On session end, the private key is zeroized.

**L5 platform key**:
1. Vendor-managed. See `docs/platform-integration.md` §1.1 and §5.1.
2. Firewall receives only the public key + attested vendor statement of hardware binding.

### 2.2 Rotation schedule

| Level | Rotation cadence | Emergency rotation |
|---|---|---|
| L0 | Every 5 years | <24h on suspected compromise |
| L1 | Every 2 years | <12h |
| L2 | Every year (or at protocol renewal) | <4h |
| L3 | Every 90 days | <1h |
| L4 | Every session (≤4h) | Immediate (current session terminated) |
| L5 | Every 90 days | Vendor SLA |

Rotation is key-chain-continuous: new key signed by old key's HSM before old key is retired. No trust gap.

### 2.3 Revocation

Reissuance-based (not CRL). Per Step 4 §7. Relies on the audit log trust-root advertisement with a freshness bound.

### 2.4 Retirement and destruction

- Private key destroyed inside HSM (hardware `erase()` call).
- Public key retained in audit log (for historical verification of past signatures).
- Certificates signed by the retired key are not retroactively invalidated if they were valid at signing time — the chain is time-bounded, and past signatures remain verifiable against the retained public key.

---

## 3. Multi-Party Key Generation

For L0, the baseline is single-custodian HSM. Two stronger options:

### 3.1 Shamir secret sharing (offline)

- Generate L0 key in HSM.
- Immediately split private key into N shares with threshold M.
- Destroy the assembled key.
- Distribute shares across M geographically-separated custodians.
- Reassembly requires M custodians physically or via signed channel.
- Caveat: *assembly* moment creates a brief single point of compromise.

### 3.2 Threshold Ed25519 (online)

- FROST or similar threshold Ed25519 protocol.
- No single point where the full key exists.
- Signing requires M-of-N custodians to each produce a partial signature; combined threshold signature is indistinguishable from a normal Ed25519 signature.
- Verifier-side code unchanged (this is the elegant part — the firewall verifies threshold signatures with the same `ed25519-dalek::Verifier` path used for ordinary signatures).
- Operational overhead is real: every L0 issuance requires M humans online.

Recommendation: institution-size-dependent. Smaller institutions use §3.1; larger institutions (pharma, gov, multi-campus universities) use §3.2 with M=3, N=5.

---

## 4. Operational Key Deployment

### 4.1 Device provisioning

Synthesis platforms arrive with vendor-attested device certificates. Provisioning:
1. Vendor's platform key + firmware version attested via vendor CA.
2. Institution's L0 signs a cross-certificate binding the platform to the institution's trust domain.
3. Platform registered in firewall's trusted-synthesizer list with scope constraints.

### 4.2 Firewall service keys

The firewall process itself holds a signing key used to countersign verdicts and emit execution tokens. This key:
- Lives in the host's TPM or HSM — never on bare disk.
- Is provisioned at firewall deployment via an L0- or L1-signed certificate.
- Rotates every 90 days.
- Has its own sequence-number counter hash-chained into the audit log (so a replay of the firewall key itself is detectable).

### 4.3 PCA chain signing authority delegation

Already covered by the chain mechanism. Emphasized here: the delegation signing *operation* happens inside the HSM; the firewall code never sees the private key material. `authority/crypto.rs::sign()` receives a `KeyHandle` that encapsulates the HSM session.

### 4.4 Cross-platform synchronization

If a research group runs multiple firewall instances (e.g., for resilience, or one per lab), their audit logs replicate to a shared Merkle-rooted witness. Key material is NOT synchronized — each firewall holds its own deployment key.

### 4.5 Tamper detection and response

- HSM tamper events (physical opening, entropy-source failure) raise an alarm to the institutional security team.
- Affected keys are revoked within the emergency-rotation SLA (§2.2).
- Audit log records tamper event; `incident.rs` auto-generates a forensic bundle.

---

## 5. Cryptographic Hardening

### 5.1 Performance benchmarks

Targets on reference hardware (Apple M-series / commodity x86):
- Ed25519 sign: < 50 µs.
- Ed25519 verify: < 150 µs.
- SHA-256 (4KB bundle): < 20 µs.
- Full chain verify (L0→L4): < 1 ms.
- PCA subset check (typical op set): < 100 µs.

All hit by `ed25519-dalek` + `sha2` on the prereq hardware; benchmarks in `benches/` enforce.

### 5.2 Hardware acceleration

When available (AVX2 for SHA-256, Ed25519 NEON, AES-NI for session-level encryption), pick it up from the underlying crates. The firewall's code is agnostic.

### 5.3 Side-channel resistance

- `ed25519-dalek` uses constant-time scalar arithmetic.
- `sha2` is constant-time.
- `authority/operations.rs` op-subset check uses short-circuit comparisons in a way that can leak op set contents by timing. For Step 7 implementation: audit this path and either confirm it's non-sensitive or make it constant-time.

### 5.4 Secure boot + attestation

Firewall hosts in high-assurance deployments run measured/secure boot. The firewall process attests its own code hash into the audit log at startup. Remote parties can verify the firewall is running the expected version before trusting verdicts.

### 5.5 RNG quality

`ed25519-dalek` with the `rand_core` feature uses the OS RNG, which on all supported platforms is a CSPRNG seeded by the kernel entropy pool. HSM-based signing uses the HSM's RNG. No use of `rand::thread_rng` for key material.

### 5.6 Algorithm agility

Ed25519-only in v1. Post-quantum migration is a long-term concern:
- Monitor NIST PQC standardization.
- Likely migration path: hybrid signatures (Ed25519 + ML-DSA) during a transition window.
- The `KeyHandle` abstraction and the canonical-bytes format are forward-compatible — the signature-bytes slot becomes polymorphic.
- Concrete migration is a v2 topic.

---

## 6. Deployment Models

### 6.1 Single-tenant laboratory

- One firewall instance, one institution L0.
- All keys on-premises.
- Air-gapped if BSL-3+ or Schedule 1 CWC.
- Typical footprint: 1 commodity server + 1 YubiHSM 2 + 1 YubiKey per lab member.

### 6.2 Multi-tenant cloud lab

- Cloud lab holds its own L0 (platform-provider root).
- Each tenant institution holds its own L0.
- Cross-certificates establish tenant → platform trust per §Step 4 §6.
- Tenant keys never visible to the cloud operator.
- Cloud operator keys never visible to tenants.
- Per-tenant audit logs, with a shared cross-tenant incident log for cloud-wide events (anonymized per §Step 6 §6.2).

### 6.3 Federated (multi-institutional consortium)

- Each institution retains its own L0.
- Cross-certification established pairwise or via a consortium CA that countersigns member L0s.
- Shared audit-log Merkle-root witness for external notarization.
- Policy harmonization at the scope-tag level (e.g., all members agree on `bsl_max` semantics).

### 6.4 Offline / air-gapped

- No network egress during signing.
- Audit log exported via one-way diode to an external witness.
- DB updates via signed removable media (per Step 6 §7.1).
- Manual L0/L1/L2 ceremonies only.

### 6.5 Mobile / edge

Rare but possible: field-deployed synthesis (e.g., disaster-response mobile lab).
- Full L4 key derivation on-site.
- Pre-provisioned L3 certificates with short TTLs.
- Periodic sync-up with institution when connectivity returns.

### 6.6 Disaster recovery

- Audit log is the long-term source of truth. Destroyed firewalls can be rebuilt from the log.
- L0 recovery via Shamir shares (§3.1) or threshold reconstitution (§3.2).
- HSM-level disasters (fire, flood) mitigated by geographic distribution of L0 backup shares.

---

## 7. Compliance and Certification

### 7.1 FIPS 140

- Use FIPS-validated crypto primitives where regulatorily required.
- `ed25519-dalek` is not FIPS-validated; compliance deployments link against an HSM's FIPS-validated Ed25519 via PKCS#11.
- The firewall's API is agnostic; swap the crypto provider per deployment.

### 7.2 Common Criteria

Target EAL4+ for the firewall core if a regulated customer requires it. Formal evaluation is multi-year and expensive; pursued only on demand.

### 7.3 Export control

Cryptographic exports follow US EAR Commerce Control List. Ed25519 + SHA-256 are mass-market and effectively unrestricted; HSM integration code carries the same classification. Institutional counsel reviews before any foreign deployment.

### 7.4 PKI integration

Institutions with existing X.509 PKIs can bridge:
- X.509 → PCA translation layer: X.509 identity vouches for the holder's L1 or L2 public key via an institutional CA cross-certificate.
- Avoids duplicate identity management.
- Does NOT replace the PCA chain at the firewall layer — X.509 provides identity; PCA provides scoped authority.

### 7.5 Audit and reporting

- Every key-material operation logged.
- HSM audit logs replicated into the firewall audit log (if vendor exports are available).
- Third-party assessors can reconstruct full key provenance from logs.

### 7.6 Penetration testing

Annual third-party pentest of:
- Key-ceremony procedures.
- HSM integration surface.
- PCA subset algebra (for logic flaws).
- Audit log tamper resistance.

---

## 8. Implementation Plan

1. **Step 7a** — implement the `KeyHandle` trait + SoftHSM backend + YubiHSM 2 backend.
2. **Step 7b** — TPM 2.0 backend (tpm2-tools bindings).
3. **Step 7c** — PKCS#11 generic backend (covers commercial FIPS 140 HSMs).
4. **Step 7d** — threshold-Ed25519 backend (FROST) for L0 §3.2.
5. **Step 7e** — ceremony scripts under `docs/ceremonies/`.
6. **Step 7f** — SGX/SEV-SNP enclave backend (cloud-deployment).
7. **Step 7g** — FPGA backend (air-gap-only customers; long tail).

Backends 7a–7c cover >90% of deployments. 7d–7g ship as demand justifies.

No v1 commitment to FIPS validation, CC evaluation, or post-quantum migration. All tracked on the roadmap.
