Invariant Biosynthesis Specification
Overview
Invariant Biosynthesis provides cryptographically-secured safety infrastructure for AI-controlled biological and chemical synthesis systems. This specification extends the cognitive-kinetic firewall architecture from Invariant Robotics to cover DNA synthesis, peptide synthesis, small molecule chemistry, and other biosynthesis execution substrates.
Repository Structure Plan:
* Primary name: invariant-biosynthesis
* Synonyms: invariant-bio, invariant-synth
* Parent architecture: Invariant (cognitive-kinetic firewall pattern)
* Sibling project: invariant-robotics (motor actuation substrate)
Architecture Foundation
The biosynthesis firewall implements the same three-layer cognitive-kinetic divide as Invariant Robotics, adapted for biological execution substrates:
Cognitive Layer (Probabilistic): AI models that generate biological sequences, chemical structures, or synthesis protocols. Examples include RFdiffusion for protein design, ProteinMPNN for sequence optimization, AlphaFold-guided structure prediction, LLM-based lab automation planners, and Claude agents running experimental workflows.
Trust Boundary (Cryptographic): Ed25519-signed synthesis request bundles carrying Provenance Causal Authority chains that establish unbroken delegation from human operator to AI executor.
Firewall Layer (Deterministic): Mathematical screening of synthesis requests against hazard databases, structural analysis for dangerous motifs, authority scope verification, and physics-based feasibility checking.
Execution Layer (Hardware-Rooted): DNA synthesizers, peptide synthesizers, chemical synthesis platforms, and cloud lab APIs that verify cryptographic signatures before executing synthesis commands.
Step 0: Copy/Paste Reuse Manifest from invariant-robotics

**Goal for Claude Code:** Bootstrap `invariant-biosynthesis` by copying the substrate-agnostic pieces of `invariant-robotics` verbatim (or with trivial renames), and skipping the robotics-specific pieces entirely. About 25–30% of the source tree carries over. Do **not** auto-delete `invariant-robotics/` at the end of this step — the user will confirm deletion separately after reviewing the copy.

**Assumed layout during Step 0:**
- Source (read-only): `./invariant-robotics/`
- Destination (create fresh): `./` (a new Cargo workspace at the repo root, sibling to the source tree while it still exists)

**Ground rules:**
1. Preserve `#![forbid(unsafe_code)]` everywhere.
2. Keep the dependency surface minimal — only `ed25519-dalek`, `sha2`, `serde`, `serde_json`, `serde_yaml`, `base64`, `chrono`, `thiserror`, `clap`, `rand`, `regex`. No tokio/axum in the core crate. No new deps beyond what robotics already uses.
3. Rename the root crate prefix from `invariant_robotics` / `invariant-robotics-core` to `invariant_biosynthesis` / `invariant-biosynthesis-core`. The binary name becomes `invariant-bio`.
4. For any file listed as "copy verbatim," do a literal copy and then do a single find/replace of the crate name. Do not refactor.
5. For any file listed as "copy as template," keep the module skeleton, public API shape, and tests-folder layout; replace the robotics-specific domain logic with stubs (`todo!()` with a tracking comment) to be filled in Step 3.
6. **Skip** anything listed under "Do NOT copy."

---

### Category A — Copy VERBATIM (only rename crate identifier)

These are substrate-agnostic. They are the cryptographic and structural core of the firewall and apply unchanged to biosynthesis.

| Source path (in `invariant-robotics/`) | Destination path (in biosynthesis repo) | Notes |
|---|---|---|
| `crates/invariant-core/src/authority/crypto.rs` | `crates/invariant-biosynthesis-core/src/authority/crypto.rs` | Ed25519 sign/verify, canonical bytes |
| `crates/invariant-core/src/authority/chain.rs` | `crates/invariant-biosynthesis-core/src/authority/chain.rs` | PCA chain validation, monotonic narrowing |
| `crates/invariant-core/src/authority/operations.rs` | `crates/invariant-biosynthesis-core/src/authority/operations.rs` | Op-scope algebra (intersection/subset). Operation *vocabulary* is domain-specific and will be extended in Step 4, but the algebra is generic. |
| `crates/invariant-core/src/authority/mod.rs` | same | Re-exports |
| `crates/invariant-core/src/authority/tests.rs` | same | Keep all tests — they validate the crypto/algebra, not robotics |
| `crates/invariant-core/src/models/authority.rs` | `crates/invariant-biosynthesis-core/src/models/authority.rs` | PCA data types |
| `crates/invariant-core/src/models/audit.rs` | same | Audit entry shape |
| `crates/invariant-core/src/models/verdict.rs` | same | Signed verdict envelope |
| `crates/invariant-core/src/models/error.rs` | same | Error taxonomy — keep, extend later |
| `crates/invariant-core/src/audit.rs` | `crates/invariant-biosynthesis-core/src/audit.rs` | Hash-chained signed JSONL audit log, tamper-detect — substrate-agnostic |
| `crates/invariant-core/src/keys.rs` | same | Key file storage / abstract key store |
| `crates/invariant-core/src/util.rs` | same | SHA-256 helpers |
| `crates/invariant-core/src/replication.rs` | same | Audit log replication + Merkle root witness |
| `crates/invariant-core/src/proof_package.rs` | same | Proof-bundle generation |
| `crates/invariant-core/src/watchdog.rs` | same | Heartbeat + safe-stop trigger. Rename the safe-stop payload type from robotics-specific "controlled_crouch" etc. to a generic `SafeStopAction` enum with a `halt_synthesis` variant; keep the timing/crypto logic verbatim. |
| `crates/invariant-core/src/differential.rs` | same | Dual-instance verdict comparison — pure pattern |
| `crates/invariant-core/src/threat.rs` | same | Runtime threat scoring engine (scoring logic is generic; individual rules will be re-weighted for bio in Step 2) |
| `crates/invariant-core/src/monitors.rs` | same | Runtime integrity monitors |
| `crates/invariant-core/src/incident.rs` | same | Incident response automation |
| `crates/invariant-core/src/sensor.rs` | `crates/invariant-biosynthesis-core/src/attestation.rs` | **Rename.** In bio the analog is signed screening-DB entries / signed instrument telemetry, not joint sensors. Keep the signed-payload + nonce + freshness logic; the caller-facing type names become `AttestedInput` / `AttestedReading`. |
| `examples/demo.sh` (structure) | `examples/demo.sh` | Keep the "keygen → inspect → adversarial → audit verify" flow; replace robot profile with a bio synthesis profile placeholder |
| `LICENSE` | `LICENSE` | MIT, verbatim |
| `SECURITY.md` | `SECURITY.md` | Verbatim, update contact/repo URL |
| `CONTRIBUTING.md` | `CONTRIBUTING.md` | Verbatim with project-name swap |
| `.gitignore` | `.gitignore` | Verbatim |
| `rust-toolchain.toml` | `rust-toolchain.toml` | Verbatim |
| `deny.toml` | `deny.toml` | Verbatim |
| `.github/dependabot.yml` | same | Verbatim |
| `.github/workflows/` | same | Copy all CI workflows; update crate names in job matrices |
| `.claude/rules/security.md` | `.claude/rules/security.md` | Verbatim — same safe-coding rules apply |

### Category B — Copy as TEMPLATE (keep structure, replace domain logic)

These files establish the *shape* of the validator, the CLI, and the test harness. The robotics domain content comes out; bio stubs go in (per Steps 3, 5, 8 of this spec).

| Source | Destination | What to keep vs. replace |
|---|---|---|
| `crates/invariant-core/src/lib.rs` | `crates/invariant-biosynthesis-core/src/lib.rs` | Keep the `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, and the module-declaration pattern. Replace module list: drop `urdf`, `cycle`, `digital_twin`, `envelopes`, `actuator`; add `screening`, `bundle`, `invariants` (for D/P/C checks). |
| `crates/invariant-core/src/validator.rs` | same | Keep the pipeline shape `authority → invariants → signed verdict`. Replace the physics-check call sites with calls into the new `invariants::{dna, peptide, chemical}` modules (stubs in Step 0; real logic in Step 3). |
| `crates/invariant-core/src/models/command.rs` | `crates/invariant-biosynthesis-core/src/models/bundle.rs` | **Rename Command → SynthesisBundle.** Keep the envelope pattern (nonce, timestamp, kid, op-ref, payload, signature). Replace the `joints` payload with a `SynthesisPayload` enum: `Dna { sequence }`, `Peptide { sequence }`, `Chemical { smiles }`, `Protocol { steps }`. |
| `crates/invariant-core/src/models/actuation.rs` | `crates/invariant-biosynthesis-core/src/models/execution_token.rs` | **Rename.** The signed "go" token that a synthesizer verifies before executing. Same Ed25519-signed structure; different semantic fields. |
| `crates/invariant-core/src/models/profile.rs` | `crates/invariant-biosynthesis-core/src/models/profile.rs` | Profile concept survives, but fields change. Robotics fields (joints, workspace, zones) are removed. Bio fields (BSL level, allowed organisms, chemical hazard classes, synthesis volume caps, export-control flags) are added per Step 4. |
| `crates/invariant-core/src/profiles.rs` | same | Keep the compile-time embedded profile library pattern; start with one stub profile `university_bsl2_dna.json`. |
| `crates/invariant-core/src/intent.rs` | same | Intent→operations narrowing pipeline — keep. Replace robotics op templates (`pick_and_place`) with bio templates (`synthesize_dna_fragment`, `run_peptide_coupling`, `dispense_reagent`). |
| `crates/invariant-cli/` (entire crate) | `crates/invariant-biosynthesis-cli/` | Keep the clap subcommand layout and the binary entry-point. Binary renamed to `invariant-bio`. Drop subcommands that are robot-only (`campaign` pointing to robot YAMLs is fine — the mechanism is generic; the YAMLs go). |
| `crates/invariant-sim/` | `crates/invariant-biosynthesis-sim/` | Keep the dry-run campaign harness pattern. Drop Isaac Lab bridge. New scenarios come in Step 8. |
| `crates/invariant-eval/` | `crates/invariant-biosynthesis-eval/` | Trace evaluation engine is substrate-agnostic. Keep presets `safety-check`, `completeness`, `regression`; drop robotics rubrics. |
| `crates/invariant-fuzz/` | `crates/invariant-biosynthesis-fuzz/` | Keep the four attack-suite categories (protocol, authority, system, cognitive). The protocol/authority/system suites are generic and survive almost verbatim. The cognitive suite needs bio-specific prompt-injection payloads (Step 2). |
| `examples/safe-command.json` | `examples/safe-bundle.json` | Template shape — replace with a minimal DNA synthesis bundle. |
| `examples/dangerous-command.json` | `examples/dangerous-bundle.json` | Template shape — replace with a bundle that should fail screening (e.g., a known toxin gene fragment). |
| `examples/demo-campaign.yaml` | same | Keep the YAML schema; swap the scenarios. |
| `Cargo.toml` (workspace) | `Cargo.toml` | Keep workspace structure; swap members list; update keywords to `["biosynthesis", "biosecurity", "cryptography", "ed25519", "safety"]` and categories to `["science", "cryptography"]`. Drop robotics-only deps if the crate that used them is not copied. |
| `Dockerfile` | `Dockerfile` | Keep the multi-stage Rust build; update binary name. |
| `CLAUDE.md` | `CLAUDE.md` | Keep the short-form project guide pattern; update crate list. |
| `.codelicious/` | `.codelicious/` | Keep the harness config verbatim. |

### Category C — Do NOT copy (robotics-specific, delete from consideration)

These have no bio analog or need a complete rewrite. Ignoring them is faster than trying to port.

- `crates/invariant-core/src/physics/` (entire directory, all 25 physics check files: `joint_limits.rs`, `velocity.rs`, `torque.rs`, `acceleration.rs`, `workspace.rs`, `exclusion_zones.rs`, `self_collision.rs`, `delta_time.rs`, `stability.rs`, `proximity.rs`, `iso15066.rs`, `grasp_force.rs`, `payload.rs`, `friction_cone.rs`, `ground_reaction.rs`, `heading_rate.rs`, `step_length.rs`, `foot_clearance.rs`, `locomotion_velocity.rs`, `ee_force.rs`, `force_rate.rs`, `environment.rs`, `geometry.rs`, `mod.rs`, `tests.rs`) — bio invariants are a new substrate and will be written fresh in Step 3.
- `crates/invariant-core/src/urdf.rs` — URDF parsing is robotics-only.
- `crates/invariant-core/src/cycle.rs` — CNC tending state machine.
- `crates/invariant-core/src/envelopes.rs` — robotics task envelopes.
- `crates/invariant-core/src/digital_twin.rs` — robotics digital-twin divergence. (The *concept* maps to e.g. reaction-kinetics simulation, but the code does not port cleanly; reimplement if/when needed.)
- `crates/invariant-core/src/actuator.rs` — replaced by `execution_token.rs` template above.
- `crates/invariant-coordinator/` — multi-robot separation / workspace partitioning. (If multi-synthesizer coordination is ever needed, start from scratch.)
- `crates/invariant-core/src/models/trace.rs` — robotics trajectory traces. (A bio equivalent — protocol execution traces — will be defined in Step 5.)
- `invariant-ros2/` — ROS 2 bridge.
- `isaac/` — NVIDIA Isaac Lab integration (python + rust).
- `campaigns/` — every YAML in here is a robot-specific scenario; keep none.
- `profiles/` — every JSON in here is a robot profile; keep none.
- `formal/` — Lean 4 proofs of robotics invariants. (A bio formal directory can be established later, but none of the existing proofs carry over.)
- `fuzz/` (top-level `cargo-fuzz` corpus, distinct from `crates/invariant-fuzz/`) — corpora are robotics inputs.
- `docs/spec-v1.md`, `spec-v2.md`, `spec-v3.md`, `spec-15m-campaign.md`, `runpod-simulation-guide.md` — historical robotics specs.
- `audit.jsonl` at repo root — example log from robotics runs.
- `keys.json` at repo root — pre-generated robotics demo keys. **Do not copy — regenerate fresh keys for bio.**
- `target/`, `venv/` — build artifacts.
- `CHANGELOG.md` — start fresh at `0.0.1` for biosynthesis.
- `README.md` — already written fresh at the root of this repo (see `README.md`).

### Step 0 acceptance checks

After the copy is complete, Claude Code should verify:

1. `cargo build --workspace` succeeds. Stubs may be `todo!()` but the crate must compile.
2. `cargo test -p invariant-biosynthesis-core authority::` passes — the PCA chain and Ed25519 tests survived the copy unchanged.
3. `cargo test -p invariant-biosynthesis-core audit::` passes — audit hash-chain tests pass.
4. `grep -r 'invariant_robotics\|invariant-robotics' crates/` returns zero hits.
5. `grep -r 'joint\|torque\|urdf\|zmp\|iso15066' crates/` returns zero hits (robotics terms should be gone).
6. The binary runs: `cargo run --bin invariant-bio -- --help` lists subcommands.
7. `./invariant-robotics/` is still present on disk and untouched. Do not delete it in Step 0.

---

Step 1: Repository Analysis and Code Reuse Discovery
Prompt for Claude Code:
Please analyze the complete invariant-robotics repository structure and identify all components that can be directly reused, adapted, or serve as templates for invariant-biosynthesis. Generate a comprehensive mapping document that categorizes each file and directory as:


1. DIRECT_REUSE: Copy exactly with no modifications
2. ADAPT_FOR_BIO: Requires substrate-specific modifications but same structure
3. BIO_SPECIFIC: Needs completely new implementation for biological substrates
4. TEMPLATE_ONLY: Use as reference structure but rewrite content


For each component identified, provide:
- Current file path in invariant-robotics
- Proposed file path in invariant-biosynthesis  
- Modification strategy and specific biological adaptations needed
- Dependencies and integration points
- Priority level for initial implementation


Pay special attention to:
- Ed25519 signature verification components
- PCA chain validation logic
- Command bundle structures and serialization
- Hardware key integration patterns
- Watchdog and heartbeat mechanisms
- Audit logging with hash chains
- Configuration management systems
- Test frameworks and simulation harnesses


Output should be a structured markdown document that serves as the reuse roadmap for the new repository.
Step 2: Threat Model Analysis for Biosynthesis
Prompt for Claude Code:
Develop a comprehensive threat model for AI-controlled biosynthesis systems by analyzing the attack vectors, failure modes, and security boundaries specific to biological and chemical synthesis. Structure this as a formal threat analysis document that includes:


Attack Vector Categories:
1. Prompt injection through synthesis requests
2. Sequence injection via environmental data
3. Authority escalation in synthesis workflows  
4. Supply chain attacks on synthesis platforms
5. Database poisoning of screening systems
6. Replay attacks on synthesis commands
7. Model extraction and inversion attacks
8. Covert channel exploitation in synthesis data


For each attack vector, document:
- Attack methodology and required capabilities
- Potential impact scope (laboratory, institutional, population-level)
- Current defensive gaps in existing screening systems
- How PCA chains and cryptographic firewalls provide protection
- Specific implementation requirements for mitigation


Include analysis of:
- Select agent screening bypass techniques
- Novel pathogen generation risks  
- Dual-use research of concern boundaries
- Chemical weapons convention compliance
- Export control evasion methods
- Academic research vs weaponization distinctions


Reference existing biosecurity frameworks including:
- HHS Select Agent Program regulations
- Australia Group guidelines
- SecureDNA screening protocols
- IGSC voluntary guidelines
- NSABB oversight recommendations


Output a threat model that can drive technical requirements and help prioritize firewall component development.
Step 3: Biological Invariant Set Definition

**Status:** delivered. See `docs/step3-bio-invariants.md` for the formal spec covering D1–D10, P1–P10, C1–C10, and PR1–PR4 (34 invariants total). Implementations under `crates/invariant-biosynthesis-core/src/invariants/{dna,peptide,chemical,protocol}.rs`; validator wiring + `InvariantContext` in `validator.rs` and `invariants/mod.rs`; ~111 unit tests across the four families.

Prompt for Claude Code:
Design the mathematical invariant set for biosynthesis safety screening, equivalent to the P1-P20 physics invariants in robotics but adapted for biological and chemical synthesis contexts. Create a formal specification document that defines:


Safety Invariant Categories:
1. Sequence-based hazard detection
2. Structural motif screening  
3. Functional domain analysis
4. Toxicity prediction bounds
5. Pathogenicity risk assessment
6. Environmental release potential
7. Synthesis feasibility constraints
8. Authority scope boundaries


For each invariant, specify:
- Mathematical formulation and computational complexity
- Input data requirements and format specifications
- Validation algorithms and reference implementations
- False positive/negative tolerance bounds
- Performance benchmarks for real-time screening
- Database dependencies and update mechanisms
- Integration with existing screening systems


Include specific invariant definitions for:


DNA Synthesis Invariants (D1-D10):
- D1: Select agent sequence matching
- D2: Pandemic potential pathogen screening  
- D3: Toxin gene detection
- D4: Virulence factor identification
- D5: Antibiotic resistance marker screening
- D6: Synthetic biology part validation
- D7: Codon optimization bounds
- D8: GC content feasibility ranges
- D9: Secondary structure constraints
- D10: Assembly compatibility verification


Peptide Synthesis Invariants (P1-P10):
- P1: Antimicrobial peptide classification
- P2: Cell-penetrating peptide detection
- P3: Membrane-disrupting sequence screening
- P4: Protein-protein interaction inhibitors
- P5: Enzyme active site mimics
- P6: Immunogenic epitope prediction
- P7: Stability and degradation assessment
- P8: Solubility and aggregation bounds
- P9: Post-translational modification sites
- P10: Delivery mechanism compatibility


Chemical Synthesis Invariants (C1-C10):
- C1: Chemical weapons convention screening
- C2: Explosive compound detection
- C3: Narcotic and psychoactive substances
- C4: Environmental toxin identification
- C5: Carcinogen and mutagen screening
- C6: Endocrine disruptor assessment
- C7: Bioaccumulation potential
- C8: Synthetic pathway feasibility
- C9: Reaction safety constraints
- C10: Waste stream toxicity bounds


Document the mathematical foundations, computational requirements, and integration architecture for each invariant check.
Step 4: PCA Chain Implementation for Research Authorization
Prompt for Claude Code:
Implement the Provenance Causal Authority chain architecture specifically adapted for research institution hierarchies and biosynthesis authorization workflows. Design a comprehensive system that handles:


Authority Chain Structure:
1. Institution Root Authority (research institution's master key)
2. Institutional Review Board approval delegation
3. Principal Investigator project scope assignment
4. Lab Member operational permissions
5. AI Agent synthesis request generation
6. Synthesis Platform execution authorization


Create detailed technical specifications for:


PCA Chain Components:
- Authority certificate formats and validation rules
- Scope narrowing mechanisms for biological research
- Time-bounded authorization with automatic expiration
- Multi-signature requirements for high-risk synthesis
- Emergency revocation and authority recall procedures
- Cross-institutional collaboration protocols


Research Scope Definitions:
- Biological safety level containment mappings
- Organism and cell line authorization boundaries
- Chemical hazard class permission matrices  
- Synthesis volume and concentration limits
- Export control and dual-use restrictions
- Institutional ethics committee oversight integration


Implementation Requirements:
- Certificate chain validation algorithms
- Scope intersection and subset verification
- Authority delegation logging and audit trails
- Integration with institutional identity systems
- Hardware security module key management
- Backup and recovery procedures for authority chains


Include code templates and configuration examples for:
- University research lab deployment
- Pharmaceutical company R&D integration
- Government research facility implementation
- Cloud lab service provider adoption
- Multi-institutional collaborative projects


Document the cryptographic protocols, key management procedures, and operational workflows required for secure research authorization in biosynthesis contexts.
Step 5: Synthesis Platform Integration Architecture
Prompt for Claude Code:
Design the integration architecture for connecting the biosynthesis firewall to existing synthesis platforms, cloud labs, and automated laboratory equipment. Create comprehensive technical documentation for:


Platform Integration Categories:


DNA Synthesis Platforms:
- Twist Bioscience API integration
- Integrated DNA Technologies (IDT) ordering systems
- Ansa Biotechnologies synthesis platforms
- Kilobaser benchtop synthesizers
- BioXp 3250 workstation integration


Peptide Synthesis Equipment:
- CEM Liberty series synthesizers
- Biotage automated peptide synthesizers  
- CSBio automated synthesis systems
- Gyros Protein Technologies platforms


Chemical Synthesis Systems:
- Chemspeed automated synthesis platforms
- Unchained Labs synthesis equipment
- Hamilton automated liquid handling
- Tecan automated workstations


Cloud Lab Providers:
- Emerald Cloud Lab integration
- Strateos automated lab services
- Transcriptic platform connectivity
- Academic core facility APIs


For each platform category, specify:


Integration Technical Requirements:
- API authentication and authorization mechanisms
- Command bundle format translation layers
- Real-time status monitoring and feedback loops
- Error handling and retry logic implementation
- Batch processing and queue management systems
- Hardware key provisioning and certificate deployment


Security Implementation:
- Ed25519 signature verification at synthesis endpoints
- Hardware security module integration requirements
- Tamper-evident logging of all synthesis operations
- Encrypted communication channels and certificate validation
- Air-gapped operation modes for high-security environments
- Emergency shutdown and synthesis termination procedures


Operational Workflows:
- Synthesis request validation and screening pipelines
- Multi-platform synthesis coordination protocols
- Inventory management and reagent tracking integration
- Quality control and verification procedures
- Compliance reporting and audit trail generation
- Incident response and forensic investigation capabilities


Include reference implementations, configuration templates, and deployment guides for each major platform category.
Step 6: Screening Database Integration and Management
Prompt for Claude Code:
Implement the screening database architecture and management system that provides deterministic hazard detection while maintaining operational security and update integrity. Design comprehensive technical specifications for:


Database Architecture Components:


Hazard Classification Databases:
- HHS Select Agent Program pathogen lists
- Australia Group dual-use biological equipment lists  
- Chemical Weapons Convention prohibited substances
- FDA controlled substance classifications
- EPA toxic substances control act inventories
- IATA dangerous goods shipping classifications


Sequence and Structure Databases:
- Known pathogen genome assemblies and annotations
- Virulence factor protein sequences and domains
- Toxin protein structures and active sites
- Antibiotic resistance gene variants
- Synthetic biology standardized part libraries
- Chemical structure databases and property predictions


Implementation Requirements:


Database Security and Integrity:
- Cryptographic hash verification for database updates
- Digital signature validation for authoritative sources
- Tamper-evident logging of all database modifications
- Rollback capabilities and version control systems
- Access control and audit trails for database queries
- Air-gapped update procedures for sensitive databases


Screening Algorithm Integration:
- BLAST-based sequence homology screening
- Hidden Markov model protein domain detection
- Chemical fingerprint similarity calculations
- Machine learning toxicity prediction models
- Network analysis for pathway reconstruction
- Phylogenetic analysis for pathogen classification


Performance and Scalability:
- Sub-second screening response requirements
- Distributed database replication strategies
- Caching mechanisms for frequently accessed data
- Load balancing and query optimization
- Database indexing and search acceleration
- Memory-efficient algorithms for large-scale screening


Privacy-Preserving Screening:
- Integration with SecureDNA cryptographic screening protocols
- Oblivious database query mechanisms
- Differential privacy for aggregate screening statistics
- Secure multi-party computation for collaborative screening
- Zero-knowledge proof systems for compliance verification


Create detailed technical documentation including database schemas, API specifications, update procedures, and integration protocols for secure and efficient hazard screening operations.
Step 7: Hardware Security Module and Key Management
Prompt for Claude Code:
Design the hardware security module integration and cryptographic key management system for biosynthesis firewall deployments. Create comprehensive technical specifications covering:


HSM Integration Architecture:


Hardware Platform Support:
- TPM 2.0 integration for standard deployments
- FIPS 140-2 Level 3 HSMs for high-security environments
- ARM TrustZone implementation for embedded systems
- Intel SGX enclave integration for cloud deployments
- YubiHSM and similar USB-connected security modules
- Custom FPGA-based security processors for air-gapped systems


Key Management Lifecycle:


Root Authority Key Generation:
- Institutional master key ceremony procedures
- Multi-party key generation with threshold signatures
- Hardware entropy source requirements and validation
- Key backup and recovery procedures with geographic distribution
- Regular key rotation schedules and migration protocols
- Emergency key revocation and replacement procedures


Operational Key Deployment:
- Device provisioning and certificate installation
- Synthesis platform key distribution and verification
- Firewall authentication key management
- PCA chain signing authority delegation procedures
- Cross-platform key synchronization mechanisms
- Hardware tampering detection and response protocols


Security Implementation Requirements:


Cryptographic Operations:
- Ed25519 signature generation and verification performance benchmarks
- Hardware-accelerated cryptographic operations where available
- Side-channel attack resistance for key operations
- Secure boot and attestation procedures for firewall components
- Random number generation quality assurance and testing
- Cryptographic algorithm agility and upgrade pathways


Deployment Models:
- Single-tenant laboratory deployment architectures
- Multi-tenant cloud lab security isolation requirements
- Federated key management for inter-institutional collaboration
- Offline operation capabilities for air-gapped environments
- Mobile and edge deployment security considerations
- Disaster recovery and business continuity procedures


Compliance and Certification:
- Common Criteria evaluation requirements and procedures
- FIPS 140 certification pathways and validation testing
- Export control compliance for cryptographic technologies
- Integration with institutional PKI and certificate authorities
- Audit logging and compliance reporting capabilities
- Third-party security assessment and penetration testing frameworks


Document the complete key management architecture, operational procedures, and security controls required for production biosynthesis firewall deployments.
Step 8: Testing Framework and Validation Pipeline
Prompt for Claude Code:
Create a comprehensive testing framework and validation pipeline for biosynthesis firewall components, adapted from robotics simulation approaches but specialized for biological and chemical synthesis contexts. Design technical specifications for:


Testing Framework Architecture:


Simulation and Modeling Components:
- Biological sequence generation and property prediction models
- Chemical synthesis pathway simulation and feasibility analysis
- Laboratory workflow automation and equipment simulation
- Adversarial sequence generation for penetration testing
- Synthetic biology design automation and validation tools
- Regulatory compliance checking and documentation verification


Validation Pipeline Stages:


Stage 1: Dry-Run Simulation Testing
- Synthetic sequence generation covering expected research distributions
- Adversarial input generation including known attack vectors
- False positive and false negative rate measurement procedures
- Performance benchmarking under realistic workload conditions
- Invariant validation using known hazardous and safe sequences
- PCA chain validation with complex authorization scenarios


Stage 2: Hardware-in-the-Loop Testing
- Real synthesis platform integration without actual synthesis execution
- Hardware security module operation validation and performance testing
- Network communication testing including failure and recovery scenarios
- Database integration testing with realistic screening workloads
- Timing analysis and real-time performance validation
- Security boundary validation and penetration testing


Stage 3: Shadow Mode Operation
- Parallel operation with existing synthesis workflows and screening systems
- Statistical analysis of screening decisions compared to human expert review
- False positive rate measurement in operational research environments
- Integration testing with institutional authorization and approval systems
- Compliance verification with existing regulatory oversight procedures
- Performance impact assessment on laboratory operations and throughput


Stage 4: Guardian Mode Deployment
- Supervised deployment with human oversight and approval workflows
- Real-time monitoring and anomaly detection for unusual screening patterns
- Incident response and escalation procedures for safety violations
- Comprehensive audit logging and forensic investigation capabilities
- Gradual transition procedures from supervised to autonomous operation
- Continuous monitoring and performance optimization procedures


Statistical Validation Requirements:
- Clopper-Pearson confidence interval calculations for safety-critical metrics
- Power analysis and sample size requirements for validation studies
- Bayesian updating procedures for screening accuracy assessment
- Cross-validation methodologies for machine learning components
- Regression testing procedures for database and algorithm updates
- Performance benchmarking and comparison with existing screening systems


Test Case Development:
- Comprehensive test sequence libraries covering biological diversity
- Known hazardous sequence collections for sensitivity testing
- Edge case and boundary condition testing scenarios
- Regulatory compliance test cases for different jurisdictions
- Integration test scenarios for multi-platform synthesis workflows
- Security test cases including adversarial attacks and penetration attempts


Document the complete testing methodology, statistical validation procedures, and quality assurance frameworks required for reliable biosynthesis firewall deployment.
Step 9: Regulatory Compliance and Certification Strategy
Prompt for Claude Code:
Develop a comprehensive regulatory compliance and certification strategy for biosynthesis firewall systems, addressing the complex intersection of biosafety, export control, research ethics, and AI governance requirements. Create detailed technical documentation for:


Regulatory Framework Analysis:


Biosafety and Public Health Regulations:
- CDC Select Agent Program compliance requirements and procedures
- NIH Guidelines for Research Involving Recombinant or Synthetic Nucleic Acid Molecules
- FDA oversight of synthetic biology products and manufacturing processes
- USDA APHIS biotechnology regulatory framework for agricultural applications
- EPA TSCA biotechnology risk assessment procedures and reporting requirements
- International Health Regulations and WHO pandemic preparedness frameworks


Export Control and Dual-Use Regulations:
- Commerce Control List biological equipment and technology restrictions
- International Traffic in Arms Regulations biological defense articles
- Australia Group guidelines for biological dual-use research oversight
- Wassenaar Arrangement dual-use and military technology controls
- Nuclear Suppliers Group transfer guidelines for dual-use biotechnology
- Chemical Weapons Convention implementation and compliance verification


Research Ethics and Institutional Oversight:
- Institutional Review Board approval procedures for synthetic biology research
- Institutional Biosafety Committee oversight requirements and protocols
- National Science Advisory Board for Biosecurity dual-use research guidelines
- Research Security Program requirements for foreign collaboration disclosure
- Export Administration Regulations deemed export compliance procedures
- International collaboration agreements and technology transfer protocols


AI Governance and Safety Standards:
- NIST AI Risk Management Framework implementation for biosynthesis applications
- ISO/IEC standards for AI system safety and security requirements
- IEEE standards for autonomous and intelligent systems in laboratory environments
- Algorithmic accountability and explainability requirements for safety decisions
- Data protection and privacy regulations for biological sequence information
- Intellectual property protection for AI-generated biological designs


Certification Strategy Implementation:


Safety Certification Pathways:
- IEC 61508 functional safety standard adaptation for biosynthesis applications
- ISO 13849 safety-related control systems certification for laboratory automation
- ANSI/UL standards for laboratory equipment safety and cybersecurity
- Common Criteria evaluation for security-critical software components
- FIPS 140 cryptographic module validation for hardware security components
- Third-party assessment and certification procedures for safety-critical systems


Compliance Documentation Requirements:
- System design documentation and safety analysis reports
- Risk assessment and mitigation strategy documentation
- Operational procedures and emergency response protocols
- Training and competency requirements for system operators and administrators
- Audit trail and incident reporting procedures for regulatory oversight
- Quality management systems and continuous improvement processes


International Harmonization:
- Mutual recognition agreements for safety certifications across jurisdictions
- International standards development participation and technical contributions
- Regulatory sandbox programs for innovative biotechnology safety approaches
- Stakeholder engagement with regulatory agencies and standards organizations
- Best practice sharing and coordination with international research institutions
- Diplomatic engagement on biosafety governance and technology transfer issues


Document the complete regulatory compliance strategy, certification pathways, and international coordination requirements for biosynthesis firewall deployment across different jurisdictions and institutional contexts.
Step 10: Open Source Community and Ecosystem Development
Prompt for Claude Code:
Design the open source community strategy and ecosystem development plan for invariant-biosynthesis, building on lessons learned from invariant-robotics while addressing the unique challenges and opportunities in the biosafety and synthetic biology communities. Create comprehensive documentation for:


Community Building Strategy:


Target Stakeholder Groups:
- Academic researchers in synthetic biology and biotechnology
- Biosafety and security professionals in government and industry
- Open source software developers with interest in safety-critical systems
- Regulatory specialists and policy researchers in biosafety governance
- Synthetic biology standardization organizations and working groups
- International biosafety and biosecurity research communities


Engagement and Outreach:
- Conference presentations at synthetic biology and biosafety meetings
- Workshop organization for hands-on training and community feedback
- Collaboration with existing open source synthetic biology projects
- Integration with educational curricula in biotechnology and biosafety programs
- Publication strategy for peer-reviewed research and technical documentation
- Social media and online community engagement through appropriate channels


Open Source Project Management:


Repository Structure and Governance:
- Code organization and modular architecture for community contributions
- Contribution guidelines and code review processes adapted for security-critical code
- Issue tracking and feature request management for diverse stakeholder needs
- Documentation standards and technical writing guidelines for complex biosafety topics
- Testing and validation procedures that community contributors can execute safely
- Release management and version control strategies for safety-critical software


Security and Safety Considerations:
- Responsible disclosure procedures for security vulnerabilities in safety systems
- Code audit and security review processes for community contributions
- Dual-use research oversight and responsible innovation practices
- Export control compliance for international community participation
- Legal and liability considerations for open source safety-critical software
- Coordination with national and international biosafety authorities


Ecosystem Integration:


Interoperability and Standards:
- Integration with existing synthetic biology software tools and platforms
- Participation in biosafety and biotechnology standards development processes
- API design and documentation for third-party integration and extension
- Compatibility testing with major synthesis platforms and laboratory equipment
- Data format standardization and interoperability with existing databases
- Protocol development for federated deployment and multi-institutional collaboration


Commercial and Academic Partnerships:
- Technology transfer and commercialization pathways for derivative products
- Academic research collaboration agreements and joint development projects
- Industry partnership strategies for synthesis platform integration and validation
- Government agency collaboration for regulatory development and compliance testing
- International research consortium participation and leadership opportunities
- Intellectual property management and patent landscape analysis


Sustainability and Long-term Development:


Funding and Resource Strategy:
- Grant funding opportunities from government agencies and private foundations
- Corporate sponsorship and partnership revenue models that preserve open source principles
- Academic institution support and resource sharing agreements
- Volunteer developer community cultivation and recognition programs
- Infrastructure and hosting cost management for project sustainability
- Legal and administrative support for long-term project governance


Impact Measurement and Evaluation:
- Adoption metrics and community engagement assessment procedures
- Safety impact measurement and risk reduction quantification methods
- Research output and publication tracking for academic community engagement
- Policy influence assessment and regulatory adoption monitoring
- Educational impact evaluation and curriculum integration success metrics
- International cooperation and technology transfer impact documentation


Document the complete community development strategy, governance procedures, and sustainability plans required for long-term success of the invariant-biosynthesis open source project and ecosystem.
Implementation Roadmap
The invariant-biosynthesis project will follow a four-phase development schedule aligned with the validation pipeline:
Phase 1 (Foundation): Repository setup with code reuse from invariant-robotics, basic PCA chain implementation, initial screening database integration, and simulation framework development.
Phase 2 (Integration): Synthesis platform API integration, hardware security module support, comprehensive testing framework implementation, and shadow mode deployment preparation.
Phase 3 (Validation): Shadow mode operation with partner research institutions, statistical validation and safety certification preparation, regulatory engagement and compliance documentation.
Phase 4 (Production): Guardian mode deployment, open source community development, ecosystem partnerships, and international adoption support.
This specification serves as the technical foundation for implementing cryptographically-secured biosynthesis safety infrastructure that extends the proven cognitive-kinetic firewall architecture to biological and chemical synthesis domains.