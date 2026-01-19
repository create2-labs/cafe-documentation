# CAFE: Crypto-Agility Framework for Ethereum

## Document versionning

- v0.1.0
  - Date: Jan 19th, 2026
  - Author: Oleg Lodygensky
  - Comments: initial version

## Introduction

Quantum computing is arriving. It promises major advances in many fields, but this disruptive power also threatens the cryptographic foundations that protect our digital world. Quantum algorithms such as Shor's and Grover's threaten to compromise the asymmetric and symmetric cryptography that secures today's internet communications, financial systems, blockchain networks, and digital identities.

The transition to quantum-resistant cryptography (*post-quantum cryptography* or *PQC*) has become an urgent global priority. Understanding and mitigating this quantum threat is essential to preserve the confidentiality, integrity, and authenticity of our digital assets in the quantum era.

### CAFE Status: Alpha Version

**Important**: CAFE is currently in **alpha version**. All results and features should be taken "as is" for testing and evaluation purposes. The platform is actively being developed and refined based on user feedback.

**Current Objectives**:
- Test and verify the interest of the Ethereum blockchain ecosystem in our crypto-agility solution
- Gather valuable feedback from early testers and the community
- Validate the approach and identify areas for improvement
- Build understanding of user needs and use cases

We welcome feedback, bug reports, and feature requests from the community to help shape CAFE's development.

## The Problem: Ethereum's Quantum Vulnerability

### Ethereum and Current Cryptography

Ethereum is a blockchain enabling the execution of smart contracts and decentralized applications (dApps). Unlike Bitcoin, which primarily manages digital currency transfers, Ethereum provides a virtual machine (the EVM) that executes arbitrary code on-chain in a decentralized manner.

Users interact with Ethereum through wallets, which manage their cryptographic key pairs. Each wallet corresponds to one or more accounts—either Externally Owned Accounts (EOAs) controlled by private keys, or contract accounts controlled by smart contract code.

The security of these wallets relies on:
- The secrecy of the private key
- The robustness of cryptographic algorithms (currently ECDSA over secp256k1)

The wallet address is derived from the last 20 bytes of the Keccak-256 hash of the uncompressed public key. Signatures are verified on-chain via the `ecrecover` precompile.

### The Quantum Vulnerability

Ethereum wallets rely on ECDSA (Elliptic Curve Digital Signature Algorithm) over the secp256k1 elliptic curve, which solves the elliptic curve discrete logarithm problem. While this scheme is secure against classical computers, it becomes vulnerable once a large-scale fault-tolerant quantum computer exists.

**Shor's algorithm** can efficiently break the elliptic curve discrete logarithm problem, allowing an attacker to derive private keys from exposed public keys.

#### The Public Key Exposure Problem

The critical vulnerability lies in public key exposure. When an Ethereum wallet signs and broadcasts a transaction, the public key becomes recoverable from the signature and is permanently recorded on the blockchain. This creates a "store-now, decrypt-later" risk:

1. An attacker can store encrypted or signed data today
2. Wait for quantum computers to become available
3. Retroactively decrypt or derive private keys from historical blockchain data

Even wallets that have never signed a transaction are at risk if they are reused after quantum computers become available, as any future transaction would expose the public key.

#### Vulnerability States

Three critical states can be identified:

1. **🔴 Public Key Exposed On-Chain** — The wallet has executed at least one transaction. The public key is permanently visible on the blockchain, making it vulnerable to future quantum attacks. This is the most critical state.

2. **🟡 Public Key Not Exposed** — The wallet has never executed a transaction. While not immediately threatened, its use is discouraged under quantum risk considerations, as any future transaction would expose the public key.

3. **🟢 CAFE Wallet Attached** — The user owns a CAFE Wallet (Account Abstraction wallet using PQC inside a TDX enclave). This represents the most secure configuration available today.

### Network Layer Risk: Understanding TLS Endpoint Security

Beyond wallet-level risks, the transport layer (TLS/HTTPS) connecting users to blockchain infrastructure also presents quantum vulnerabilities. Understanding these risks is important for users to make informed decisions about which endpoints to trust.

**The Current TLS Landscape**

- Most RPC nodes, APIs, and blockchain services use classical TLS (ECDHE/ECDSA or RSA)
- Certificate Authorities (CAs) still issue X.509 certificates signed with quantum-vulnerable algorithms (ECDSA, RSA)
- Pure post-quantum TLS is not yet possible today—we are waiting for PKI migration to support certificates with PQC signatures
- However, what **is feasible today** is deploying TLS 1.3+ with post-quantum Key Encapsulation Mechanisms (KEM) to combat the "harvest now, decrypt later" threat

**What CAFE TLS Scanning Verifies**

CAFE's TLS scanning focuses on verifying that endpoints:
- Use **TLS 1.3 or higher** (modern, secure protocol)
- Support **post-quantum KEM** (Key Encapsulation Mechanisms like ML-KEM/Kyber) in hybrid mode
- This provides protection against "harvest now, decrypt later" attacks on encrypted traffic

**Important Limitations**

- **Pure PQC TLS is not possible today** — Full post-quantum TLS requires PQC certificates, which are not yet available from Certificate Authorities
- **PKI migration is pending** — We are waiting for the broader PKI ecosystem to migrate to post-quantum certificate signing
- ⚠️ **CAFE does not provide TLS remediation** ⚠️ — Our TLS scans are informational only, designed to help users understand endpoint security posture and make informed choices about which services to use

**Why This Matters**

Even if a wallet is locally secure, the communication channel may remain vulnerable to future quantum attacks if endpoints don't support post-quantum KEM. CAFE's TLS scanning helps users identify which endpoints provide better quantum resistance in their TLS handshakes, enabling informed decisions about endpoint selection.

### Current Recommendations

The [Post-Quantum Financial Infrastructure Framework (PQFIF)](https://www.sec.gov/about/crypto-task-force/written-submission/cft-written-input-daniel-bruno-corvelo-costa-090325) submitted to the SEC proposes a structured framework to migrate global financial infrastructure to post-quantum cryptography, focusing on automated discovery, hybrid transition, and regulatory alignment.

The main recommendations include:

1. Avoid reusing EOAs that have already signed; rotate to new, "unspent" addresses
2. Obfuscate public keys using zero-knowledge technology
3. Use ERC-4337 smart wallets with multi-factor or multi-signature policies
4. Execute post-quantum cryptographic operations on the user's device
5. Add timelocks, social recovery, or guardian mechanisms to mitigate "in-transit" attacks

### Situation Summary

| Aspect           | Current Ethereum              | Quantum Status               | Migration Path                         |
| ---------------- | ----------------------------- | ---------------------------- | -------------------------------------- |
| Signature        | ECDSA (secp256k1)             | ❌ Broken by Shor             | Replace via smart-wallet                |
| Address          | Keccak-256(pubkey) → 20 bytes | ✅ Grover-safe (~128-bit)     | Keep short hashes              |
| Storage funds    | Hidden pubkey                 | ✅ Safe (for now)             | Avoid reusing addresses                |
| Active wallets   | Pubkey exposed                | ⚠️ Vulnerable on quantum day | Move to smart-wallet (EIP7702; ERC4337)                       |
| PQC-ready option | None natively                 | 🚧 In research               | Use smart wallet upgradeable policy |

## The Solution: Crypto-Agility Framework for Ethereum (CAFE)

### What is Crypto-Agility?

[Crypto-agility](https://www.ibm.com/quantum/blog/crypto-agility) is a process to adapt cryptographic mechanisms in response to evolving threats, without disrupting core functionality. In a world moving toward quantum computing, crypto-agility becomes a strategic necessity: it ensures that organizations can replace or upgrade vulnerable algorithms (such as RSA or ECDSA) with quantum-resistant alternatives as they mature and are standardized.

Rather than a one-time migration, crypto-agility establishes a continuous capability—to define, enforce, and evolve cryptographic policies across distributed systems, applications, and blockchains. It transforms security from a static configuration into a dynamic, policy-driven process, enabling resilience, compliance, and long-term trust in the post-quantum era.

### CAFE Overview

**Crypto-Agility Framework for Ethereum (CAFE)** is a three-service platform designed to discover, govern, and remediate cryptographic assets on Ethereum—ensuring compliance, resilience, and trust in the post-quantum and zero-knowledge era.


**CAFE's core mission** is to secure Ethereum wallets against quantum threats. The platform's primary focus is on wallet discovery, risk assessment, and remediation—helping users migrate from vulnerable EOA wallets to quantum-safe Account Abstraction wallets using post-quantum cryptography.

While CAFE includes TLS endpoint scanning capabilities, this feature serves an **informational purpose only** to help users understand the quantum risks associated with the endpoints they connect to (RPC nodes, APIs, blockchain services). CAFE does **not** provide remediation services for TLS endpoints.

CAFE operationalizes PQFIF principles on Ethereum with smart wallets (EIP7702, ERC-4337), PQC library, and ZK-verifiable policy enforcement.

CAFE delivers significant value under DORA (*Digital Operational Resilience Act*), as DORA applies to financial institutions and their ICT service providers—especially those handling cryptography, keys, transaction integrity, or critical digital operations. CAFE gives institutions the technical evidence and resilience mechanisms that DORA expects.

**Current Status: Alpha Version**

CAFE is currently in **alpha version**. Results should be taken "as is" for testing and evaluation purposes. The current objective is to test and verify the interest of the Ethereum blockchain ecosystem in our solution and gather valuable feedback from early adopters.

### Three-Layer Architecture

CAFE unifies four integrated layers:

| Service        | Goal                                                                  | Key Functions                                        | Output                          |
| ------------------ | ------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------- |
| **Discovery**      | Identify on-chain and network quantum exposures                           | Wallet scan, EOA/AA detection, TLS audit, NIST level     | [CBOM (Crypto BOM)](https://cyclonedx.org/capabilities/cbom/)          |
| **Crypto Policy Manager**        | Define and apply cryptographic governance policies                        | JSON policy, enforcement API                             | Policy snapshot + compliance status |
| **Remediation**    | Securely sign and migrate wallets using PQC + ZK  | Key generation, ZK attestation, proxy signing (ERC-4337) | Signed TX + verifiable audit logs   |
| **Infrastructure** | Orchestrate and monitor the full CAFE ecosystem                           | Resource provisioning, orhcestration, security, telemetry etc.          | Logs, metrics, audit trail          |

### Discovery: Cryptographic Visibility and Risk Mapping

**Discovery** is the entry point of CAFE. It provides a complete, verifiable inventory of cryptographic posture across Ethereum and connected systems.

#### Objectives

- **Complete Cryptographic Inventory** — Automated discovery of all cryptographic assets, algorithms, and dependencies
- **Risk Quantification** — Clear assessment of quantum exposure levels across wallets and infrastructure
- **Compliance Evidence** — Verifiable CBOM (Cryptographic Bill of Materials) for auditors and regulators
- **Continuous Monitoring** — Ongoing visibility as new transactions and endpoints are introduced

#### Core Functions

**Wallet Quantum-Risk Assessment**

Discovery analyzes Ethereum wallets (EOAs) across multiple chains to determine their quantum exposure status:

- Detection of public key exposure on-chain
- Account type classification (EOA vs AA/ERC-4337)
- NIST security level calculation
- Multi-chain support (Ethereum, Arbitrum, Polygon, Base, Optimism, etc.)

**Endpoint TLS Security Audit (Informational)**

Discovery evaluates the quantum-security posture of blockchain endpoints (RPC nodes, APIs, relays) by analyzing:

- TLS Version — Detection of TLS 1.2 vs 1.3 (TLS 1.3+ is required for modern security)
- Post-Quantum KEM Support — Detection of post-quantum Key Encapsulation Mechanisms (ML-KEM/Kyber) in hybrid mode
- Cipher Suites — Analysis of negotiated encryption algorithms
- Certificate Analysis — Evaluation of X.509 certificate signatures and chains (note: PQC certificates are not yet available from CAs)
- NIST Security Levels — Classification of cryptographic components according to NIST PQC standards

**Important Notes on TLS Scanning:**

- **Complexity**: TLS scanning is complex due to the multi-layered nature of TLS handshakes, certificate chains, and algorithm negotiation
- **Pure PQC Not Possible**: Pure post-quantum TLS is not possible today because Certificate Authorities do not yet issue PQC-signed certificates
- **What We Verify**: CAFE focuses on verifying TLS 1.3+ with post-quantum KEM support, which provides protection against "harvest now, decrypt later" attacks
- **Informational Only**: TLS scan results are provided for informational purposes to help users understand endpoint security posture—CAFE does not provide TLS remediation services

**Cryptographic Bill of Materials (CBOM)**

Discovery generates standardized CBOM entries that provide a complete inventory of cryptographic assets, including:

- Algorithms in use (ECDSA, Keccak, Blake2, etc.)
- NIST security levels
- Hash functions used for entropy and signing
- Presence or absence of PQC

### Discovery: Future Work

Discovery is continuously evolving to provide deeper insights into wallet security and quantum risk assessment. Planned enhancements include:

#### Wallet Blast Radius Analysis

Public key exposure assessment is only the first step in security assessment. EOA owners must understand and verify the **impact** of such a security breach on their overall wallet usage and operations.

**Blast Radius** analysis will extend wallet risk assessment by analyzing:

- **Multi-Signature Wallets** — Impact of public key exposure on multi-sig configurations and threshold requirements
- **Interchain Bridges** — Risk propagation across blockchain bridges when a wallet key is exposed
- **DeFi Interactions** — Impact on DeFi positions, liquidity pools, and smart contract interactions
- **Web2-Web3 Links** — Analysis of connections between exposed wallets and centralized services (exchanges, custodians, etc.)
- **Transaction Patterns** — Understanding how exposed keys affect transaction history and future operations
- **Asset Exposure** — Comprehensive view of all assets and positions at risk if a key is compromised

This analysis will help users understand not just *that* their wallet is at risk, but *what* is at risk and *how* a quantum attack could impact their entire blockchain ecosystem.

#### AI-Powered Scan Analysis

To provide more actionable insights and automated risk assessment, CAFE is exploring AI-powered analysis capabilities:

- **Intelligent Risk Scoring** — Machine learning models trained on blockchain patterns to provide more accurate risk assessments
- **Anomaly Detection** — Identify unusual patterns in wallet behavior that may indicate security concerns
- **Predictive Analysis** — Forecast potential security issues based on wallet usage patterns and blockchain trends
- **Automated Recommendations** — AI-generated, context-aware security recommendations tailored to specific wallet configurations and usage patterns
- **Pattern Recognition** — Detect common vulnerabilities and attack vectors across the Ethereum ecosystem
- **Natural Language Insights** — Convert complex cryptographic and blockchain data into understandable, actionable security insights

These AI capabilities will help users make informed decisions about wallet security without requiring deep technical expertise in cryptography or blockchain technology.

### Crypto Policy Manager: Governance, Policies, and Continuous Compliance

The Crypto Policy Manager transforms cryptographic visibility into actionable governance.

#### Objectives

Enable to define, enforce, and attest cryptographic policies across Ethereum operations—ensuring alignment with DORA, NIST, ANSSI, and internal risk frameworks.

#### Core Functions

- **Cryptographic Policy Definition** — Institutions define JSON-based rules (minimum NIST level, mandatory PQC algorithms, rotation cycles, etc.)
- **Automated Policy Validation** — Every operation is checked against the policy framework
- **Continuous Monitoring** — Tracks deviations, drifts, and exceptions over time
- **ZK Compliance Proofs** — Policies can be proven without exposing sensitive data

### Remediation: PQC Migration and Attested Key Operations

**Remediation** is CAFE's execution layer and **core business focus**: it performs cryptographic operations for wallet security under strict guarantees of confidentiality, integrity, and policy compliance.

**This is CAFE's primary value proposition**—providing secure wallet migration and quantum-safe signing services for Ethereum wallets.

#### Objectives

Upgrade vulnerable wallet assets, securely generate new PQC keys, and sign Ethereum transactions using post-quantum algorithms—without ever exposing private keys.

#### Core Functions

- **Secure Key Generation (PQC + Hybrid)** — Generates ML-DSA / Falcon / hybrid classical-PQC keys entirely within user resources
- **Account Migration (EOA → AA)** — Automated creation of quantum-safe Account Abstraction wallets (ERC-4337 / EIP-7702)
- **Proxy Signing (ERC-4337)** — Signs user operations (UserOps) without exposing private material
- **Zero-Knowledge Attestations** — Every signature, key generation, or migration step can be validated using ZK proofs

**Note**: again, CAFE provides remediation services **only for wallets**, not for TLS endpoints. TLS scanning is informational only—users must work with their endpoint providers to improve TLS security.


## Why CAFE is Necessary

### Regulatory Compliance

CAFE addresses key requirements of DORA (Digital Operational Resilience Act) and similar regulatory frameworks:

1. **ICT Asset Visibility** — Complete inventory of cryptographic components
2. **Risk Assessment** — Quantified exposure to quantum threats
3. **Continuous Monitoring** — Ongoing surveillance of cryptographic posture
4. **Audit Trail** — Verifiable CBOM and scan history
5. **Evidence Generation** — Exportable reports for regulators

### Post-Quantum Preparation

As quantum computing advances, the window for preparation is closing. CAFE enables organizations to:

- Understand their current cryptographic posture
- Quantify their quantum exposure
- Prioritize remediation efforts
- Demonstrate compliance to regulators
- Prepare for the post-quantum transition

### Multi-Chain Support

CAFE natively supports all EVM-compatible networks with ERC-4337 support:

- Ethereum Mainnet, Sepolia, Goerli
- Arbitrum One, Optimism, Base
- Polygon, Polygon zkEVM
- Linea, Scroll, Mantle, Taiko, Blast, Mode
- And more...

## Conclusion

CAFE transforms wallet security from a reactive, incident-driven process into a proactive, policy-driven capability. By automating the discovery, classification, and monitoring of wallet cryptographic assets, CAFE transforms quantum security from a theoretical concern into a manageable, measurable capability.

**Core Mission**: CAFE's primary focus is on **wallet security**—discovering vulnerable wallets, assessing quantum risks, and providing remediation services to migrate users to quantum-safe Account Abstraction wallets.

**TLS Scanning**: Our TLS endpoint scanning serves an informational purpose, helping users understand the security posture of the endpoints they connect to. While we verify TLS 1.3+ with post-quantum KEM support (what's feasible today), we acknowledge that pure PQC TLS is not yet possible due to pending PKI migration. CAFE does not provide TLS remediation services.

**Alpha Status**: CAFE is currently in alpha version. Results should be taken "as is" for testing and evaluation. Our current objective is to test and verify the interest of the Ethereum blockchain ecosystem in our solution and gather valuable feedback from early adopters.

CAFE is the first step in building crypto-agile infrastructure that can adapt to evolving threats while maintaining operational continuity and regulatory compliance.

---

## References

- [Post-Quantum Financial Infrastructure Framework (PQFIF)](https://www.sec.gov/about/crypto-task-force/written-submission/cft-written-input-daniel-bruno-corvelo-costa-090325)
- [ERC-4337: Account Abstraction](https://docs.erc4337.io/index.html)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [DORA: Digital Operational Resilience Act](https://finance.ec.europa.eu/regulation-and-supervision/financial-services-legislation/implementing-and-delegated-acts/digital-operational-resilience-act-dora_en)
- [Deloitte: Quantum Risk to the Ethereum Blockchain](https://www.deloitte.com/nl/en/services/consulting-risk/perspectives/quantum-risk-to-the-ethereum-blockchain.html)
