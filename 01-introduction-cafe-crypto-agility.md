# CAFE: Crypto-Agility Framework for Ethereum

## Introduction

Quantum computing is arriving. It promises major advances in many fields, but this disruptive power also threatens the cryptographic foundations that protect our digital world. Quantum algorithms such as Shor's and Grover's threaten to compromise the asymmetric and symmetric cryptography that secures today's internet communications, financial systems, blockchain networks, and digital identities.

The transition to quantum-resistant cryptography (*post-quantum cryptography* or *PQC*) has become an urgent global priority. Understanding and mitigating this quantum threat is essential to preserve the confidentiality, integrity, and authenticity of our digital assets in the quantum era.

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

### Network Layer Risk

Beyond wallet-level risks, the transport layer (TLS/HTTPS) connecting users to blockchain infrastructure also presents quantum vulnerabilities:

- Most RPC nodes, APIs, and blockchain services use classical TLS (ECDHE/ECDSA or RSA)
- Certificate Authorities still issue X.509 certificates signed with quantum-vulnerable algorithms
- Few infrastructures deploy post-quantum TLS (hybrid Kyber/Dilithium modes)

This means that even if a wallet is locally secure, the communication channel may remain vulnerable to future quantum attacks.

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
| Signature        | ECDSA (secp256k1)             | ❌ Broken by Shor             | Replace via smart-wallet               |
| Address          | Keccak-256(pubkey) → 20 bytes | ✅ Grover-safe (~128-bit)     | Keep short hashes              |
| Storage funds    | Hidden pubkey                 | ✅ Safe (for now)             | Avoid reusing addresses                |
| Active wallets   | Pubkey exposed                | ⚠️ Vulnerable on quantum day | Move to ERC-4337                       |
| PQC-ready option | None natively                 | 🚧 In research               | Use ERC-4337 upgradeable policy |

## The Solution: Crypto-Agility Framework for Ethereum (CAFE)

### What is Crypto-Agility?

[Crypto-agility](https://www.ibm.com/quantum/blog/crypto-agility) is a process to adapt cryptographic mechanisms in response to evolving threats, without disrupting core functionality. In a world moving toward quantum computing, crypto-agility becomes a strategic necessity: it ensures that organizations can replace or upgrade vulnerable algorithms (such as RSA or ECDSA) with quantum-resistant alternatives as they mature and are standardized.

Rather than a one-time migration, crypto-agility establishes a continuous capability—to define, enforce, and evolve cryptographic policies across distributed systems, applications, and blockchains. It transforms security from a static configuration into a dynamic, policy-driven process, enabling resilience, compliance, and long-term trust in the post-quantum era.

### CAFE Overview

**Crypto-Agility Framework for Ethereum (CAFE)** is a three-service platform designed to discover, govern, and remediate cryptographic assets on Ethereum—ensuring compliance, resilience, and trust in the post-quantum and zero-knowledge era.

CAFE operationalizes PQFIF principles on Ethereum with ERC-4337 AA wallets, confidential computing, and ZK-verifiable policy enforcement.

CAFE delivers significant value under DORA (*Digital Operational Resilience Act*), as DORA applies to financial institutions and their ICT service providers—especially those handling cryptography, keys, transaction integrity, or critical digital operations. CAFE gives institutions the technical evidence and resilience mechanisms that DORA expects.

### Three-Layer Architecture

CAFE unifies four integrated layers:

| Service        | Goal                                                                  | Key Functions                                        | Output                          |
| ------------------ | ------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------- |
| **Discovery**      | Identify on-chain and network quantum exposures                           | Wallet scan, EOA/AA detection, TLS audit, NIST level     | On-chain CBOM (Crypto BOM)          |
| **Crypto Policy Manager**        | Define and apply cryptographic governance policies                        | JSON policy, enforcement API                             | Policy snapshot + compliance status |
| **Remediation**    | Securely sign and migrate wallets using PQC + ZK  | Key generation, ZK attestation, proxy signing (ERC-4337) | Signed TX + verifiable audit logs   |
| **Infrastructure** | Orchestrate and monitor the full CAFE ecosystem                           | Resource provisioning, telemetry, message bus          | Logs, metrics, audit trail          |

### Discovery: Cryptographic Visibility and Risk Mapping

**Discovery** is the entry point of CAFE. It provides a complete, verifiable inventory of an institution's cryptographic posture across Ethereum and connected systems.

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

**Endpoint TLS Security Audit**

Discovery evaluates the quantum-security posture of blockchain endpoints (RPC nodes, APIs, relays) by analyzing:

- TLS Version — Detection of TLS 1.2 vs 1.3
- Cipher Suites — Analysis of negotiated encryption algorithms
- Post-Quantum Readiness — Detection of PQC algorithms (ML-KEM, ML-DSA, etc.)
- Certificate Analysis — Evaluation of X.509 certificate signatures and chains
- NIST Security Levels — Classification of cryptographic components according to NIST PQC standards

**Cryptographic Bill of Materials (CBOM)**

Discovery generates standardized CBOM entries that provide a complete inventory of cryptographic assets, including:

- Algorithms in use (ECDSA, Keccak, Blake2, etc.)
- NIST security levels
- Hash functions used for entropy and signing
- Presence or absence of PQC

### Crypto Policy Manager: Governance, Policies, and Continuous Compliance

The **Crypto Policy Manager** transforms cryptographic visibility into actionable governance.

#### Objectives

Enable institutions to define, enforce, and attest cryptographic policies across Ethereum operations—ensuring alignment with DORA, NIST, ANSSI, and internal risk frameworks.

#### Core Functions

- **Cryptographic Policy Definition** — Institutions define JSON-based rules (minimum NIST level, mandatory PQC algorithms, rotation cycles, etc.)
- **Automated Policy Validation** — Every operation is checked against the policy framework
- **Continuous Monitoring** — Tracks deviations, drifts, and exceptions over time
- **ZK Compliance Proofs** — Policies can be proven without exposing sensitive data

### Remediation: PQC Migration and Attested Key Operations

**Remediation** is CAFE's execution layer: it performs cryptographic operations under strict guarantees of confidentiality, integrity, and policy compliance.

#### Objectives

Upgrade vulnerable assets, securely generate new keys, and sign Ethereum transactions using PQC algorithms—without ever exposing private keys.

#### Core Functions

- **Secure Key Generation (PQC + Hybrid)** — Generates ML-DSA / Falcon / hybrid classical-PQC keys entirely within user resources
- **Account Migration (EOA → AA)** — Automated creation of quantum-safe Account Abstraction wallets (ERC-4337 / EIP-7702)
- **Proxy Signing (ERC-4337)** — Signs user operations (UserOps) without exposing private material
- **Zero-Knowledge Attestations** — Every signature, key generation, or migration step can be validated using ZK proofs

### Infrastructure: Orchestration, Monitoring, and Evidence Generation

The **Infrastructure** layer binds the entire CAFE platform together.

#### Core Functions

- **Telemetry and Observability** — Collects logs, metrics, traces, and events
- **Message Bus and Workflow Routing** — Coordinates operations between Discovery, Crypto Policy Manager, and Remediation
- **Attested Evidence Pipeline** — Produces CBOM updates, compliance certificates, ZK proofs, and DORA-ready audit reports

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

CAFE transforms cryptographic security from a reactive, incident-driven process into a proactive, policy-driven capability. By automating the discovery, classification, and monitoring of cryptographic assets, CAFE transforms quantum security from a theoretical concern into a manageable, measurable capability.

CAFE is the first step in building crypto-agile infrastructure that can adapt to evolving threats while maintaining operational continuity and regulatory compliance.

---

## References

- [Post-Quantum Financial Infrastructure Framework (PQFIF)](https://www.sec.gov/about/crypto-task-force/written-submission/cft-written-input-daniel-bruno-corvelo-costa-090325)
- [ERC-4337: Account Abstraction](https://docs.erc4337.io/index.html)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [DORA: Digital Operational Resilience Act](https://finance.ec.europa.eu/regulation-and-supervision/financial-services-legislation/implementing-and-delegated-acts/digital-operational-resilience-act-dora_en)
- [Deloitte: Quantum Risk to the Ethereum Blockchain](https://www.deloitte.com/nl/en/services/consulting-risk/perspectives/quantum-risk-to-the-ethereum-blockchain.html)
