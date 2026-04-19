# CAFE Documentation

This directory contains the official documentation for the CAFE (Crypto-Agility Framework for Ethereum) project. Last updated: April 2026.

## Available Documents

### Introduction

- **[01-introduction-cafe-crypto-agility.md](./01-introduction-cafe-crypto-agility.md)** — Introduction to CAFE and the crypto-agility problem for the Ethereum blockchain

### User Guide

- **[02-cafe-user-guide.md](./02-cafe-user-guide.md)** — Complete user guide for the CAFE frontend: navigation (Discovery, Platform, CPM, Remediation), anonymous mode (view-only without account; sign-in to run scans), and all features

### Developer Guide

- [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) — Complete developer guide with API documentation (including anonymous token and anonymous scan endpoints), code examples in multiple languages (cURL, Go, Python, Java, JavaScript), and the Discovery -> CPM normalized wallet observation contract (`discovery.wallet.observed` v0.1) for cross-service integration

## About CAFE

CAFE (Crypto-Agility Framework for Ethereum) is a three-service platform designed to discover, govern, and remediate cryptographic assets on Ethereum—ensuring compliance, resilience, and trust in the post-quantum and zero-knowledge era.

### Architecture

CAFE is composed of three main services:

1. **Discovery** — Identification of on-chain and network quantum exposures
2. **Crypto Policy Manager** — Definition and enforcement of cryptographic policies
3. **Remediation** — Secure migration and attested key operations

## Additional Resources

- [CAFE Whitepaper](https://github.com/create2-labs/cafe-whitepaper) — May be private while content is prepared for public release
- [Discovery Repository](../cafe-discovery/) — Cryptographic discovery service with PQC (see README *Data structure (CPM export contract)* for the CPM-facing observation shape)
- [Crypto Policy Management (`cafe-cpm`)](https://github.com/create2-labs/cafe-cpm) — Policy service; normative contract and vocabulary for Discovery exports
- [Frontend Repository](../cafe-frontend/) — User interface
- [Infrastructure Repository](../cafe-infra/) — Infrastructure and deployment
- [Crypto backend Repository](https://github.com/create2-labs/cafe-crypto-backend) — Cryptographic backend; tooling for building and running applications with Post-Quantum Cryptography (PQC) support
- [Edge Repository](https://github.com/create2-labs/cafe-edge) — Reverse-proxy images with PQC
- [TLS scanner Repository](https://github.com/create2-labs/cafe-scanner-tls) — TLS scanner service with PQC
- [CAFE Website](../cafe-website/) — Public website
- Deploy repository is not public for security reasons; deployment is straightforward to reproduce without it

## Contributing

To contribute to the documentation, please follow Markdown formatting conventions and maintain consistency with existing documents.
