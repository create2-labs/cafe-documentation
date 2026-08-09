# CAFE Documentation

This directory contains the official documentation for the CAFE (Crypto-Agility Framework for Ethereum) project. Last updated: August 2026.

## Available Documents

### Specifications (English)

- **[functional-specifications.md](./functional-specifications.md)** — CAFE product behavior: Discovery scans, CPM policies, CPM UI user stories (**US1–US21**), governance rules (W1–W8), workflows, and compliance overview
- **[technical-specifications.md](./technical-specifications.md)** — CAFE technical architecture: services, APIs, persistence, messaging, deployment (including **Cloudflare Tunnel** home hosting), and testing

> **Note:** [specs-fonctionnelles.md](./specs-fonctionnelles.md) is a deprecated stub. It previously held a legacy *Ponybook* document; use the English specifications above.

### Introduction

- **[01-introduction-cafe-crypto-agility.md](./01-introduction-cafe-crypto-agility.md)** — Introduction to CAFE and the crypto-agility problem for the Ethereum blockchain

### User Guide

- **[02-cafe-user-guide.md](./02-cafe-user-guide.md)** — Complete user guide for the CAFE frontend: navigation (Discovery, Platform, CPM, Remediation), **Crypto Policy Management** graph workflow, account-based access, and all features

### Developer Guide

- [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) — Canonical API v1 developer guide for Discovery (`/api/discovery/v1`) and CPM (`/api/cpm/v1`), including **dual local deployments** (cafe-deploy Compose + cafe-expresso minikube), edge at **`http://localhost:8080`** on minikube for signup/signin, scan `scan_id` correlation, CPM-owned policy assessment, and QA sign-off checks.

### Admin Guide

- [04-cafe-admin-guide.md](./04-cafe-admin-guide.md) — Platform administration for **Compose and minikube**: environments, Helm/kubectl deploy, ingress edge, **Cloudflare Tunnel** (home / no inbound ports), deploy and health checks (`/api/version`, `/api/cpm/version`), pgweb, CPM catalog, observability, operator diagnosis, and user-support scenarios.

### Architecture

- [CPM — Discovery v1 to policy flow](./docs/architecture/cpm-v1-flow.md) — What Option A is (post-V1 real scan context via Discovery); scan → list/detail → explore → persist; links to [CPM design workplan](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/CPM_post_v_1_option_a_scan_context.md) and maintainer contracts.
- [CAFE MBSE / SysML Modelio project](./docs/architecture/cafe-mbse-sysml-modelio-project.md) — Step-by-step project plan to build a SysML/MBSE model of CAFE for Modelio, from system context and logical architecture to behavior flows, state machines, and traceability.
- [CPM UI specifications (`cafe-frontend/CPM-specs-ui.md`)](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) — Normative CPM page user stories **US1–US21** and delivery epics **CPM-UI-1…8** (graph workspace, persist UX).

### API QA

- [API v1 QA Checklist](./docs/api/api-v1-qa-checklist.md) — Compact reviewer checklist for route names, removed paths, assessment ownership, delete semantics, and cross-repository follow-up.

### Security and Operations

- [CPM Auth contract](./docs/security/cpm-contract.md) — Authenticated CPM behavior, scan authorization, owner-scoped persistence, error contract
- [CPM explore — no deployable candidate (observability & admin diagnosis)](./docs/operations/cpm-explore-no-candidate-observability.md) — **REQ9** / **IMM-OPS-1…2**: structured logs, Prometheus/Grafana, `curl` admin workflow, `incompatible.chain_scope` diagnosis (complements user-facing **REQ8** in the SPA)

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
- [Crypto Policy Management (`cafe-crypto-policy-mgt`)](https://github.com/create2-labs/cafe-crypto-policy-mgt) — Policy service; normative contract and vocabulary for Discovery exports
- [Frontend Repository](../cafe-frontend/) — User interface
- [cafe-deploy](https://github.com/create2-labs/cafe-deploy) — Docker Compose deployment (VM / local / **Cloudflare Tunnel** home)
- [cafe-deploy — Cloudflare Tunnel (README)](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#cloudflare-tunnel-home--no-inbound-ports) — Prod-tunnel compose + `cloudflared` quick path
- [cafe-deploy — Home selfhosted guide](https://github.com/create2-labs/cafe-deploy/blob/main/docs/CAFE_selfhosted.md) — OpenWrt, DNS, tunnel, firewall end-to-end
- [cafe-expresso](https://github.com/create2-labs/cafe-expresso) — minikube / Helm / Argo CD (Kubernetes P0)
- [Crypto backend Repository](https://github.com/create2-labs/cafe-crypto-backend) — Cryptographic backend; tooling for building and running applications with Post-Quantum Cryptography (PQC) support
- [Edge Repository](https://github.com/create2-labs/cafe-edge) — Reverse-proxy images with PQC
- [TLS scanner Repository](https://github.com/create2-labs/cafe-scanner-tls) — TLS scanner service with PQC
- [CAFE Website](../cafe-website/) — Public website

## Contributing

To contribute to the documentation, please follow Markdown formatting conventions and maintain consistency with existing documents.
