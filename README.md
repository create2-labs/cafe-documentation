# CAFE Documentation

This directory contains the official documentation for the CAFE (Crypto-Agility Framework for Ethereum) project. Last updated: September 2026.

## Available Documents

### Specifications (English)

- **[functional-specifications.md](./functional-specifications.md)** — CAFE product behavior: Discovery scans, CPM policies, CPM UI user stories (**US1–US21**), governance rules (W1–W8), workflows, and compliance overview
- **[technical-specifications.md](./technical-specifications.md)** — CAFE technical architecture: services, APIs, persistence, messaging, deployment (including **Cloudflare Tunnel** home hosting), and testing

> **Note:** [specs-fonctionnelles.md](./specs-fonctionnelles.md) is a deprecated stub. It previously held a legacy *Ponybook* document; use the English specifications above.

### Introduction

- **[01-introduction-cafe-crypto-agility.md](./01-introduction-cafe-crypto-agility.md)** — Introduction to CAFE and the crypto-agility problem for the Ethereum blockchain

### User Guide

- **[02-cafe-user-guide.md](./02-cafe-user-guide.md)** — Complete user guide for the CAFE frontend: navigation (Discovery, Platform, CPM, Remediation), **Crypto Policy Management** two-layer workflow (catalogue Crypto Policy → scan-compatible providers → user constraints → persist), catalog provider table, greenfield empty-chain explore, multi-chain provider choice, account-based access, and all features

### Developer Guide

- [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) — Canonical API v1 developer guide for Discovery (`/api/discovery/v1`) and CPM (`/api/cpm/v1`), including **dual local deployments** (cafe-deploy Compose + cafe-expresso minikube), edge at **`http://localhost:8080`** on minikube for signup/signin, scan `scan_id` correlation, CPM-owned policy assessment, **product catalogue** (`/crypto-policies*` + derived `compatible_networks` + `allowed_provider_summaries`; `/providers*` ops-only), **explore v0.2** (greenfield empty `chain_ids`, `scan_compatible_providers` + `composition`), **persist** (CPM snapshot assist with multi-chain `chain_support_used[]` + `user_constraints`), and QA sign-off checks.

### Admin Guide

- [04-cafe-admin-guide.md](./04-cafe-admin-guide.md) — Platform administration for **Compose and minikube**: environments, Helm/kubectl deploy, ingress edge, **Cloudflare Tunnel** (home / no inbound ports), deploy and health checks (`/api/version`, `/api/cpm/version`), pgweb, CPM catalogue (read-only mount of `cafe-deploy/catalogs/cpm/files`, pins `CPM_VERSION` + `CPM_CATALOGUE_REVISION`, recreate without a new image), ADR §7.2.1 signals (catalogue and runtime), observability, operator diagnosis, and user-support scenarios.

### Architecture

- [CPM — Discovery v1 to policy flow](./docs/architecture/cpm-v1-flow.md) — Option A: scan → catalogue CP → explore (couche A, W2) → local composition (NB2) → signed persist; **no server drafts**; links ADR_20260824 + OpenAPI.
- [CAFE MBSE / SysML Modelio project](./docs/architecture/cafe-mbse-sysml-modelio-project.md) — Step-by-step project plan to build a SysML/MBSE model of CAFE for Modelio (**out of scope / not started** for the Capability Provider amendement train — see ADR PR plan). From system context and logical architecture to behavior flows, state machines, and traceability.
- [CPM UI specifications (`cafe-frontend/CPM-specs-ui.md`)](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) — Normative CPM page user stories **US1–US21** and delivery epics **CPM-UI-1…8** (solution profile view, scénario A).
- [ADR — Capability Provider abstraction (ADR_20260803)](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) — ADR governing the Capability Provider model: two-layer explore/persist, `ProviderManifest`, `SolutionProfile`, posture matching, Nicetry pilote.
- [ADR — CPM catalog facts / FE boundary (ADR_20260918)](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260918_cpm_catalog_facts_frontend_boundary.md) — CPM certifies catalogue/explore/persist facts; product FE does not mirror providers or join `GET /providers`; [PR plan CFB-\*](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260918_cpm_catalog_facts_frontend_boundary_PR_PLAN.md).
- [ADR — Remove CP drafts (ADR_20260824)](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md) — No `/drafts*`; signed `POST /policies`; W2; NB1/NB2; [PR plan](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts_PR_PLAN.md).
- [CPM README — Capability Providers](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md) — CPM service README covering the provider model, env var (`CPM_CATALOGUE_DIR`), explore v0.2 (incl. greenfield), persist `user_constraints` + multi-chain snapshot, catalogue/runtime signals.

### API QA

- [API v1 QA Checklist](./docs/api/api-v1-qa-checklist.md) — Compact reviewer checklist for route names, retired catalog paths, explore v0.2 / assessment ownership, delete semantics, and cross-repository follow-up.

### Security and Operations

- [CPM Auth contract](./docs/security/cpm-contract.md) — Authenticated CPM behavior, scan authorization, owner-scoped **policies** (no `/drafts*`), error contract (explore legacy **400**, W2 / persist codes, assessment v0.2)
- [CP-PERSIST (no drafts)](./docs/security/cp-persist-v1.md) — Signed `POST /policies`, `payload_sha256`, W2, NB1/NB2; links ADR + OpenAPI + `CP_PERSIST.md`
- [CPM explore — no scan-compatible provider (observability & admin diagnosis)](./docs/operations/cpm-explore-no-candidate-observability.md) — **REQ9** / **IMM-OPS-1…2**: runtime signal `runtime.no_scan_compatible`, structured logs, Prometheus/Grafana, `curl` admin workflow (complements user-facing **REQ8** in the SPA; couche B is a separate signal)

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
