# CAFE — Functional Specifications

1. [CAFE — Functional Specifications](#cafe--functional-specifications)
   1. [Introduction](#introduction)
      1. [Application purpose](#application-purpose)
      2. [Functional scope](#functional-scope)
      3. [Technical scope (summary)](#technical-scope-summary)
   2. [Architecture](#architecture)
   3. [Compliance](#compliance)
      1. [Data collection and processing](#data-collection-and-processing)
      2. [User rights](#user-rights)
      3. [Security and data protection](#security-and-data-protection)
      4. [Consent and cookies](#consent-and-cookies)
      5. [Sub-processors and data sharing](#sub-processors-and-data-sharing)
      6. [Retention](#retention)
      7. [Contact](#contact)
   4. [Security](#security)
   5. [Features](#features)
      1. [User accounts and authentication](#user-accounts-and-authentication)
         1. [Create account](#create-account)
         2. [Read account](#read-account)
         3. [Update account](#update-account)
         4. [Delete account](#delete-account)
      2. [Wallet scans (Discovery)](#wallet-scans-discovery)
         1. [Create (queue scan)](#create-queue-scan)
         2. [Read](#read)
         3. [Update](#update)
         4. [Delete](#delete)
         5. [Lifecycle (API)](#lifecycle-api)
      3. [TLS scans (Discovery)](#tls-scans-discovery)
         1. [Create](#create)
         2. [Read](#read-1)
         3. [Delete](#delete-1)
         4. [CPM exclusion](#cpm-exclusion)
      4. [Cryptographic policies (CPM)](#cryptographic-policies-cpm)
         1. [Read catalog](#read-catalog)
         2. [Explore (preview)](#explore-preview)
         3. [Persist](#persist)
         4. [Read instances](#read-instances)
         5. [Delete](#delete-2)
         6. [Assessment (async)](#assessment-async)
      5. [Policy drafts (CPM)](#policy-drafts-cpm)
         1. [Create / read](#create--read)
         2. [Delete](#delete-3)
      6. [Remediation (product direction)](#remediation-product-direction)
      7. [Governance — scan immutability and CPM coupling](#governance--scan-immutability-and-cpm-coupling)
   6. [Data structures](#data-structures)
      1. [Scan list item (wallet)](#scan-list-item-wallet)
      2. [Scan detail (wallet)](#scan-detail-wallet)
      3. [Scan list item (TLS)](#scan-list-item-tls)
      4. [CPM policy instance](#cpm-policy-instance)
      5. [Discovery → CPM observation contract](#discovery--cpm-observation-contract)
   7. [Workflows](#workflows)
      1. [Queue wallet scan and read result](#queue-wallet-scan-and-read-result)
      2. [Create policy from scan (Option A)](#create-policy-from-scan-option-a)
      3. [Delete scan protected by policy (W3 / W4)](#delete-scan-protected-by-policy-w3--w4)
      4. [Rescan after failure (W8 + W1)](#rescan-after-failure-w8--w1)
      5. [Reject CPM on TLS scan](#reject-cpm-on-tls-scan)
   8. [Glossary](#glossary)
   9. [References](#references)

---

## Introduction

**CAFE** (*Crypto-Agility Framework for Ethereum*) is a platform that helps organizations **discover**, **govern**, and **remediate** cryptographic exposure on Ethereum and related infrastructure. The product focuses on **wallet quantum risk** (on-chain ECDSA exposure, account types, NIST levels) and provides **informational TLS endpoint audits** for blockchain infrastructure (RPC nodes, APIs, relays).

CAFE is currently in **alpha**. Results are provided for evaluation; APIs and behavior may evolve based on community feedback.

For a product narrative, see [01-introduction-cafe-crypto-agility.md](./01-introduction-cafe-crypto-agility.md). For integration details, see [03-cafe-developer-guide.md](./03-cafe-developer-guide.md).

### Application purpose

CAFE enables security and platform teams to:

1. **Inventory** cryptographic posture (wallets, algorithms, TLS handshakes) and produce evidence (CBOM).
2. **Define and enforce** institution-specific cryptographic policies against real scan results.
3. **Plan and execute** wallet remediation toward post-quantum–ready Account Abstraction configurations (roadmap).

The platform operationalizes crypto-agility: policies and scan results evolve under explicit rules rather than silent overwrites.

### Functional scope

| In scope (current release) | Out of scope (current release) |
| --- | --- |
| Authenticated wallet and TLS scan lifecycle under Discovery v1 | Pure post-quantum TLS certificates (PKI not ready) |
| Scan history per target; immutable terminal results | CPM policies or assessment on TLS `scan_id` |
| CPM catalog, explore, persist, drafts, async assessment (wallet) | Automated TLS endpoint remediation |
| CBOM per wallet `scan_id` (on-demand) | Native mobile clients |
| Owner-scoped lists, detail, delete with CPM guards | |

### Technical scope (summary)

CAFE is delivered as **multiple services** behind an edge proxy:

- **Discovery** — scan orchestration, persistence, public v1 HTTP API, authentication.
- **Crypto Policy Manager (CPM)** — policy catalog, decision exploration, persisted policies, drafts.
- **Remediation** — execution layer for PQC migration (roadmap; separate repository).
- **Frontend** — web UI for Discovery, CPM, and platform flows.
- **Deploy / edge** — routing, smoke tests, operational runbooks.

Normative HTTP contracts: [WORKPLAN_API.md](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/WORKPLAN_API.md) (maintainer source; French). Technical detail: [technical-specifications.md](./technical-specifications.md).

---

## Architecture

CAFE follows a **three-layer product architecture** plus shared infrastructure:

| Layer | Responsibility | Primary outputs |
| --- | --- | --- |
| **Discovery** | Identify on-chain and network exposures | Scan lists, detail DTOs, CBOM |
| **Crypto Policy Manager** | Govern cryptographic choices | Policy instances, compliance assessment |
| **Remediation** | Sign and migrate wallets with PQC + ZK (roadmap) | Signed operations, audit trail |
| **Infrastructure** | Deploy, monitor, secure the ecosystem | Metrics, logs, edge routing |

```text
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Frontend   │────▶│ Edge / API   │────▶│  Discovery  │
│  (browser)  │     │   gateway    │     │   (scans)   │
└─────────────┘     └──────┬───────┘     └──────┬──────┘
                           │                    │
                           ▼                    ▼
                    ┌──────────────┐     ┌─────────────┐
                    │     CPM      │◀────│  Scanners   │
                    │  (policies)  │     │  (wallet/TLS)│
                    └──────────────┘     └─────────────┘
```

**CPM integration:** the UI and CPM correlate work by **`scan_id`** from Discovery v1 wallet scans. TLS scans remain Discovery-only for product flows. See [docs/architecture/cpm-option-a-v1-flow.md](./docs/architecture/cpm-option-a-v1-flow.md).

---

## Compliance

### Data collection and processing

CAFE processes, per authenticated user:

- Account identifiers (email, session tokens).
- Wallet addresses and chain identifiers submitted for scans.
- TLS endpoint URLs submitted for scans.
- Scan results, policy payloads, and draft content owned by the user.
- Operational logs (access, errors) for security and support.

Processing is justified by **legitimate interest** in cryptographic risk assessment and contract fulfillment for alpha testers.

### User rights

Users may request, subject to applicable law:

- **Access** to personal data held for their account.
- **Rectification** of account metadata.
- **Erasure** (“right to be forgotten”) — account and owned artifacts deleted per product rules (scans, policies, drafts).
- **Portability** — export of owned scan and policy data where technically supported.

### Security and data protection

- **Encryption in transit:** TLS 1.2+ between clients and edge; post-quantum KEM where deployed on edge images.
- **Authentication:** session tokens issued by Discovery; CPM reuses the same Bearer token (no separate user JWT).
- **Authorization:** owner-scoped resources; scan and policy operations require authenticated identity matching resource owner.
- **Logging:** access and security events retained per operational policy (typically up to one year for audit).

### Consent and cookies

If analytics or non-essential cookies are enabled in a given deployment, users must be able to accept or refuse them and change preferences. A privacy notice must describe processing.

### Sub-processors and data sharing

Deployments may use cloud hosting, email, and CAPTCHA providers. Each sub-processor must meet contractual data-protection requirements. Cross-border transfers, if any, require documented safeguards.

### Retention

Scan rows and policies persist until the user deletes them or deletes their account, subject to backup retention windows. Terminal scan **`result`** payloads are not rewritten (immutability).

### Contact

Product and security contact points are defined per deployment (DPO where applicable).

---

## Security

CAFE follows [OWASP](https://owasp.org/) practices, including:

- **Authentication** via Discovery sign-in (password + bot protection where configured); optional PQC JWT algorithms on supported deployments.
- **Authorization** documented per feature (owner scope, CPM scan guards W1–W8).
- **Fail-closed** behavior when upstream Discovery or CPM lookups are unavailable for guards (no silent bypass of W1).
- **TLS scanning** is informational; it does not remediate endpoints.

**TLS and CPM:** CPM must **never** create or bind a persisted policy to a TLS `scan_id`. All CPM explore, persist, and assessment entry points reject TLS scans with **`404 not_found`** (or equivalent documented error). This is a hard product rule, not a defensive edge case.

---

## Features

### User accounts and authentication

#### Create account

- User signs up with email and password (and Turnstile or equivalent where enabled).
- Account is activated after verification rules configured for the deployment.

#### Read account

- Authenticated user can read own profile and session state.

#### Update account

- User can update allowed profile fields.

#### Delete account

- User can request account deletion; owned scans, policies, and drafts are removed per cascade rules.

### Wallet scans (Discovery)

#### Create (queue scan)

- **`POST /api/discovery/v1/scan`** with `{ "address": "0x…" }`.
- Server allocates **`scan_id`** (UUID) at acceptance (`requested`), before async pipeline publish.
- Guards (**W8**, then **W1**): refuse if a scan is in progress (`409 SCAN_IN_PROGRESS`) or if an active CPM policy or draft exists for the target address (`409 CPM_EXISTS_FOR_WALLET_TARGET`).
- Re-scan after **`failed`** is allowed when guards pass; creates a **new** row and **new** `scan_id`.

#### Read

- **List:** `GET /api/discovery/v1/wallets/scans` with pagination (`items`, `total`, `limit`, `offset`).
- **Filter by address:** `?address=0x…` returns all executions for that address (**W5**).
- **Filter by chain:** `?address=…&chain_id=N` ( `chain_id` alone → `400` ).
- **Latest completed:** `?address=…&latest=true` returns ≤1 item — newest **`completed`** only (**W2** helper for CPM/UI). Do not use `limit=1` alone as a substitute.
- **Detail:** `GET /api/discovery/v1/wallets/scans/{scan_id}` — full DTO including **`result`** when terminal.
- **CBOM:** `GET /api/discovery/v1/wallets/scans/{scan_id}/cbom` — generated on demand from that scan row (**W6**).

#### Update

- Lifecycle metadata (`status`, timestamps) may change until terminal state (`completed` or `failed`).
- After terminal state, **`result`** is **immutable** for that `scan_id`.

#### Delete

- **`DELETE /api/discovery/v1/wallets/scans/{scan_id}`** — owner only.
- **`409 SCAN_REFERENCED_BY_POLICY`** if a CPM persisted policy references this `scan_id` (**W3**). User must delete policies first.
- **`204`** when deleted; **`404`** when absent (idempotent second delete → `404`).

#### Lifecycle (API)

States: `requested` → `started` → `completed` | `failed` (or `requested` → `failed`). API must not expose legacy values `RUNNING` / `running` (use `started`).

### TLS scans (Discovery)

#### Create

- **`POST /api/discovery/v1/scan`** with `{ "url": "https://…" }` (mutually exclusive with `address`).
- Same immutability and history rules as wallet scans, scoped per URL.

#### Read

- **List:** `GET /api/discovery/v1/tls/scans`.
- **Defaults catalog:** `GET /api/discovery/v1/tls/scans/defaults`.
- **Detail:** `GET /api/discovery/v1/tls/scans/{scan_id}`.
- Optional: `GET …/tls/scans/{scan_id}/cbom` where implemented.

#### Delete

- **`DELETE /api/discovery/v1/tls/scans/{scan_id}`** — same owner and idempotence rules as wallet scans.
- No CPM product flows bind to TLS scans; defensive `409` for policy reference should not occur in normal operation.

#### CPM exclusion

- No explore, persist, or assessment on TLS `scan_id`. Attempts return **`404 not_found`**.

### Cryptographic policies (CPM)

#### Read catalog

- **`GET /api/cpm/v1/policies/catalog`**, **`/templates`**, **`/instances`** — authenticated.

#### Explore (preview)

- **`POST /api/cpm/v1/policies/decisions/explore`** with `scan_id`, **`policy_context`**, `selection_request`.
- Guards: **W7** (newest row must be `completed`), **W2** (`scan_id` must match latest completed for target), wallet-only (**TLS → 404**).

#### Persist

- **`POST /api/cpm/v1/policies`** with `binding=discovery`, `scan_id`, payload.
- Same guards as explore.

#### Read instances

- **`GET /api/cpm/v1/policies`** — list owner policies; filter by `scan_id` query param.

#### Delete

- **`DELETE /api/cpm/v1/policies?id=…`** — removes policy only; scans unchanged (**W4**).

#### Assessment (async)

- **`POST /api/cpm/v1/policies/assessment/request`** — wallet scans only; server loads Discovery detail; client must not send `policy_context`.

### Policy drafts (CPM)

#### Create / read

- **`POST /api/cpm/v1/drafts`**, **`GET /api/cpm/v1/drafts?id=…`** — owner-scoped working state before persist.

#### Delete

- **`DELETE /api/cpm/v1/drafts?id=…`** — removes platform draft; satisfies **W1** for rescan when no persisted policy remains.

### Remediation (product direction)

Remediation will consume CPM policy outcomes to plan and execute wallet migration (PQC keys, ERC-4337 UserOps). It is **not** part of the immutability v1 API surface documented here. TLS remediation is explicitly out of scope.

### Governance — scan immutability and CPM coupling

Rules **W1–W8** apply to **wallet** targets with CPM `binding=discovery`:

| ID | Rule | Discovery | CPM |
| --- | --- | --- | --- |
| **W1** | At most one active CPM context per address (persisted policy **or** draft) | `POST …/scan` → `409 CPM_EXISTS_FOR_WALLET_TARGET` | Lookup policies + drafts by address |
| **W2** | CPM only on latest **`completed`** scan | `GET …/wallets/scans?address=&latest=true` | `400` if `scan_id` ≠ latest completed |
| **W3** | Delete scan only after policies removed | `409 SCAN_REFERENCED_BY_POLICY` | User deletes policies first |
| **W4** | Delete policy does not delete scans | Unchanged | `DELETE …/policies?id=` only |
| **W5** | History per address | `GET …/wallets/scans?address=` | Read-only correlation |
| **W6** | CBOM per scan execution | `GET …/wallets/scans/{scan_id}/cbom` | No CBOM storage |
| **W7** | CPM blocked until newest row is **`completed`** | No POST guard | `400 LATEST_SCAN_NOT_COMPLETED` |
| **W8** | Rescan blocked only while in progress | `409 SCAN_IN_PROGRESS` if `requested`/`started` | Independent of W7 |

**Guard order:** `POST …/scan` — **W8** then **W1**. CPM explore/persist — **W7** then **W2**.

**W7 vs W8:** CPM may stay blocked while Discovery allows rescan after `failed` (e.g. completed scan A + newer failed scan B).

**Client UX (draft + rescan):** when a platform draft blocks W1, the UI may offer: local export → delete draft → new scan → reload local draft only if `target_address` and `wallet_type` match the new latest completed scan. See [cafe-frontend IMMUTABILITE.md](https://github.com/create2-labs/cafe-frontend/blob/main/IMMUTABILITE.md).

---

## Data structures

### Scan list item (wallet)

| Field | Description |
| --- | --- |
| `scan_id` | UUID; stable for the lifetime of the row |
| `created_at` | Creation timestamp |
| `status` | Lifecycle only: `requested`, `started`, `completed`, `failed` |
| `target_address` | Normalized EVM address when known |
| `chain_ids` | Chains observed for this execution (may be multiple) |

### Scan detail (wallet)

| Field | Description |
| --- | --- |
| `scan_id`, `status`, `scan_family` | Identity and lifecycle |
| `result` | Terminal immutable payload (observation, risk, algorithms) |
| `policy_context` | Subset used by CPM explore (from detail projection) |

### Scan list item (TLS)

| Field | Description |
| --- | --- |
| `scan_id` | UUID |
| `endpoint` | URL or stable display identifier |
| `created_at`, `status` | As for wallet |

### CPM policy instance

| Field | Description |
| --- | --- |
| `id` | Policy instance identifier |
| `scan_id` | Discovery wallet scan UUID (`binding=discovery`) |
| `payload` | Policy document body |

### Discovery → CPM observation contract

Wire event: `cafe.discovery.wallet.observed` v0.1 — see [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) and [CPM README](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md).

---

## Workflows

### Queue wallet scan and read result

1. User authenticates (`POST /auth/signin`).
2. User calls `POST /api/discovery/v1/scan` with address.
3. Client polls `GET …/wallets/scans/{scan_id}` until `completed` or `failed`.
4. User views `result` and optional `…/cbom`.

### Create policy from scan (Option A)

1. List scans: `GET …/wallets/scans?address=…`.
2. Load detail for selected `scan_id`.
3. Explore: `POST …/policies/decisions/explore` with `policy_context`.
4. Persist: `POST …/policies` with same `scan_id`.

### Delete scan protected by policy (W3 / W4)

1. `DELETE …/wallets/scans/{scan_id}` → `409 SCAN_REFERENCED_BY_POLICY`.
2. `GET …/policies?scan_id=…` — list policies.
3. `DELETE …/policies?id=…` for each — scans remain.
4. `DELETE …/wallets/scans/{scan_id}` → `204`.

### Rescan after failure (W8 + W1)

1. Newest scan `failed`; no policy/draft → `POST …/scan` accepted.
2. New `scan_id` allocated; CPM may still return `400` until newest is `completed` (**W7**).

### Reject CPM on TLS scan

1. User obtains TLS `scan_id` from Discovery.
2. `POST …/policies/decisions/explore` with TLS `scan_id` → **`404 not_found`**.

---

## Glossary

| Term | Definition |
| --- | --- |
| **CAFE** | Crypto-Agility Framework for Ethereum |
| **CBOM** | Cryptographic Bill of Materials (CycloneDX-style inventory) |
| **CPM** | Crypto Policy Manager service |
| **Discovery** | Scan orchestration and observation service |
| **EOA** | Externally Owned Account (classical ECDSA wallet) |
| **Option A** | CPM integration path using real Discovery v1 `scan_id` |
| **PQC** | Post-quantum cryptography |
| **scan_id** | UUID identifying one scan execution row |
| **W1–W8** | Wallet/CPM coupling rules (see governance table) |

---

## References

| Document | Role |
| --- | --- |
| [01-introduction-cafe-crypto-agility.md](./01-introduction-cafe-crypto-agility.md) | Product introduction |
| [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) | API v1 integration guide |
| [technical-specifications.md](./technical-specifications.md) | Technical architecture and implementation |
| [WORKPLAN_API.md](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/WORKPLAN_API.md) | Normative HTTP contract (maintainer) |
| [IMMUTABILITE_PR.md](https://github.com/create2-labs/cafe-discovery/blob/main/IMMUTABILITE_PR.md) | Discovery immutability PR plan |
| [api-v1-qa-checklist.md](./docs/api/api-v1-qa-checklist.md) | QA checklist |
| [cafe-deploy README — smoke scripts](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) | End-to-end test scripts |
