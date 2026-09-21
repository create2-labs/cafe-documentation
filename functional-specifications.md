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
         1. [Read catalogue](#read-catalogue)
         2. [Explore (preview) — couche A](#explore-preview--couche-a)
         3. [Persist (EOA -- CP-PERSIST V1) — rejeu A+B](#persist-eoa----cp-persist-v1--rejeu-ab)
         4. [Read policies](#read-policies)
         5. [Delete](#delete-2)
         6. [Assessment (async)](#assessment-async)
      5. [Composition (no server draft)](#composition-no-server-draft)
         1. [Create / read](#create--read)
         2. [Delete](#delete-3)
      6. [Remediation (product direction)](#remediation-product-direction)
      7. [Governance — scan immutability and CPM coupling](#governance--scan-immutability-and-cpm-coupling)
      8. [Platform observability — CPM explore (REQ9)](#platform-observability--cpm-explore-no-scan-compatible-provider-req9)
      9. [Platform Status — deployed service versions (US18)](#platform-status--deployed-service-versions-us18)
      10. [CPM user interface — graph workspace (US1–US21)](#cpm-user-interface--graph-workspace-us1us21)
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
| CPM catalog, explore, signed persist, async assessment (wallet) | Automated TLS endpoint remediation |
| CBOM per wallet `scan_id` (on-demand) | Native mobile clients |
| Owner-scoped lists, detail, delete with CPM guards | |

### Technical scope (summary)

CAFE is delivered as **multiple services** behind an edge proxy:

- **Discovery** — scan orchestration, persistence, public v1 HTTP API, authentication.
- **Crypto Policy Manager (CPM)** — policy catalog, decision exploration, persisted policies (client composition only — no server drafts).
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

**CPM integration:** the UI and CPM correlate work by **`scan_id`** from Discovery v1 wallet scans. TLS scans remain Discovery-only for product flows. See [docs/architecture/cpm-v1-flow.md](./docs/architecture/cpm-v1-flow.md).

---

## Compliance

### Data collection and processing

CAFE processes, per authenticated user:

- Account identifiers (email, session tokens).
- Wallet addresses and chain identifiers submitted for scans.
- TLS endpoint URLs submitted for scans.
- Scan results and policy payloads owned by the user.
- Operational logs (access, errors) for security and support.

Processing is justified by **legitimate interest** in cryptographic risk assessment and contract fulfillment for alpha testers.

### User rights

Users may request, subject to applicable law:

- **Access** to personal data held for their account.
- **Rectification** of account metadata.
- **Erasure** (“right to be forgotten”) — account and owned artifacts deleted per product rules (scans, policies).
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

- User can request account deletion; owned scans and policies are removed per cascade rules.

### Wallet scans (Discovery)

#### Create (queue scan)

- **`POST /api/discovery/v1/scan`** with `{ "address": "0x…" }`.
- Server allocates **`scan_id`** (UUID) at acceptance (`requested`), before async pipeline publish.
- Guards (**W8**, then **W1**): refuse if a scan is in progress (`409 SCAN_IN_PROGRESS`) or if a **persisted CPM policy** exists for the target address (`409`, prefer `blocking_kind: "policy"`). There is **no** platform draft resource that blocks or accompanies rescan.
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

#### Read catalogue

- **`GET /api/cpm/v1/crypto-policies`**, **`GET /api/cpm/v1/crypto-policies/{crypto_policy_id}`** — authenticated; Crypto Policy intention (`required_posture` + `allowed_providers`) plus CPM-derived **`compatible_networks`** (deployable chains from allowed provider manifests; `planned` excluded). This is the **product** catalogue contract for the SPA.
- **`GET /api/cpm/v1/providers`**, **`GET /api/cpm/v1/providers/{provider_id}`** — authenticated; Capability Provider manifests. **Ops / admin / debug only** — not the product FE contract for catalog display, Expected result, rejection messaging, or persist snapshot assembly ([ADR_20260918](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260918_cpm_catalog_facts_frontend_boundary.md)).
- Static files are loaded at CPM startup via `CPM_CRYPTO_POLICY_PATHS` and `CPM_PROVIDER_MANIFEST_PATHS`; administration is documented in [04-cafe-admin-guide.md](./04-cafe-admin-guide.md#cpm-catalogue-administration).
- **Retired (not live):** `/policies/templates`, `/policies/instances`, `/policies/catalog`.

#### Explore (preview) — couche A

- **`POST /api/cpm/v1/policies/decisions/explore`** with optional `scan_id`, **`crypto_policy_id`**, **`policy_context`**.
- Guards: **W2** (`scan_id` must match latest completed for owner+address), wallet-only (**TLS -> 404**). Discovery fail-closed → **503**.
- **Wire v0.2:** no `selection_request`; no couche B fields (`allow_new_wallet`, `address_continuity_required`, `key_rotation_model`, `target_posture`). Legacy explore → HTTP **400**.
- **Couche A (ADR amendement):** CPM returns **`scan_compatible_providers`** by matching catalogue CP posture + `allowed_providers` against provider SolutionProfiles (deployable chain + capabilities, including `rotate_signer` when profile is `per_userop`). Hard codes: `incompatible.posture`, `incompatible.provider.chain`, `incompatible.provider.rotation`, `incompatible.provider.wallet_type`. Response carries `required_posture`, `resulting_posture`, `solution_profile_ref`, `maturity`, `claim_status`, soft findings, indicative **`suggested_user_constraints`**, and derived **`composition`** (Expected result facts). No `graphEdges` / `nodeInstances` / `node_path`. The SPA displays explore facts as-is (**option A**) and does **not** call `GET /providers` to reformulate.
- **Vocabulary:** **scan-compatible** (couche A), **user-qualified** (couche B UI indicative), **persistable** (CPM rejeu A+B). Avoid `ranked_candidates` as normative vocabulary.
- **`claim_status: "declared"`** means the provider declared this capability -- it is **not** an audited or executed proof.
- **No scan-compatible provider (HTTP 200):** when `scan_compatible_providers` is empty and `rejected_candidates` is non-empty, the response is still **success**. The SPA explains why (**REQ8**). Platform ops consume **REQ9** / ADR §7.2.1 family-2 signal ([operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md)): `cpm.explore.no_deployable_candidate` + `adr_signal=runtime.no_scan_compatible`, counter `cpm_explore_no_deployable_candidate_total`.

#### Persist (EOA — signed `POST /policies`) — rejeu A+B

- **Normative EOA path:** `POST /api/cpm/v1/wallet-challenges` (stateless canonical message + `payload_sha256`) → EIP-191 / `personal_sign` → **`POST /api/cpm/v1/policies`** with closed `payload` + `signed_message` + `signature`.
- **Wallet proof required** for persist. Scan, explore, and **local composition** (NB2 sessionStorage) do **not** require proof.
- **No server drafts:** `/api/cpm/v1/drafts*` removed ([ADR_20260824](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md)).
- **Persist payload v0.2:** `schema_version: "cafe.crypto_policy.v0.2"` with closed hashed fields including top-level **`accepted_findings`**. Server computes/stores `payload_sha256` (JCS). Clients obtain `accepted_provider_snapshot` from CPM (`POST /accepted-provider-snapshots`) — not from a frontend provider mirror. Nicetry refs are pinned (**CPM-P7** done).
- CPM **rejoue couche A then B**; couche B failure → **400** `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE`.
- **W2** on explore / challenge / persist: non-latest → **422** `SCAN_NOT_LATEST`; Discovery down → **503** `DISCOVERY_UNAVAILABLE`.
- EOA without signed authorization → **403** `WALLET_CONTROL_PROOF_REQUIRED`. Active policy conflict / retry → **409** `POLICY_ALREADY_EXISTS` (reconcile via GET + `payload_sha256`).
- **NB1 replace:** DELETE policy (JWT) then new signed persist — not atomic.
- V1 persist is **EOA-only**; non-EOA → **422** `UNSUPPORTED_WALLET_TYPE`.
- Details: [CP-PERSIST runbook](./docs/security/cp-persist-v1.md).

#### Read policies

- **`GET /api/cpm/v1/policies`** — list owner policies; filter by `scan_id` query param.

#### Delete

- **`DELETE /api/cpm/v1/policies?id=…`** — removes policy only; scans unchanged (**W4**).

#### Assessment (async)

- **`POST /api/cpm/v1/policies/assessment/request`** — wallet scans only; body **`scan_id` + `crypto_policy_id`** only; server loads Discovery detail; client must not send `policy_context` or `selection_request` (HTTP → **400**; NATS → validation error).

### Composition (no server draft)

- Working composition lives **client-side** (page memory / `sessionStorage` indexed by `scan_id` — **NB2**). It is **not** a CPM API resource.
- **Removed:** `POST|GET|DELETE /api/cpm/v1/drafts` and `POST /api/cpm/v1/drafts/{id}/persist`.
- Rescan / W1 concern only **persisted** policies. Orphan draft / rebind product flows are **retired**.

### Remediation (product direction)

Remediation will consume CPM policy outcomes to plan and execute wallet migration (PQC keys, ERC-4337 UserOps). It is **not** part of the immutability v1 API surface documented here. TLS remediation is explicitly out of scope.

### Governance — scan immutability and CPM coupling

Rules **W1–W8** apply to **wallet** targets with CPM `binding=discovery`:

| ID | Rule | Discovery | CPM |
| --- | --- | --- | --- |
| **W1** | **Persisted policy** blocks rescan (at most one active policy per owner+address) | `POST …/scan` → `409` when **policy** on address (prefer `blocking_kind: "policy"`) | Lookup policies for POST guard |
| **W2** | CPM only on latest **`completed`** scan for **owner+address** | `GET …/wallets/scans?address=&latest=true` | Explore / challenge / persist → **422** `SCAN_NOT_LATEST` if non-latest; Discovery fail → **503** |
| **W3** | Delete scan only after policies removed | `409 SCAN_REFERENCED_BY_POLICY` | User deletes policies first |
| **W4** | Delete policy does not delete scans | Unchanged | `DELETE …/policies?id=` only (JWT; NB1) |
| **W5** | History per address | `GET …/wallets/scans?address=` | Read-only correlation |
| **W6** | CBOM per scan execution | `GET …/wallets/scans/{scan_id}/cbom` | No CBOM storage |
| **W8** | Rescan blocked only while in progress | `409 SCAN_IN_PROGRESS` if `requested`/`started` | Independent of W2 |

**Retired:** **W1b** orphan draft / rebind; product **W7** “newest row must be completed” as a separate explore gate — ADR_20260824 / RD-P6 keep **W2 only** (`latest=true` completed). Full IMM doc amend → RD-P14.

**Guard order:** `POST …/scan` — **W8** then **W1**. CPM explore / challenge / persist — **W2** (owner-scoped latest completed).

**Client UX (no server draft):** composition is local (NB2). Rescan does not create orphan drafts. FE anchors on W2. **Persisted policy** still blocks rescan. See [ADR_20260824_remove_cp_drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md) and [cafe-frontend IMMUTABILITE.md](https://github.com/create2-labs/cafe-frontend/blob/main/IMMUTABILITE.md) (formal REQ10/REQ14 amend → RD-P14).

### Platform observability — CPM explore no scan-compatible provider (REQ9)

When explore returns HTTP **200** with no scan-compatible provider (`scan_compatible_providers` empty, `rejected_candidates` non-empty), the product must give **operators** exploitable visibility without exposing wallet identities in metrics or real-time end-user alerts.

#### Product intent

Discovery has produced a **usable wallet scan context**, and the user selected a catalogue Crypto Policy, but CPM couche A cannot propose a **scan-compatible** provider. Typical reasons:

- **Catalogue / provider gap** — no allowed provider supports the wallet’s chain set or posture.
- **Hard provider constraints** — wallet type, rotation capability, continuity flags at couche A.
- **Other blocking codes** — erroneous suggested constraints, maturity (less common in early deployments).

This **runtime signal** (ADR §7.2.1 family 2: `adr_signal=runtime.no_scan_compatible`) helps product and ops detect coverage gaps or misconfigured catalogues. It is **not** a failed API call and does **not** warrant per-wallet email or Slack from the platform core. Couche B failures at persist are a **separate** signal (`runtime.no_provider_after_user_constraints`).

#### Separation of concerns (REQ8 vs REQ9)

| Audience | Requirement | Delivery |
| --- | --- | --- |
| **End user** | Understand why no provider is scan-compatible | **REQ8** — SPA banner (`CpmExploreRejectionBanner`, **FE-IMM-13**): dominant `rejection_reasons[].code` |
| **Platform / SRE** | Trend, alert, and investigate incidents | **REQ9** — **IMM-OPS-1** (CPM log + Prometheus counter), **IMM-OPS-2** (Grafana dashboard + sustained alert on `cafe-deploy`) |
| **Future admin** | Actionable coverage-gap synthesis | **IMM-OPS-3** — deferred; not in current release scope |

#### Operator expectations

- **Grafana** dashboard **CAFE - CPM Explore Rejections** shows rates and breakdowns by `rejection_code`, `wallet_type`, `missing_chain_count` bucket — not individual wallets.
- **Alert** `CpmExploreIncompatibleChainScopeSustained` fires on **sustained** elevation of chain-scope style rejections, not a single explore event.
- **Investigation** uses API explore JSON, `GET /crypto-policies` + `GET /providers`, CPM structured logs (`cpm.explore.no_deployable_candidate`), and optional Prometheus queries — documented in the [operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md).

#### Privacy and data handling

- Prometheus labels stay **low cardinality** (`rejection_code`, `wallet_type`, `binding`, `missing_chain_count` bucket only).
- **Never** label `scan_id`, wallet address, raw or hashed wallet, `chain_ids`, catalog ids, `tenant_id`, `owner_id`, or `request_id` on metrics.
- Structured logs may include `scan_id`, chain id lists, catalog instance ids, and **hashed** wallet (`wallet_address_hash`) for support — never raw wallet address in logs or metrics.

#### Out of scope for REQ9

- Changing compatibility evaluator semantics.
- Real-time per-wallet notifications.
- Admin UI in `cafe-frontend` (deferred **IMM-OPS-3**).

**Technical detail:** [technical-specifications.md — IMM-OPS](./technical-specifications.md#explore-no-deployable-candidate-observability-imm-ops-12) · [operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md)

### Platform Status — deployed service versions (US18)

Authenticated users can confirm which **deployed builds** are running from **Platform → Status** → **Version Information**.

| Tile | Source | Notes |
| --- | --- | --- |
| Frontend Version | Static `/version.json` (baked at image build) | SPA bundle tag |
| Discovery Version | `GET /api/version` → Discovery `GET /version` | Image tag from `APP_VERSION` |
| CPM Version | `GET /api/cpm/version` → CPM `GET /version` (**CPM-OPS-3**) | Same JSON contract as Discovery; **CPM-UI-7A** |

**Acceptance:**

- Versions are read at runtime (not hard-coded in the frontend).
- Loading/error UX matches existing tiles (`Unknown` when unreachable).
- CPM graph and policy workflows are unchanged.

**Out of scope:** catalog `catalog_version`, template `version` fields, or CPM policy instance metadata.

### CPM user interface — composition workspace

The **Crypto Policy Management** page (`/crypto-policy-management`) is a **Capability Provider workspace** for EOA wallet scans only. TLS scans are never CPM targets. The UI shows a **solution profile view** (scénario A): candidate list + structured provider card. No policy graph (nodes/edges) in the normative UI. Normative UI acceptance criteria live in [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md). See [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) and [ADR_20260824_remove_cp_drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md).

#### Vocabulary (UI)

| Term | Meaning |
| --- | --- |
| **Composition / editor state** | In-progress CP configuration — **client-only** (memory / sessionStorage NB2); not a server resource |
| **Persisted CP** | Currently **recommended** policy for owner+address (wallet-signed at persist; W1) |
| **Scan-only shell** | Scan selected; no active composition and no persisted CP |

A wallet may have at most **one** active persisted CP (W1). There is **no** dual-branch “replacement draft” server resource.

#### Entry modes

| Mode | Behavior |
| --- | --- |
| **Cold start** | Scan picker; **no** scan pre-selected |
| **Session resume** | Last active scan + local editor restore when returning without `?scanId=` (NB2) |
| **Discovery deep link** | `?scanId=<uuid>` from **Open CPM** on wallet scan rows |
| **In-page scan change** | Switch scan; warn if unsaved local composition at risk; re-anchor W2 |

`?scanId=` in the URL overrides session resume.

#### Persist UX

1. User clicks **Persist**.
2. **Local structural validation** runs — not a CPM backend validate API.
3. On failure: show validation issues; **do not** open MetaMask or call `wallet-challenges` / `POST /policies`.
4. On success: `POST …/wallet-challenges` → `personal_sign` → **`POST …/policies`** ([CP-PERSIST](./docs/security/cp-persist-v1.md)).
5. If **409** / existing policy: reconcile via GET + `payload_sha256`; replace via **NB1** (DELETE then new persist).

#### Historical US1–US21 note

Earlier CPM-UI user stories assumed **platform drafts**, orphan **rebind**, and replacement-draft dual-branch. Those product surfaces are **removed**. Treat draft-centric US wording as **superseded**; formal IMM/TODO closure is **RD-P14**. Current product intent: explore (W2) → compose locally (NB2) → signed persist → policy-only durability.

#### Out of scope (CPM UI V1)

On-chain remediation lifecycle, TLS as CPM target, automated persist without user action, historical policy browsing, separate backend **validate** route, server draft CRUD.

**Maintainer spec:** [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) · immutability UX: [`IMMUTABILITE.md`](https://github.com/create2-labs/cafe-frontend/blob/main/IMMUTABILITE.md) (amend RD-P14)

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

1. List scans: `GET …/wallets/scans?address=…` (or select scan in CPM UI — **US2**, **US12**).
2. Load detail for selected `scan_id`.
3. Select Crypto Policy from catalogue: `GET …/crypto-policies`.
4. Explore: `POST …/policies/decisions/explore` with `scan_id`, `crypto_policy_id`, `policy_context`.
5. Validate user constraints in UI (couche B indicative); keep composition locally (NB2) — **no** `POST …/drafts`.
6. Persist (EOA): `POST …/wallet-challenges` → EIP-191 sign → **`POST …/policies`** with `signed_message` + `signature` + closed payload.

See [CP-PERSIST runbook](./docs/security/cp-persist-v1.md) and CPM UI persist flow above.

### Delete scan protected by policy (W3 / W4)

1. `DELETE …/wallets/scans/{scan_id}` → `409 SCAN_REFERENCED_BY_POLICY`.
2. `GET …/policies?scan_id=…` — list policies.
3. `DELETE …/policies?id=…` for each — scans remain.
4. `DELETE …/wallets/scans/{scan_id}` → `204`.

### Rescan after failure (W8 + W1)

1. Newest scan `failed`; no policy → `POST …/scan` accepted.
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
| [cafe-frontend CPM-specs-ui.md](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) | CPM UI user stories US1–US21 |
| [cafe-deploy README — smoke scripts](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) | End-to-end test scripts |
