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
      8. [Platform observability — CPM explore (REQ9)](#platform-observability--cpm-explore-no-deployable-candidate-req9)
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

**CPM integration:** the UI and CPM correlate work by **`scan_id`** from Discovery v1 wallet scans. TLS scans remain Discovery-only for product flows. See [docs/architecture/cpm-v1-flow.md](./docs/architecture/cpm-v1-flow.md).

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
- Guards (**W8**, then **W1**): refuse if a scan is in progress (`409 SCAN_IN_PROGRESS`) or if a **persisted CPM policy** exists for the target address (`409`, prefer `blocking_kind: "policy"`). **Platform draft alone** does not block rescan (**IMM-W1-4**).
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
- Static catalog files are loaded at CPM startup; administration (add template, widen chain scope) is documented in [04-cafe-admin-guide.md](./04-cafe-admin-guide.md#cpm-catalog-administration).

#### Explore (preview)

- **`POST /api/cpm/v1/policies/decisions/explore`** with `scan_id`, **`policy_context`**, `selection_request`.
- Guards: **W7** (newest row must be `completed`), **W2** (`scan_id` must match latest completed for target), wallet-only (**TLS → 404**).
- **Chain scope (all-or-nothing):** every id in `selection_request.target_chain_ids` must appear in a candidate instance `scope.chain_ids` for that candidate to be deployable. Partial coverage is rejected (e.g. `incompatible.chain_scope` when chain `56` is observed and requested but absent from catalog scope).
- **No deployable candidate (HTTP 200):** when no ranked candidate remains and `rejected_candidates` is non-empty, the response is still **success** — not an error. The SPA explains why (**REQ8** / **FE-IMM-13**). Platform ops consume **REQ9** observability ([operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md)): structured log `cpm.explore.no_deployable_candidate`, counter `cpm_explore_no_deployable_candidate_total`, Grafana dashboard **IMM-OPS-2**.

#### Persist (EOA — CP-PERSIST V1)

- **Normative EOA path:** `POST /api/cpm/v1/wallet-challenges` (mandatory stateless canonical message) → EIP-191 / `personal_sign` → **`POST /api/cpm/v1/drafts/{draft_id}/persist`** with `signed_message` + `signature`.
- **Wallet proof required** for persist. Scan, explore, and platform draft save do **not** require proof (non-regression S1–S3).
- Same immutability guards as explore (**W7**, **W2**, wallet-only, TLS → **404**).
- Legacy **`POST /api/cpm/v1/policies`** is **not** the normative EOA persist endpoint; Discovery-bound EOA payloads without signed authorization return **403** `WALLET_CONTROL_PROOF_REQUIRED`.
- V1 persist is **EOA-only**; non-EOA drafts return **422** `UNSUPPORTED_WALLET_TYPE` on persist routes.
- Details: [CP-PERSIST V1 runbook](./docs/security/cp-persist-v1.md).

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
| **W1** | **Persisted policy** blocks rescan; **platform draft alone** does **not** block (`IMM-W1-4`) | `POST …/scan` → `409` when **policy** on address (prefer `blocking_kind: "policy"`) | Lookup policies for POST guard |
| **W1b** | **Orphan draft** after rescan — CPM workflow blocked until **rebind** to latest **completed** scan | — | Explore/validate/persist blocked until draft on **W2** `scan_id` |
| **W2** | CPM only on latest **`completed`** scan | `GET …/wallets/scans?address=&latest=true` | `400` if `scan_id` ≠ latest completed |
| **W3** | Delete scan only after policies removed | `409 SCAN_REFERENCED_BY_POLICY` | User deletes policies first |
| **W4** | Delete policy does not delete scans | Unchanged | `DELETE …/policies?id=` only |
| **W5** | History per address | `GET …/wallets/scans?address=` | Read-only correlation |
| **W6** | CBOM per scan execution | `GET …/wallets/scans/{scan_id}/cbom` | No CBOM storage |
| **W7** | CPM blocked until newest row is **`completed`** | No POST guard | `400 LATEST_SCAN_NOT_COMPLETED` |
| **W8** | Rescan blocked only while in progress | `409 SCAN_IN_PROGRESS` if `requested`/`started` | Independent of W7 |

**Guard order:** `POST …/scan` — **W8** then **W1**. CPM explore/persist — **W7** then **W2**.

**W7 vs W8:** CPM may stay blocked while Discovery allows rescan after `failed` (e.g. completed scan A + newer failed scan B).

**Client UX (draft + rescan, tranché 2026-06):** rescan is allowed with a **platform draft** on the address. The draft may stay on an older `scan_id` until the user clicks **Rebind to last scan for this address** (upsert `POST /api/cpm/v1/drafts` onto **W2**). **Explore**, **validate**, and **persist** stay blocked while the draft is orphaned. **`wallet_type`** must match on rebind or the UI refuses. **No** local export / `localStorage` / client reload. **Persisted policy** still blocks rescan. See [cafe-frontend IMMUTABILITE.md](https://github.com/create2-labs/cafe-frontend/blob/main/IMMUTABILITE.md).

### Platform observability — CPM explore no deployable candidate (REQ9)

When explore returns HTTP **200** with no deployable Crypto Policy (`selected_policy_id` empty, `rejected_candidates` non-empty), the product must give **operators** exploitable visibility without exposing wallet identities in metrics or real-time end-user alerts.

#### Product intent

Discovery has produced a **usable wallet scan context**, but CPM cannot propose a catalog route that satisfies the selection request. Typical reasons:

- **Catalog gap** — a discovered chain (e.g. `56`) has no CP instance whose `scope.chain_ids` covers it.
- **Scope mismatch** — instance scope is narrower than the wallet’s multi-chain set (**all-or-nothing** on `target_chain_ids`).
- **Other blocking codes** — posture, maturity, multichain flags (less common in early deployments).

This signal helps product and ops detect coverage gaps, misconfigured catalogs, or frequent user paths that need new CP templates. It is **not** a failed API call and does **not** warrant per-wallet email or Slack from the platform core.

#### Separation of concerns (REQ8 vs REQ9)

| Audience | Requirement | Delivery |
| --- | --- | --- |
| **End user** | Understand why no policy applies during explore | **REQ8** — SPA banner (`CpmExploreRejectionBanner`, **FE-IMM-13**): observed vs requested chains, dominant `rejection_reasons[].code` (e.g. `incompatible.chain_scope`) |
| **Platform / SRE** | Trend, alert, and investigate incidents | **REQ9** — **IMM-OPS-1** (CPM log + Prometheus counter), **IMM-OPS-2** (Grafana dashboard + sustained alert on `cafe-deploy`) |
| **Future admin** | Actionable coverage-gap synthesis | **IMM-OPS-3** — deferred; not in current release scope |

#### Operator expectations

- **Grafana** dashboard **CAFE - CPM Explore Rejections** shows rates and breakdowns by `rejection_code`, `wallet_type`, `missing_chain_count` bucket — not individual wallets.
- **Alert** `CpmExploreIncompatibleChainScopeSustained` fires on **sustained** elevation of `incompatible.chain_scope`, not a single explore event.
- **Investigation** uses API explore JSON, `GET /policies/instances` (scope vs targets), CPM structured logs (`cpm.explore.no_deployable_candidate`), and optional Prometheus queries — documented in the [operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md).

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

### CPM user interface — graph workspace (US1–US21)

The **Crypto Policy Management** page (`/crypto-policy-management`) is a **graph-first workspace** for EOA wallet scans only. TLS scans are never CPM targets. Normative UI acceptance criteria live in [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) (delivery epics **CPM-UI-1…8**).

#### Vocabulary (UI)

| Term | Meaning |
| --- | --- |
| **Draft** | Non-actionable in-progress CP configuration (platform draft on backend) |
| **Persisted CP** | Currently **recommended** policy for a scan (owner-scoped, wallet-signed at persist) |
| **Replacement draft** | Draft prepared while a persisted CP already exists; does not change the recommendation until persist succeeds |
| **Scan-only shell** | Scan node selected; no draft and no persisted CP on backend |

A scan may have at most one persisted CP and at most one draft; both may coexist (dual-branch graph, State 7).

#### Entry modes

| Mode | Behavior |
| --- | --- |
| **Cold start** | Scan picker (State 2); **no** scan pre-selected (**US15**) |
| **Session resume** | Last active scan and graph state restored when returning without `?scanId=` (**US13**) |
| **Discovery deep link** | `?scanId=<uuid>` from **Open CPM** on wallet scan rows (**US12**) |
| **In-page scan change** | Click scan node → modal; hydrates draft/persisted CP for newly selected scan (**US14**, **US15**) |

`?scanId=` in the URL overrides session resume.

#### User stories summary

| ID | Intent |
| --- | --- |
| **US1** | Empty state when no EOA scan — CTA to Discovery; no catalog |
| **US2** | Select eligible EOA scan; first graph node + edge; hydrate draft/persisted CP when backend has them |
| **US3** | First edge opens CP catalog; compatible policies selectable; selecting creates/updates draft |
| **US4** | Change draft CP freely; confirm when draft has meaningful progress; persisted CP unchanged |
| **US5** | Resume platform draft on scan select, session resume, or deep link |
| **US6** | View persisted CP read-only branch; clearly marked **recommended** |
| **US7** | Prepare replacement draft via first edge; persisted CP unchanged until successful persist |
| **US8** | **Persist** new draft in one action — implicit local structural check, then wallet sign + backend persist (**CPM-UI-8**) |
| **US9** | **Persist** replacement draft — local validation → confirm → wallet → persist; prior persisted CP unchanged on failure |
| **US10** | Delete draft / replacement draft with confirmation; persisted CP unchanged |
| **US11** | Delete persisted CP with confirmation (no wallet signature); replacement draft unchanged if any |
| **US12** | **Open CPM** from Discovery wallet scan list → `/crypto-policy-management?scanId=…` |
| **US13** | Same-tab session resume of last CPM workspace |
| **US14** | Change scan from scan-node modal; warn on unsaved platform draft at risk |
| **US15** | Graph shell matches scan CP state (scan-only vs draft vs persisted vs dual-branch) |
| **US16** | Policy node click → details/parameter modal (no legacy side column) |
| **US17** | Single full-width graph column; legacy right workspace removed |
| **US18** | **CPM Version** tile on Platform Status (see above) |
| **US19** | Warn before leaving CPM with unsaved platform draft at risk (`beforeunload` + in-app navigation) |
| **US20** | CP branch header node (**Draft** / **Persisted** / **Replacement Draft**) before topology |
| **US21** | Structural validation runs implicitly on **Persist** — no separate **Validate** button |

#### Persist UX (US8, US9, US21 — CPM-UI-8)

The graph draft panel exposes a single primary action: **Persist** (replacement: e.g. **Replace persisted policy**).

1. User clicks **Persist**.
2. **Local structural validation** runs (`policyDraftValidation` / `usePolicyValidation`) — not a CPM backend validate API.
3. On failure: show validation issues; **do not** open MetaMask or call `wallet-challenges` / `POST …/drafts/{id}/persist`.
4. On success: save backend draft if needed → `POST …/wallet-challenges` → `personal_sign` → `POST …/drafts/{draft_id}/persist` ([CP-PERSIST V1](./docs/security/cp-persist-v1.md)).
5. Replacement path adds an explicit confirmation dialog **after** local validation succeeds and **before** wallet signature.

#### Graph states (reference)

| State | Situation |
| --- | --- |
| 1 | No EOA scans |
| 2 | Scan picker (cold start) |
| 3 | Scan selected; scan-only shell |
| 4 | CP catalog open (first edge) |
| 5 | Draft branch visible |
| 6 | Persisted CP read-only branch |
| 7 | Persisted + replacement draft (dual branch) |

#### Out of scope (CPM UI V1)

On-chain remediation lifecycle, TLS as CPM target, automated persist without user action, historical policy browsing, separate backend **validate** route for drafts.

**Maintainer spec:** [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) · immutability UX: [`IMMUTABILITE.md`](https://github.com/create2-labs/cafe-frontend/blob/main/IMMUTABILITE.md)

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
3. Explore: `POST …/policies/decisions/explore` with `scan_id`, `policy_context`, `selection_request`.
4. Save platform draft: `POST …/drafts` (optional resume via `GET …/drafts?id=…`).
5. Persist (EOA, CP-PERSIST V1): `POST …/wallet-challenges` → EIP-191 sign → `POST …/drafts/{draft_id}/persist` with `signed_message` + `signature` — not legacy `POST …/policies` without proof.

See [CP-PERSIST V1 runbook](./docs/security/cp-persist-v1.md) and CPM UI persist flow (**US8**, **US21**).

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
| [cafe-frontend CPM-specs-ui.md](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) | CPM UI user stories US1–US21 |
| [cafe-deploy README — smoke scripts](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) | End-to-end test scripts |
