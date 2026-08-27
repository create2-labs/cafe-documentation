# CAFE Developer Guide

This guide is the canonical integration reference for the CAFE API v1 rollout. It covers the public Discovery and CPM HTTP surfaces used by browsers, scripts, and partner integrations after the API coherency work.

## Document Versioning

- v0.17.0
  - Date: August 27th, 2026
  - Comments: Align CP persist with ADR_20260824 (no drafts): normative engagement is signed `POST /api/cpm/v1/policies` + `payload_sha256`; `/drafts*` removed; W2 on explore/challenge/persist; NB1/NB2. See [ADR_20260824_remove_cp_drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md) and [CP-PERSIST runbook](./docs/security/cp-persist-v1.md).
- v0.16.0
  - Date: August 22nd, 2026
  - Comments: Align with ADR amendement two-layer model: catalogue `GET /crypto-policies` + `/providers` (retired `/policies/templates|instances|catalog`); explore v0.2 input `scan_id?` + `crypto_policy_id` + `policy_context` → `scan_compatible_providers` (legacy explore → **400**); persist `cafe.crypto_policy.v0.2` with `crypto_policy_id` + `user_constraints` (CPM rejeu A+B; `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE`); assessment body `scan_id` + `crypto_policy_id` only. See [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md).
- v0.15.0
  - Date: August 18th, 2026
  - Comments: Align with ADR Capability Providers (2026-08): explore `selection_request` uses `key_rotation_model` (`none` | `per_userop`) instead of `key_rotation_required` bool; `target_posture` is the stable v0.1 wire alias for required posture; explore response carries `required_posture`, `resulting_posture`, `solution_profile_ref`, `maturity`, `claim_status`, soft findings — no `graphEdges` / `nodeInstances`; persist payload is `cafe.crypto_policy.v0.2` with `accepted_provider_snapshot`. See [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md).
- v0.14.0
  - Date: August 9th, 2026
  - Comments: Note **Cloudflare Tunnel** public base (`https://cafe.create2-labs.fr`) for home Compose prod-tunnel; same `/api/*` path contract as classic edge.
- v0.13.0
  - Date: July 21st, 2026
  - Comments: Document dual local deployments — **cafe-deploy** (Docker Compose) and **cafe-expresso** (minikube); edge UI/API via `http://localhost:8080` on minikube; signup/signin through ingress (not frontend-only port-forward).
- v0.12.0
  - Date: June 21st, 2026
  - Comments: Align CPM persist table with CP-PERSIST V1 (`wallet-challenges`, `drafts/{id}/persist`); reference CPM UI user stories **US1–US21** / [`CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md).
- v0.11.0
  - Date: June 21st, 2026
  - Comments: Document public service version endpoints (`GET /api/version`, `GET /api/cpm/version`) and Platform Status CPM version tile (**CPM-OPS-3** / **CPM-UI-7A**).
- v0.10.0
  - Date: June 9th, 2026
  - Comments: Document explore **no deployable candidate** (HTTP 200 + `rejected_candidates`), chain-scope all-or-nothing diagnosis, and pointers to platform observability (**IMM-OPS-1…2**) and admin `curl` workflow — see [CPM explore observability runbook](./docs/operations/cpm-explore-no-candidate-observability.md).
- v0.9.0
  - Date: May 19th, 2026
  - Comments: Align the guide with API v1: Discovery routes live under `/discovery/v1` direct to the service and `/api/discovery/v1` at the edge; CPM business routes live under `/api/cpm/v1`; scan detail is loaded by `scan_id`; policy assessment is CPM-owned through `POST /api/cpm/v1/policies/assessment/request`; the removed Discovery CBOM and assessment routes are no longer integration paths.
- v0.8.0
  - Date: May 10th, 2026
  - Comments: Documented the pre-v1 wallet scan correlation state, authenticated CPM explore calls, and HTTPS script ergonomics. Superseded by v0.9 for API route names and scan correlation.
- v0.7.0
  - Date: Apr 29th, 2026
  - Comments: Defined cross-service address casing, health endpoints, explicit assessment trigger semantics, and CPM read APIs.
- v0.6.0
  - Date: Apr 19th, 2026
  - Comments: Documented the Discovery -> CPM normalized wallet observation contract (`cafe.discovery.wallet.observed` v0.1).

## Local deployments (Compose and minikube)

CAFE currently supports **two parallel local deployments**. Both stay documented; Compose is not removed while minikube P0 matures.

| Deployment | Repository | Edge (browser UI + `/api`) | Notes |
| --- | --- | --- | --- |
| **Docker Compose** | [`cafe-deploy`](https://github.com/create2-labs/cafe-deploy) | `https://localhost` (NGINX) or `http://localhost` | Classic VM/dev stack; env files + `docker compose` |
| **Compose + Cloudflare Tunnel** | [`cafe-deploy`](https://github.com/create2-labs/cafe-deploy) | `https://cafe.create2-labs.fr` (TLS at Cloudflare; origin `http://127.0.0.1:8080`) | Home hosting; `docker-compose.prod-tunnel.yml` — see [admin guide](./04-cafe-admin-guide.md#cloudflare-tunnel-home-hosting) |
| **minikube (P0)** | [`cafe-expresso`](https://github.com/create2-labs/cafe-expresso) | **`http://localhost:8080`** via ingress-nginx port-forward | Helm chart `cafe-platform`; kubectl/Helm ops in [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md) |

Architecture / backlog: [ADR GitOps](https://github.com/create2-labs/cafe-deploy/blob/main/ADR/ADR_20260708_gitops.md). Operator kubectl cheat-sheet: [cafe-expresso `docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md). Admin day-2: [04-cafe-admin-guide.md](./04-cafe-admin-guide.md).

### minikube — necessary and sufficient edge access

On Mac + docker driver, do **not** rely on `minikube ip`. Forward the **ingress controller** (not `svc/cafe-frontend` alone — that nginx is SPA-only and returns **405** on `POST /api/...`):

```bash
export NS=cafe-platform
minikube addons enable ingress   # once
kubectl -n ingress-nginx port-forward svc/ingress-nginx-controller 8080:80
```

Then:

| Use | URL |
| --- | --- |
| Signup / Signin (browser) | **`http://localhost:8080/signup`** / **`http://localhost:8080/signin`** |
| SPA home | `http://localhost:8080/` |
| Edge API (Discovery) | `http://localhost:8080/api/...` (e.g. `/api/auth/signup`, `/api/discovery/v1/...`) |
| Edge API (CPM) | `http://localhost:8080/api/cpm/v1/...` |

HTTPS on minikube P0 is **not** configured (TLS/cert-manager → staging). Use **HTTP** on `:8080`.

### minikube — deploy + secrets (from `k8s.md`)

```bash
cd cafe-expresso
export NS=cafe-platform
minikube start --memory=8192 --cpus=4 --driver=docker   # prefer --cni=calico for NetworkPolicies (PR6+)
kubectl cluster-info

helm upgrade --install cafe-platform charts/cafe-platform \
  --namespace "$NS" --create-namespace \
  -f charts/cafe-platform/values.yaml \
  -f charts/cafe-platform/values-minikube.yaml

kubectl -n "$NS" create secret generic cafe-platform-secrets \
  --from-literal=JWT_SECRET=dev-not-secret \
  --from-literal=POSTGRES_PASSWORD=cafe \
  --from-literal=CAFE_PERSISTENCE_SERVICE_TOKEN=dev-cafe-auth06-shared-internal-token \
  --from-literal=DISCOVERY_INTERNAL_AUTHZ_SERVICE_TOKEN=dev-cafe-auth06-shared-internal-token \
  --from-literal=CAFE_SESSION_JWT_VALIDATION_SERVICE_TOKEN=dev-cafe-auth06-shared-internal-token \
  --from-literal=CAFE_SCAN_AUTHORIZATION_SERVICE_TOKEN=dev-cafe-auth06-shared-internal-token \
  --from-literal=MORALIS_API_KEY= \
  --from-literal=TURNSTILE_SECRET_KEY= \
  --from-literal=TURNSTILE_SITE_KEY= \
  --dry-run=client -o yaml | kubectl apply -f -

./scripts/smoke/smoke-minikube.sh   # optional full smoke
```

Empty `TURNSTILE_*` is valid in dev: the UI uses Cloudflare always-pass keys (`XXXX.DUMMY.TOKEN.XXXX`); Discovery accepts any non-empty token when the secret key is empty. Scripts may send `"turnstile_token":"dev-pass"`.

## Base URLs

Use one of these bases depending on where the caller runs.

| Context | Discovery base | CPM base | Notes |
| --- | --- | --- | --- |
| Direct local services (Compose ports or kubectl port-forward to pods) | `http://localhost:8080` | `http://localhost:8082` | Backend paths exactly as registered by each service (`/auth/...`, `/discovery/v1/...`, `/api/cpm/v1/...` on CPM). |
| **Edge — cafe-deploy NGINX** | `https://<host>/api` | `https://<host>` | Discovery `/api/discovery/v1/...`; CPM `/api/cpm/v1/...`. Local often `https://localhost`. Home tunnel: same paths on `https://cafe.create2-labs.fr` (TLS at Cloudflare). |
| **Edge — cafe-expresso minikube** | `http://localhost:8080/api` | `http://localhost:8080` | After ingress port-forward `8080:80`. **Signup/signin UI:** `http://localhost:8080`. No TLS on P0. |

Examples below use:

```bash
# Direct Discovery (Compose published port, or: kubectl -n cafe-platform port-forward svc/cafe-discovery-backend 8080:8080)
export DISCOVERY_BASE="http://localhost:8080"
export CPM_BASE="http://localhost:8082"

# Edge — Compose NGINX (HTTPS, may need -k)
export EDGE_API_BASE="https://localhost/api"
export EDGE_BASE="https://localhost"

# Edge — minikube (HTTP via ingress port-forward) — preferred for browser + /api on K8s
export EDGE_BASE="http://localhost:8080"
export EDGE_API_BASE="http://localhost:8080/api"
```

For development HTTPS with a self-signed or private CA on **Compose**, add `-k` to `curl` only in local/dev contexts. On **minikube P0**, prefer plain HTTP on `:8080`.

## Authentication

Most Discovery and CPM business endpoints require a Discovery-issued session token.

**Browser (minikube):** open **`http://localhost:8080/signup`** or **`http://localhost:8080/signin`** (ingress port-forward must be running).

**curl — direct Discovery** (Compose or port-forward to `cafe-discovery-backend`):

```bash
JWT=$(curl -s -X POST "${DISCOVERY_BASE}/auth/signin" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "turnstile_token": "dev-pass"
  }' | jq -r '.token')
```

**curl — edge on minikube** (same host as the SPA):

```bash
export EDGE_BASE="http://localhost:8080"
JWT=$(curl -s -X POST "${EDGE_BASE}/api/auth/signin" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "turnstile_token": "dev-pass"
  }' | jq -r '.token')

# Signup (create account)
curl -s -X POST "${EDGE_BASE}/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "confirm_password": "password",
    "turnstile_token": "dev-pass"
  }' | jq .
```

The token is an opaque Bearer value for callers. The frontend and CPM both reuse the Discovery session token; CPM does not issue a separate user JWT.

## Public API Surface

### Discovery v1

| Purpose | Direct service path | Edge path | Auth |
| --- | --- | --- | --- |
| Queue wallet or TLS scan | `POST /discovery/v1/scan` | `POST /api/discovery/v1/scan` | Bearer |
| List wallet scan synopsis | `GET /discovery/v1/wallets/scans` | `GET /api/discovery/v1/wallets/scans` | Bearer |
| Get wallet scan detail | `GET /discovery/v1/wallets/scans/{scan_id}` | `GET /api/discovery/v1/wallets/scans/{scan_id}` | Bearer |
| Delete wallet scan | `DELETE /discovery/v1/wallets/scans/{scan_id}` | `DELETE /api/discovery/v1/wallets/scans/{scan_id}` | Bearer |
| List TLS scan synopsis | `GET /discovery/v1/tls/scans` | `GET /api/discovery/v1/tls/scans` | Bearer |
| List default TLS scans | `GET /discovery/v1/tls/scans/defaults` | `GET /api/discovery/v1/tls/scans/defaults` | Bearer |
| Get TLS scan detail | `GET /discovery/v1/tls/scans/{scan_id}` | `GET /api/discovery/v1/tls/scans/{scan_id}` | Bearer |
| Delete TLS scan | `DELETE /discovery/v1/tls/scans/{scan_id}` | `DELETE /api/discovery/v1/tls/scans/{scan_id}` | Bearer |
| List configured RPCs | `GET /discovery/v1/rpcs` | `GET /api/discovery/v1/rpcs` | Public |
| List scanner capabilities | `GET /discovery/v1/scanners` | `GET /api/discovery/v1/scanners` | Public |

Technical endpoints such as `GET /health`, `GET /metrics`, and internal `/internal/*` routes are not part of this public v1 product surface. `/plans` remains a separate account/quota API and is not versioned under Discovery v1 by this rollout.

### Service version (deploy observability)

Discovery and CPM each expose a **public** deploy-time version JSON contract (no auth). The frontend Platform Status page reads these at runtime (**CPM-UI-7A**).

| Service | Direct path | Edge path | Response |
| --- | --- | --- | --- |
| Discovery | `GET /version` on `:8080` | `GET /api/version` | `{"version": "<image-tag>"}` |
| CPM | `GET /version` on `:8082` (dev) / `:8080` (compose) | `GET /api/cpm/version` | `{"version": "<image-tag>"}` |

```bash
curl -fsS "${DISCOVERY_BASE}/version" | jq .
curl -fsS "${CPM_BASE}/version" | jq .
curl -kfsS "${EDGE_BASE}/api/version" | jq .
curl -kfsS "${EDGE_BASE}/api/cpm/version" | jq .
```

Version strings come from the image build (`APP_VERSION` / Git tag). They are **not** catalog `catalog_version` fields.

### CPM v1

| Purpose | Direct or edge path | Auth |
| --- | --- | --- |
| Crypto Policies catalogue | `GET /api/cpm/v1/crypto-policies` | Bearer |
| Crypto Policy by id | `GET /api/cpm/v1/crypto-policies/{crypto_policy_id}` | Bearer |
| Providers catalogue | `GET /api/cpm/v1/providers` | Bearer |
| Provider by id | `GET /api/cpm/v1/providers/{provider_id}` | Bearer |
| Explore decision (v0.2) | `POST /api/cpm/v1/policies/decisions/explore` | Bearer |
| Wallet challenge (EOA persist prep) | `POST /api/cpm/v1/wallet-challenges` | Bearer; W2; computes `payload_sha256`; stores nothing |
| Persist policy (EOA — normative) | `POST /api/cpm/v1/policies` | Bearer + signed body (`payload` + `signed_message` + `signature`); W2 |
| List / read policies | `GET /api/cpm/v1/policies` | Bearer; exposes `payload_sha256` |
| Delete policy (NB1) | `DELETE /api/cpm/v1/policies?id=...` | Bearer (JWT only) |
| Async policy assessment request | `POST /api/cpm/v1/policies/assessment/request` | Bearer |
| Health | `GET /healthz` direct, `GET /api/cpm/healthz` at edge | Public |
| Deployed version | `GET /version` direct, `GET /api/cpm/version` at edge | Public |

Retired / removed routes (do not use): `GET /api/cpm/v1/policies/templates`, `/policies/instances`, `/policies/catalog`; **all** `/api/cpm/v1/drafts*` (ADR_20260824 — no shim).

## Discovery Workflows

### Queue a scan

`POST /discovery/v1/scan` accepts exactly one target: `address` for a wallet scan or `url` for a TLS endpoint scan.

```bash
curl -X POST "${DISCOVERY_BASE}/discovery/v1/scan" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"address":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e"}' | jq .
```

```bash
curl -X POST "${DISCOVERY_BASE}/discovery/v1/scan" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.github.com"}' | jq .
```

Typical accepted response:

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_family": "wallet",
  "status": "requested",
  "location": "/discovery/v1/wallets/scans/550e8400-e29b-41d4-a716-446655440000"
}
```

The `scan_id` is the stable client correlation key. Do not correlate follow-up work by wallet address or TLS URL.

### List scan synopsis

Wallet lists use `items`, `total`, `limit`, and `offset`. Filter with `chain_id` only when an `address` filter is also present.

```bash
curl "${DISCOVERY_BASE}/discovery/v1/wallets/scans?limit=10&offset=0" \
  -H "Authorization: Bearer ${JWT}" | jq .
```

TLS owner lists do not accept wallet-specific filters such as `address` or `chain_id`.

```bash
curl "${DISCOVERY_BASE}/discovery/v1/tls/scans?limit=10&offset=0" \
  -H "Authorization: Bearer ${JWT}" | jq .
```

Default TLS scans are exposed through a separate catalog endpoint:

```bash
curl "${DISCOVERY_BASE}/discovery/v1/tls/scans/defaults" \
  -H "Authorization: Bearer ${JWT}" | jq .
```

### Fetch scan detail

Load full renderable details through the v1 detail endpoints using `scan_id`.

```bash
curl "${DISCOVERY_BASE}/discovery/v1/wallets/scans/${SCAN_ID}" \
  -H "Authorization: Bearer ${JWT}" | jq .result

curl "${DISCOVERY_BASE}/discovery/v1/tls/scans/${SCAN_ID}" \
  -H "Authorization: Bearer ${JWT}" | jq .result
```

The `result` object is the supported UI and integration payload for wallet and TLS detail. Wallet CBOM is available on demand via `GET /discovery/v1/wallets/scans/{scan_id}/cbom` when needed.

### Delete scan

Discovery owns scan lifecycle, but it asks CPM whether a persisted policy references the `scan_id` before deleting wallet or TLS scans.

Expected outcomes:

| Situation | Response |
| --- | --- |
| Scan deleted | `204` |
| Scan does not exist, is not visible, or was already deleted | `404` |
| CPM says a policy references the scan | `409 SCAN_REFERENCED_BY_POLICY` |
| CPM reference check is unavailable or misconfigured | `503 POLICY_REFERENCE_CHECK_UNAVAILABLE` |

Discovery never reads CPM persistence directly, and it must not map CPM internal `401` or `403` responses to a user-facing `403` on scan delete.

## CPM Policy Workflows

### Two-layer model (ADR amendement)

| Layer | Where | Authority |
| --- | --- | --- |
| **Couche A** | Explore → `scan_compatible_providers` | CPM (scan × Crypto Policy × solution profile) |
| **Couche B** | Persist `user_constraints` (UI filter is indicative) | CPM rejeu at persist |

Vocabulary: **scan-compatible** (couche A), **user-qualified** (couche B UI indicative), **persistable** (CPM rejeu A+B + gates).

A catalogue **Crypto Policy** is intention only: `required_posture` + `allowed_providers`. There is no `default_selection` and no template/instance catalogue.

### Explore a decision synchronously (wire v0.2)

`decisions/explore` is a synchronous preview. It evaluates a Crypto Policy and wallet `policy_context` against Capability Provider manifests (**couche A only**) and returns **`scan_compatible_providers`**. It does not persist a final policy and does not trigger the async assessment pipeline. Couche B fields do **not** belong on explore.

#### Explore request fields (v0.2)

| Field | Required | Notes |
| --- | --- | --- |
| `crypto_policy_id` | **Yes** | Catalogue Crypto Policy id (e.g. `cpm_pq_account_validation_v1`) |
| `policy_context` | **Yes** (Option A) | Discovery v1 wallet scan detail envelope |
| `scan_id` | Optional | Top-level scan binding for AUTH-02; must match `policy_context.scan_id` when both set |

**Do not send** on explore: `selection_request`, `target_posture`, `allow_new_wallet`, `address_continuity_required`, `key_rotation_model`, or other couche B fields. Legacy explore bodies → HTTP **400**.

Required posture comes from the catalogue Crypto Policy (`required_posture`). `key_rotation_model` lives in persist `user_constraints` (and UI constraints panel), not on explore.

```bash
curl -X POST "${CPM_BASE}/api/cpm/v1/policies/decisions/explore" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "crypto_policy_id": "cpm_pq_account_validation_v1",
    "policy_context": {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      "wallet_type": "eoa",
      "chain_ids": [11155111],
      "current_algorithm": "secp256k1_ecrecover",
      "current_pq_posture": "classical_only",
      "scanned_at": "2026-08-01T00:00:00Z",
      "status": "completed"
    }
  }' | jq .
```

#### Explore response — `scan_compatible_providers`

Each scan-compatible member carries Capability Provider fields. **No** `graphEdges`, `nodeInstances`, or `node_path`:

```json
{
  "candidate_id": "cpx_pq_account_validation_nicetry_v1",
  "crypto_policy_id": "cpm_pq_account_validation_v1",
  "required_posture": "hybrid",
  "solution_profile_ref": {
    "provider_id": "nicetry",
    "solution_profile_id": "nicetry.fors_c.erc4337.v0_1",
    "manifest_version": "2026-08"
  },
  "resulting_posture": "hybrid",
  "maturity": "research",
  "claim_status": "declared",
  "compatibility_status": "compatible",
  "compatibility_findings": [
    { "code": "requires_bundler", "severity": "soft" },
    { "code": "requires_local_signer_state", "severity": "soft" }
  ],
  "suggested_user_constraints": {
    "allow_new_wallet": true,
    "address_continuity_required": false,
    "key_rotation_model": "per_userop"
  }
}
```

Key semantics:
- Public response key is **`scan_compatible_providers`** (not `ranked_candidates` as normative vocabulary).
- `claim_status: "declared"` — the provider has **declared** this capability; it is **not** an audited or executed proof.
- Soft findings (`requires_bundler`, `requires_local_signer_state`) are non-blocking for couche A but must be explicitly accepted before persist.
- Hard findings move the candidate to `rejected_candidates`.
- `suggested_user_constraints` is **indicative** (seed for the UI panel). When the profile needs `per_userop`, couche A also requires `rotate_signer` capability.
- Couche B does **not** influence explore membership.

#### Option A: explore with Discovery v1 `policy_context`

**Option A** (post-V1 CPM) means policy workflows run against **real user-owned wallet scans** via authenticated Discovery—see [CPM `workplans/CPM_post_v_1_option_a_scan_context.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/CPM_post_v_1_option_a_scan_context.md).

Production UI and integrators load wallet scan **detail** from `GET /discovery/v1/wallets/scans/{scan_id}` and send that shape as **`policy_context`**, plus `crypto_policy_id` and optional top-level **`scan_id`**. Field mapping: [Discovery `CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md`](https://github.com/create2-labs/cafe-discovery/blob/main/docs/CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md) §3.1; flow: [Option A architecture](./docs/architecture/cpm-v1-flow.md). CPM UI: [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) and [`docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md).

```bash
DETAIL=$(curl -s "${DISCOVERY_BASE}/discovery/v1/wallets/scans/${SCAN_ID}" \
  -H "Authorization: Bearer ${JWT}")
curl -X POST "${CPM_BASE}/api/cpm/v1/policies/decisions/explore" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg sid "${SCAN_ID}" \
    --argjson ctx "${DETAIL}" \
    '{
      scan_id: $sid,
      crypto_policy_id: "cpm_pq_account_validation_v1",
      policy_context: $ctx
    }')" | jq .
```

#### No scan-compatible provider (HTTP 200 — not an error)

Explore may return **200** with empty `scan_compatible_providers` and populated `rejected_candidates` — for example when no allowed provider can deploy on the wallet’s chain set. This is a **runtime signal** (ADR §7.2.1 family 2: `adr_signal=runtime.no_scan_compatible`), not a failed HTTP call. Distinct from persist couche B failure (`PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE`).

| Audience | What to use |
| --- | --- |
| End user | SPA rejection banner (**REQ8**) |
| Admin / SRE | [Operations runbook — admin `curl` workflow](./docs/operations/cpm-explore-no-candidate-observability.md#admin-diagnosis--curl-workflow): explore JSON, `GET /crypto-policies` + `/providers`, CPM structured logs, Prometheus/Grafana |
| Integrators | Treat HTTP 200 + rejections as a valid outcome; inspect `rejection_reasons[].code` before persist |

**Smoke (integrated path):** from `cafe-deploy`, `SKIP_PERSIST=1 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh` with `SCAN_ID`, `DISCOVERY_BASE`, `CPM_BASE`, and credentials — stops after explore when no candidate is selected.

### Persist payload — `cafe.crypto_policy.v0.2`

Normative engagement is **`POST /api/cpm/v1/policies`** (signed). There is **no** `/drafts*` path. The closed hashed `payload` must be **schema version `cafe.crypto_policy.v0.2`** with `crypto_policy_id`, `user_constraints`, `accepted_provider_snapshot`, and top-level `accepted_findings`. See [CP-PERSIST runbook](./docs/security/cp-persist-v1.md).

Flow: compose locally (NB2) → `POST /wallet-challenges` → EIP-191 sign → `POST /policies`. Explore / challenge / persist require **W2** (`422 SCAN_NOT_LATEST` / `503 DISCOVERY_UNAVAILABLE`). Replace = **NB1** DELETE then new signed persist. Retry / conflict → **409** `POLICY_ALREADY_EXISTS` — reconcile via `GET /policies` + `payload_sha256`.

**Minimum required fields (v0.2):**

```json
{
  "schema_version": "cafe.crypto_policy.v0.2",
  "crypto_policy_id": "cpm_pq_account_validation_v1",
  "required_posture": "hybrid",
  "user_constraints": {
    "allow_new_wallet": true,
    "address_continuity_required": false,
    "key_rotation_model": "per_userop"
  },
  "solution_profile_ref": {
    "provider_id": "nicetry",
    "solution_profile_id": "nicetry.fors_c.erc4337.v0_1",
    "manifest_version": "2026-08"
  },
  "accepted_provider_snapshot": {
    "provider_id": "nicetry",
    "solution_profile_id": "nicetry.fors_c.erc4337.v0_1",
    "manifest_version": "2026-08",
    "snapshot_at": "2026-08-01T00:00:00Z",
    "accepted_findings": ["requires_bundler", "requires_local_signer_state"]
  }
}
```

**Gate rules at persist:**
- `schema_version` must be `cafe.crypto_policy.v0.2` (empty or `v0.1` → `400 CRYPTO_POLICY_PAYLOAD_INVALID`).
- `crypto_policy_id` is required (legacy `template_id` on the wire → invalid).
- `user_constraints` is required; CPM **rejoue couche A then B**. Couche B failure → **400** `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` (runtime signal `adr_signal=runtime.no_provider_after_user_constraints`).
- Provider refs in `accepted_provider_snapshot` must be **pinned** — `unpinned_pending_fixture` is rejected. Nicetry fixture refs are pinned (**CPM-P7** done).
- Soft findings listed in `accepted_findings` must match those returned by explore for that candidate.
- Wallet proof (signed message from `wallet-challenges`) is required on `POST /policies`.
- Client-supplied `payload_sha256` on write is **ignored** (server authority).

### Request async policy assessment

`POST /api/cpm/v1/policies/assessment/request` is the canonical HTTP trigger for `policy.assessment.requested.v0.1`.

This endpoint is wallet-scan only. TLS scan IDs are not eligible for CPM migration policy assessment.

**Body (v0.2):** `scan_id` + `crypto_policy_id` only — no `policy_context`, no `selection_request`.

```bash
curl -X POST "${CPM_BASE}/api/cpm/v1/policies/assessment/request" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "crypto_policy_id": "cpm_pq_account_validation_v1",
    "client_request_id": "demo-001"
  }' | jq .
```

Expected outcomes:

| Situation | Response |
| --- | --- |
| Valid wallet scan, event accepted | `202 Accepted` |
| `policy_context` or legacy `selection_request` / couche B fields present | `400` |
| Malformed `scan_id`, missing `crypto_policy_id`, or disallowed unknown field | `400` |
| Unknown scan, scan not readable by the owner, or TLS/non-wallet scan | `404` |
| Discovery authz or detail lookup unavailable | `503` |

CPM reconstructs the authoritative wallet observation server-side from Discovery v1 wallet scan detail. Clients must not send `policy_context` to this endpoint.

On the **NATS** assessment path, legacy payloads produce a **validation error** (reject/nack + failure event and/or structured log) — not an HTTP 400.

## Discovery to CPM Observation Contract

The normalized wallet observation event remains `cafe.discovery.wallet.observed` version `v0.1`. It is informational and must not auto-start assessment by itself. The explicit async command is `policy.assessment.requested.v0.1`, now triggered through CPM.

The normative shared vocabulary lives in `cafe-contracts` under `observation/wallet/v01`. CPM owns policy semantics and Discovery owns scan persistence and scan detail projection.

## QA Sign-off Checklist

Use this checklist before opening or merging API coherency documentation changes.

- Discovery examples use `/discovery/v1` direct paths or `/api/discovery/v1` edge paths.
- CPM examples use `/api/cpm/v1`, except health at `/healthz` direct or `/api/cpm/healthz` at the edge, and version at `/version` direct or `/api/cpm/version` at the edge.
- Discovery deploy version uses `/version` direct or `/api/version` at the edge (`{"version":"…"}`).
- Scan examples use `scan_id`, `status: requested`, and `location` from `POST /discovery/v1/scan`.
- Scan list examples expect `items`, not `results`, for v1 list envelopes.
- Wallet and TLS detail examples fetch `.../scans/{scan_id}` and read `result`.
- Policy assessment docs say CPM-owned, wallet-scan only, body `scan_id` + `crypto_policy_id`, `202` on acceptance, `policy_context` / legacy `selection_request` rejected, TLS scan IDs rejected.
- Delete scan docs mention CPM reference verification, `409 SCAN_REFERENCED_BY_POLICY`, and `503 POLICY_REFERENCE_CHECK_UNAVAILABLE`.
- Edge docs preserve `/api/internal/*` as not exposed.
- **Catalogue:** `GET /crypto-policies` and `GET /providers` documented; retired `/policies/templates|instances|catalog` not presented as live.
- **Explore v0.2:** input `crypto_policy_id` + `policy_context` (+ optional `scan_id`); output `scan_compatible_providers`; legacy explore → **400**.
- **Capability Providers:** explore response carries `required_posture`, `resulting_posture`, `solution_profile_ref`, `maturity`, `claim_status`, `suggested_user_constraints` — no `graphEdges`/`nodeInstances`.
- **`claim_status: "declared"`** is documented as a provider declaration, not an audited or executed proof.
- **Persist (no drafts):** signed `POST /policies` with `schema_version: "cafe.crypto_policy.v0.2"`, closed hashed fields + `payload_sha256` (server); CPM rejeu A+B; `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` on couche B KO; `unpinned_pending_fixture` refs rejected (Nicetry refs pinned); W2; NB1/NB2.
- **Removed:** `/api/cpm/v1/drafts*` — do not document as live.
- **Vocabulary:** scan-compatible / user-qualified / persistable; avoid `ranked_candidates` as normative term.

## Additional Resources

- `cafe-discovery/openapi/discovery-v1.yaml` for the Discovery v1 contract.
- `cafe-crypto-policy-mgt/openapi/cpm-v1.yaml` for the CPM v1 contract (includes Capability Provider fields post-CPM-P4b / amendement P8–P10).
- [docs/security/cpm-contract.md](./docs/security/cpm-contract.md) for CPM authentication, scan authorization, service-token, and troubleshooting details.
- `docs/api/api-v1-qa-checklist.md` for a compact reviewer checklist.
- [04-cafe-admin-guide.md](./04-cafe-admin-guide.md) for platform administration (deploy Compose + minikube, CPM catalogue, signals).
- [cafe-deploy](https://github.com/create2-labs/cafe-deploy) — Docker Compose deployment (still supported).
- [cafe-expresso](https://github.com/create2-labs/cafe-expresso) — minikube / Helm / Argo CD; operator tutorial [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md).
- [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) — Capability Provider ADR.
- [CPM README — Capability Providers](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md) — CPM service, env vars (`CPM_CRYPTO_POLICY_PATHS`, `CPM_PROVIDER_MANIFEST_PATHS`), signals.
- [cafe-frontend `docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md) — FE two-layer maintainer guide (FE-DOC-AMEND).
- [cafe-frontend `CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) — CPM UI user stories US1–US21 and delivery epics.
