# CAFE Developer Guide

This guide is the canonical integration reference for the CAFE API v1 rollout. It covers the public Discovery and CPM HTTP surfaces used by browsers, scripts, and partner integrations after the API coherency work.

## Document Versioning

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

## Base URLs

Use one of these bases depending on where the caller runs.

| Context | Discovery base | CPM base | Notes |
| --- | --- | --- | --- |
| Direct local services | `http://localhost:8080` | `http://localhost:8082` | Use backend paths exactly as registered by each service. |
| Edge / NGINX | `https://<host>/api` | `https://<host>` | Discovery is reached as `/api/discovery/v1/...`; CPM is reached as `/api/cpm/v1/...`. |

Examples below use:

```bash
export DISCOVERY_BASE="http://localhost:8080"
export EDGE_API_BASE="https://localhost/api"
export CPM_BASE="http://localhost:8082"
export EDGE_BASE="https://localhost"
```

For development HTTPS with a self-signed or private CA, add `-k` to `curl` only in local/dev contexts.

## Authentication

Most Discovery and CPM business endpoints require a Discovery-issued session token.

```bash
JWT=$(curl -s -X POST "${DISCOVERY_BASE}/auth/signin" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "turnstile_token": "dev"
  }' | jq -r '.token')
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
| Catalog | `GET /api/cpm/v1/policies/catalog` | Bearer |
| Templates | `GET /api/cpm/v1/policies/templates` | Bearer |
| Instances | `GET /api/cpm/v1/policies/instances` | Bearer |
| Explore decision | `POST /api/cpm/v1/policies/decisions/explore` | Bearer |
| List or read policies | `GET /api/cpm/v1/policies` | Bearer |
| Wallet challenge (EOA persist prep) | `POST /api/cpm/v1/wallet-challenges` | Bearer |
| Persist draft (EOA — normative) | `POST /api/cpm/v1/drafts/{draft_id}/persist` | Bearer + signed authorization |
| Legacy policy upsert | `POST /api/cpm/v1/policies` | Bearer — **not** normative EOA persist; missing proof → **403** |
| Delete policy | `DELETE /api/cpm/v1/policies?id=...` | Bearer |
| Drafts | `/api/cpm/v1/drafts` | Bearer |
| Async policy assessment request | `POST /api/cpm/v1/policies/assessment/request` | Bearer |
| Health | `GET /healthz` direct, `GET /api/cpm/healthz` at edge | Public |
| Deployed version | `GET /version` direct, `GET /api/cpm/version` at edge | Public |

## Discovery Workflows

### Queue a scan

`POST /discovery/v1/scan` accepts exactly one target: `address` for a wallet scan or `url` for a TLS endpoint scan.

```bash
curl -X POST "${DISCOVERY_BASE}/discovery/v1/scan" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"address":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e"}' | jq .
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

### Explore a decision synchronously

`decisions/explore` is a synchronous preview. It evaluates an observation and a selection request, but it does not persist a final policy and does not trigger the async assessment pipeline.

```bash
curl -X POST "${CPM_BASE}/api/cpm/v1/policies/decisions/explore" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "observation": {
      "chain_ids": [1, 8453],
      "account_kind": "eoa",
      "current_algorithm": "secp256k1_ecrecover",
      "current_pq_posture": "classical_only",
      "public_key_exposed": true,
      "is_multichain": true,
      "observed_at": "2026-04-17T09:59:58Z"
    },
    "selection_request": {
      "target_posture": "hybrid",
      "target_chain_ids": [1, 8453],
      "require_multichain": true,
      "allow_new_wallet": false,
      "address_continuity_required": true,
      "key_rotation_required": true,
      "recovery_required": true,
      "minimum_maturity": 1,
      "approval_mode": "manual"
    }
  }' | jq .
```

When `scan_id` is supplied, CPM may authorize scan visibility against Discovery, but the explore endpoint still consumes the provided observation. It does not fetch authoritative scan detail as a substitute for `observation`.

#### Option A: explore with Discovery v1 `policy_context`

**Option A** (post-V1 CPM) means policy workflows run against **real user-owned wallet scans** exposed by the authenticated Discovery backend—see [CPM `workplans/CPM_post_v_1_option_a_scan_context.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/CPM_post_v_1_option_a_scan_context.md). The v1 implementation uses list/detail under `/discovery/v1/wallets/scans` and CPM explore with client-built **`policy_context`** from scan detail (distinct from async assessment, which forbids `policy_context`).

Production UI and integrators on **Option A** load wallet scan **detail** from `GET /discovery/v1/wallets/scans/{scan_id}` (edge: `/api/discovery/v1/...`) and send that shape as **`policy_context`** on explore, plus top-level **`scan_id`** and **`selection_request`**. Field mapping is normative in [Discovery `CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md`](https://github.com/create2-labs/cafe-discovery/blob/main/docs/CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md) §3.1; the integrated story is in [CPM `CPM_OPTION_A_INTEGRATED.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CPM_OPTION_A_INTEGRATED.md) and [Option A architecture](./docs/architecture/cpm-v1-flow.md). CPM UI behavior (graph workspace, **US1–US21**): [`cafe-frontend/CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md).

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
      policy_context: $ctx,
      selection_request: {
        target_posture: "hybrid",
        target_chain_ids: [1],
        require_multichain: false,
        allow_new_wallet: false,
        address_continuity_required: true,
        key_rotation_required: true,
        recovery_required: true,
        minimum_maturity: 1,
        approval_mode: "manual"
      }
    }')" | jq .
```

#### No deployable candidate (HTTP 200 — not an error)

Explore may return **200** with an empty `decision.selected_policy_id` and populated `decision.rejected_candidates` — for example when `target_chain_id 56` is in the wallet context but the catalog instance `scope.chain_ids` does not include chain `56` (`incompatible.chain_scope`). This is a **product/ops signal**, not a failed HTTP call.

| Audience | What to use |
| --- | --- |
| End user | SPA rejection banner (**REQ8**) |
| Admin / SRE | [Operations runbook — admin `curl` workflow](./docs/operations/cpm-explore-no-candidate-observability.md#admin-diagnosis--curl-workflow): explore JSON, `GET /policies/instances`, CPM structured logs, Prometheus/Grafana |
| Integrators | Treat HTTP 200 + rejections as a valid outcome; inspect `rejection_reasons[].code` and messages before persist |

**Smoke (integrated path):** from `cafe-deploy`, `SKIP_PERSIST=1 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh` with `SCAN_ID`, `DISCOVERY_BASE`, `CPM_BASE`, and credentials — stops after explore when no candidate is selected.

### Request async policy assessment

`POST /api/cpm/v1/policies/assessment/request` is the canonical HTTP trigger for `policy.assessment.requested.v0.1`.

This endpoint is wallet-scan only. TLS scan IDs are not eligible for CPM migration policy assessment.

```bash
curl -X POST "${CPM_BASE}/api/cpm/v1/policies/assessment/request" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "client_request_id": "demo-001",
    "selection_request": {
      "target_posture": "hybrid",
      "target_chain_ids": [1],
      "require_multichain": false,
      "allow_new_wallet": false,
      "address_continuity_required": true,
      "key_rotation_required": true,
      "recovery_required": true,
      "minimum_maturity": 1,
      "approval_mode": "manual"
    }
  }' | jq .
```

Expected outcomes:

| Situation | Response |
| --- | --- |
| Valid wallet scan, event accepted | `202 Accepted` |
| `policy_context` is present in the request body | `400` |
| Malformed `scan_id`, invalid `selection_request`, or disallowed unknown field | `400` |
| Unknown scan, scan not readable by the owner, or TLS/non-wallet scan | `404` |
| Discovery authz or detail lookup unavailable | `503` |

CPM reconstructs the authoritative wallet observation server-side from Discovery v1 wallet scan detail. Clients must not send `policy_context` to this endpoint.

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
- Policy assessment docs say CPM-owned, wallet-scan only, `202` on acceptance, `policy_context` rejected, TLS scan IDs rejected.
- Delete scan docs mention CPM reference verification, `409 SCAN_REFERENCED_BY_POLICY`, and `503 POLICY_REFERENCE_CHECK_UNAVAILABLE`.
- Edge docs preserve `/api/internal/*` as not exposed.

## Additional Resources

- `cafe-discovery/openapi/discovery-v1.yaml` for the Discovery v1 contract.
- `cafe-crypto-policy-mgt/openapi/cpm-v1.yaml` for the CPM v1 contract.
- `docs/security/cpm-auth-only-contract.md` for CPM authentication, scan authorization, service-token, and troubleshooting details.
- `docs/api/api-v1-qa-checklist.md` for a compact reviewer checklist.
- [04-cafe-admin-guide.md](./04-cafe-admin-guide.md) for platform administration (deploy, CPM catalog, observability).
