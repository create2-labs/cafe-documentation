# CAFE API v1 QA Checklist

Use this checklist when reviewing API coherency docs, runbooks, scripts, and release notes.

## Canonical Routes

| Area | Expected route family |
| --- | --- |
| Discovery direct backend | `/discovery/v1/...` |
| Discovery edge | `/api/discovery/v1/...` |
| CPM direct backend and edge business APIs | `/api/cpm/v1/...` |
| CPM edge health | `/api/cpm/healthz` |
| CPM direct health | `/healthz` |

## Discovery Checks

- `POST /discovery/v1/scan` examples return `scan_id`, `scan_family`, `status: requested`, and `location`.
- Wallet scan lists use `GET /discovery/v1/wallets/scans`.
- TLS scan lists use `GET /discovery/v1/tls/scans`.
- TLS defaults use `GET /discovery/v1/tls/scans/defaults`.
- Scan detail is fetched by `scan_id` through `GET .../wallets/scans/{scan_id}` or `GET .../tls/scans/{scan_id}`.
- Detail consumers read the v1 `result` object; CBOM uses `GET /discovery/v1/wallets/scans/{scan_id}/cbom` when needed.
- Public utilities use `GET /discovery/v1/rpcs` and `GET /discovery/v1/scanners`.

## CPM Checks

- Policy catalog, templates, instances, drafts, policies, and explore examples use `/api/cpm/v1`.
- `POST /api/cpm/v1/policies/decisions/explore` is described as synchronous preview and non-persistent.
- `POST /api/cpm/v1/policies/assessment/request` is described as the async assessment trigger.
- Assessment request is wallet-scan only.
- Assessment request rejects client `policy_context`.
- Unknown, unauthorized, TLS, or non-wallet `scan_id` values return `404` on assessment request.
- Discovery lookup outages return `503` and must not emit `policy.assessment.requested.v0.1`.

## Delete and Operations Checks

- Scan delete docs state that Discovery owns scan deletion and CPM owns policy-reference truth.
- `409 SCAN_REFERENCED_BY_POLICY` comes only from CPM's internal reference verdict.
- CPM reference-check outages, malformed responses, timeouts, and internal `401` or `403` are documented as `503 POLICY_REFERENCE_CHECK_UNAVAILABLE` to the end user.
- Edge docs keep `/api/internal/*` blocked from public routing.
- Service-token docs distinguish user Bearer JWTs from internal service tokens.

## Cross-Repository Follow-up

When stale docs are found outside `cafe-documentation`, do not edit them in this PR. Record a follow-up PR in `WORKPLAN_API_PR.md` with a suffix such as PR12a, PR12b, or PR12c.
