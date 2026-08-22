# CPM explore — no scan-compatible provider (observability & admin diagnosis)

**REQ9** platform observability when CPM cannot select a **scan-compatible** Capability Provider during explore (couche A). Complements user-facing **REQ8** (explore rejection banner in the SPA).

**Tracking:** [CPM `IMMUTABILITE_PR.md` — IMM-OPS-1…3](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/IMMUTABILITE_PR.md) · [Frontend `TODO.md` — REQ9](https://github.com/create2-labs/cafe-frontend/blob/main/TODO.md)

**ADR Capability Providers (amendement):** ADR §7.2.1 **family 2** runtime signal — empty `scan_compatible_providers` with non-empty `rejected_candidates`. Prefer **signaux / signals** (not “alarmes” as the unique term). Couche B failures at persist are a **separate** signal (`runtime.no_provider_after_user_constraints`). See [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) and [CPM README](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md).

---

## What this signal means

`POST /api/cpm/v1/policies/decisions/explore` may return HTTP **200** with:

- empty `decision.scan_compatible_providers`, and
- non-empty `decision.rejected_candidates`.

This is **not** a transport or auth failure. Discovery supplied a usable wallet context and the client selected a catalogue Crypto Policy, but **couche A** found **no scan-compatible** provider (posture, wallet type, deployable chain + capabilities). Structured observability uses:

- `event=cpm.explore.no_deployable_candidate`
- `adr_signal=runtime.no_scan_compatible`
- counter `cpm_explore_no_deployable_candidate_total`

**Not this signal:** persist **400** `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` (couche B KO after a scan-compatible snapshot) — that emits `cpm.persist.user_constraints_incompatible` + `adr_signal=runtime.no_provider_after_user_constraints`.

Typical rejection codes (couche A / provider hard):

| Code | Category | Trigger |
| --- | --- | --- |
| `incompatible.chain_scope` / `incompatible.provider.chain` | Chain support | Provider cannot deploy on the wallet’s chain set |
| `incompatible.posture` | Posture mismatch | Crypto Policy `required_posture` != profile `resulting_posture` |
| `incompatible.provider.rotation` | Capability | Profile needs rotation capability (e.g. `rotate_signer` for `per_userop`) that couche A cannot satisfy |
| `incompatible.provider.wallet_type` | Provider hard constraint | Provider does not support the account type |
| `compatibility_status=erroneous` | Manifest | Contradictory `suggested_user_constraints` (not scan-compatible) |

---

## Separation of concerns

| Layer | Track | Repository | Role |
| --- | --- | --- | --- |
| End user | **REQ8** / **FE-IMM-13** | `cafe-frontend` | Banner explaining rejection in the CPM UI (`CpmExploreRejectionBanner`) |
| Backend instrumentation | **IMM-OPS-1** / **CPM-P11b** | `cafe-crypto-policy-mgt` | Structured log + Prometheus counter on each qualifying explore |
| Ops dashboard / alert | **IMM-OPS-2** | `cafe-deploy` | Grafana dashboard, Prometheus scrape, sustained-trend alert |
| Catalogue startup (family 1) | **CPM-P11a** | `cafe-crypto-policy-mgt` | Posture orphanage WARN / malformed suggestions ERROR — **not** this runbook |
| Future admin product view | **IMM-OPS-3** | TBD | Actionable coverage-gap synthesis (deferred) |

**Privacy / cardinality:** investigable fields (`scan_id`, chain id lists, catalogue ids, hashed wallet) belong in **structured logs** or a future admin UI — **never** as high-cardinality Prometheus labels.

---

## IMM-OPS-1 — CPM backend

### Hook

After building the explore decision, before `respondJSON(200)`, when `len(scan_compatible_providers)==0` and `len(rejected_candidates)>0`:

- **Log event:** `cpm.explore.no_deployable_candidate` (+ `adr_signal=runtime.no_scan_compatible`)
- **Counter:** `cpm_explore_no_deployable_candidate_total` (one increment per event)

**Endpoint:** `GET /metrics` on `cafe-cpm` (public, same class as `/healthz`). Dedicated registry — counter lines appear only after at least one qualifying explore (empty `/metrics` body is normal on a fresh deploy).

### Prometheus labels (low cardinality only)

| Label | Meaning |
| --- | --- |
| `rejection_code` | **Dominant** code for the event (priority: `incompatible.chain_scope`, else first stable blocking code, else `unknown`) |
| `wallet_type` | Canonical value from `policy_context`, or `unknown` |
| `binding` | `discovery` when `scan_id` / Discovery context is present; else `unknown` |
| `missing_chain_count` | Bucket `0` / `1` / `2` / `3` / `4_plus` / `unknown` — when chain-scope style rejections apply |

### Structured log fields (investigation)

May include:

- `scan_id`, `crypto_policy_id`
- `requested_chain_ids`, `observed_chain_ids`, `missing_chain_ids`
- `rejection_codes`, `dominant_rejection_code`
- `rejected_candidates_count`
- candidate / provider identifiers when available
- `request_id` (from `X-Request-Id` when present)
- `wallet_address_hash` — normalized address, SHA-256 truncated; **never** raw wallet address

**Read logs (dev stack):**

```bash
docker logs cafe-cpm-dev 2>&1 | grep 'cpm.explore.no_deployable_candidate' | tail -5
```

Correlate with a specific request:

```bash
docker logs cafe-cpm-dev 2>&1 | grep 'X-Request-Id: admin-diagnose-1'
# or grep the request_id value emitted in the log line
```

---

## IMM-OPS-2 — Deploy / Grafana

### Prometheus scrape

- **Job:** `cafe-cpm-api`
- **Target:** `PROMETHEUS_CPM_METRICS_TARGET` (default `cafe-cpm:8080/metrics`)
- **Render:** `./scripts/render-templates.sh env/<env>.env` then restart `prometheus`

Verify: Prometheus **Status → Targets** → `cafe-cpm-api` = UP.

### Grafana dashboard

- **Title:** CAFE - CPM Explore Rejections
- **File:** `cafe-deploy/volumes/grafana/dashboards/dashboard-cpm-explore-rejections.json`
- **Variables:** `interval`, `job`, `rejection_code`
- **Panels:** rate by `rejection_code`, focus chain-scope style codes, breakdown by `wallet_type` and `missing_chain_count` bucket

Grafana reads Prometheus (`http://prometheus:9090`), not raw CPM `/metrics` on the host.

### Alert

- **Name:** `CpmExploreIncompatibleChainScopeSustained`
- **Severity:** warning
- **Intent:** sustained elevation of chain-scope style rejections (15m rate > 3× 6h baseline), not a single event

### Smoke

```bash
# cafe-deploy
./scripts/test-imm-ops-2.sh static
./scripts/test-imm-ops-2.sh live

# Populate counter (requires JWT on stack)
DISCOVERY_BASE=http://localhost:8080 CPM_BASE_URL=http://localhost:8082 \
  ../cafe-crypto-policy-mgt/scripts/test-imm-ops-1.sh smoke
```

---

## Admin diagnosis — curl workflow

Use this when Grafana shows a spike or a user reports “no policy applies” on the CPM page.

### 0. Environment

```bash
export DISCOVERY_BASE='http://localhost:8080'   # or https://<host>/api at edge
export CPM_BASE='http://localhost:8082'         # or https://<host> at edge
export EMAIL='user@example.com'
export PASSWORD='…'
export SCAN_ID='1400d642-f0cf-4e01-ab2c-3202e0959679'   # known wallet scan
export CRYPTO_POLICY_ID='cpm_pq_account_validation_v1'
```

### 1. Session JWT

```bash
TOKEN=$(curl -fsS -X POST "${DISCOVERY_BASE}/auth/signin" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg e "$EMAIL" --arg p "$PASSWORD" \
    '{email:$e, password:$p, turnstile_token:"dev-pass"}')" \
  | jq -r '.token')
```

At the edge, use `${DISCOVERY_BASE}/auth/signin` when `DISCOVERY_BASE` already includes `/api`.

### 2. Wallet scan detail (CPM inputs)

```bash
ENC=$(jq -rn --arg u "$SCAN_ID" '$u|@uri')
DETAIL=$(curl -fsS "${DISCOVERY_BASE}/discovery/v1/wallets/scans/${ENC}" \
  -H "Authorization: Bearer ${TOKEN}")

echo "$DETAIL" | jq '{
  scan_id,
  status,
  wallet_type: .result.wallet_type,
  chain_ids: .result.chain_ids,
  current_pq_posture: .result.current_pq_posture
}'
```

### 3. Explore v0.2 — full rejection detail (primary API diagnostic)

Build `policy_context` from detail; send `crypto_policy_id` (no `selection_request`):

```bash
curl -fsS -X POST "${CPM_BASE}/api/cpm/v1/policies/decisions/explore" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'X-Request-Id: admin-diagnose-1' \
  -d "$(jq -nc \
    --arg scan_id "$SCAN_ID" \
    --arg cp "$CRYPTO_POLICY_ID" \
    --argjson pc "$(jq -c '{
      scan_id: .scan_id,
      wallet_address: .result.wallet_address,
      wallet_type: .result.wallet_type,
      chain_ids: .result.chain_ids,
      current_algorithm: (.result.current_algorithm // "secp256k1_ecrecover"),
      current_pq_posture: .result.current_pq_posture,
      scanned_at: .result.scanned_at,
      status: .status
    }' <<<"$DETAIL")" \
    '{
      scan_id: $scan_id,
      crypto_policy_id: $cp,
      policy_context: $pc
    }')" | jq .
```

**Compact admin view:**

```bash
# re-run explore and pipe to:
jq '{
  scan_compatible: [.decision.scan_compatible_providers[]? | .candidate_id],
  crypto_policy_id: $CRYPTO_POLICY_ID,
  observed: .decision.observed_wallet_summary.chain_ids,
  rejections: [.decision.rejected_candidates[]? | {
    crypto_policy_id: .crypto_policy_id,
    provider: .solution_profile_ref.provider_id,
    codes: [.rejection_reasons[]?.code],
    messages: [.rejection_reasons[]?.message]
  }]
}' --arg CRYPTO_POLICY_ID "$CRYPTO_POLICY_ID"
```

HTTP **200** with empty `scan_compatible_providers` is expected for this outcome — do not treat it as a client error. Legacy explore bodies with `selection_request` return **400**.

### 4. Catalogue — Crypto Policies + providers

```bash
curl -fsS "${CPM_BASE}/api/cpm/v1/crypto-policies" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq '[.items[] | {id, required_posture, allowed_providers}]'

curl -fsS "${CPM_BASE}/api/cpm/v1/providers" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq .
```

Diagnosis pattern: confirm the CP’s `allowed_providers` and each provider’s chain / posture / capabilities against the wallet `chain_ids` and type from Discovery detail.

Retired (do not use): `GET /policies/instances`, `/policies/templates`, `/policies/catalog`.

### 5. Metrics (complement to Grafana)

```bash
curl -fsS "${CPM_BASE}/metrics" | grep cpm_explore_no_deployable_candidate

curl -fsS -G 'http://localhost:9090/api/v1/query' \
  --data-urlencode 'query=cpm_explore_no_deployable_candidate_total' \
  | jq '.data.result[] | {metric: .metric, value: .value[1]}'
```

### 6. Integrated smoke (repeatable)

From `cafe-deploy` (sets JWT, detail, explore, optional persist):

```bash
USE_FIXED_TEST_USER=1 \
DISCOVERY_EMAIL='user@example.com' \
DISCOVERY_PASSWORD='…' \
SCAN_ID='1400d642-f0cf-4e01-ab2c-3202e0959679' \
SKIP_PERSIST=1 \
DISCOVERY_BASE='http://localhost:8080' \
CPM_BASE='http://localhost:8082' \
./scripts/test-discovery-v1-wallet-scans-to-cpm.sh
```

`SKIP_PERSIST=1` stops after explore (exit `1` when no scan-compatible provider is **expected** for uncovered chains).

---

## Diagnosis checklist

| Step | Question | Source |
| --- | --- | --- |
| 1 | Is explore HTTP 200 with empty `scan_compatible_providers`? | §3 explore JSON |
| 2 | Dominant code? | `rejection_reasons[].code` or log `dominant_rejection_code` |
| 3 | Which CP / providers are in catalogue? | §4 `/crypto-policies` + `/providers` |
| 4 | Which chains / posture / wallet type mismatch? | Detail vs provider capabilities |
| 5 | Is this a trend or one-off? | Grafana / Prometheus §5 |
| 6 | Correlation id for support? | `X-Request-Id` → CPM logs |
| 7 | Is this actually couche B at persist? | Separate signal — not this counter |

---

## Related documents

- [04-cafe-admin-guide.md](../../04-cafe-admin-guide.md) — CPM catalogue administration and operator workflows
- [Functional specifications — Explore (preview)](../../functional-specifications.md#explore-preview--couche-a)
- [Developer guide — Option A explore](../../03-cafe-developer-guide.md#option-a-explore-with-discovery-v1-policy_context)
- [CPM v1 flow](../architecture/cpm-v1-flow.md)
- [CPM README — IMM-OPS-1](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md#explore-no-deployable-candidate-observability-imm-ops-1)
- [cafe-deploy README — IMM-OPS-2](https://github.com/create2-labs/cafe-deploy/blob/main/README.md)
