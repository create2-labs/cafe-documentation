# CPM explore — no deployable candidate (observability & admin diagnosis)

**REQ9** platform observability when CPM cannot select a deployable Crypto Policy during explore. Complements user-facing **REQ8** (explore rejection banner in the SPA).

**Tracking:** [CPM `IMMUTABILITE_PR.md` — IMM-OPS-1…3](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/IMMUTABILITE_PR.md) · [Frontend `TODO.md` — REQ9](https://github.com/create2-labs/cafe-frontend/blob/main/TODO.md)

---

## What this signal means

`POST /api/cpm/v1/policies/decisions/explore` may return HTTP **200** with:

- empty `decision.selected_policy_id` (and no ranked deployable candidate), and
- non-empty `decision.rejected_candidates`.

This is **not** a transport or auth failure. Discovery supplied a usable wallet context, but the CPM compatibility engine found **no catalog instance** that satisfies the selection request — commonly `incompatible.chain_scope` when a requested chain is missing from `scope.chain_ids` (**all-or-nothing** on `selection_request.target_chain_ids`; see [WORKPLAN §5.1.1](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/WORKPLAN_API.md#511-explore--périmètre-chaînes-target_chain_ids-tout-ou-rien)).

Typical causes:

- Catalog gap (no CP covering a discovered chain, e.g. chain `56`).
- Instance scope too narrow for the wallet’s multi-chain set.
- Product mismatch (posture, maturity, multichain flags) — other rejection codes.

---

## Separation of concerns

| Layer | Track | Repository | Role |
| --- | --- | --- | --- |
| End user | **REQ8** / **FE-IMM-13** | `cafe-frontend` | Banner explaining rejection in the CPM UI (`CpmExploreRejectionBanner`) |
| Backend instrumentation | **IMM-OPS-1** | `cafe-crypto-policy-mgt` | Structured log + Prometheus counter on each qualifying explore |
| Ops dashboard / alert | **IMM-OPS-2** | `cafe-deploy` | Grafana dashboard, Prometheus scrape, sustained-trend alert |
| Future admin product view | **IMM-OPS-3** | TBD | Actionable coverage-gap synthesis (deferred) |

**Privacy / cardinality:** investigable fields (`scan_id`, chain id lists, catalog instance ids, hashed wallet) belong in **structured logs** or a future admin UI — **never** as high-cardinality Prometheus labels.

---

## IMM-OPS-1 — CPM backend

### Hook

After `PolicyDecisionEvaluator.Evaluate`, before `respondJSON(200)`, when `len(ranked)==0` and `len(rejected)>0`:

- **Log event:** `cpm.explore.no_deployable_candidate`
- **Counter:** `cpm_explore_no_deployable_candidate_total` (one increment per event)

**Endpoint:** `GET /metrics` on `cafe-cpm` (public, same class as `/healthz`). Dedicated registry — counter lines appear only after at least one qualifying explore (empty `/metrics` body is normal on a fresh deploy).

### Prometheus labels (low cardinality only)

| Label | Meaning |
| --- | --- |
| `rejection_code` | **Dominant** code for the event (priority: `incompatible.chain_scope`, else first stable blocking code, else `unknown`) |
| `wallet_type` | Canonical value from `policy_context`, or `unknown` |
| `binding` | `discovery` when `scan_id` / Discovery context is present; else `unknown` |
| `missing_chain_count` | Bucket `0` / `1` / `2` / `3` / `4_plus` / `unknown` — for `incompatible.chain_scope`, minimum missing chains among rejected candidates |

### Structured log fields (investigation)

May include:

- `scan_id`
- `requested_chain_ids`, `observed_chain_ids`, `candidate_chain_ids`, `missing_chain_ids`
- `rejection_codes`, `dominant_rejection_code`
- `rejected_candidates_count`
- candidate `instance_id` / `template_id` when available
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
- **Panels:** rate by `rejection_code`, focus `incompatible.chain_scope`, breakdown by `wallet_type` and `missing_chain_count` bucket

Grafana reads Prometheus (`http://prometheus:9090`), not raw CPM `/metrics` on the host.

### Alert

- **Name:** `CpmExploreIncompatibleChainScopeSustained`
- **Severity:** warning
- **Intent:** sustained elevation of `incompatible.chain_scope` (15m rate > 3× 6h baseline), not a single event

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

### 3. Explore — full rejection detail (primary API diagnostic)

Build `policy_context` and `selection_request` from detail (same as integrated smoke):

```bash
curl -fsS -X POST "${CPM_BASE}/api/cpm/v1/policies/decisions/explore" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'X-Request-Id: admin-diagnose-1' \
  -d "$(jq -nc \
    --arg scan_id "$SCAN_ID" \
    --argjson pc "$(jq -c '{
      wallet_address: .result.wallet_address,
      wallet_type: .result.wallet_type,
      chain_ids: .result.chain_ids,
      current_algorithm: (.result.current_algorithm // "secp256k1_ecrecover"),
      current_pq_posture: .result.current_pq_posture,
      scanned_at: .result.scanned_at
    }' <<<"$DETAIL")" \
    --argjson chains "$(jq -c '.result.chain_ids' <<<"$DETAIL")" \
    '{
      scan_id: $scan_id,
      policy_context: $pc,
      selection_request: {
        target_posture: "hybrid",
        target_chain_ids: $chains,
        require_multichain: (($chains | length) > 1),
        allow_new_wallet: false,
        address_continuity_required: true,
        minimum_maturity: 1,
        approval_mode: "manual"
      }
    }')" | jq .
```

**Compact admin view:**

```bash
# re-run explore and pipe to:
jq '{
  selected: .decision.selected_policy_id,
  targets: .decision.request_summary.target_chain_ids,
  observed: .decision.observed_wallet_summary.chain_ids,
  rejections: [.decision.rejected_candidates[]? | {
    instance: .crypto_policy_instance_id,
    template: .template_id,
    codes: [.rejection_reasons[]?.code],
    messages: [.rejection_reasons[]?.message]
  }]
}'
```

Example rejection:

```json
{
  "code": "incompatible.chain_scope",
  "message": "target_chain_id 56 not covered by instance scope"
}
```

HTTP **200** with empty `selected` is expected for this outcome — do not treat it as a client error.

### 4. Catalog — compare `scope.chain_ids` vs requested chains

```bash
curl -fsS "${CPM_BASE}/api/cpm/v1/policies/instances" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq '[.items[] | {id, template_id, scope: .scope.chain_ids}]'
```

Diagnosis pattern: for each `target_chain_id` in the explore request, it must appear in the candidate instance `scope.chain_ids`. If the wallet requests `[1, 56, 8453, 42161]` but `cpx_hybrid_prod` has `scope.chain_ids: [1, 8453]`, chains **56** and **42161** are missing → `incompatible.chain_scope`.

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

`SKIP_PERSIST=1` stops after explore (exit `1` when no candidate is **expected** for out-of-scope chains).

---

## Diagnosis checklist

| Step | Question | Source |
| --- | --- | --- |
| 1 | Is explore HTTP 200 with rejections? | §3 explore JSON |
| 2 | Dominant code? | `rejection_reasons[].code` or log `dominant_rejection_code` |
| 3 | Which chains are requested vs in catalog scope? | §3 `target_chain_ids` + §4 `scope.chain_ids` |
| 4 | Which chains are missing? | Log `missing_chain_ids` or diff targets vs scope |
| 5 | Is this a trend or one-off? | Grafana / Prometheus §5 |
| 6 | Correlation id for support? | `X-Request-Id` → CPM logs |

---

## Related documents

- [04-cafe-admin-guide.md](../../04-cafe-admin-guide.md) — CPM catalog administration and operator workflows
- [Functional specifications — Explore (preview)](../../functional-specifications.md#explore-preview)
- [Developer guide — Option A explore](../../03-cafe-developer-guide.md#option-a-explore-with-discovery-v1-policy_context)
- [CPM v1 flow](../architecture/cpm-v1-flow.md)
- [CPM README — IMM-OPS-1](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md#explore-no-deployable-candidate-observability-imm-ops-1)
- [cafe-deploy README — IMM-OPS-2](https://github.com/create2-labs/cafe-deploy/blob/main/README.md)
