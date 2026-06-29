# CAFE Admin Guide

This guide is the canonical reference for **platform administrators**: operators who deploy, configure, observe, and maintain the CAFE stack. It covers day-2 actions—environment management, health checks, observability, incident diagnosis, and **Crypto Policy (CP) catalog** administration.

Integrators and API consumers should use [03-cafe-developer-guide.md](./03-cafe-developer-guide.md). End-user product behavior is in [02-cafe-user-guide.md](./02-cafe-user-guide.md) and [functional-specifications.md](./functional-specifications.md).

## Document Versioning

- v0.3.0
  - Date: June 27th, 2026
  - Comments: PostgreSQL retention and capacity — soft-delete growth, monitoring queries, operator remediation (no automated purge in P0).
- v0.2.0
  - Date: June 21st, 2026
  - Comments: Document CPM deploy version endpoint (`GET /api/cpm/version`, **CPM-OPS-3**) and Platform Status version tile (**CPM-UI-7A**).
- v0.1.0
  - Date: June 16th, 2026
  - Comments: Initial admin guide — environments, deploy pointers, health, CPM catalog administration, observability, smoke tests, and operator diagnosis workflows.


## ToC

1. [CAFE Admin Guide](#cafe-admin-guide)
   1. [Document Versioning](#document-versioning)
   2. [ToC](#toc)
   3. [Admin scope](#admin-scope)
   4. [Environments and access](#environments-and-access)
      1. [Typical bases](#typical-bases)
      2. [SSH tunnel (non-public stacks)](#ssh-tunnel-non-public-stacks)
      3. [Environment files](#environment-files)
   5. [Deployment operations](#deployment-operations)
      1. [Local dev rebuild (all application images)](#local-dev-rebuild-all-application-images)
      2. [Frontend CPM mode (admin-relevant)](#frontend-cpm-mode-admin-relevant)
      3. [Staging / production](#staging--production)
      4. [Rollback](#rollback)
   6. [Health checks and service status](#health-checks-and-service-status)
      1. [Quick probes (dev)](#quick-probes-dev)
      2. [Compose status](#compose-status)
      3. [Prometheus / Grafana (IMM-OPS-2)](#prometheus--grafana-imm-ops-2)
   7. [PostgreSQL retention and capacity](#postgresql-retention-and-capacity)
      1. [Why the database grows](#why-the-database-grows)
      2. [Monitor size and row pressure](#monitor-size-and-row-pressure)
      3. [Operator response (today)](#operator-response-today)
      4. [Constraints before any purge](#constraints-before-any-purge)
   8. [Authentication and internal tokens (operator view)](#authentication-and-internal-tokens-operator-view)
   9. [CPM catalog administration](#cpm-catalog-administration)
      1. [Three layers (must stay consistent)](#three-layers-must-stay-consistent)
      2. [Source files (repository)](#source-files-repository)
      3. [Environment variables](#environment-variables)
      4. [Procedure: add a second Crypto Policy](#procedure-add-a-second-crypto-policy)
      5. [Common catalog mistakes](#common-catalog-mistakes)
      6. [Persisted policies vs catalog](#persisted-policies-vs-catalog)
   10. [Observability and incidents](#observability-and-incidents)
       1. [CPM explore — no deployable candidate (REQ9)](#cpm-explore--no-deployable-candidate-req9)
       2. [Integrated smoke (Discovery → CPM)](#integrated-smoke-discovery--cpm)
   11. [Diagnose CPM explore (operator `curl`)](#diagnose-cpm-explore-operator-curl)
   12. [User-support scenarios](#user-support-scenarios)
   13. [Secrets and compliance](#secrets-and-compliance)
   14. [Verification checklist (after catalog or CPM deploy)](#verification-checklist-after-catalog-or-cpm-deploy)
   15. [Additional resources](#additional-resources)

---

## Admin scope

| Area | This guide | Other reference |
| --- | --- | --- |
| Compose deploy, image tags, env templates | Overview + pointers | [cafe-deploy README](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) |
| HTTP API integration (`curl`, payloads) | Minimal (diagnosis only) | [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) |
| CPM auth contract, error codes | Pointers | [docs/security/cpm-contract.md](./docs/security/cpm-contract.md) |
| Explore rejection observability | Pointers + checklist | [docs/operations/cpm-explore-no-candidate-observability.md](./docs/operations/cpm-explore-no-candidate-observability.md) |
| PostgreSQL retention, soft-delete growth, capacity | Monitoring + remediation | This guide § [PostgreSQL retention and capacity](#postgresql-retention-and-capacity) |
| Product rules (W1–W8, immutability) | Summary | [functional-specifications.md](./functional-specifications.md) |

**Out of scope:** application feature development, Terraform/Ansible authoring (see cafe-deploy), and future admin product UI (**IMM-OPS-3**).

---


## Environments and access

### Typical bases

| Context | User / edge | Discovery (direct) | CPM (direct) |
| --- | --- | --- | --- |
| Local dev | `http://localhost` or `https://localhost` | `http://localhost:8080` | `http://localhost:8082` |
| Staging / prod | `https://<host>` | Internal only | Internal only |

Public routes at the edge:

- Discovery: `/api/discovery/v1/...`
- CPM: `/api/cpm/v1/...`
- CPM health (probes): `/api/cpm/healthz`
- Discovery deploy version: `/api/version` (public, no auth)
- CPM deploy version: `/api/cpm/version` (public, no auth; **CPM-OPS-3**)

CPM **`GET /metrics`** is scraped inside the Docker network (not exposed through NGINX). See **Observability** below.

### SSH tunnel (non-public stacks)

When services are not published on the public host, use the tunnel workflow documented in [cafe-deploy README — Access to non-public services](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#access-to-non-public-services-ssh-tunnel).

### Environment files

Each deployment uses an env file rendered before `docker compose up`:

```bash
cd cafe-deploy
cp env/dev.env.template env/dev.local.env   # edit secrets locally; never commit
./scripts/render-templates.sh env/dev.local.env
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env up -d
```

Key version pins (examples): `DISCOVERY_VERSION`, `FRONTEND_VERSION`, `CPM_VERSION`, `NGINX_VERSION`. Image tags are the primary rollback lever.

---

## Deployment operations

### Local dev rebuild (all application images)

From `cafe-deploy`:

```bash
./scripts/redeployalldev.sh
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env up -d
```

This rebuilds sibling repos (`cafe-discovery`, `cafe-frontend`, `cafe-crypto-policy-mgt`, scanners) and bakes frontend `VITE_*` build args from `env/dev.local.env`.

### Frontend CPM mode (admin-relevant)

| Variable | Effect |
| --- | --- |
| `VITE_CPM_DATA_SOURCE=api` | CPM page calls real CPM HTTP (required to test catalog, explore, persist) |
| `VITE_CPM_DATA_SOURCE=mock` | Fixtures only — no backend catalog |

Set in `env/dev.local.env` before `redeployalldev.sh`. Release images default to `api`.

### Staging / production

Follow [cafe-deploy — Release & Deployment Workflow](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#release--deployment-workflow-rc--staging--production): RC images → staging validation → promoted tags → production compose update.

### Rollback

Change image version env vars to the last known-good tag, re-render templates if needed, `docker compose up -d`. Do not mix IMM schema migrations across incompatible Discovery versions without reading [RUNBOOK_SCAN_HISTORY.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_SCAN_HISTORY.md).

---

## Health checks and service status

### Quick probes (dev)

```bash
curl -fsS http://localhost/api/health          # edge → Discovery health path
curl -fsS http://localhost:8080/health         # Discovery direct
curl -fsS http://localhost:8080/version        # Discovery version direct
curl -kfsS https://localhost/api/version       # Discovery version via NGINX
curl -fsS http://localhost:8082/healthz        # CPM direct
curl -fsS http://localhost:8082/version        # CPM version direct
curl -kfsS https://localhost/api/cpm/healthz   # CPM via NGINX (prod-like path)
curl -kfsS https://localhost/api/cpm/version   # CPM version via NGINX (prod-like path)
```

Expected version response shape (both services): `{"version":"vX.Y.Z"}` or an RC tag. The SPA **Platform Status** page displays Frontend, Discovery, and CPM versions from `/version.json`, `/api/version`, and `/api/cpm/version` respectively (**CPM-UI-7A**).

### Compose status

```bash
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env ps
docker logs cafe-cpm-dev --tail 100
docker logs cafe-discovery-dev --tail 100
```

### Prometheus / Grafana (IMM-OPS-2)

After `render-templates.sh`, verify:

- Prometheus **Targets** → `cafe-cpm-api` = UP (`PROMETHEUS_CPM_METRICS_TARGET`, default `cafe-cpm:8080`)
- Blackbox job `cafe-cpm-health` → `PROMETHEUS_CPM_HEALTH_URL` (default `https://nginx/api/cpm/healthz`)
- Grafana dashboard **CAFE - CPM Explore Rejections** (UID `cafe-cpm-explore-rejections`)

Smoke:

```bash
./scripts/test-imm-ops-2.sh static    # config files
./scripts/test-imm-ops-2.sh live      # against running stack
```

---

## PostgreSQL retention and capacity

CAFE stores durable scan and Crypto Policy (CP) state in a single **PostgreSQL** instance (`cafe-postgres-${ENV}` in compose). **There is no automated compaction job in P0** — operators must plan for monotonic growth and monitor disk and backup size.

Product intent ([functional-specifications.md — Retention](./functional-specifications.md#retention)): scan rows and policies remain until the user deletes them or deletes their account. User-initiated `DELETE` is implemented as **soft delete** (`deleted_at` set); rows stay in the database. That is correct for product semantics but increases **row count**, **on-disk size**, and **backup volume** over time.

### Why the database grows

| Source | Tables | Behavior |
| --- | --- | --- |
| User delete (scan / draft / policy) | `scan_results`, `tls_scan_results`, `crypto_policy_drafts`, `crypto_policies` | Row kept with `deleted_at` set — hidden from API lists and W1/W3 guards (partial indexes `WHERE deleted_at IS NULL`) |
| Policy replacement | `crypto_policies` | Previous row becomes `status = superseded` (still stored; not a soft delete) |
| Persist idempotence | `draft_persist_state` | After successful persist the draft is hard-deleted, but the state row remains (`completed = true`) so `409 DRAFT_ALREADY_PERSISTED` replays work |
| Plan quota ledger (IMM-6b) | `scan_usage_events` | **Append-only** — `used` is monotonic; soft-deleting a scan lowers `visible` but **does not** remove ledger rows |

Hot queries stay fast thanks to partial indexes, but **disk and backups grow without bound** until a retention or purge policy is applied. Acceptable for P0/dev; track before long-lived staging or production scale.

Further schema context: [cafe-persistence README — CP tables](https://github.com/create2-labs/cafe-persistence/blob/main/README.md#pourquoi-trois-tables), [RUNBOOK_CP_PERSISTENCE.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md).

### Monitor size and row pressure

Set `ENV` to your stack (`dev`, `staging`, `prod`). Default Postgres container: `cafe-postgres-${ENV}`; credentials from `POSTGRES_*` in the env file (`cafe` / `cafe` in dev templates).

**Database and table sizes:**

```bash
export ENV=dev
export POSTGRES_CONTAINER="cafe-postgres-${ENV}"
export POSTGRES_USER=cafe POSTGRES_PASSWORD=cafe POSTGRES_DATABASE=cafe

docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "
SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size;

SELECT relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       n_live_tup AS live_rows,
       n_dead_tup AS dead_rows
FROM pg_stat_user_tables
WHERE schemaname = 'public'
  AND relname IN (
    'scan_results', 'tls_scan_results',
    'crypto_policy_drafts', 'crypto_policies', 'draft_persist_state',
    'scan_usage_events'
  )
ORDER BY pg_total_relation_size(relid) DESC;"
```

**Active vs soft-deleted / superseded row counts:**

```bash
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "
SELECT 'scan_results' AS tbl,
       COUNT(*) FILTER (WHERE deleted_at IS NULL) AS active,
       COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) AS soft_deleted
FROM scan_results
UNION ALL
SELECT 'tls_scan_results', COUNT(*) FILTER (WHERE deleted_at IS NULL),
       COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) FROM tls_scan_results
UNION ALL
SELECT 'crypto_policy_drafts', COUNT(*) FILTER (WHERE deleted_at IS NULL),
       COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) FROM crypto_policy_drafts
UNION ALL
SELECT 'crypto_policies (persisted)', COUNT(*) FILTER (WHERE status = 'persisted' AND deleted_at IS NULL),
       COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) FROM crypto_policies
UNION ALL
SELECT 'crypto_policies (superseded)', COUNT(*) FILTER (WHERE status = 'superseded' AND deleted_at IS NULL), 0
FROM crypto_policies
UNION ALL
SELECT 'draft_persist_state (completed)', COUNT(*) FILTER (WHERE completed), 0 FROM draft_persist_state
UNION ALL
SELECT 'scan_usage_events', COUNT(*), 0 FROM scan_usage_events;"
```

**Suggested cadence:** weekly in staging/prod (or after large test campaigns). Alert informally when `database_size` or `soft_deleted` + `superseded` counts trend up faster than disk budget. Future work: Prometheus on `pg_total_relation_size` (see [cafe-deploy TODO — Postgres retention](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md#postgres-retention--cp--scan-tables-grow-without-bound-soft-delete)).

**Compose volume:** also check the Postgres Docker volume / host mount size (`docker system df -v` or cloud disk metrics).

### Operator response (today)

| Situation | Action |
| --- | --- |
| Approaching disk limit | Expand volume; shorten backup retention if policy allows; run monitoring queries above to find dominant tables |
| High `dead_rows` after bulk activity | `VACUUM (ANALYZE)` on affected tables during a maintenance window (reclaims space from updated/deleted tuples; does not remove soft-deleted business rows) |
| Staging / dev cleanup of test data | **Hard-delete** old soft-deleted rows only after dry-run `SELECT` and sign-off — see constraints below. **Never** ad-hoc purge in production without product/legal approval |
| No automated purge yet | Planned: retention windows, scheduled job, account-deletion cascade (RGPD). Track [cafe-deploy TODO — Postgres retention](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md#postgres-retention--cp--scan-tables-grow-without-bound-soft-delete) |

**Staging-only example** — preview rows eligible for hard-delete (adjust interval and environment):

```sql
-- Dry run: soft-deleted CP rows older than 90 days
SELECT id, deleted_at FROM crypto_policy_drafts
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

SELECT id, status, deleted_at FROM crypto_policies
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

-- Dry run: superseded policies older than 90 days (still visible to DB, not to users)
SELECT id, scan_id, persisted_at FROM crypto_policies
WHERE status = 'superseded' AND deleted_at IS NULL
  AND persisted_at < NOW() - INTERVAL '90 days';
```

After an approved hard-delete in staging:

```sql
-- Example — execute only after dry-run counts match expectation
DELETE FROM crypto_policy_drafts
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

DELETE FROM crypto_policies
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

-- Optional: completed persist state older than N days (409 replay is immediate-only in practice)
DELETE FROM draft_persist_state
WHERE completed = true AND persisted_at < NOW() - INTERVAL '90 days';

VACUUM (ANALYZE) crypto_policy_drafts, crypto_policies, draft_persist_state;
```

Do **not** bulk-delete from `scan_usage_events` to “free space” — that breaks **IMM-6b** monotonic `used` semantics unless coordinated with a contract change.

### Constraints before any purge

- **W1 / W3:** guards count only active (`deleted_at IS NULL`) persisted policies — hard-deleting already soft-deleted rows is safe; hard-deleting **active** rows is not.
- **IMM-6b:** `scan_usage_events` is append-only; purging it changes plan `used` accounting.
- **`draft_persist_state`:** removing recent `completed` rows can weaken `409 DRAFT_ALREADY_PERSISTED` replay behavior for in-flight clients.
- **Backups:** smaller live DB does not shrink existing backup objects — align backup retention with legal/audit policy.
- **Production:** no documented automated purge path yet — coordinate with product and `cafe-persistence` before any hard-delete policy.

---

## Authentication and internal tokens (operator view)

CPM business routes require a **Discovery session JWT**. There is no separate CPM user login.

| Variable | Service | Purpose |
| --- | --- | --- |
| `CPM_AUTH_REQUIRED` | CPM | When `true`, anonymous business API access returns 401 |
| `CAFE_SESSION_JWT_VALIDATION_URL` | CPM → Discovery | Session validation endpoint |
| `CAFE_SESSION_JWT_VALIDATION_SERVICE_TOKEN` | CPM → Discovery | Service auth for validation calls |
| `CAFE_SCAN_AUTHORIZATION_URL` | CPM → Discovery | Scan visibility checks (W2, W7, etc.) |
| `CAFE_SCAN_AUTHORIZATION_SERVICE_TOKEN` | CPM → Discovery | Service auth for scan authorization |
| `CAFE_POLICY_REFERENCE_INTERNAL_SERVICE_TOKEN` | Discovery ↔ CPM | Scan delete policy reference check |

Tokens must match across Discovery and CPM compose env. Mismatch symptoms: CPM `503` on explore, scan delete `503 POLICY_REFERENCE_CHECK_UNAVAILABLE`, or persistent `401`/`403` on CPM while Discovery works.

Full route classification: [docs/security/cpm-contract.md](./docs/security/cpm-contract.md).

**Admin `curl` diagnosis** uses a normal user JWT (sign-in) — same as the developer guide. Service tokens are for inter-service calls only.

---

## CPM catalog administration

The **CP catalog** is not a single database table. CPM loads **static JSON files at startup** and serves them through read APIs. Changing the catalog requires new or updated files and a **CPM process restart** (new container / redeploy).

### Three layers (must stay consistent)

```text
policy_graph_catalog_valid.json     → nodes + allowed transitions (vocabulary)
        ↓
crypto_policy_template_*.json       → reusable CP templates (node_path, posture, constraints)
        ↓
crypto_policy_instance_*.json       → deployable instances (template_id + scope.chain_ids)
```

| Layer | API | What users see |
| --- | --- | --- |
| Graph catalog | `GET /api/cpm/v1/policies/catalog` | Node definitions (internal graph vocabulary) |
| Templates | `GET /api/cpm/v1/policies/templates` | Rows in the CPM policy picker (“Crypto Policy” names) |
| Instances | `GET /api/cpm/v1/policies/instances` | Reference instances used by **explore** for deployability |

**Critical rule:** a template alone does not make a CP selectable. Explore ranks **instances**. An instance must reference a `template_id` and its `scope.chain_ids` must cover **every** chain in `selection_request.target_chain_ids` (**all-or-nothing**). See [WORKPLAN_API §5.1.1](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/WORKPLAN_API.md).

### Source files (repository)

Canonical fixtures and examples live in **cafe-crypto-policy-mgt**:

```
internal/domain/policy/testdata/
├── policy_graph_catalog_valid.json
├── crypto_policy_template_valid.json
├── crypto_policy_instance_valid.json
└── (+ invalid_* fixtures for tests only)
```

Validation logic: `internal/domain/policy/template.go`, `instance.go`, `catalog.go`.  
Loader: `internal/api/read_api.go` → `LoadReadStore()`.

In the **CPM Docker image**, files are copied to `/app/policy/` (`Dockerfile-cpm`).

### Environment variables

| Variable | Default (image) | Meaning |
| --- | --- | --- |
| `CPM_POLICY_CATALOG_PATH` | `/app/policy/policy_graph_catalog_valid.json` | Graph catalog file |
| `CPM_POLICY_TEMPLATE_PATHS` | comma-separated template JSON paths | One entry per CP template |
| `CPM_POLICY_INSTANCE_PATHS` | comma-separated instance JSON paths | One entry per deployable instance |

Example (local `go run` with fixtures):

```bash
export CPM_AUTH_REQUIRED=false
export CPM_POLICY_CATALOG_PATH=internal/domain/policy/testdata/policy_graph_catalog_valid.json
export CPM_POLICY_TEMPLATE_PATHS=internal/domain/policy/testdata/crypto_policy_template_valid.json
export CPM_POLICY_INSTANCE_PATHS=internal/domain/policy/testdata/crypto_policy_instance_valid.json
go run ./cmd/cafe-cpm
```

Multiple templates / instances — comma-separated paths (no spaces required, but trim-safe):

```bash
export CPM_POLICY_TEMPLATE_PATHS=/app/policy/tpl_a.json,/app/policy/tpl_b.json
export CPM_POLICY_INSTANCE_PATHS=/app/policy/inst_a.json,/app/policy/inst_b.json
```

**Deploy note:** `cafe-deploy` compose does not override these by default; the running catalog is whatever is **baked into** `oleglod/cafe-cpm:${CPM_VERSION}`. To change catalog content in dev:

1. Edit or add JSON under `cafe-crypto-policy-mgt/internal/domain/policy/testdata/`
2. Update defaults in `internal/config/config.go` **or** set env vars in `compose/25-cpm.yml` / env file
3. Rebuild CPM image (`redeployalldev.sh` or `docker build -f Dockerfile-cpm`)
4. Restart `cafe-cpm` container

### Procedure: add a second Crypto Policy

1. **Graph catalog** — only if new nodes or transitions are needed. Otherwise reuse existing `node_path` entries from `policy_graph_catalog_valid.json`.

2. **New template file** — unique `id`, `name`, `version`, `catalog_version`, `target_posture`, valid `node_path` (transitions must exist in catalog). Example reference: `crypto_policy_template_valid.json`.

3. **New instance file** — unique `id`, `template_id` matching the template, `scope.chain_ids` listing **all chains** you intend to support (e.g. `1`, `8453`, `137` if Polygon scans must succeed). Example reference: `crypto_policy_instance_valid.json`.

4. **Register paths** in `CPM_POLICY_TEMPLATE_PATHS` and `CPM_POLICY_INSTANCE_PATHS`.

5. **Validate locally:**

   ```bash
   cd cafe-crypto-policy-mgt
   go test ./internal/domain/policy/...
   go test ./internal/api/...
   ```

6. **Rebuild and restart CPM**, then verify APIs with a user JWT:

   ```bash
   curl -fsS "${CPM_BASE}/api/cpm/v1/policies/templates" \
     -H "Authorization: Bearer ${TOKEN}" \
     | jq '[.items[] | {id, name, version}]'

   curl -fsS "${CPM_BASE}/api/cpm/v1/policies/instances" \
     -H "Authorization: Bearer ${TOKEN}" \
     | jq '[.items[] | {id, template_id, chain_ids: .scope.chain_ids}]'
   ```

7. **Verify explore** for a real wallet scan (see **Diagnose CPM explore** below). Both templates should appear in the UI catalog; only **compatible** instances are selectable.

### Common catalog mistakes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Only one CP in UI picker | Single template path configured | Add second template JSON + env path |
| Two CPs listed, one greyed “Incompatible” | No instance for template, or `incompatible.chain_scope` | Add instance; widen `scope.chain_ids` |
| Explore 200, empty selection, `incompatible.chain_scope` | Instance scope narrower than wallet `chain_ids` | Extend `scope.chain_ids` or add new instance |
| CPM fails to start | Invalid JSON, unknown node, bad transition | Check startup logs; run `go test` on policy package |
| Catalog unchanged after edit | Old image still running | Rebuild `cafe-cpm` image and restart container |

### Persisted policies vs catalog

**Owner persisted policies** (`GET /api/cpm/v1/policies`, drafts) are separate from the static catalog. Catalog changes do **not** mutate user drafts or persisted CPs. Users keep existing work; new explore only affects new selections.

---

## Observability and incidents

### CPM explore — no deployable candidate (REQ9)

When users see “no policy applies” but HTTP is healthy, use the dedicated runbook:

**[CPM explore — no deployable candidate (observability & admin diagnosis)](./docs/operations/cpm-explore-no-candidate-observability.md)**

Summary for admins:

| Signal | Where |
| --- | --- |
| User-facing explanation | SPA `CpmExploreRejectionBanner` (REQ8) |
| Structured log | `cpm.explore.no_deployable_candidate` in `docker logs cafe-cpm-*` |
| Counter | `cpm_explore_no_deployable_candidate_total` on `GET /metrics` |
| Dashboard | Grafana **CAFE - CPM Explore Rejections** |
| Alert | `CpmExploreIncompatibleChainScopeSustained` (sustained `incompatible.chain_scope`) |

**Privacy:** never put `scan_id`, wallet address, or per-chain ids on Prometheus labels. Use logs or API explore JSON for investigation.

### Integrated smoke (Discovery → CPM)

From `cafe-deploy`:

```bash
USE_FIXED_TEST_USER=1 \
DISCOVERY_EMAIL='user@example.com' \
DISCOVERY_PASSWORD='…' \
SCAN_ID='<wallet-scan-uuid>' \
SKIP_PERSIST=1 \
DISCOVERY_BASE='http://localhost:8080' \
CPM_BASE='http://localhost:8082' \
./scripts/test-discovery-v1-wallet-scans-to-cpm.sh
```

`SKIP_PERSIST=1` stops after explore — useful when validating catalog scope without persisting.

CPM-only observability smoke: `cafe-crypto-policy-mgt/scripts/test-imm-ops-1.sh`.

---

## Diagnose CPM explore (operator `curl`)

Minimal workflow when supporting a user report. Full detail: [operations runbook § Admin diagnosis](./docs/operations/cpm-explore-no-candidate-observability.md#admin-diagnosis--curl-workflow).

```bash
export DISCOVERY_BASE='http://localhost:8080'
export CPM_BASE='http://localhost:8082'
export SCAN_ID='<scan-uuid>'

TOKEN=$(curl -fsS -X POST "${DISCOVERY_BASE}/auth/signin" \
  -H 'Content-Type: application/json' \
  -d '{"email":"…","password":"…","turnstile_token":"dev"}' \
  | jq -r '.token')

DETAIL=$(curl -fsS "${DISCOVERY_BASE}/discovery/v1/wallets/scans/${SCAN_ID}" \
  -H "Authorization: Bearer ${TOKEN}")

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
    }')" | jq '{
      selected: .decision.selected_policy_id,
      rejections: [.decision.rejected_candidates[]? | {
        template: .template_id,
        codes: [.rejection_reasons[]?.code]
      }]
    }'
```

Compare `selection_request.target_chain_ids` with each instance `scope.chain_ids` from `GET /policies/instances`.

---

## User-support scenarios

| User report | Check first | Admin action |
| --- | --- | --- |
| “No wallet scan on CPM page” | Discovery scans exist, scan `completed` | W7 gate — newest scan must be completed; see functional specs |
| “Policy greyed out / incompatible” | Explore rejection code | Catalog instance `scope.chain_ids` vs scan chains |
| “Cannot delete scan” | `409 SCAN_REFERENCED_BY_POLICY` | User must delete or rebind CPM policy first (W3/W4) |
| “CPM page errors / session” | Browser network tab on `/api/cpm/v1` | CPM auth env, Discovery session validation URL |
| “Persist failed” | Wallet challenge + draft state | [CP-PERSIST V1 runbook](./docs/security/cp-persist-v1.md) |
| Draft on old scan after rescan | Orphan draft (FE-IMM-4) | User must **Rebind to last scan** in CPM UI — not automatic |

Admins do **not** mutate user drafts or persisted policies through catalog files. Catalog is read-only platform configuration.

---

## Secrets and compliance

- Env templates (`env/*.env.template`) document required secrets; local overrides use `*.local.env` (gitignored).
- Use cafe-deploy **pre-commit** hooks to reduce accidental secret commits.
- Service tokens (`CAFE_*_SERVICE_TOKEN`) are rotation-sensitive — update Discovery and CPM together.
- Logs may contain `scan_id` and hashed wallet identifiers for CPM explore events; do not export raw wallet addresses to metrics.

---

## Verification checklist (after catalog or CPM deploy)

- [ ] `GET /healthz` and `/api/cpm/healthz` succeed
- [ ] `GET /version` (Discovery direct) and `/api/version` (edge) return `{"version":"…"}`
- [ ] `GET /version` (CPM direct) and `/api/cpm/version` (edge) return `{"version":"…"}`
- [ ] Platform Status → Version Information shows Frontend, Discovery, and CPM versions (or `Unknown` when a service is down)
- [ ] `GET /api/cpm/v1/policies/templates` returns expected template count
- [ ] `GET /api/cpm/v1/policies/instances` shows correct `scope.chain_ids`
- [ ] Explore smoke with a known `scan_id` selects a candidate (or expected rejection documented)
- [ ] Prometheus target `cafe-cpm-api` UP
- [ ] Frontend built with `VITE_CPM_DATA_SOURCE=api` if testing real catalog in UI
- [ ] `go test ./...` passed in `cafe-crypto-policy-mgt` before image publish

---

## Additional resources

- [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) — API v1 integration reference
- [technical-specifications.md](./technical-specifications.md) — architecture, IMM-OPS, testing matrix
- [functional-specifications.md](./functional-specifications.md) — product rules and governance (W1–W8)
- [cafe-crypto-policy-mgt README](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md) — CPM service, env vars, local run
- [cafe-deploy README](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) — compose, release workflow, env catalog
- [CPM v1 flow](./docs/architecture/cpm-v1-flow.md) — Option A scan → explore → persist
- [CPM explore observability runbook](./docs/operations/cpm-explore-no-candidate-observability.md)
- [CPM auth contract](./docs/security/cpm-contract.md)
- [CP-PERSIST V1](./docs/security/cp-persist-v1.md)
- [RUNBOOK_CP_PERSISTENCE](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md) — durable CP via cafe-persistence
- [cafe-deploy TODO — Postgres retention](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md#postgres-retention--cp--scan-tables-grow-without-bound-soft-delete) — planned compaction work
