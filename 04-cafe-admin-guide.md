# CAFE Admin Guide

This guide is the canonical reference for **platform administrators**: operators who deploy, configure, observe, and maintain the CAFE stack. It covers day-2 actions—environment management, health checks, observability, incident diagnosis, and **Crypto Policy (CP) catalog** administration.

Integrators and API consumers should use [03-cafe-developer-guide.md](./03-cafe-developer-guide.md). End-user product behavior is in [02-cafe-user-guide.md](./02-cafe-user-guide.md) and [functional-specifications.md](./functional-specifications.md).

## Document Versioning

- v0.7.0
  - Date: August 22nd, 2026
  - Comments: Rewrite **CPM catalogue administration** for two-layer amendement: Crypto Policies (`CPM_CRYPTO_POLICY_PATHS`) + provider manifests (`CPM_PROVIDER_MANIFEST_PATHS`); routes `/crypto-policies` + `/providers`; ADR §7.2.1 signals (catalogue family 1 + runtime family 2); Nicetry refs pinned (CPM-P7 done); diagnose curl uses explore v0.2 (`crypto_policy_id` + `policy_context`).
- v0.6.0
  - Date: August 18th, 2026
  - Comments: Update **CPM catalog administration** for Capability Provider model (ADR 2026-08): `ProviderManifest` + `SolutionProfile` files via `CPM_PROVIDER_MANIFEST_PATHS`; catalog is now template + instance + provider manifest (three layers); pin refs (`unpinned_pending_fixture` rejected at persist gate); RAZ fixtures procedure.
- v0.5.0
  - Date: August 9th, 2026
  - Comments: **Cloudflare Tunnel** home hosting — `docker-compose.prod-tunnel.yml`, HTTP origin on `127.0.0.1:8080`, pointers to cafe-deploy README and `CAFE_selfhosted.md`.
- v0.4.0
  - Date: July 21st, 2026
  - Comments: Dual local deployments — keep **cafe-deploy** (Compose) and add **cafe-expresso** (minikube): Helm deploy, ingress edge at `http://localhost:8080`, signup/signin, pgweb, probes; commands aligned with cafe-expresso `docs/k8s.md`.
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
      1. [Two local deployments](#two-local-deployments)
      2. [Typical bases](#typical-bases)
      3. [SSH tunnel (non-public stacks)](#ssh-tunnel-non-public-stacks)
      4. [Cloudflare Tunnel (home hosting)](#cloudflare-tunnel-home-hosting)
      5. [Environment files (Compose)](#environment-files-compose)
   5. [Deployment operations](#deployment-operations)
      1. [Local Compose rebuild (cafe-deploy)](#local-compose-rebuild-cafe-deploy)
      2. [Local minikube (cafe-expresso)](#local-minikube-cafe-expresso)
      3. [Frontend CPM mode (admin-relevant)](#frontend-cpm-mode-admin-relevant)
      4. [Staging / production](#staging--production)
      5. [Production via Cloudflare Tunnel](#production-via-cloudflare-tunnel)
      6. [Rollback](#rollback)
   6. [Health checks and service status](#health-checks-and-service-status)
      1. [Quick probes (Compose)](#quick-probes-compose)
      2. [Quick probes (minikube)](#quick-probes-minikube)
      3. [Compose status](#compose-status)
      4. [minikube status](#minikube-status)
      5. [Prometheus / Grafana (IMM-OPS-2)](#prometheus--grafana-imm-ops-2)
   7. [PostgreSQL retention and capacity](#postgresql-retention-and-capacity)
      1. [Why the database grows](#why-the-database-grows)
      2. [Monitor size and row pressure](#monitor-size-and-row-pressure)
      3. [Operator response (today)](#operator-response-today)
      4. [Constraints before any purge](#constraints-before-any-purge)
      5. [pgweb (manual Postgres UI)](#pgweb-manual-postgres-ui)
   8. [Authentication and internal tokens (operator view)](#authentication-and-internal-tokens-operator-view)
   9. [CPM catalogue administration](#cpm-catalogue-administration)
      1. [Three layers (must stay consistent)](#three-layers-must-stay-consistent)
      2. [Source files (repository)](#source-files-repository)
      3. [Environment variables](#environment-variables)
      4. [Provider manifest and pin refs](#provider-manifest-and-pin-refs)
      5. [RAZ fixtures -- dev catalog reset](#raz-fixtures----dev-catalog-reset)
      6. [Procedure: add a second Capability Provider](#procedure-add-a-second-capability-provider)
      7. [Common catalog mistakes](#common-catalog-mistakes)
      8. [Persisted policies vs catalog](#persisted-policies-vs-catalog)
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
| Cloudflare Tunnel (selfhosted, no inbound ports) | Overview + commands | [cafe-deploy Cloudflare Tunnel](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#cloudflare-tunnel-home--no-inbound-ports), [CAFE_selfhosted.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/CAFE_selfhosted.md) |
| minikube / Helm / kubectl | Overview + necessary commands | [cafe-expresso](https://github.com/create2-labs/cafe-expresso), [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md), [ADR GitOps](https://github.com/create2-labs/cafe-deploy/blob/main/ADR/ADR_20260708_gitops.md) |
| HTTP API integration (`curl`, payloads) | Minimal (diagnosis only) | [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) |
| CPM auth contract, error codes | Pointers | [docs/security/cpm-contract.md](./docs/security/cpm-contract.md) |
| Explore rejection observability | Pointers + checklist | [docs/operations/cpm-explore-no-candidate-observability.md](./docs/operations/cpm-explore-no-candidate-observability.md) |
| PostgreSQL retention, soft-delete growth, capacity | Monitoring + remediation | This guide § [PostgreSQL retention and capacity](#postgresql-retention-and-capacity) |
| Product rules (W1–W8, immutability) | Summary | [functional-specifications.md](./functional-specifications.md) |

**Out of scope:** application feature development, Terraform/Ansible authoring (see cafe-deploy / cafe-expresso), and future admin product UI (**IMM-OPS-3**).

---


## Environments and access

### Two local deployments

Both remain valid. Do not drop Compose references while minikube P0 is the GitOps path under construction.

| Deployment | Repo | Operator entry |
| --- | --- | --- |
| **Docker Compose** | `cafe-deploy` | `docker compose` + env files + NGINX edge |
| **minikube P0** | `cafe-expresso` | Helm `cafe-platform` + ingress-nginx; full kubectl tutorial in [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md) |

### Typical bases

| Context | User / edge | Discovery (direct) | CPM (direct) |
| --- | --- | --- | --- |
| Local Compose | `http://localhost` or `https://localhost` | `http://localhost:8080` | `http://localhost:8082` |
| **Local minikube** | **`http://localhost:8080`** (ingress port-forward) | port-forward `svc/cafe-discovery-backend 8080:8080` if needed | port-forward `svc/cafe-cpm 8082:8080` if needed |
| Staging / prod (public VM) | `https://<host>` | Internal only | Internal only |
| **Prod + Cloudflare Tunnel** | `https://cafe.create2-labs.fr` (TLS at Cloudflare) | Internal only; origin `http://127.0.0.1:8080` | Internal only |

**minikube signup / signin (browser):** use **`http://localhost:8080/signup`** and **`http://localhost:8080/signin`**. Keep a terminal with:

```bash
kubectl -n ingress-nginx port-forward svc/ingress-nginx-controller 8080:80
```

Do **not** port-forward only `svc/cafe-frontend` for UI+API — that pod is static SPA nginx and answers **405** on `POST /api/auth/signup`. The edge is **ingress-nginx** (Compose equivalent: cafe-deploy NGINX).

Public routes at the edge (same path contract on Compose NGINX and minikube Ingress):

- Discovery: `/api/discovery/v1/...`
- Auth: `/api/auth/signup`, `/api/auth/signin`
- CPM: `/api/cpm/v1/...`
- CPM health (probes): `/api/cpm/healthz`
- Discovery deploy version: `/api/version` (public, no auth)
- CPM deploy version: `/api/cpm/version` (public, no auth; **CPM-OPS-3**)
- Platform status: `/status` (minikube PR5 — Prometheus `platform_up` via status-proxy; not the Prometheus UI)

CPM **`GET /metrics`** is scraped inside the cluster / Docker network (not exposed through the public edge). See **Observability** below. Grafana is **not** in minikube P0 (phase 1b / PR10–PR11).

### SSH tunnel (non-public stacks)

When services are not published on the public host, use the tunnel workflow documented in [cafe-deploy README — Access to non-public services](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#access-to-non-public-services-ssh-tunnel).

### Cloudflare Tunnel (home hosting)

Use Cloudflare Tunnel when CAFE runs on a **home** network and you must not open inbound 80/443 on the ISP box (double NAT / CGNAT friendly).

| Piece | Role |
| --- | --- |
| Cloudflare DNS + Tunnel | Public HTTPS for `cafe.create2-labs.fr` |
| `cloudflared` on the host | Outbound tunnel to origin `http://localhost:8080` |
| `docker-compose.prod-tunnel.yml` | Same prod images; NGINX HTTP edge on loopback only |

Do **not** publish only the frontend container: `/api/*` still requires the NGINX edge. Named tunnels reject self-signed HTTPS origins unless TLS verify is disabled; the tunnel compose path uses plain HTTP instead.

Canonical operator docs:

- Quick path: [cafe-deploy README — Cloudflare Tunnel](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#cloudflare-tunnel-home--no-inbound-ports)
- Full home guide (OpenWrt, DNS, firewall): [CAFE_selfhosted.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/CAFE_selfhosted.md)

### Environment files (Compose)

Each Compose deployment uses an env file rendered before `docker compose up`:

```bash
cd cafe-deploy
cp env/dev.env.template env/dev.local.env   # edit secrets locally; never commit
./scripts/render-templates.sh env/dev.local.env
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env up -d
```

Key version pins (examples): `DISCOVERY_VERSION`, `FRONTEND_VERSION`, `CPM_VERSION`, `NGINX_VERSION`. Image tags are the primary rollback lever.

On **minikube**, secrets are a Kubernetes Secret (`cafe-platform-secrets`) — see [cafe-expresso `docs/secrets.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/secrets.md) and deploy commands below (never commit plaintext).

---

## Deployment operations

### Local Compose rebuild (cafe-deploy)

From `cafe-deploy`:

```bash
./scripts/redeployalldev.sh
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env up -d
```

This rebuilds sibling repos (`cafe-discovery`, `cafe-frontend`, `cafe-crypto-policy-mgt`, scanners) and bakes frontend `VITE_*` build args from `env/dev.local.env`.

### Local minikube (cafe-expresso)

Necessary and sufficient commands (from [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md)):

```bash
cd cafe-expresso
export NS=cafe-platform

# Cluster (16 GB Mac: 8 GB for minikube). Use Calico when NetworkPolicies matter (PR6+).
minikube start --memory=8192 --cpus=4 --driver=docker
# or: minikube start --memory=8192 --cpus=4 --driver=docker --cni=calico
kubectl cluster-info
minikube addons enable ingress

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

# Edge for browser + /api (leave running)
kubectl -n ingress-nginx port-forward svc/ingress-nginx-controller 8080:80
# → http://localhost:8080/  (signup: http://localhost:8080/signup)

# Optional full smoke
./scripts/smoke/smoke-minikube.sh
```

Stop / tear down:

```bash
helm uninstall cafe-platform -n "$NS"          # workloads; keep NS/PVC
kubectl delete namespace "$NS"                  # full wipe including PVC
minikube stop                                  # stop cluster
# minikube delete                              # destructive
```

RBAC / Argo CD (PR7–PR8): ServiceAccounts, AppProject without `Secret`/`Namespace` sync — see cafe-expresso [`docs/security-rbac.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/security-rbac.md) and `./scripts/smoke/pr8-rbac-argocd.sh`.

### Frontend CPM mode (admin-relevant)

| Variable | Effect |
| --- | --- |
| `VITE_CPM_DATA_SOURCE=api` | CPM page calls real CPM HTTP (required to test catalog, explore, persist) |
| `VITE_CPM_DATA_SOURCE=mock` | Fixtures only — no backend catalog |

Set in `env/dev.local.env` before `redeployalldev.sh` (Compose). Release / minikube images typically ship with `api`.

### Staging / production

Follow [cafe-deploy — Release & Deployment Workflow](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#release--deployment-workflow-rc--staging--production): RC images → staging validation → promoted tags → production compose update. Cloud Kubernetes (OVH MKS) follows cafe-expresso after minikube PR9 validation (ADR).

On a public VM, use `docker-compose.prod.yml` (TLS on 80/443). For home hosting without inbound ports, use [Production via Cloudflare Tunnel](#production-via-cloudflare-tunnel) instead.

### Production via Cloudflare Tunnel

From `cafe-deploy` on the home host:

```bash
cp env/prod.tunnel.env.template env/prod.tunnel.env
./scripts/render-templates.sh env/prod.local.env env/prod.tunnel.env
docker compose -f docker-compose.prod-tunnel.yml \
  --env-file env/prod.local.env --env-file env/prod.tunnel.env up -d
curl -fsS http://127.0.0.1:8080/healthz
```

In Cloudflare → **Networks → Tunnels** → Public Hostname:

```text
Hostname : cafe.create2-labs.fr
Service  : http://localhost:8080
```

Then run `cloudflared` on the host (`CLOUDFLARED_TUNNEL_TOKEN` + `./scripts/cloudflare-tunnel.sh`).

Probes after tunnel is healthy:

```bash
curl -fsS https://cafe.create2-labs.fr/api/version
curl -fsS https://cafe.create2-labs.fr/api/cpm/version
curl -fsS https://cafe.create2-labs.fr/api/cpm/healthz
```

Do not stack `overrides/prod.yml` with the tunnel override. Grafana / Prometheus remain on loopback (SSH LocalForward), same as classic prod.

### Rollback

**Compose:** change image version env vars to the last known-good tag, re-render templates if needed, `docker compose up -d`. Do not mix IMM schema migrations across incompatible Discovery versions without reading [RUNBOOK_SCAN_HISTORY.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_SCAN_HISTORY.md).

**minikube:** re-`helm upgrade` with previous chart/values or known-good image tags in values; or `helm rollback cafe-platform` if revisions exist.

---

## Health checks and service status

### Quick probes (Compose)

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

### Quick probes (minikube)

With ingress port-forward on `:8080`:

```bash
export EDGE_BASE=http://localhost:8080
curl -fsS "${EDGE_BASE}/api/health"
curl -fsS "${EDGE_BASE}/api/version"
curl -fsS "${EDGE_BASE}/api/cpm/healthz"
curl -fsS "${EDGE_BASE}/api/cpm/version"
curl -fsS "${EDGE_BASE}/status"                # platform_up (PR5)
curl -fsS "${EDGE_BASE}/healthz"               # edge guards
```

Direct pod Services (optional):

```bash
export NS=cafe-platform
kubectl -n "$NS" port-forward svc/cafe-discovery-backend 18080:8080 &
curl -fsS http://127.0.0.1:18080/health
kubectl -n "$NS" port-forward svc/prometheus 9090:9090   # Prometheus UI (not on Ingress)
```

Expected version response shape (both services): `{"version":"vX.Y.Z"}` or an RC tag. The SPA **Platform Status** page displays Frontend, Discovery, and CPM versions from `/version.json`, `/api/version`, and `/api/cpm/version` respectively (**CPM-UI-7A**).

### Compose status

```bash
docker compose -f docker-compose.dev.yml --env-file env/dev.local.env ps
docker logs cafe-cpm-dev --tail 100
docker logs cafe-discovery-dev --tail 100
```

### minikube status

```bash
export NS=cafe-platform
kubectl -n "$NS" get pods,svc,pvc
kubectl -n "$NS" logs -f deployment/cafe-discovery-backend
kubectl -n "$NS" describe pod <name>
kubectl -n "$NS" get events --sort-by='.lastTimestamp' | tail -20
```

### Prometheus / Grafana (IMM-OPS-2)

**Compose** — after `render-templates.sh`, verify:

- Prometheus **Targets** → `cafe-cpm-api` = UP (`PROMETHEUS_CPM_METRICS_TARGET`, default `cafe-cpm:8080`)
- Blackbox job `cafe-cpm-health` → `PROMETHEUS_CPM_HEALTH_URL` (default `https://nginx/api/cpm/healthz`)
- Grafana dashboard **CAFE - CPM Explore Rejections** (UID `cafe-cpm-explore-rejections`)

```bash
./scripts/test-imm-ops-2.sh static    # config files
./scripts/test-imm-ops-2.sh live      # against running stack
```

**minikube P0:** Prometheus + blackbox + `/status` only (PR5). **No Grafana** until phase 1b. Operator UI: `kubectl -n cafe-platform port-forward svc/prometheus 9090:9090`.

---

## PostgreSQL retention and capacity

CAFE stores durable scan and Crypto Policy (CP) state in a single **PostgreSQL** instance (`cafe-postgres-${ENV}` in compose). **There is no automated compaction job in P0** — operators must plan for monotonic growth and monitor disk and backup size.

Product intent ([functional-specifications.md — Retention](./functional-specifications.md#retention)): scan rows and policies remain until the user deletes them or deletes their account. User-initiated `DELETE` is implemented as **soft delete** (`deleted_at` set); rows stay in the database. That is correct for product semantics but increases **row count**, **on-disk size**, and **backup volume** over time.

### Why the database grows

| Source | Tables | Behavior |
| --- | --- | --- |
| User delete (scan / policy) | `scan_results`, `tls_scan_results`, `crypto_policies` | Row kept with `deleted_at` set — hidden from API lists and W1/W3 guards (partial indexes `WHERE deleted_at IS NULL`) |
| Policy replace (NB1) | `crypto_policies` | DELETE (soft) then new signed persist — not atomic; W1 unique partial on active rows |
| Persist conflict / retry | `crypto_policies.payload_sha256` | **409** `POLICY_ALREADY_EXISTS` — reconcile via GET + hash compare (no `draft_persist_state`) |
| Plan quota ledger (IMM-6b) | `scan_usage_events` | **Append-only** — `used` is monotonic; soft-deleting a scan lowers `visible` but **does not** remove ledger rows |

Hot queries stay fast thanks to partial indexes, but **disk and backups grow without bound** until a retention or purge policy is applied. Acceptable for P0/dev; track before long-lived staging or production scale.

Further schema context: [cafe-persistence README — CP tables](https://github.com/create2-labs/cafe-persistence/blob/main/README.md) (draft tables **dropped** in RD-P3), [RUNBOOK_CP_PERSISTENCE.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md), [ADR_20260824_remove_cp_drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md).

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
    'crypto_policies',
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
SELECT 'crypto_policies (active)', COUNT(*) FILTER (WHERE deleted_at IS NULL),
       COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) FROM crypto_policies
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
-- Dry run: soft-deleted policies older than 90 days
SELECT id, deleted_at, payload_sha256 FROM crypto_policies
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';
```

After an approved hard-delete in staging:

```sql
-- Example — execute only after dry-run counts match expectation
-- crypto_policy_drafts dropped (RD-P3)
-- DELETE FROM crypto_policies
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

DELETE FROM crypto_policies
WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '90 days';

VACUUM (ANALYZE) crypto_policies;
```

Do **not** bulk-delete from `scan_usage_events` to “free space” — that breaks **IMM-6b** monotonic `used` semantics unless coordinated with a contract change.

### Constraints before any purge

- **W1 / W3:** guards count only active (`deleted_at IS NULL`) persisted policies — hard-deleting already soft-deleted rows is safe; hard-deleting **active** rows is not.
- **IMM-6b:** `scan_usage_events` is append-only; purging it changes plan `used` accounting.
- **Idempotence:** rely on W1 unique + `payload_sha256` reconciliation — no `draft_persist_state` table after RD-P3.
- **Backups:** smaller live DB does not shrink existing backup objects — align backup retention with legal/audit policy.
- **Production:** no documented automated purge path yet — coordinate with product and `cafe-persistence` before any hard-delete policy.

### pgweb (manual Postgres UI)

Operator-only tool — **not** in the Helm chart / Compose stack. Same idea as starting `sosedoff/pgweb` by hand on `cafe-network` in cafe-deploy.

**minikube** (from [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md)):

```bash
export NS=cafe-platform
PW=$(kubectl -n "$NS" get secret cafe-platform-secrets \
  -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)

kubectl -n "$NS" port-forward svc/postgres 5432:5432
# other terminal:
docker run --rm -p 8081:8081 \
  sosedoff/pgweb \
  --url "postgres://cafe:${PW}@host.docker.internal:5432/cafe?sslmode=disable"
```

UI: http://127.0.0.1:8081 — user/DB `cafe`/`cafe`.

With Calico NetworkPolicies, an in-cluster pgweb pod must use `persistence` (or `discoveryBackend`) component labels — see k8s.md Option B.

**Compose:** attach pgweb to the compose network and point at `postgres:5432` with the same credentials from the env file.

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

On **minikube**, sign up / sign in via the edge:

```bash
export EDGE_BASE=http://localhost:8080   # ingress port-forward required
curl -sS -X POST "${EDGE_BASE}/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin-test@example.com","password":"TestPass123!","confirm_password":"TestPass123!","turnstile_token":"dev-pass"}'
```

Browser: **`http://localhost:8080/signup`** / **`http://localhost:8080/signin`**.

---

## CPM catalogue administration

The **CP catalogue** is not a single database table. CPM loads **static JSON files at startup** and serves them through read APIs. Changing the catalogue requires new or updated files and a **CPM process restart** (new container / redeploy).

### Two layers (must stay consistent)

Starting with **CPM-P8** (ADR amendement 2026-08), the catalogue model is:

```text
provider_manifest_*.json            -> ProviderManifest: SolutionProfile(s) + refs (provider layer)
        |
crypto_policy_*.json                -> Crypto Policy intention: required_posture + allowed_providers
```

> **Retired:** template/instance catalogue files and routes (`/policies/templates`, `/policies/instances`, `/policies/catalog`, `CPM_POLICY_TEMPLATE_PATHS`, `CPM_POLICY_INSTANCE_PATHS`). Do not document them as live. Legacy `policy_graph_catalog_valid.json` remains removed.

| Layer | API | What operators configure |
| --- | --- | --- |
| Provider manifests | `GET /api/cpm/v1/providers` via `CPM_PROVIDER_MANIFEST_PATHS` | `ProviderManifest` files per Capability Provider |
| Crypto Policies | `GET /api/cpm/v1/crypto-policies` via `CPM_CRYPTO_POLICY_PATHS` | One file per CP (`required_posture` + `allowed_providers`) |

**Critical rule:** a Crypto Policy is **intention only** (`required_posture` + `allowed_providers`). There is no `default_selection`. Explore (**couche A**) resolves providers from `allowed_providers` against loaded manifests and returns **scan-compatible** providers. User constraints (**couche B**) apply at persist (and as an indicative UI filter), not as catalogue rows.

### Source files (repository)

Canonical fixtures live in **cafe-crypto-policy-mgt**:

```
internal/domain/provider/testdata/
+-- provider_manifest_nicetry_v0_1.json       <- ProviderManifest (Nicetry pilot; refs pinned)
internal/domain/policy/testdata/
+-- crypto_policy_pq_account_validation_v1.json  <- id cpm_pq_account_validation_v1
+-- (+ invalid_* fixtures for tests only)
```

Validation logic: `internal/domain/provider/`, `internal/domain/policy/`.
Loader: `internal/api/read_api.go` -> `LoadReadStore()` + `LoadProviderManifestFromFile()`.

In the **CPM Docker image**, files are copied under `/app/policy/` (`Dockerfile-cpm`).

### Environment variables

| Variable | Default (image) | Meaning |
| --- | --- | --- |
| `CPM_PROVIDER_MANIFEST_PATHS` | `/app/policy/provider_manifest_nicetry_v0_1.json` | Comma-separated Capability Provider manifests |
| `CPM_CRYPTO_POLICY_PATHS` | `/app/policy/crypto_policy_pq_account_validation_v1.json` | Comma-separated Crypto Policy JSON paths |

Example (local `go run` with fixtures):

```bash
export CPM_AUTH_REQUIRED=false
export CPM_PROVIDER_MANIFEST_PATHS=internal/domain/provider/testdata/provider_manifest_nicetry_v0_1.json
export CPM_CRYPTO_POLICY_PATHS=internal/domain/policy/testdata/crypto_policy_pq_account_validation_v1.json
go run ./cmd/cafe-cpm
```

Multiple providers / policies -- comma-separated paths (trim-safe):

```bash
export CPM_PROVIDER_MANIFEST_PATHS=/app/policy/nicetry.json,/app/policy/another.json
export CPM_CRYPTO_POLICY_PATHS=/app/policy/cp_a.json,/app/policy/cp_b.json
```

**Deploy note:** `cafe-deploy` compose does not override these by default; the running catalogue is whatever is **baked into** `oleglod/cafe-cpm:${CPM_VERSION}`. To change catalogue content in dev:

1. Edit or add JSON under the relevant `testdata/` directories.
2. Update defaults in `internal/config/config.go` **or** set env vars in `compose/25-cpm.yml` / env file.
3. Rebuild CPM image (`redeployalldev.sh` or `docker build -f Dockerfile-cpm`).
4. Restart `cafe-cpm` container.

### Provider manifest and pin refs

A `ProviderManifest` declares one or more `SolutionProfile`(s), each with:
- `solution_profile_id` -- stable identifier
- `resulting_posture` -- what the provider achieves (e.g. `hybrid`)
- `signature` -- `scheme` + `family` (e.g. ERC-4337 + ML-DSA)
- `suggested_user_constraints` -- indicative defaults for the UI constraints panel
- `refs` -- commit/version pointers for pinned verification

**`unpinned_pending_fixture`** is rejected by the persist gate. The shipped Nicetry fixture refs are **pinned** (**CPM-P7** done). Explore and signed persist work with the pinned fixture; any snapshot that still carries `unpinned_pending_fixture` (or empty commit/version) fails the gate.

### Catalogue startup signals (ADR §7.2.1 family 1 / CPM-P11a)

After loading Crypto Policies and manifests, CPM emits structured **signals** (prefer this term over “alarmes” alone):

| Severity | When | Counter (optional) |
| --- | --- | --- |
| `WARN catalogue: posture orphanage …` | CP has empty `allowed_providers` or no allowed profile with `resulting_posture == required_posture` | `cpm_catalogue_posture_orphan_total` |
| `ERROR catalogue: malformed suggested_user_constraints …` | Profile suggestions contradict `constraints` / signature; profile marked `Erroneous` | `cpm_catalogue_malformed_manifest_total` |

These fire at **startup/load**, not per scan. Chain `planned` / wallet type are **not** part of the static posture-orphan check.

### Runtime signals (ADR §7.2.1 family 2 / CPM-P11b)

Contextual to a scan + Crypto Policy (+ user constraints). Distinct from catalogue startup:

| Signal | When | Log / metric |
| --- | --- | --- |
| No scan-compatible | Explore HTTP 200, empty `scan_compatible_providers`, non-empty `rejected_candidates` | `event=cpm.explore.no_deployable_candidate` + `adr_signal=runtime.no_scan_compatible` ; `cpm_explore_no_deployable_candidate_total` |
| Couche B KO | Persist `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` | `event=cpm.persist.user_constraints_incompatible` + `adr_signal=runtime.no_provider_after_user_constraints` ; `cpm_persist_user_constraints_incompatible_total` |

Full explore diagnosis: [operations runbook](./docs/operations/cpm-explore-no-candidate-observability.md).

### RAZ fixtures -- dev catalogue reset

When changing catalogue fixtures during development:

1. Stop CPM (`docker stop cafe-cpm-dev` or equivalent).
2. Replace fixture files (Crypto Policy and/or provider manifest).
3. **RAZ DB drafts**: delete in-progress drafts that reference the old catalogue IDs (or run full dev DB wipe if safe):
   ```bash
   # Soft delete orphaned drafts (dev only -- never in production without sign-off)
   docker exec -e PGPASSWORD=cafe cafe-postgres-dev psql -U cafe -d cafe \
     -c "UPDATE crypto_policies SET deleted_at=NOW() WHERE deleted_at IS NULL;"
   ```
4. Rebuild and restart CPM.
5. Verify via `GET /api/cpm/v1/crypto-policies` and `GET /api/cpm/v1/providers`.

### Procedure: add a second Capability Provider

1. **New provider manifest file** -- unique `provider_id`, `manifest_version`, `solution_profiles[]` with `resulting_posture`, `signature`, pinned refs, optional `suggested_user_constraints`. Register in `CPM_PROVIDER_MANIFEST_PATHS`.

2. **New or updated Crypto Policy file** -- unique `id`, `name`, `version`, `required_posture`, `allowed_providers` including the new `provider_id`. Register in `CPM_CRYPTO_POLICY_PATHS`.

3. **Validate locally:**

   ```bash
   cd cafe-crypto-policy-mgt
   go test -tags dev ./...
   ```

4. **Rebuild and restart CPM**, then verify APIs with a user JWT:

   ```bash
   curl -fsS "${CPM_BASE}/api/cpm/v1/crypto-policies" \
     -H "Authorization: Bearer ${TOKEN}" \
     | jq '[.items[] | {id, name, required_posture, allowed_providers}]'

   curl -fsS "${CPM_BASE}/api/cpm/v1/providers" \
     -H "Authorization: Bearer ${TOKEN}" \
     | jq '[.items[] | {provider_id, manifest_version}]'
   ```

5. **Verify explore** for a real wallet scan (see **Diagnose CPM explore** below). The new provider should appear in `scan_compatible_providers` (or in `rejected_candidates` with an explicit code).

### Common catalogue mistakes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Only one CP in UI picker | Single Crypto Policy path configured | Add second CP JSON + env path |
| Candidate rejected "incompatible.posture" | `required_posture` != `resulting_posture` on provider | Fix manifest `resulting_posture` or CP `required_posture` |
| Empty `scan_compatible_providers` / chain codes | Provider chain support narrower than wallet chains | Extend provider chain support or adjust CP `allowed_providers` |
| Persist returns 400 `CRYPTO_POLICY_PAYLOAD_INVALID` | `schema_version` empty or not `v0.2`, missing `crypto_policy_id` / `user_constraints`, or unpinned refs | Use `cafe.crypto_policy.v0.2` with pinned snapshot |
| Persist returns 400 `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` | Couche B KO after explore was scan-compatible | Adjust `user_constraints` or choose another provider |
| Catalogue startup WARN posture orphanage | CP has no posture-matching allowed profile | Fix `allowed_providers` / profile `resulting_posture` |
| CPM fails to start | Invalid JSON in manifest/CP | Check startup logs; run `go test -tags dev ./...` |
| Catalogue unchanged after edit | Old image still running | Rebuild `cafe-cpm` image and restart container |

### Persisted policies vs catalogue

**Owner persisted policies** (`GET /api/cpm/v1/policies`) are separate from the static catalogue. Catalogue changes do **not** mutate persisted CPs. Users keep existing policies; new explore only affects new compositions.

---

## Observability and incidents

### CPM explore — no scan-compatible provider (REQ9)

When users see “no policy applies” but HTTP is healthy, use the dedicated runbook:

**[CPM explore — no scan-compatible provider (observability & admin diagnosis)](./docs/operations/cpm-explore-no-candidate-observability.md)**

Summary for admins:

| Signal | Where |
| --- | --- |
| User-facing explanation | SPA `CpmExploreRejectionBanner` (REQ8) |
| Runtime signal (family 2) | `cpm.explore.no_deployable_candidate` + `adr_signal=runtime.no_scan_compatible` |
| Structured log | `docker logs cafe-cpm-*` |
| Counter | `cpm_explore_no_deployable_candidate_total` on `GET /metrics` |
| Couche B (separate) | `cpm.persist.user_constraints_incompatible` + `adr_signal=runtime.no_provider_after_user_constraints` |
| Dashboard | Grafana **CAFE - CPM Explore Rejections** |
| Alert | `CpmExploreIncompatibleChainScopeSustained` (sustained chain-scope style rejections) |

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
# minikube edge alternative (ingress on :8080):
# export EDGE_BASE='http://localhost:8080'
# TOKEN via POST ${EDGE_BASE}/api/auth/signin ; Discovery calls via ${EDGE_BASE}/api/discovery/v1/...
export SCAN_ID='<scan-uuid>'
export CRYPTO_POLICY_ID='cpm_pq_account_validation_v1'

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
    }')" | jq '{
      scan_compatible: [.decision.scan_compatible_providers[]? | {
        candidate: .candidate_id,
        provider: .solution_profile_ref.provider_id,
        posture: .resulting_posture
      }],
      rejections: [.decision.rejected_candidates[]? | {
        crypto_policy_id: .crypto_policy_id,
        codes: [.rejection_reasons[]?.code]
      }]
    }'
```

Compare wallet `chain_ids` from Discovery detail with provider chain support from `GET /providers` and the CP’s `allowed_providers` from `GET /crypto-policies`.

---

## User-support scenarios

| User report | Check first | Admin action |
| --- | --- | --- |
| “Cannot signup / empty `users` table” (minikube) | Browser URL must be **`http://localhost:8080`** with ingress port-forward; Network tab `POST /api/auth/signup` | If **405**, user hit `cafe-frontend` alone — switch to ingress. Turnstile dummy token `XXXX.DUMMY.TOKEN.XXXX` is OK in dev |
| “No wallet scan on CPM page” | Discovery scans exist, scan `completed` | W7 gate — newest scan must be completed; see functional specs |
| “Policy greyed out / incompatible” | Explore rejection code | Catalogue CP `allowed_providers` + provider chain/posture vs scan |
| “Cannot delete scan” | `409 SCAN_REFERENCED_BY_POLICY` | User must delete or rebind CPM policy first (W3/W4) |
| “CPM page errors / session” | Browser network tab on `/api/cpm/v1` | CPM auth env, Discovery session validation URL |
| “Persist failed” / constraints incompatible | Wallet challenge + signed `POST /policies` + `user_constraints` | [CP-PERSIST runbook](./docs/security/cp-persist-v1.md); couche B signal if `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` |
| Scan not latest on explore/persist | W2 gate | Re-select latest completed scan; **422** `SCAN_NOT_LATEST` |

Admins do **not** mutate user persisted policies through catalogue files. Catalogue is read-only platform configuration.

---

## Secrets and compliance

- **Compose:** env templates (`env/*.env.template`) document required secrets; local overrides use `*.local.env` (gitignored). Use cafe-deploy **pre-commit** hooks to reduce accidental secret commits.
- **minikube:** `cafe-platform-secrets` via `kubectl` only — not in Git; AppProject (PR8) must not sync `kind: Secret`. See [cafe-expresso `docs/secrets.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/secrets.md).
- Service tokens (`CAFE_*_SERVICE_TOKEN`) are rotation-sensitive — update Discovery and CPM together (same values in Compose env or the K8s Secret).
- Logs may contain `scan_id` and hashed wallet identifiers for CPM explore events; do not export raw wallet addresses to metrics.

---

## Verification checklist (after catalogue or CPM deploy)

- [ ] `GET /healthz` and `/api/cpm/healthz` succeed
- [ ] `GET /version` (Discovery direct) and `/api/version` (edge) return `{"version":"…"}`
- [ ] `GET /version` (CPM direct) and `/api/cpm/version` (edge) return `{"version":"…"}`
- [ ] Platform Status → Version Information shows Frontend, Discovery, and CPM versions (or `Unknown` when a service is down)
- [ ] `GET /api/cpm/v1/crypto-policies` returns expected CPs with `required_posture` + `allowed_providers`
- [ ] `GET /api/cpm/v1/providers` shows expected manifests / solution profiles
- [ ] Explore smoke with a known `scan_id` + `crypto_policy_id` returns `scan_compatible_providers` (or expected rejections); response has `resulting_posture`, `claim_status`, `suggested_user_constraints`, no `graphEdges`
- [ ] Legacy explore body with `selection_request` returns **400**
- [ ] Persist smoke uses `cafe.crypto_policy.v0.2` with `crypto_policy_id` + `user_constraints` (Nicetry refs pinned)
- [ ] Prometheus target `cafe-cpm-api` UP
- [ ] Frontend built with `VITE_CPM_DATA_SOURCE=api` if testing real catalogue in UI
- [ ] `go test -tags dev ./...` passed in `cafe-crypto-policy-mgt` before image publish
- [ ] Provider manifest + Crypto Policy loaded: `CPM_PROVIDER_MANIFEST_PATHS` and `CPM_CRYPTO_POLICY_PATHS` set; startup logs show load (and any catalogue signals)

---

## Additional resources

- [03-cafe-developer-guide.md](./03-cafe-developer-guide.md) — API v1 integration reference (Compose + minikube bases)
- [technical-specifications.md](./technical-specifications.md) — architecture, IMM-OPS, testing matrix
- [functional-specifications.md](./functional-specifications.md) — product rules and governance (W1–W8)
- [cafe-crypto-policy-mgt README](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md) — CPM service, env vars, local run
- [cafe-deploy README](https://github.com/create2-labs/cafe-deploy/blob/main/README.md) — Docker Compose, release workflow, env catalog
- [cafe-deploy — Cloudflare Tunnel](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#cloudflare-tunnel-home--no-inbound-ports) — prod-tunnel compose + cloudflared
- [CAFE_selfhosted.md](https://github.com/create2-labs/cafe-deploy/blob/main/docs/CAFE_selfhosted.md) — home OpenWrt + tunnel end-to-end
- [cafe-expresso](https://github.com/create2-labs/cafe-expresso) — minikube Helm / Argo CD; [`docs/k8s.md`](https://github.com/create2-labs/cafe-expresso/blob/main/docs/k8s.md) kubectl tutorial
- [ADR GitOps](https://github.com/create2-labs/cafe-deploy/blob/main/ADR/ADR_20260708_gitops.md) — P0 backlog PR0–PR9
- [CPM v1 flow](./docs/architecture/cpm-v1-flow.md) — Option A scan → explore → persist
- [CPM explore observability runbook](./docs/operations/cpm-explore-no-candidate-observability.md)
- [CPM auth contract](./docs/security/cpm-contract.md)
- [CP-PERSIST (no drafts)](./docs/security/cp-persist-v1.md)
- [ADR — remove CP drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md)
- [RUNBOOK_CP_PERSISTENCE](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md) — durable CP via cafe-persistence
- [cafe-deploy TODO — Postgres retention](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md#postgres-retention--cp--scan-tables-grow-without-bound-soft-delete) — planned compaction work
