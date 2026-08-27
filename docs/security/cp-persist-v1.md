# CP-PERSIST — EOA wallet authorization for Crypto Policy persistence (no drafts)

Product and integrator guide for **signed Crypto Policy persist** after [ADR_20260824_remove_cp_drafts](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md).

**Normative contract:** [`cafe-crypto-policy-mgt` / `docs/CP_PERSIST.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CP_PERSIST.md) (section **Current normative contract v1.0.0 — no drafts**) + [`openapi/cpm-v1.yaml`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/openapi/cpm-v1.yaml).

> **Supersedes** the draft-based CP-PERSIST V1 path (`POST /drafts` → `POST /drafts/{id}/persist`). Those routes are **removed** (no shim, no dual-run).

## Core rule

> A wallet can be **scanned** and **explored** without proving wallet ownership.
> Composition lives in the **client** (page memory / `sessionStorage` — **NB2**). There is **no** server CP draft API.
> A Crypto Policy can only be **persisted** for an EOA after proving control via a CPM-verified signed authorization message **and** providing a closed hashed payload (`accepted_provider_snapshot` with pinned provider refs).

Session JWT (Discovery) and wallet signature are **orthogonal**: JWT identifies the user/tenant; the signature proves technical control of the EOA for the persist action.

## Scan vs explore vs compose vs persist

| Step | Requires wallet proof? | Typical route(s) | Notes |
| --- | --- | --- | --- |
| **Discovery scan** | No | `POST /api/discovery/v1/scan`, `GET …/wallets/scans/{scan_id}` | Public on-chain observation; owner-scoped via JWT |
| **CP explore (couche A)** | No | `POST /api/cpm/v1/policies/decisions/explore` | Synchronous preview; **W2**-gated (`scan_id` = latest completed for owner+address) |
| **Local composition (NB2)** | No | *client only* (`sessionStorage` indexed by `scan_id`) | Not an API; no `/drafts*` |
| **Wallet challenge** | No (prepares proof) | `POST /api/cpm/v1/wallet-challenges` | Stateless helper: CPM computes `payload_sha256` (JCS), builds canonical message, **stores nothing** |
| **EOA persist (normative)** | **Yes** | `POST /api/cpm/v1/policies` | Body: closed `payload` + `signed_message` + `signature` (EIP-191 / `personal_sign`) |

**Removed from the public contract:**

- Removed: `POST|GET|DELETE /api/cpm/v1/drafts`
- Removed: `POST /api/cpm/v1/drafts/{draft_id}/persist`
- Removed: any `draft_id` in challenge request/response or canonical message
- Removed: `DRAFT_ALREADY_PERSISTED` and other draft-centric error codes

## Product flow (EOA)

```text
Discovery scan (owner-scoped)
  → explore (catalogue / soft findings; no wallet proof; W2)
  → local editor state (sessionStorage NB2 — FE; no server draft)
  → POST /api/cpm/v1/wallet-challenges   # payload hashed; CPM computes payload_sha256; stores nothing
  → EIP-191 personal_sign
  → POST /api/cpm/v1/policies            # signed body; verify hash + signature; rejeu A+B; W1 write
```

## W2 (latest completed, owner-scoped)

`POST /policies/decisions/explore`, `POST /wallet-challenges`, and `POST /policies` require `scan_id` = **latest completed** Discovery wallet scan for **(authenticated user, address)**.

| Outcome | HTTP | Code |
| --- | --- | --- |
| Non-latest completed scan | **422** | `SCAN_NOT_LATEST` |
| Discovery timeout / 5xx / unset | **503** | `DISCOVERY_UNAVAILABLE` (fail-closed) |

Legacy IMM-10 explore codes (`SCAN_ID_NOT_LATEST_FOR_TARGET` / `LATEST_SCAN_NOT_COMPLETED`) are **not** the current contract.

## Stateless authorization model

1. Client calls `POST /api/cpm/v1/wallet-challenges` with wallet, chain, scan, and the **closed hashed payload** fields.
2. CPM computes **`payload_sha256`** (RFC 8785 JCS → SHA-256 hex), returns the **canonical human-readable message** (clients must not invent an alternative format).
3. User signs with EOA wallet (**EIP-191 / `personal_sign`**).
4. Client calls `POST /api/cpm/v1/policies` with binding (`wallet_address`, `chain_id`, `scan_id`), `payload`, exact `signed_message`, and `signature`.
5. CPM verifies message content, freshness, bindings, hash match, EIP-191 signature, then **rejoue** métier gates (couches A+B). Signature ≠ business bypass.

**Not in V1:** `POST /wallet-challenges/verify`, Redis / `CPM_REDIS_URL`, `ChallengeStore`, `ProofStore`, `wallet_control_proof_id`, server draft store.

### Signed message validity (TTL)

- Maximum window: **10 minutes** (`expires_at - issued_at`).
- `expires_at` must not be in the past at persist time.
- `issued_at` must not be more than **30 seconds** in the future (clock skew).

### Canonical message (no Draft ID)

```text
CAFE Crypto Policy Persistence

Domain: <frontend_or_api_domain>
Action: persist_crypto_policy
Wallet: <wallet_address>
Chain ID: <chain_id>
Scan ID: <scan_id>
Payload SHA-256: <payload_sha256>
Issued At: <issued_at>
Expiration Time: <expires_at>

By signing this message, I prove control of the wallet and authorize CAFE to persist this Crypto Policy for this wallet.
```

| Enforced via signed message | Enforced server-side only |
| --- | --- |
| `wallet_address`, `chain_id`, `scan_id` | `user_id` / `tenant_id` (JWT) |
| `payload_sha256`, `action`, `issued_at`, `expires_at` | W2 latest-completed; rejeu A+B; EOA-only |

### `payload_sha256` (server authority)

Closed hashed fields: `schema_version`, `crypto_policy_id`, `required_posture`, `user_constraints`, `solution_profile_ref`, `accepted_provider_snapshot`, `accepted_findings` (top-level authoritative).

Rules:

- Canonicalization: **RFC 8785 JCS**, then lowercase hex SHA-256.
- Hashed subtree: **string | boolean | object | array only** — **no** `number`, **no** `null`.
- Chain ids inside the snapshot are **strings** (e.g. `"11155111"`).
- Before JCS: lexicographic sort + dedupe of `accepted_findings` (server always normalizes; persists the canonical form).
- Client-supplied `payload_sha256` on write is **ignored**.
- Shared vectors: [`internal/contract/testdata/payload_sha256/`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/internal/contract/testdata/payload_sha256/) (same set as FE).

### Idempotence / W1 / NB1

Successful persist commits one active `crypto_policies` row (owner + wallet). Retry or second policy → **409** `POLICY_ALREADY_EXISTS`.

- Client reconciles via `GET /policies` + compare **`payload_sha256`**.
- Same hash → “already persisted” (network retry).
- Different hash → W1 conflict; show existing policy; replace via **NB1**: **DELETE** policy (JWT only) then new signed persist — **not** an atomic replace.

### NB2 (client resume)

Editor state may be restored from **`sessionStorage` indexed by `scan_id`** (opaque envelope, no secrets/signatures). Recalculate hash intent on restore. Discard if scan is not W2 / 404. This is **not** a draft API.

## Persist payload v0.2 — Capability Provider fields

`POST /api/cpm/v1/policies` body includes a `payload` with:

| Field | Required | Notes |
| --- | --- | --- |
| `schema_version` | **Yes** | Must be `"cafe.crypto_policy.v0.2"` |
| `crypto_policy_id` | **Yes** | Catalogue Crypto Policy id (not `template_id`) |
| `required_posture` | **Yes** | From catalogue CP |
| `user_constraints` | **Yes** | Couche B |
| `solution_profile_ref` | **Yes** | Provider + profile identifiers |
| `accepted_provider_snapshot` | **Yes** | Pinned refs + descriptive findings |
| `accepted_findings` | **Yes** | Top-level; authoritative for hash + rejeu |

**Gate rules at persist time:**

- Schema / closed fields / no `null` / no `number` in hashed subtree.
- CPM **rejoue couche A then B**. Couche B failure → **400** `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE`.
- Snapshot `refs` must be **pinned** (not `"unpinned_pending_fixture"`).
- Snapshot descriptive findings must not diverge from top-level `accepted_findings` (else **400**).
- Wallet proof remains required for EOA.

## End-to-end scenarios

Prerequisites: stack up (`cafe-deploy`), EOA scan (`wallet_type: eoa`). Signing via test key / `cafe.sh` / MetaMask depending on surface.

```bash
# From cafe-deploy — explore only (no wallet proof)
SKIP_PERSIST=1 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh

# Full path: scan → explore → challenge → sign → POST /policies
SKIP_PERSIST=0 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh
```

Backend gate smokes (RD-P8): see [`cafe-deploy` README — Discovery/CPM smoke scripts](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#discoverycpm-smoke-scripts) and [RUNBOOK_CP_PERSISTENCE](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md).

Web UI: sign in → **Crypto Policy Management** → select **W2** EOA scan → Crypto Policy → explore → validate constraints → accept soft findings → **Persist** → `personal_sign` → signed `POST /policies`. Composition may restore from sessionStorage (NB2); there is **no** Save draft server CTA.

CLI: [`cafe-frontend` / `docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md) and `cafe.sh` policies persist commands (no `cpm draft *`).

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| **403** `WALLET_CONTROL_PROOF_REQUIRED` | Missing/invalid signed authorization on EOA persist | Complete wallet-challenges → sign → `POST /policies` |
| **422** `SCAN_NOT_LATEST` | `scan_id` not latest completed for owner+address | Re-select W2 scan; re-explore |
| **503** `DISCOVERY_UNAVAILABLE` | Discovery W2 lookup failed | Discovery health; CPM Discovery base URL / tokens |
| **400** `PAYLOAD_SHA256_MISMATCH` | Signed A, persisted B (or message edited) | Same payload for challenge and persist; do not edit canonical message |
| **409** `POLICY_ALREADY_EXISTS` | Active policy already present (retry or conflict) | `GET /policies` + compare `payload_sha256`; NB1 DELETE then re-persist if replace |
| **400** `CRYPTO_POLICY_PAYLOAD_INVALID` | null/number/unknown/missing closed field; divergent snapshot findings | Align payload to OpenAPI + vectors |
| **400** `PROVIDER_USER_CONSTRAINTS_INCOMPATIBLE` | Couche B KO after rejeu | Adjust constraints or provider |
| **422** `UNSUPPORTED_WALLET_TYPE` | Non-EOA target | V1 persist is EOA-only |
| Caller still uses `/drafts*` | Stale client / docs | Routes removed — migrate to signed `POST /policies` |

For auth/session errors (`401`, `403` scan authz), see [CPM contract runbook](./cpm-contract.md).

## Canonical references

| Document | Location |
| --- | --- |
| ADR — remove CP drafts | [`ADR_20260824_remove_cp_drafts.md`](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts.md) |
| PR plan (RD-*) | [`ADR_20260824_remove_cp_drafts_PR_PLAN.md`](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260824_remove_cp_drafts_PR_PLAN.md) |
| Normative CPM persist contract | [`CP_PERSIST.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CP_PERSIST.md) |
| OpenAPI | [`openapi/cpm-v1.yaml`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/openapi/cpm-v1.yaml) |
| Option A flow | [../architecture/cpm-v1-flow.md](../architecture/cpm-v1-flow.md) |
| Frontend maintainer guide | [`cafe-frontend/docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md) |
| Deploy smoke / runbook | [`cafe-deploy` README](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#discoverycpm-smoke-scripts) · [RUNBOOK_CP_PERSISTENCE](https://github.com/create2-labs/cafe-deploy/blob/main/docs/RUNBOOK_CP_PERSISTENCE.md) |
