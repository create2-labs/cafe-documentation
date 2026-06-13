# CP-PERSIST V1 — EOA wallet authorization for Crypto Policy persistence

Product and integrator guide for **CP-PERSIST V1** (stateless signature-at-persist). Normative contract: [`cafe-crypto-policy-mgt` / `docs/CP_PERSIST.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CP_PERSIST.md) (Part VI frozen decisions).

## Core rule

> A wallet can be **scanned**, **explored**, and **drafted** without proving wallet ownership.
> A Crypto Policy can only be **persisted** for an EOA wallet after proving control via a CPM-verified signed authorization message.

Session JWT (Discovery) and wallet signature are **orthogonal**: JWT identifies the user/tenant; the signature proves technical control of the EOA for the persist action.

## Scan vs explore vs draft vs persist

| Step | Requires wallet proof? | Typical route(s) | Notes |
| --- | --- | --- | --- |
| **Discovery scan** | No | `POST /api/discovery/v1/scan`, `GET …/wallets/scans/{scan_id}` | Public on-chain observation; owner-scoped via JWT |
| **CP explore** | No | `POST /api/cpm/v1/policies/decisions/explore` | Synchronous preview; may return HTTP **200** with only `rejected_candidates` |
| **Platform draft save** | No | `POST /api/cpm/v1/drafts`, `GET …/drafts?id=…` | Non-actionable working state; owner-scoped |
| **Wallet challenge (canonical message)** | No (prepares proof) | `POST /api/cpm/v1/wallet-challenges` | **Mandatory** stateless helper before sign; stores nothing server-side |
| **EOA persist (normative)** | **Yes** | `POST /api/cpm/v1/drafts/{draft_id}/persist` | Body: `signed_message` + `signature` (EIP-191 / `personal_sign`) |
| **Legacy policy upsert** | **Yes** for EOA product flows | `POST /api/cpm/v1/policies` | **Not** the normative CP-PERSIST path; EOA Discovery-bound payloads without proof → **403** `WALLET_CONTROL_PROOF_REQUIRED` |

**Non-regression (S1–S3):** scan, explore, and platform draft save remain available without wallet signature. Only **persist** requires proof.

## Stateless V1 authorization model

1. Client calls `POST /api/cpm/v1/wallet-challenges` with wallet, chain, scan, draft bindings.
2. CPM returns the **canonical human-readable message** to sign (clients must not invent an alternative format).
3. User signs with EOA wallet (**EIP-191 / `personal_sign`**).
4. Client calls `POST /api/cpm/v1/drafts/{draft_id}/persist` with the exact `signed_message` and `signature`.
5. CPM verifies message content, freshness, bindings, and signature at persist time.

**Not in V1:** `POST /api/cpm/v1/wallet-challenges/verify`, Redis / `CPM_REDIS_URL`, `ChallengeStore`, `ProofStore`, `wallet_control_proof_id`.

### Signed message validity (TTL)

- Maximum window: **10 minutes** (`expires_at - issued_at`).
- `expires_at` must not be in the past at persist time.
- `issued_at` must not be more than **30 seconds** in the future (clock skew).

### Replay policy (V1)

Replay is controlled without a server-side proof store:

- Strict binding to `draft_id`, `scan_id`, `wallet_address`, `chain_id`, `action`.
- Transactional **persist-once** per draft (`DRAFT_ALREADY_PERSISTED` after success).
- Retry with the **same signature** is acceptable if persist failed before the draft was marked persisted and the message is still valid.

### Binding split (frozen)

The signed message binds **wallet, chain, scan, draft, action, issued_at, expires_at**. **User** and **tenant** are **not** in the signed message; CPM enforces them via session/JWT and draft/scan ownership.

## End-to-end manual scenario (EOA)

Prerequisites: dev stack up (`cafe-deploy`), `python3` + `eth-account` for script signing, EOA scan (`wallet_type: eoa`).

```bash
# From cafe-deploy (explore only — no wallet proof)
SKIP_PERSIST=1 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh

# Full V1 path: scan → explore → draft → wallet-challenges → sign → persist
SKIP_PERSIST=0 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh
```

Layered smokes (same contract, narrower scope):

| Script | Interface |
| --- | --- |
| `test-cpm-cp-persist-t3-wallet-challenges.sh` | Canonical message helper |
| `test-cpm-cp-persist-t4-draft-persist.sh` | Backend persist + negative cases |
| `test-cpm-cp-persist-t5-web-ui-flow.sh` | Web UI API contract (+ optional vitest) |
| `test-cpm-cp-persist-t6-cli-flow.sh` | `cafe.sh` CLI |

Web UI manual path: sign in → **Crypto Policy Management** → select EOA scan → explore → save backend draft → validate → **Persist validated policy** (injected wallet `personal_sign`).

CLI manual path: see [`cafe-frontend` / `docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md#cli--cp-persist-v1-cp-persist-t6).

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| **403** `WALLET_CONTROL_PROOF_REQUIRED` | Legacy `POST /api/cpm/v1/policies` or EOA persist without valid signed authorization | Use normative `POST …/drafts/{draft_id}/persist`; complete wallet-challenges → sign flow |
| **422** `UNSUPPORTED_WALLET_TYPE` | Non-EOA draft (`smart_account`, etc.) | V1 is EOA-only; use EOA scan or wait for Part V wallet types |
| **400** `WALLET_AUTHORIZATION_EXPIRED` (or equivalent) | Signed message past `expires_at` | Re-run `wallet-challenges`, re-sign within 10-minute window |
| **400** binding mismatch codes | `signed_message` for wrong draft/scan/wallet/chain | Ensure challenge and persist use same bindings; do not edit canonical message |
| **409** `DRAFT_ALREADY_PERSISTED` | Second persist on same draft after success | Expected persist-once semantics; create new draft if needed |
| Explore/draft work but persist fails auth | Session OK but wallet address mismatch | Injected wallet account must match scan wallet address |
| `wallet-challenges` **404** / draft not found | Wrong `draft_id` or cross-owner access | Verify `POST /drafts` saved under same JWT owner |
| Smart Account scan: persist blocked end-to-end | By design in V1 | Explore + draft still work; persist requires future non-EOA proof model |

For auth/session errors (`401`, `403` scan authz), see [CPM contract runbook](./cpm-contract.md).

## Canonical references

| Document | Location |
| --- | --- |
| Normative spec (Part VI frozen) | [`CP_PERSIST.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CP_PERSIST.md) |
| OpenAPI | [`openapi/cpm-v1.yaml`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/openapi/cpm-v1.yaml) |
| Option A flow (scan → explore → persist) | [../architecture/cpm-v1-flow.md](../architecture/cpm-v1-flow.md) |
| Frontend maintainer guide | [`cafe-frontend/docs/cpm-developer.md`](https://github.com/create2-labs/cafe-frontend/blob/main/docs/cpm-developer.md) |
| Deploy smoke index | [`cafe-deploy` README — Discovery/CPM smoke scripts](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#discoverycpm-smoke-scripts) |
