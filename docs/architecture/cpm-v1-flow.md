
# CPM — Discovery v1 scan to policy flow

**What is Option A?** Option A is the **post-V1 CPM integration path**: after the CPM frontend V1 policy workflow shipped, the product connects that page to **real user-owned wallet scans** via the **authenticated Discovery backend** (scan data is persisted behind Discovery today; Persistence Service remains the long-term owner). The UI selects a **`scan_id`**, loads v1 scan detail, and drives CPM explore/persist—**not** mock placeholders or direct DB access. A future **Option B** would expose scan context through an extracted Persistence Service API; Option A is the short-term path that respects current AuthN/AuthZ in Discovery. Full product intent, constraints, and data-flow rationale: [CPM `workplans/CPM_post_v_1_option_a_scan_context.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/CPM_post_v_1_option_a_scan_context.md).

Public architecture summary for integrators and technical writers. Normative HTTP fields and **`policy_context`** mapping live in the Discovery maintainer contract and CPM workplans linked below.

**ADR Capability Providers (2026-08):** the CPM engine now selects candidates through **Capability Providers** — providers declare a `ProviderManifest` with `SolutionProfile`(s) describing their `resulting_posture`. The policy graph (nodes / edges / `node_path`) is **not** a business contract; the UI derives its view from `solution_profile` fields. See [ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) and [CPM README — Capability Providers](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md).

**CP-PERSIST V1 (EOA persist):** scan, explore, and platform draft save require **no** wallet proof. Normative EOA persist is `wallet-challenges` → EIP-191 sign → `POST /api/cpm/v1/drafts/{draft_id}/persist`. See [CP-PERSIST V1 runbook](../security/cp-persist-v1.md).

## End-to-end path (with Capability Providers)

1. **Wallet scan** is queued and stored (Discovery DB today; Persistence Service is the long-term scan-data owner). **No wallet proof required.**
2. **List + detail** — authenticated `GET /api/discovery/v1/wallets/scans` and `GET /api/discovery/v1/wallets/scans/{scan_id}`.
3. **CPM UI** — `cafe-frontend` solution profile view (**scénario A**): scan selection, candidate list, **fiche** structured by provider fields (input / account / signature / posture), bandeau `required_posture` → `resulting_posture`. Spec: [`CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md).
4. **Explore** — `POST /api/cpm/v1/policies/decisions/explore` with `scan_id`, **`policy_context`**, `selection_request` (including `key_rotation_model`, `target_posture`). Returns ranked candidates with `required_posture`, `resulting_posture`, `solution_profile_ref`, `maturity`, `claim_status`, and soft findings. **No wallet proof required.**
5. **Platform draft** — `POST /api/cpm/v1/drafts` (owner-scoped); payload includes `solution_profile_ref` + candidate selection. **No wallet proof required.**
6. **Persist (EOA, CP-PERSIST V1)** — `POST /api/cpm/v1/wallet-challenges` → EIP-191 / `personal_sign` → `POST /api/cpm/v1/drafts/{draft_id}/persist` with `signed_message` + `signature` + `accepted_provider_snapshot`. **Wallet proof required.** Provider refs must be pinned (not `unpinned_pending_fixture`).

```mermaid
sequenceDiagram
  participant U as User / UI
  participant D as Discovery v1
  participant C as CPM v1
  U->>D: GET wallets/scans
  U->>D: GET wallets/scans/{scan_id}
  U->>C: POST policies/decisions/explore
  Note over C: ranks candidates with<br/>required_posture / resulting_posture<br/>solution_profile_ref / soft findings
  U->>C: POST drafts (platform draft, incl. solution_profile_ref)
  U->>C: POST wallet-challenges
  Note over U: personal_sign (EOA)
  U->>C: POST drafts/{draft_id}/persist<br/>(accepted_provider_snapshot, pinned refs)
```

## Scan vs explore vs draft vs persist

| Phase | Wallet proof? | CPM route |
| --- | --- | --- |
| Scan (Discovery) | No | `POST /api/discovery/v1/scan`, `GET …/wallets/scans/{scan_id}` |
| Explore | No | `POST /api/cpm/v1/policies/decisions/explore` |
| Platform draft | No | `POST /api/cpm/v1/drafts` |
| Persist (EOA V1) | **Yes** | `POST …/wallet-challenges` then `POST …/drafts/{draft_id}/persist` |

Legacy `POST /api/cpm/v1/policies` is **not** the normative EOA persist path; EOA Discovery-bound payloads without signed authorization return **403** `WALLET_CONTROL_PROOF_REQUIRED`.

## Capability Provider — solution profile in the flow

The explore response for each ranked candidate includes:

```json
{
  "candidate_id": "cpx_pq_account_validation_nicetry_v1",
  "template_id": "tpl_pq_account_validation_v1",
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
  "compatibility_findings": []
}
```

Key rules:
- **`required_posture`** comes from the template / candidate (business requirement).
- **`resulting_posture`** comes from the provider's `SolutionProfile` (what the provider achieves).
- Hard compat check: `required_posture` must match `resulting_posture`. Failure → `rejected_candidate`.
- **`claim_status: "declared"`** means the provider has *declared* this capability — it is **not** an audited or executed proof.
- `maturity` reflects the provider's own assessment (`research`, `beta`, `production`).
- Soft findings (`requires_bundler`, `requires_local_signer_state`) are non-blocking but must be accepted by the user before persist.
- **No policy graph** (`graphEdges`, `nodeInstances`, `node_path`) in explore response or UI.

### `target_posture` wire alias (v0.1)

On the explore `selection_request`, the field `target_posture` is the stable **v0.1 alias** for the required posture. It is **not** renamed to `required_posture` at the wire level. CPM documentation on the backend maps this alias explicitly.

## Explore vs async assessment

| Endpoint | Client `policy_context` | Purpose |
|----------|-------------------------|---------|
| `POST /api/cpm/v1/policies/decisions/explore` | **Required** (v1-aligned) | Synchronous ranked preview; may return HTTP **200** with only `rejected_candidates` (no deployable CP) — see [observability runbook](../operations/cpm-explore-no-candidate-observability.md) |
| `POST /api/cpm/v1/policies/assessment/request` | **Forbidden** | Async pipeline; CPM loads detail server-side |

Do not send `policy_context` to the assessment endpoint. See [CPM auth runbook](../security/cpm-contract.md) troubleshooting for **400** / **404** on assessment.

## Canonical references

| Document | Location |
|----------|----------|
| ADR Capability Providers | [cafe-adr — ADR_20260803_cp_provider_abstraction](https://github.com/create2-labs/cafe-adr/blob/main/ADR_20260803_cp_provider_abstraction.md) |
| CPM README — Capability Providers | [cafe-crypto-policy-mgt README](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/README.md) |
| CP-PERSIST V1 (stateless EOA persist) | [../security/cp-persist-v1.md](../security/cp-persist-v1.md) |
| Integrated narrative (CPM repo) | [cafe-crypto-policy-mgt `docs/CPM_OPTION_A_INTEGRATED.md`](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/docs/CPM_OPTION_A_INTEGRATED.md) |
| Field mapping §3.1 | [cafe-discovery `docs/CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md`](https://github.com/create2-labs/cafe-discovery/blob/main/docs/CPM_OPTION_A_DISCOVERY_V1_CONTRACT.md) |
| API v1 developer guide | [03-cafe-developer-guide.md](../../03-cafe-developer-guide.md) |
| CPM UI specs | [cafe-frontend `CPM-specs-ui.md`](https://github.com/create2-labs/cafe-frontend/blob/main/CPM-specs-ui.md) |
| Merged PR index | [WORKPLAN_API_PR.md](https://github.com/create2-labs/cafe-crypto-policy-mgt/blob/main/workplans/WORKPLAN_API_PR.md) |
| Smoke scripts | [cafe-deploy README](https://github.com/create2-labs/cafe-deploy/blob/main/README.md#discoverycpm-smoke-scripts) |

## Smoke tests

```bash
# Explore only (S1–S3 non-regression — no wallet proof)
export DISCOVERY_EMAIL='user@example.com' DISCOVERY_PASSWORD='secret'
SKIP_PERSIST=1 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh

# Full CP-PERSIST V1: scan → explore → draft → sign → persist
# Note: persist requires pinned provider refs (CPM-P7). Until then, persist gate
# returns 400 CRYPTO_POLICY_PAYLOAD_INVALID for unpinned_pending_fixture refs.
SKIP_PERSIST=0 ./scripts/test-discovery-v1-wallet-scans-to-cpm.sh
```

Run from the `cafe-deploy` repository root; see script `--help` for edge path overrides. Layered CP-PERSIST smokes: `test-cpm-cp-persist-t3` … `t6` (see deploy README).

> **Known smoke debt (post-P6):** draft IDs must be UUIDs (non-UUID → 503); explore wire must use `key_rotation_model` (not `key_rotation_required`); persist payload must be `cafe.crypto_policy.v0.2` with `accepted_provider_snapshot`. These are resolved in the FE train (FE-P1b–FE-P5) and CPM-P7 (pin Nicetry refs).
