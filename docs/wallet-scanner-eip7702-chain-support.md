# Wallet scanner — EIP-7702 chain activation

This document is the common CAFE reference for interpreting EIP-7702 delegation designators during a **wallet scan**. It is intentionally scoped to `cafe-scanner-wallet`: it does not qualify the delegation target, inspect smart-contract interfaces, or decide which Crypto Policy should be proposed.

Last verified: **September 30th, 2026**.

> **Delivery status:** `delegations` is part of the wallet scan result. Each entry is a chain id and a delegation target address. The eight CAFE chains set `supports_eip7702: true` in the Compose source and in the Helm copy. An absent or unknown capability stays disabled. The normative behavior is described in [`cafe-scanner-wallet/ScanEIP7702.md`](https://github.com/create2-labs/cafe-scanner-wallet/blob/main/ScanEIP7702.md).

## Why chain activation matters

The byte sequence defined by EIP-7702 is exactly 23 bytes: `0xef0100` followed by a 20-byte target address. Those bytes have EIP-7702 delegation semantics only on a chain where the relevant protocol upgrade has been activated.

The wallet scanner must therefore combine two facts:

1. the chain is explicitly configured as supporting EIP-7702; and
2. `eth_getCode(address, "latest")` returns exactly `0xef0100 || target`.

The byte pattern alone is not sufficient. There is no standard execution JSON-RPC method that reliably answers whether EIP-7702 is active on an arbitrary chain. Transaction type support in a node, the absence of type-4 transactions, or a matching byte sequence must not be used as automatic activation detection.

CAFE currently scans `latest`, not historical blocks. An explicit boolean is therefore sufficient for the current scanner. If historical scans are introduced, the configuration and evaluation must also carry the activation block or timestamp and compare it with the observed block.

## Current CAFE chain inventory

All chains currently configured for the wallet scanner have activated EIP-7702. This does not remove the need for an explicit capability flag: a newly added chain must default to unsupported until its activation is verified from an official source.

| Scanner network | Chain ID | EIP-7702 activation used by CAFE | Official source |
| --- | ---: | --- | --- |
| Ethereum Mainnet | `1` | Pectra, epoch `364032`, May 7th 2025 at 10:05:11 UTC | [Ethereum Foundation — Pectra Mainnet Announcement](https://blog.ethereum.org/2025/04/23/pectra-mainnet) |
| Ethereum Sepolia | `11155111` | Pectra, timestamp `1741159776`, epoch `222464` | [Ethereum Foundation — Pectra Testnet Announcement](https://blog.ethereum.org/2025/02/14/pectra-testnet-announcement) |
| Optimism | `10` | Isthmus, timestamp `1746806401` | [OP Stack specification — Isthmus and EIP-7702](https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/isthmus/derivation.md), [Superchain Registry — OP Mainnet](https://github.com/ethereum-optimism/superchain-registry/blob/main/superchain/configs/mainnet/op.toml) |
| Base | `8453` | Isthmus, timestamp `1746806401` | [Base node v0.12.3 — mandatory Isthmus upgrade](https://github.com/base/node/releases/tag/v0.12.3), [OP Stack specification — Isthmus and EIP-7702](https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/isthmus/derivation.md) |
| Arbitrum One | `42161` | ArbOS 40 Callisto, June 17th 2025 at 22:56:23 UTC | [Arbitrum Foundation — Network upgrades](https://docs.arbitrum.foundation/network-upgrades), [ArbOS 40 Callisto](https://docs.arbitrum.io/run-arbitrum-node/arbos-releases/arbos40) |
| BNB Smart Chain | `56` | Pascal / BEP-441, March 20th 2025 at 02:10:00 UTC | [BNB Chain — Pascal Upgrade](https://docs.bnbchain.org/announce/pascal-bsc/) |
| Polygon PoS | `137` | Bhilai, block `73,440,256` | [Polygon PIP-63 — Bhilai activation blocks](https://forum.polygon.technology/t/pip-63-bhilai-hardfork/20872), [Polygon PIP-61 — EIP-7702 enabled](https://github.com/0xPolygon/Polygon-Improvement-Proposals/blob/main/PIPs/PIP-61.md), [Polygon — Bhilai is live with EIP-7702](https://polygon.technology/blog/first-milestone-to-gigagas-1000-tps-with-bhilai-hardfork) |
| Polygon Amoy | `80002` | Bhilai, block `22,765,056` | [Polygon PIP-63 — Bhilai activation blocks](https://forum.polygon.technology/t/pip-63-bhilai-hardfork/20872), [Polygon PIP-61 — EIP-7702 enabled](https://github.com/0xPolygon/Polygon-Improvement-Proposals/blob/main/PIPs/PIP-61.md) |

Protocol definition: [EIP-7702 — Set Code for EOAs](https://eips.ethereum.org/EIPS/eip-7702).

## What users should understand

- A wallet scan reports a delegation only when the address contains a valid designator on a chain configured by CAFE as EIP-7702-enabled.
- The scanned account remains classified as an EOA when its only code is a valid EIP-7702 designator.
- The reported address is an **EIP-7702 delegation target address**. The wallet scanner does not claim that it is a contract, a smart account, an ERC-4337 implementation, or a safe target.
- An empty `delegations` array means that no designator was found on the **responding, EIP-7702-enabled chains scanned by CAFE**. It is not proof about unsupported chains or chains whose RPC call failed.
- An address can be delegated on one chain and be an ordinary EOA, a contract, or unavailable on another chain. Results are evaluated independently per chain.

## Administrator rule

Every wallet-scanner chain entry carries an explicit `supports_eip7702` capability. The Compose source is `cafe-deploy/config/discovery/config.yaml`. The Helm copy is `cafe-expresso/charts/cafe-platform/config/discovery-config.yaml`. An absent or unknown value stays disabled. Chain activation alone does not make the scanner report a delegation.

The configuration shape is:

```yaml
blockchains:
  - name: ethereum-mainnet
    chain_id: 1
    rpc: "https://…"
    supports_eip7702: true
```

Operational rules:

- `supports_eip7702` defaults to `false` when absent; unknown must never mean enabled.
- `name` and `chain_id` must be unique, and `chain_id` must match the configured RPC network.
- Set the flag to `true` only after an official chain source confirms activation on the network being configured.
- Before rollout, use `eth_chainId` and `eth_getBlockByNumber("latest", false)` as operator checks: the endpoint must serve the expected chain and a head at or beyond the documented activation block or timestamp. These checks validate the configured endpoint; they do not replace the official activation source.
- Record the source and verification date in this common inventory when adding or changing a chain.
- Update the Compose source configuration first, then keep Helm/minikube configuration in sync.
- A node software release that implements EIP-7702 is not by itself proof that the fork is active on the configured network.

For the current eight chains, the configured value is `supports_eip7702: true`.

## Developer rule

For each configured chain, the wallet scanner applies the following decision:

```text
empty code
    => EOA on this chain

exactly 0xef0100 || 20-byte target
and supports_eip7702 == true
    => delegated EOA on this chain; append one delegation result

any other non-empty code
or matching bytes with supports_eip7702 != true
    => not an EOA on this chain; ignore this chain in the wallet result
```

The parser must not:

- accept a longer bytecode that merely begins with `0xef0100`;
- follow the target or inspect its code;
- infer ERC-4337 or smart-account status;
- infer chain activation from the returned bytecode;
- let a contract result on one chain suppress valid EOA results from other chains.

Minimum tests must cover:

- enabled chain plus exact designator → delegated EOA;
- disabled or unspecified chain plus the same 23 bytes → not interpreted as EIP-7702;
- enabled chain plus wrong length or prefix → not a designator;
- mixed chains: delegated EOA, ordinary EOA, contract bytecode, and RPC error are handled independently;
- `delegations=[]` when no responding enabled chain returns a valid designator.

## Ownership and update path

| Concern | Owner |
| --- | --- |
| Protocol parsing and per-chain decision | `cafe-scanner-wallet` |
| Canonical Compose chain configuration | `cafe-deploy/config/discovery/config.yaml` |
| Helm/minikube copy | `cafe-expresso/charts/cafe-platform/config/discovery-config.yaml` |
| Persistence of the scanner result | `cafe-persistence` |
| Public wallet-scan DTO and OpenAPI | `cafe-discovery` |
| User-facing display | `cafe-frontend` |
| Common inventory and official evidence | `cafe-documentation` — this document |
