# SelfCoin Whitepaper Summary

SelfCoin is a neutral digital-cash prototype implemented in modern C++20 with deterministic finality, UTXO ownership, and non-custodial wallet integration.

## What SelfCoin is
SelfCoin is a finalized-chain-first blockchain design:
- nodes only extend the latest finalized tip,
- committee votes finalize blocks,
- and finalization is deterministic given the same finalized history.

Implementation anchors:
- consensus loop and finalization: [`src/node/node.cpp`](../src/node/node.cpp)
- leader/committee selection and quorum: [`src/consensus/validators.cpp`](../src/consensus/validators.cpp)
- vote dedup/equivocation tracking: [`src/consensus/votes.cpp`](../src/consensus/votes.cpp)

## How finality works
For each height:
1. ACTIVE validators are derived from finalized state.
2. Leader is chosen deterministically from finalized hash, height, and round.
3. Committee is chosen deterministically using seed+score sorting.
4. Committee members validate proposal and sign vote over `block_id`.
5. Block finalizes at quorum `floor(2N/3)+1` valid committee signatures.

This model avoids probabilistic “wait more confirmations” UX and instead exposes explicit finalized state.

## Ownership and transaction model
SelfCoin uses a UTXO ledger with strict P2PKH rules and Ed25519 signatures.
- `txid = sha256d(tx_bytes)`
- `block_id = sha256d("SC-BLOCK-V0" || header_bytes)`
- serialization is explicit LE + canonical varint parsing.

Implementation anchors:
- tx/block serialization: [`src/utxo/tx.cpp`](../src/utxo/tx.cpp)
- script and sighash validation: [`src/utxo/validate.cpp`](../src/utxo/validate.cpp)
- hash/signatures: [`src/crypto/hash.cpp`](../src/crypto/hash.cpp), [`src/crypto/ed25519.cpp`](../src/crypto/ed25519.cpp)

## Validator accountability
Validators are permissionless via on-chain bond registration outputs (`SCVALREG`), then:
- `PENDING -> ACTIVE` after warmup,
- optional unbond via `SCVALUNB` with delay before funds unlock,
- slash path (`SCSLASH`) can consume bond on valid equivocation evidence.

Implementation anchors:
- script formats and spend paths: [`src/utxo/tx.cpp`](../src/utxo/tx.cpp), [`src/utxo/validate.cpp`](../src/utxo/validate.cpp)
- state machine: [`src/consensus/validators.cpp`](../src/consensus/validators.cpp)

## Monetary policy
Monetary issuance is deterministic and integer-only by block height.
Current implementation includes:
- hard-cap schedule logic (`reward_units`),
- coinbase validation against reward+fees,
- deterministic split of block value: leader 20%, signer pool 80% with sorted remainder assignment.

Implementation anchors:
- policy math: [`src/consensus/monetary.cpp`](../src/consensus/monetary.cpp)
- enforcement in block validation: [`src/utxo/validate.cpp`](../src/utxo/validate.cpp)

## Network hardening
P2P transport uses fixed framing and strict handshake identity.
The stack includes timeout deadlines, per-peer/global bounds, token-bucket limits, misbehavior scoring, soft mute, and bans.

Implementation anchors:
- framing/checksum/timeouts: [`src/p2p/framing.cpp`](../src/p2p/framing.cpp)
- peer lifecycle and queue caps: [`src/p2p/peer_manager.cpp`](../src/p2p/peer_manager.cpp)
- scoring/rate-control: [`src/p2p/hardening.cpp`](../src/p2p/hardening.cpp), [`src/node/node.cpp`](../src/node/node.cpp)

## Wallet integration
Wallet-facing access is through the finalized-only lightserver API and Wallet API v1 spec.
Endpoints include tip/header/block/tx/utxo/committee queries and tx broadcast.
A TypeScript SDK (`sdk/selfcoin-wallet-js`) provides key management, deterministic coin selection, tx build/sign, broadcast, and finality wait helpers.

Anchors:
- lightserver implementation: [`src/lightserver/server.cpp`](../src/lightserver/server.cpp)
- API contract: [`spec/SELFCOIN_WALLET_API_V1.md`](../spec/SELFCOIN_WALLET_API_V1.md)
- SDK: [`sdk/selfcoin-wallet-js`](../sdk/selfcoin-wallet-js)

## Mainnet readiness scaffolding
The repository includes:
- isolated `--mainnet` profile,
- deterministic genesis tooling (`genesis.json -> genesis.bin -> hash`),
- startup checks preventing cross-chain DB reuse,
- planning docs for ceremony/seeds/launch checklist.

Anchors:
- profile constants: [`src/common/network.cpp`](../src/common/network.cpp)
- genesis tooling: [`src/genesis/genesis.cpp`](../src/genesis/genesis.cpp), [`apps/selfcoin-cli/main.cpp`](../apps/selfcoin-cli/main.cpp)
- docs: [`mainnet/`](../mainnet)

## Bottom line
SelfCoin currently delivers a deterministic finalized-chain-first cash prototype with accountable validators, strict UTXO validation, hardened networking, and practical wallet integration paths.
It is technical infrastructure, not an investment product.
