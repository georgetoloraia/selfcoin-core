# selfcoin-core

## What Is selfcoin-core
`selfcoin-core` is the C++20 reference implementation of the SelfCoin network.

SelfCoin is a deterministic settlement chain with a deliberately narrow base-layer scope:
- deterministic proposer selection
- deterministic committee selection
- committee-membership voting
- quorum from committee size
- explicit finalized-chain read surfaces
- no VM
- no general-purpose smart contracts

The repository includes:
- `selfcoin-node` (full node)
- `selfcoin-lightserver` (finalized-chain JSON-RPC server)
- `selfcoin-cli` (utility CLI)
- TypeScript wallet SDK in `sdk/selfcoin-wallet-js`

The shipped runtime uses one fixed deterministic consensus interpretation with current validator/bond validation semantics in transaction and block validation.

Base-layer execution is limited to:
- P2PKH value transfer
- validator register
- validator unbond
- slash-burn and the validator-related settlement forms already implemented in the repo

Historical activation/version-routing code is not part of the active mainnet runtime. See `docs/runtime-consensus.md` and `docs/consensus-history.md`.
Operational hardening notes for hostile network traffic live in `docs/ADVERSARIAL_RUNTIME_HARDENING.md`.

Finality certificates are now available as separate persisted objects and through lightserver RPC. Snapshot export/import is available as an implementation-first recovery/bootstrap tool; it is not a trust-minimized sync protocol.

## Why SelfCoin
SelfCoin is aimed at operators and developers who want a base layer that is easier to reason about than a feature-maximal L1.

Why use it:
- deterministic final settlement instead of probabilistic confirmation semantics
- narrow, explicit validation rules instead of a general-purpose execution surface
- cheap full-node reasoning and smaller conceptual surface
- finalized-only lightserver read paths for wallet and client integrations

What it is not trying to be:
- an Ethereum-style general-purpose application runtime
- a VM platform
- a broad execution layer for arbitrary on-chain logic

## Finality Certificates
SelfCoin finalizes blocks through committee votes that reach quorum. The runtime now persists a separate `FinalityCertificate` alongside the finalized block.

Implemented now:
- a raw-signature certificate object built from the same finalized vote material already used by the runtime
- separate persistence in storage
- separate exposure through lightserver RPC
- compatibility with the existing embedded `Block.finality_proof`

Intentionally deferred:
- header commitment of certificates
- aggregated signatures
- standalone P2P certificate distribution

The current certificate surface is a durability and readability improvement over the existing finality proof path. It is not yet a deeper protocol-format redesign.

## Snapshot Export / Import
Snapshot export/import is currently implementation-first operational tooling.

Implemented now:
- deterministic snapshot export from the finalized-state DB keyspace
- deterministic snapshot import into the ordinary runtime DB layout
- empty-DB-only import as the conservative first import mode

Operational expectations:
- export is intended for a stopped or otherwise quiescent node DB
- import is intended for an empty DB only
- this is useful for recovery, migration, and local bootstrap workflows

Intentionally not claimed:
- trust-minimized fast sync
- protocol-grade checkpoint verification
- incremental sync
- live hot-backup guarantees

The active protocol does not yet chain-commit state checkpoints/roots strongly enough to describe snapshots as trust-minimized sync.

## Stability Note
The recent recurring late-run test-suite segfault was traced to local-bus shutdown handling in test/runtime teardown, not to deterministic consensus behavior. That teardown path has been hardened and the full suite now completes cleanly again.

## Build (Full)
### 1) Auto-bootstrap build (recommended)
```bash
./scripts/bootstrap_build.sh
```

### 2) Manual build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run Mainnet Node
```bash
./build/selfcoin-node
```

optional encrypted keystore:
```bash
export SELFCOIN_VALIDATOR_PASS="change-me"
./build/selfcoin-node --validator-passphrase-env SELFCOIN_VALIDATOR_PASS
```

Public node (operator mode):
```bash
./build/selfcoin-node --public
```

Default mainnet data dir:
```text
~/.selfcoin/mainnet
```

## Run Lightserver
Local-only (same machine):
```bash
./build/selfcoin-lightserver --db ~/.selfcoin/mainnet --bind 127.0.0.1 --port 19444 --relay-host 127.0.0.1 --relay-port 19440
```

RPC endpoint:
```text
http://127.0.0.1:19444/rpc
```

Public/global (external clients can connect):
```bash
./build/selfcoin-lightserver --db ~/.selfcoin/mainnet --bind 0.0.0.0 --port 19444 --relay-host 127.0.0.1 --relay-port 19440
```

If using public mode, open firewall port `19444/tcp`.

Actual defaults if flags are omitted:
- `--db`: network default DB dir
- `--bind`: `127.0.0.1`
- `--port`: network default lightserver port
- `--relay-host`: `127.0.0.1`
- `--relay-port`: network default node P2P port
- `--max-committee`: network default committee cap

Current JSON-RPC surface:
- `get_tip`
- `get_status`
- `get_headers`
- `get_header_range`
- `get_block`
- `get_finality_certificate`
- `get_tx`
- `get_utxos`
- `get_committee`
- `get_roots`
- `get_utxo_proof`
- `get_validator_proof`
- `broadcast_tx`

Current conservative semantics:
- `get_finality_certificate` accepts `height`, `hash`, or no selector, in which case it returns the current finalized tip certificate
- `get_roots` returns finalized roots when present and otherwise reports unavailable
- `get_utxo_proof` and `get_validator_proof` are current-tip proof surfaces; historical proof requests are not supported in this fixed runtime
- `broadcast_tx` validates and relays to the configured node relay target; it does not maintain a lightserver-side mempool

## Use SDK
Path:
```text
sdk/selfcoin-wallet-js
```

Install + build:
```bash
cd sdk/selfcoin-wallet-js
npm install
npm run build
```

Run example:
```bash
npm run example:node-demo
```

Read SDK docs:
```text
sdk/selfcoin-wallet-js/README.md
```

## Keystore CLI
Create encrypted wallet/validator keystore:
```bash
./build/selfcoin-cli wallet_create --out ~/.selfcoin/mainnet/keystore/validator.json --pass "change-me" --network mainnet
```

Create wallet/validator keystore without passphrase:
```bash
./build/selfcoin-cli wallet_create --out ~/.selfcoin/mainnet/keystore/validator.json --network mainnet
```

Show address:
```bash
./build/selfcoin-cli wallet_address --file ~/.selfcoin/mainnet/keystore/validator.json --pass "change-me"
```

Export keys (for backup/import):
```bash
./build/selfcoin-cli wallet_export --file ~/.selfcoin/mainnet/keystore/validator.json --pass "change-me"
```

Snapshot export/import:
```bash
./build/selfcoin-cli snapshot_export --db ~/.selfcoin/mainnet --out ~/.selfcoin/mainnet.snapshot
./build/selfcoin-cli snapshot_import --db /path/to/empty-db --in ~/.selfcoin/mainnet.snapshot
```

Snapshot export is intended for a stopped or otherwise quiescent node DB in this first slice. Snapshot imports are conservative and intended for empty DBs only. The current protocol does not chain-commit snapshot checkpoints/state roots strongly enough to describe this as trust-minimized fast sync.
