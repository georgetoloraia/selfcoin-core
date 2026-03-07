# SelfCoin Wallet API v1

## Scope
SelfCoin Wallet API v1 is a finalized-chain JSON-RPC contract for non-custodial wallets.

Goals:
- stable, minimal surface for app integrations
- finalized-only semantics
- no server-side user state
- deterministic, reproducible results from finalized DB state

This document describes the wallet-facing subset of the current lightserver RPC surface.
The implementation also exposes additional certificate and proof-oriented methods such as
`get_finality_certificate`, `get_roots`, `get_utxo_proof`, and `get_validator_proof`, but
those are not required parts of the minimal wallet API contract.

Transport:
- HTTP `POST /rpc`
- JSON-RPC 2.0 request/response

## Deterministic Definitions

### Units
- `1 SelfCoin = 100,000,000` base units.
- Wallets must use integer units only.

### Address
- Address encoding follows `spec/SELFCOIN_ADDRESS_V0.md` and `src/address/address.cpp`.
- Accepted HRP values in v1: `sc` (main-style), `tsc` (test/dev).

### P2PKH script_pubkey
- Exactly: `76 A9 14 <20-byte pubkey_hash> 88 AC`.

### Scripthash for wallet queries
- `scripthash = sha256(script_pubkey)` (single SHA-256, not sha256d).
- Returned/accepted as lowercase hex (64 chars).

### Tx encoding/signing
- Tx bytes, varints, little-endian rules, txid, and signature message are defined by existing core:
  - `src/utxo/tx.cpp`
  - `src/utxo/validate.cpp`
  - `src/utxo/signing.cpp`
- txid is `sha256d(tx_bytes)`.

### Finality confirmation rule
A wallet may treat a tx as finalized when:
1. `get_tx(txid)` returns `{height, tx_hex}`.
2. `get_headers` covering `height` returns the corresponding finalized block header chain.

## Error Model
Servers return JSON-RPC error object with numeric code + message.

Standard names mapped to numeric codes used in v1:
- `INVALID_REQUEST` -> `-32600`
- `METHOD_NOT_FOUND` -> `-32601`
- `INVALID_PARAMS` -> `-32602`
- `NOT_FOUND` -> `-32001`
- `NOT_FINALIZED` -> `-32002` (reserved for future extensions)
- `RATE_LIMITED` -> `-32029` (reserved; optional)
- `INTERNAL` -> `-32000`

For `broadcast_tx`, server may also return `result.accepted=false` with an `error` string.

## Methods

### 1) get_status
Request:
```json
{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}
```
Response:
```json
{
  "network_name":"mainnet|devnet|testnet",
  "protocol_version":1,
  "feature_flags":1,
  "network_id":"<hex16>",
  "magic":1396919630,
  "genesis_hash":"<hex32>",
  "genesis_source":"embedded|db|file",
  "chain_id_ok":true,
  "tip":{"height":123,"hash":"<hex32>"},
  "peers":null,
  "mempool_size":null,
  "uptime_s":42,
  "version":"selfcoin-core/0.x"
}
```

### 2) get_tip
Params: `{}`

Response:
```json
{"height":123,"hash":"<hex32>"}
```

### 3) get_headers
Params:
- `from_height` (u64)
- `count` (u64)

Response:
- list ordered by height ascending, truncated when unavailable:
```json
[
  {
    "height":123,
    "header_hex":"...",
    "block_hash":"<hex32>",
    "finality_proof":[
      {"pubkey_hex":"<hex32>","sig_hex":"<hex64>"}
    ]
  }
]
```

Pagination:
- caller controls paging via `(from_height,count)`.
- no cursor in v1.

### 4) get_block
Params:
- `hash` (`hex32`)

Response:
```json
{"block_hex":"..."}
```
(finalized blocks only)

### 5) get_tx
Params:
- `txid` (`hex32`)

Response:
```json
{"height":123,"tx_hex":"..."}
```
(finalized tx index only)

### 6) get_utxos
Params:
- `scripthash_hex` (`hex32`, single-sha scripthash)

Response:
```json
[
  {
    "txid":"<hex32>",
    "vout":0,
    "value":1000,
    "height":120,
    "script_pubkey_hex":"..."
  }
]
```

### 7) get_committee
Params:
- `height` (u64)

Response:
```json
["<pubkey_hex32>","..."]
```

### 8) broadcast_tx
Params:
- `tx_hex` (raw tx hex)

Response:
```json
{"accepted":true,"txid":"<hex32>"}
```
or
```json
{"accepted":false,"txid":"<hex32>","error":"..."}
```

## Client Verification Modes

### Single-server mode
- simplest mode
- trust one operator endpoint

### Multi-server cross-check mode
Recommended for consumer wallets:
1. query `get_tip` from 2-3 independent servers
2. require matching `(height, hash)` quorum before critical actions (send)
3. if mismatch persists, warn user and do not broadcast blindly

### Advanced verification note
`get_headers` includes finality proofs and `get_committee` provides committee members.
A fully self-verifying light client can validate quorum signatures and committee derivation using finalized state rules, but complete trustless UX (validator state proofs over history) is out of Wallet API v1 and can be expanded in v2.
