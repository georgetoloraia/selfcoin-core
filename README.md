# SelfCoin Core v0

SelfCoin Core is a C++20 prototype implementation of:
- `spec/SELFCOIN_CONSENSUS_V0.md`
- `spec/SELFCOIN_P2P_V0.md`
- `spec/SELFCOIN_ADDRESS_V0.md`

Implemented in this repo:
- Canonical codec (LE primitives, minimal ULEB128 varint, strict parsing)
- Double-SHA256 + H160 + Ed25519 (OpenSSL)
- Tx/Block/FinalityProof serialization and hashing
- UTXO validation with strict v0 P2PKH script checks
- Minimal mempool (validation, double-spend checks, deterministic fee-based selection)
- Deterministic leader selection + quorum finality (`floor(2N/3)+1`)
- Vote dedup + equivocation detection and banning
- TCP P2P framing + handshake + core message types (including TX propagation)
- Persistent state DB wrapper (RocksDB if available, file-backed fallback)
- `selfcoin-node` devnet node
- `selfcoin-cli` tip/key/address/tx build/tx broadcast helpers
- Unit + integration tests (fault recovery, tx finalization, restart determinism)

## Build

Requirements:
- CMake >= 3.20
- C++20 compiler
- OpenSSL development libs
- Optional: RocksDB development libs (auto-detected)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run 4-node devnet (TCP)

Terminal 1:
```bash
./build/selfcoin-node --devnet --node-id 0 --port 19040 --db /tmp/sc-node0
```

Terminal 2:
```bash
./build/selfcoin-node --devnet --node-id 1 --port 19041 --db /tmp/sc-node1 --peers 127.0.0.1:19040
```

Terminal 3:
```bash
./build/selfcoin-node --devnet --node-id 2 --port 19042 --db /tmp/sc-node2 --peers 127.0.0.1:19040,127.0.0.1:19041
```

Terminal 4:
```bash
./build/selfcoin-node --devnet --node-id 3 --port 19043 --db /tmp/sc-node3 --peers 127.0.0.1:19040,127.0.0.1:19041,127.0.0.1:19042
```

Example finalization log line:
```text
[node 1] finalized height=40 round=0 leader=... votes=3/3 txs=2 hash=... included_txid=...
```

## CLI

Tip from local DB:
```bash
./build/selfcoin-cli tip --db /tmp/sc-node0
```

Create keypair (optional deterministic seed):
```bash
./build/selfcoin-cli create_keypair --seed-hex <64-hex-chars>
```

Address from pubkey hex:
```bash
./build/selfcoin-cli address_from_pubkey --hrp tsc --pubkey <64-hex-chars>
```

Build a signed single-input P2PKH tx:
```bash
./build/selfcoin-cli build_p2pkh_tx \
  --prev-txid <hex32> \
  --prev-index <u32> \
  --prev-value <u64> \
  --from-privkey <hex32> \
  --to-address <tsc1...> \
  --amount <u64> \
  --fee <u64>
```

Broadcast raw tx to a node over P2P:
```bash
./build/selfcoin-cli broadcast_tx --host 127.0.0.1 --port 19040 --tx-hex <hex>
```

## Tests

```bash
./build/selfcoin-tests
```

Or with CTest:
```bash
cd build && ctest --output-on-failure
```

Example tx/mempool logs:
```text
[node 1] mempool-accept txid=... mempool_size=1
[node 0] propose-assembled height=41 round=0 txs=1 fees=1000
[node 2] finalized height=41 round=0 leader=... votes=3/3 txs=2 hash=... included_txid=...
```
