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
- Deterministic leader selection + quorum finality (`floor(2N/3)+1`)
- Vote dedup + equivocation detection and banning
- TCP P2P framing + handshake + core message types
- Persistent state DB wrapper (RocksDB if available, file-backed fallback)
- `selfcoin-node` devnet node
- `selfcoin-cli` tip/address helpers
- Unit + integration tests (4-node devnet, timeout recovery, equivocation banning)

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

Example log line:
```text
[node 1] finalized height=40 round=0 leader=... votes=3/3 hash=...
```

## CLI

Tip from local DB:
```bash
./build/selfcoin-cli tip --db /tmp/sc-node0
```

Address from pubkey hex:
```bash
./build/selfcoin-cli addr --hrp tsc --pubkey <64-hex-chars>
```

## Tests

```bash
./build/selfcoin-tests
```

Or with CTest:
```bash
cd build && ctest --output-on-failure
```
