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
- `selfcoin-lightserver` finalized-chain JSON-RPC server for light clients
- `selfcoin-cli` tip/key/address/tx build/tx broadcast helpers
- `scripts/observe.py` multi-endpoint observer for divergence checks
- Unit + integration tests (fault recovery, tx finalization, restart determinism)

## Network Profiles

`selfcoin-node` and `selfcoin-lightserver` support:
- `--devnet` (default)
- `--testnet`

Fixed profile constants include:
- distinct network magic (`devnet`: `0x53434F49`, `testnet`: `0x5343544E`)
- default ports (`devnet`: P2P `18444`, lightserver `19444`; `testnet`: P2P `28444`, lightserver `29444`)
- `MAX_COMMITTEE`, `ROUND_TIMEOUT_MS`, `MAX_PAYLOAD_LEN`
- bond/warmup/unbond-delay constants

Testnet bootstrap:
- `--seeds host:port,...` for explicit seed list
- built-in default seeds are used when `--testnet` is set and `--seeds` is omitted
- peer cache persisted at `<db>/peers.dat`

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

Run lightserver against node0 DB:
```bash
./build/selfcoin-lightserver --db /tmp/sc-node0 --bind 127.0.0.1 --port 19444 --relay-host 127.0.0.1 --relay-port 19040 --devnet --devnet-initial-active 4
```

## Run Testnet

Seed node:
```bash
./build/selfcoin-node --testnet --node-id 0 --db /tmp/sc-test-seed --port 28444 --log-json
```

Join node (no manual peers, uses seeds):
```bash
./build/selfcoin-node --testnet --node-id 1 --db /tmp/sc-test-node1 --port 28445
```

Lightserver on testnet:
```bash
./build/selfcoin-lightserver --testnet --db /tmp/sc-test-seed --bind 127.0.0.1 --port 29444 --relay-host 127.0.0.1 --relay-port 28444
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

## Lightserver JSON-RPC

Single endpoint: `POST /rpc` (JSON-RPC 2.0).

Scripthash definition used by `get_utxos`:
- `scripthash = sha256(script_pubkey)` (single SHA-256, 32 bytes, hex-encoded in RPC).

Examples:
```bash
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":0,"method":"get_status","params":{}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":2,"method":"get_headers","params":{"from_height":1,"count":10}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":3,"method":"get_block","params":{"hash":"<block_hash_hex>"}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":4,"method":"get_tx","params":{"txid":"<txid_hex>"}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":5,"method":"get_utxos","params":{"scripthash_hex":"<sha256_script_pubkey_hex>"}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":6,"method":"get_committee","params":{"height":100}}'
curl -s http://127.0.0.1:19444/rpc -d '{"jsonrpc":"2.0","id":7,"method":"broadcast_tx","params":{"tx_hex":"<raw_tx_hex>"}}'
```

`get_status` response shape:
```json
{"tip":{"height":123,"hash":"..."}, "peers":null, "mempool_size":null, "uptime_s":42, "version":"selfcoin-core/0.4", "network":"testnet"}
```

## Observer

Poll multiple lightservers and detect persistent divergence:
```bash
python3 scripts/observe.py --interval 2 --mismatch-threshold 3 \
  http://127.0.0.1:19444/rpc \
  http://127.0.0.1:19445/rpc
```

Example output:
```text
server  height  hash              lag  status
http://127.0.0.1:19444/rpc  120  8c2d...  0  ok
http://127.0.0.1:19445/rpc  120  8c2d...  0  ok
```

## Docker

Build image:
```bash
docker build -t selfcoin-core:latest .
```

Run seed node container:
```bash
docker run --rm -p 28444:28444 -v selfcoin_data:/data selfcoin-core:latest \
  --testnet --node-id 0 --db /data/seed --port 28444 --log-json
```

Run testnet sample stack:
```bash
docker compose -f docker-compose.testnet.yml up --build
```

### VPS/UFW

Open required ports:
```bash
sudo ufw allow 28444/tcp
sudo ufw allow 29444/tcp
sudo ufw reload
```

## 3-Region Testnet

1. Region A (seed): run `selfcoin-node --testnet --port 28444` and allow inbound `28444/tcp`.
2. Region B/C: run `selfcoin-node --testnet --seeds <seedA_ip>:28444 --port 28444`.
3. Run one `selfcoin-lightserver --testnet --relay-host <local_node_ip> --relay-port 28444`.
4. Verify convergence with observer:
   `python3 scripts/observe.py https://ls-a/rpc https://ls-b/rpc https://ls-c/rpc`
