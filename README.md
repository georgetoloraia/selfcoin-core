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

## Monetary Policy (7M Hard Cap)

Monetary schedule is deterministic by block height (no wall-clock logic):
- Base unit: `1 SelfCoin = 100,000,000` units.
- Total cap: `7,000,000` coins = `700,000,000,000,000` units.
- Emission length: `3,504,000` blocks (`20 * 175,200`, 3-minute target cadence).

Reward function:
- `q = 199,771,689`
- `r = 1,744,000`
- `reward_units(h) = q + (h < r ? 1 : 0)` for `h < 3,504,000`, else `0`.

Examples:
- `reward_units(0) = 199,771,690`
- `reward_units(r-1) = reward_units(1,743,999) = 199,771,690`
- `reward_units(r) = reward_units(1,744,000) = 199,771,689`
- `reward_units(3,504,000) = 0`

Per-block payout split (`T = reward + fees`):
- Leader bonus: `floor(T * 20 / 100)`
- Remaining `80%` split equally among deterministic signer list
- Remainder units assigned to lexicographically smallest signer pubkeys first

## Network Profiles

`selfcoin-node` and `selfcoin-lightserver` support:
- `--devnet` (default)
- `--testnet`
- `--mainnet`

Fixed profile constants include:
- distinct network magic (`devnet`: `0x53434F49`, `testnet`: `0x5343544E`)
- default ports (`devnet`: P2P `18444`, lightserver `19444`; `testnet`: P2P `28444`, lightserver `29444`)
- `MAX_COMMITTEE`, `ROUND_TIMEOUT_MS`, `MAX_PAYLOAD_LEN`
- bond/warmup/unbond-delay constants

Mainnet planning artifacts live under `mainnet/` and include:
- `MAINNET_PLAN.md`
- `MAINNET_PARAMS.md`
- `GENESIS_SPEC.md`
- `GENESIS_VALIDATOR_CEREMONY.md`
- `SEEDS.md`
- `THREAT_MODEL_AND_LAUNCH_CHECKLIST.md`
- template `genesis.json`

Genesis tooling commands:
```bash
./build/selfcoin-cli genesis_build --in mainnet/genesis.json --out mainnet/genesis.bin
./build/selfcoin-cli genesis_hash --in mainnet/genesis.bin
./build/selfcoin-cli genesis_verify --json mainnet/genesis.json --bin mainnet/genesis.bin
```

Testnet bootstrap:
- `--seeds host:port,...` for explicit seed list
- built-in default seeds are used when `--testnet` is set and `--seeds` is omitted
- peer cache persisted at `<db>/peers.dat`

## Handshake Version Policy (v0.7)

`VERSION` payload now carries explicit network/protocol identity:
- `protocol_version` (`u32`)
- `network_id` (`16 bytes`)
- `feature_flags` (`u64`)
- `node_software_version` (`varbytes string`)
- plus existing tip/time fields

Handshake acceptance policy:
- framing `magic` mismatch: reject/disconnect
- `network_id` mismatch: reject/disconnect (counted as peer rejection)
- unsupported `protocol_version`: reject/disconnect (graceful, no ban score)
- consensus messages are ignored/rejected before full `VERSION`/`VERACK`

## Build

Requirements:
- CMake >= 3.20
- C++20 compiler
- OpenSSL development libs
- Optional: RocksDB development libs (auto-detected)

One-command bootstrap (installs missing dependencies, then builds):
```bash
./scripts/bootstrap_build.sh
```

Optional overrides:
```bash
BUILD_DIR=build BUILD_TYPE=Release GENERATOR=Ninja ./scripts/bootstrap_build.sh
```

Manual build:
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

Run mainnet with embedded canonical genesis (recommended):
```bash
./build/selfcoin-node --mainnet
```

Default data dir (when `--db` is omitted):
- mainnet: `~/.selfcoin/mainnet`
- testnet: `~/.selfcoin/testnet`
- devnet: `~/.selfcoin/devnet`

Operator mode (public seed/full node):
```bash
./build/selfcoin-node --mainnet --public
```

`--public` enables inbound listening, binds to `0.0.0.0` by default, and applies inbound caps.
Open firewall for `19440/tcp` for mainnet operators.

Note: chain finalization still requires validator quorum online.

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

Network regression loop (10 runs for flaky-port checks):
```bash
./scripts/run_network_regression.sh
```

Example tx/mempool logs:
```text
[node 1] mempool-accept txid=... mempool_size=1
[node 0] propose-assembled height=41 round=0 txs=1 fees=1000
[node 2] finalized height=41 round=0 leader=... votes=3/3 txs=2 hash=... included_txid=...
```

## v0.5 Hardening

Node hardening defaults:
- handshake timeout: `10000ms`
- frame read timeout: `3000ms`
- idle timeout: `120000ms`
- peer outbound queue cap: `2MB` / `2000` messages
- soft mute score: `30`, ban score: `100`, ban duration: `600s`

New node flags:
```bash
--handshake-timeout-ms <ms>
--frame-timeout-ms <ms>
--idle-timeout-ms <ms>
--peer-queue-max-bytes <n>
--peer-queue-max-msgs <n>
--ban-seconds <s>
--min-relay-fee <sats>   # defaults to 1000 on --testnet, 0 on devnet
```

Sanitizers:
```bash
cmake -S . -B build-asan -DSELFCOIN_SANITIZE=ON
cmake --build build-asan -j
```

Fuzz harness targets:
```bash
cmake -S . -B build-fuzz -DSELFCOIN_BUILD_FUZZ=ON
cmake --build build-fuzz -j
./build-fuzz/fuzz_p2p_frame
./build-fuzz/fuzz_tx_parse
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
{"network_name":"testnet","protocol_version":1,"feature_flags":1,"tip":{"height":123,"hash":"..."},"peers":null,"mempool_size":null,"uptime_s":42,"version":"selfcoin-core/0.7"}
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

## Wallet Integration

Any application can embed a non-custodial SelfCoin wallet over lightserver JSON-RPC.

- Wallet API contract: `spec/SELFCOIN_WALLET_API_V1.md`
- Reference TypeScript SDK: `sdk/selfcoin-wallet-js`
- Example apps:
  - `sdk/selfcoin-wallet-js/examples/node-demo.ts`
  - `sdk/selfcoin-wallet-js/examples/watch.ts`

Quick start:
```bash
cd sdk/selfcoin-wallet-js
npm install
npm test
```
