# Mainnet 3-Server Runbook

This runbook matches the repository's current behavior:

- mainnet-only build: do **not** pass `--mainnet`
- current `mainnet/genesis.json` has `initial_validators: []`
- that means launch starts in **bootstrap-template mode**

With the current genesis, you can safely start:

- 1 bootstrap validator/full node
- 2 follower full nodes
- 1 lightserver later on one of those machines

You **cannot** get 3 validators at height 0 from the current genesis.
If you want 3 validators from the first block, regenerate genesis with 3 fixed
`initial_validators` before launch.

## Topology

- `server1`: first bootstrap node, public P2P seed, first validator
- `server2`: follower full node, later validator candidate
- `server3`: follower full node, later validator candidate
- `server2` or `server3`: public `selfcoin-lightserver`

Ports:

- P2P: `19440/tcp`
- Lightserver: `19444/tcp`

## Before You Start

All three servers must use the exact same:

- `mainnet/genesis.bin`
- `mainnet/genesis.json`
- binary build

Check the genesis hash once locally and write it down:

```bash
./build/selfcoin-cli genesis_hash --in mainnet/genesis.bin
sha256sum mainnet/genesis.bin
```

Also prepare the public P2P endpoint for `server1`, for example:

- `203.0.113.10:19440`

## Recommended Launch Model

Because you said you do not want coins owned in advance, the clean launch path
with the current genesis is:

1. bootstrap `server1`
2. bring up `server2` and `server3` as followers
3. let `server1` mine/finalize blocks and receive the first block rewards
4. fund validator bond UTXOs for `server2` and `server3`
5. submit join-request transactions for those two servers
6. wait through warmup
7. only then do you have 3 validators

That is the honest consequence of "no premine" plus empty `initial_validators`.

## Build

On your build machine:

```bash
cd /home/greendragon/Desktop/selfcoin-core
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target selfcoin-node selfcoin-lightserver selfcoin-cli -j"$(nproc)"
```

Copy these to each server:

- `build/selfcoin-node`
- `build/selfcoin-lightserver`
- `build/selfcoin-cli`
- `mainnet/genesis.bin`

## Server 1: Bootstrap Validator

On `server1`, keep `mainnet/SEEDS.json` empty or do not use it for the first
start. Then launch:

```bash
mkdir -p ~/.selfcoin/mainnet
./selfcoin-node \
  --db ~/.selfcoin/mainnet \
  --genesis /path/to/genesis.bin \
  --allow-unsafe-genesis-override \
  --public \
  --listen \
  --bind 0.0.0.0 \
  --port 19440 \
  --no-dns-seeds \
  --outbound-target 0
```

What this does:

- starts the chain in bootstrap-template mode
- creates a local validator keystore if missing
- self-binds that local validator as the first validator
- begins producing/finalizing blocks

Check:

```bash
ss -ltnp | rg 19440
tail -f ~/.selfcoin/mainnet/MiningLOG
./selfcoin-cli print_logs --db ~/.selfcoin/mainnet --tail 50
```

## Update Seeds For Followers

After `server1` is running and reachable, put its public P2P endpoint into
`mainnet/SEEDS.json` on the follower servers:

```json
{
  "network": "mainnet",
  "seeds_p2p": ["203.0.113.10:19440"],
  "lightservers_rpc": [],
  "notes": ["bootstrap seed for initial launch"]
}
```

## Server 2 and Server 3: Follower Full Nodes

On `server2` and `server3`:

```bash
mkdir -p ~/.selfcoin/mainnet
./selfcoin-node \
  --db ~/.selfcoin/mainnet \
  --genesis /path/to/genesis.bin \
  --allow-unsafe-genesis-override \
  --port 19440 \
  --no-dns-seeds \
  --peers 203.0.113.10:19440
```

Check:

```bash
./selfcoin-cli print_logs --db ~/.selfcoin/mainnet --tail 50
```

You want to see sync progress, finalized height growth, and no
`genesis-fingerprint-mismatch`.

## Add More Public Seeds After Followers Are Stable

Once `server2` and `server3` are stable and publicly reachable, update
published seed lists to include all public P2P nodes:

- `server1:19440`
- `server2:19440`
- `server3:19440`

Do not publish `19444` as a seed. That is lightserver, not P2P.

## Lightserver

You do not need lightserver to start mainnet, but you should run one after the
core network is stable so wallets and services can query chain state.

Run it on one server that already has a synced node DB, usually `server2`:

```bash
./selfcoin-lightserver \
  --db ~/.selfcoin/mainnet \
  --bind 0.0.0.0 \
  --port 19444 \
  --relay-host 127.0.0.1 \
  --relay-port 19440
```

Check:

```bash
./selfcoin-cli rpc_status --url http://127.0.0.1:19444/rpc
```

If you publish it publicly, publish it as:

- `http://host:19444/rpc`

not as a seed node.

## Turning Server 2 and Server 3 Into Validators

With the current genesis, `server2` and `server3` start as full nodes first.
They only become validators later, after you fund their bond transactions.

High-level process:

1. let `server1` accumulate spendable coinbase rewards
2. read validator pubkeys/addresses from each server keystore
3. send enough coins to create bond UTXOs
4. create `SCVALJRQ + SCVALREG` join-request transactions
5. broadcast those txs
6. wait for finalization
7. wait for warmup
8. validator becomes `ACTIVE`

Useful commands:

Show local validator info on each server:

```bash
./selfcoin-cli print_logs --db ~/.selfcoin/mainnet --tail 20
```

Create a join request once you have a funding UTXO:

```bash
./selfcoin-cli create_validator_join_request_tx \
  --prev-txid <funding-txid> \
  --prev-index <vout> \
  --prev-value <value> \
  --funding-privkey <funding-privkey-hex> \
  --validator-privkey <validator-privkey-hex>
```

Broadcast the resulting tx hex to a node:

```bash
./selfcoin-cli broadcast_tx --host 127.0.0.1 --port 19440 --tx-hex <hex>
```

Warmup is currently `100` blocks on mainnet.

## If You Want 3 Validators From Block 0 Instead

Do **not** use the current `mainnet/genesis.json` as-is.

Instead:

1. generate validator keys for all 3 servers first
2. put those 3 validator pubkeys into `initial_validators`
3. set `initial_active_set_size` to `3`
4. rebuild and verify `genesis.bin`
5. publish that exact genesis artifact before launch

That gives you 3 validators from height 0, but it is a different launch model
from the current bootstrap-template genesis.

## Safe Defaults

- only `server1` should start first
- only one bootstrap node should self-bind from an empty-validator genesis
- followers must use the same `genesis.bin`
- do not put HTTP or TLS in front of `19440`
- do not expose `19444` as a seed
- add lightserver only after at least one follower is syncing cleanly

## Minimum First-Day Checklist

- `server1` finalizing blocks
- `server2` syncing from `server1`
- `server3` syncing from `server1`
- no genesis mismatch logs
- one public P2P seed reachable
- one public lightserver reachable

After that, move to validator expansion.
