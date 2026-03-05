# selfcoin-core

## What Is selfcoin-core
`selfcoin-core` is the C++20 reference implementation of the SelfCoin network.
It includes:
- `selfcoin-node` (full node)
- `selfcoin-lightserver` (finalized-chain JSON-RPC server)
- `selfcoin-cli` (utility CLI)
- TypeScript wallet SDK in `sdk/selfcoin-wallet-js`

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
