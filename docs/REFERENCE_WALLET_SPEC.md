# SelfCoin Reference Wallet Spec

## Goal
Build a minimal desktop reference wallet for `selfcoin-core`.

This is not the final mass-market wallet.
It is a disciplined first wallet that proves:
- self-custody works
- normal send/receive works
- mint deposit and redemption work
- backup and restore work

## Current implementation status

Implemented now in `selfcoin-wallet`:
- Qt desktop app target in the main build
- create wallet
- open wallet
- import wallet from 32-byte private key hex
- encrypted keystore reuse via `src/keystore/*`
- export backup material by explicit user action
- receive address display and copy
- local lightserver / mint URL settings persisted with `QSettings`
- configurable mint ID persisted with `QSettings`
- disciplined tab layout: `Home`, `Receive`, `Send`, `History`, `Mint`, `Settings`
- real lightserver-backed balance sync via `get_status` + `get_utxos`
- real address activity sync via `get_history` + `get_tx`
- real GUI transaction build and broadcast for simple on-chain sends
- real GUI mint flow for:
  - `SCMINTDEP` deposit build and broadcast
  - deposit registration with `selfcoin-mint`
  - one-note blind issuance request
  - redemption creation
  - redemption status polling

Intentionally deferred to the next wallet phase:
- QR rendering
- local metadata DB / SQLite layer
- richer note selection / denomination handling beyond exact-note redemption

## Product boundary
The reference wallet should support:
- one chain: `selfcoin-core`
- one asset: `selfcoin`
- one user profile / wallet file
- one mint connection at a time

It should not support:
- exchange features
- multi-asset management
- validator operations
- governance
- browser extension flows
- merchant POS
- social/chat features
- advanced privacy analytics

## Recommended implementation split

### UI layer
Desktop-only first.

Suggested stack:
- Qt Widgets or Qt Quick/QML

Reason:
- mature C++ desktop toolkit
- good cross-platform path
- easier to ship a minimal reference wallet without inventing a UI framework

### Wallet/application layer
New wallet-specific application code in this repo or adjacent wallet repo.

Suggested modules:
- `wallet/app/*`
- `wallet/ui/*`
- `wallet/model/*`

### Existing repo pieces to reuse
- address encoding/decoding:
  - `src/address/*`
- tx building/signing:
  - `src/utxo/signing.*`
- wallet file / key handling patterns:
  - `src/keystore/*`
- lightserver access model:
  - `src/lightserver/*`
- mint JSON contract types:
  - `src/privacy/mint_client.*`
- mint deposit script support:
  - `src/privacy/mint_scripts.*`

### External dependencies allowed
- Qt
- SQLite for local wallet metadata
- existing OpenSSL already used in repo, only if needed consistently

## Required screens

### 1. Home
Must show:
- on-chain available balance
- pending outgoing amount
- current receive address
- lightserver connection state
- mint connection state

Actions:
- `Receive`
- `Send`
- `Mint Deposit`
- `Redeem`
- `History`
- `Settings`

### 2. Receive
Must show:
- current address
- copy button
- QR code

Optional:
- label field stored locally

### 3. Send
Fields:
- destination address
- amount
- fee

Must include:
- address validation
- insufficient balance validation
- confirmation dialog:
  - destination
  - amount
  - fee
  - total spend

### 4. History
Entries:
- received
- sent
- mint deposit
- mint redemption

Per entry show:
- type
- amount
- timestamp
- txid or batch id
- status: pending / broadcast / finalized / failed

### 5. Mint
Sections:
- active mint deposit status
- issue notes step
- redemption step
- redemption status

Actions:
- create deposit tx
- register deposit with mint
- request issuance
- create redemption
- query redemption status

### 6. Settings
Fields:
- wallet file path
- lightserver URL
- mint URL
- network name

Actions:
- export backup
- import wallet
- change wallet password
- rescan

## Required flows

### Flow A: Create wallet
1. User opens wallet first time.
2. Wallet offers:
   - create new wallet
   - import existing wallet
3. On create:
   - generate key material
   - create encrypted wallet file
   - display backup phrase or export secret material
   - require confirmation that backup was saved

### Flow B: Import wallet
1. User chooses import.
2. User enters private key or seed.
3. Wallet derives receive address.
4. Wallet rescans via lightserver.

### Flow C: Receive
1. User opens Receive.
2. Wallet shows address and QR.
3. User shares address.

### Flow D: Send on-chain
1. User opens Send.
2. User enters address + amount.
3. Wallet estimates or defaults fee.
4. Wallet builds tx locally.
5. User confirms.
6. Wallet broadcasts through lightserver.
7. History shows pending then finalized.

### Flow E: Deposit to mint
1. User opens Mint.
2. User enters deposit amount.
3. Wallet builds mint deposit tx with `SCMINTDEP`.
4. User confirms and broadcasts.
5. Wallet registers deposit with mint.
6. Wallet shows deposit status until ready.

### Flow F: Issue private notes
1. Wallet submits blind payloads to mint.
2. Wallet stores returned note references / issuance data locally.
3. Wallet shows issued note balance as separate mint balance.

### Flow G: Redeem back to chain
1. User enters redeem amount and destination address.
2. Wallet selects notes locally.
3. Wallet creates redemption request against mint.
4. Wallet polls status.
5. Once finalized, history shows on-chain redemption result.

### Flow H: Restore and rescan
1. User imports key material.
2. Wallet reconnects to lightserver.
3. Wallet reconstructs on-chain history and balances.
4. Wallet restores mint metadata if available from local backup, otherwise only on-chain funds are guaranteed.

## Local data model

### Wallet file
Store:
- encrypted private key or seed
- public key
- primary address
- wallet version

Do not store plaintext private key.

### Local metadata DB
Suggested SQLite tables:
- `settings`
- `addresses`
- `transactions`
- `mint_deposits`
- `mint_notes`
- `mint_redemptions`
- `sync_state`

### Transaction record fields
- local id
- txid
- kind
- amount
- fee
- direction
- created_at
- updated_at
- status
- raw metadata JSON if needed

### Mint note record fields
- note_ref
- issuance_id
- amount
- state: issued / reserved / redeemed
- mint_url
- created_at

## Security requirements

Must:
- encrypt wallet file with password
- require explicit secret export action
- validate destination addresses before send
- keep signing local
- never send private key to lightserver or mint
- lock wallet after inactivity

Should:
- support OS keychain integration later
- support read-only mode later

Must not:
- silently auto-approve sends
- automatically export keys
- mix mint and on-chain balances without clear labels

## UX rules

Use plain language:
- `Available balance`
- `Pending`
- `Private balance`
- `Deposit to mint`
- `Redeem to wallet`

Do not expose protocol terms in primary UI:
- `SCVALREG`
- `SCMINTDEP`
- `script_pubkey`
- `finality certificate`

Those may appear only in advanced details dialogs.

## Connection model

### Lightserver
Use lightserver for:
- tip status
- balance reconstruction from UTXOs
- tx broadcast
- tx status
- history lookups

### Mint
Use mint service for:
- deposit registration
- blind issuance
- redemption creation
- redemption status

## Error handling

Must provide clear user-facing errors for:
- invalid address
- insufficient balance
- cannot connect to lightserver
- cannot connect to mint
- broadcast failed
- mint deposit registration failed
- redemption rejected

Avoid raw internal errors unless user opens advanced details.

## Non-goals for v1
- multiple accounts
- multisig
- hardware wallets
- mobile
- push notifications
- seed phrase social recovery
- embedded exchange / swaps
- validator staking UI

## Definition of done
The reference wallet is done when a normal user can:
1. create wallet
2. back it up
3. receive coins
4. send coins
5. see finalized history
6. deposit to mint
7. redeem from mint
8. restore wallet from backup

## Implementation order

### Phase 1
- wallet file
- receive screen
- send screen
- history
- lightserver connection

### Phase 2
- mint deposit flow
- mint redemption flow
- mint status/history

### Phase 3
- packaging
- backup/restore polish
- QR and UX cleanup
- error handling polish
