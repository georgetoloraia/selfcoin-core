# Chaumian Mint Boundary

This repo keeps privacy outside consensus. L1 only accepts tagged mint deposit outputs and ordinary redemption transactions.

## L1 role

- Accept `SCMINTDEP` outputs as standard settlement-layer outputs.
- Track those outputs in the normal UTXO set.
- Do not verify blind signatures, note issuance, note spends, or mint anonymity sets.
- Treat redemptions as ordinary spends from mint-controlled UTXOs back to normal addresses.

## `SCMINTDEP` script

Format:

```text
"SCMINTDEP" || mint_id[32] || recipient_pubkey_hash[20]
```

Semantics:

- `mint_id`: operator/federation identifier chosen by the mint layer.
- `recipient_pubkey_hash`: destination/refund identity the external mint uses to bind off-chain issuance.

Consensus impact:

- Only script recognition. No special spend rules.

## External mint service role

The Chaumian mint service must live outside this repo. It is responsible for:

- blinded note issuance
- note spend validation
- double-spend tracking
- reserve/accounting controls
- redemption tx construction/broadcast from mint reserve UTXOs
- redemption status reconciliation against finalized L1 state

## Suggested service API

Suggested example HTTP endpoints:

- `POST /deposits/register`
- `POST /issuance/blind`
- `POST /redemptions/create`
- `POST /redemptions/approve_broadcast`
- `POST /reserves/consolidate`
- `POST /redemptions/status`
- `POST /redemptions/update`
- `POST /policy/redemptions`
- `GET /accounting/summary`
- `GET /reserves`
- `GET /reserves/consolidate_plan`
- `GET /policy/redemptions`
- `GET /monitoring/reserve_health`
- `GET /operator/key`
- `GET /attestations/reserves`
- `GET /audit/export`

### 1. Deposit registration

Request:

```json
{
  "chain": "mainnet",
  "deposit_txid": "hex32",
  "deposit_vout": 0,
  "mint_id": "hex32",
  "recipient_pubkey_hash": "hex20",
  "amount": 100000
}
```

Response:

```json
{
  "accepted": true,
  "confirmations_required": 1,
  "mint_deposit_ref": "opaque-string"
}
```

### 2. Blind issuance

Request:

```json
{
  "mint_deposit_ref": "opaque-string",
  "blinded_messages": ["hex", "hex"],
  "note_amounts": [40000, 60000]
}
```

Response:

```json
{
  "issuance_id": "opaque-string",
  "signed_blinds": ["hex", "hex"],
  "note_refs": ["opaque-note-ref-1", "opaque-note-ref-2"],
  "note_amounts": [40000, 60000],
  "mint_epoch": 42
}
```

### 3. Redemption

Request:

```json
{
  "notes": ["opaque-note-1", "opaque-note-2"],
  "redeem_address": "sc1...",
  "amount": 100000
}
```

Response:

```json
{
  "accepted": true,
  "redemption_batch_id": "opaque-string"
}
```

### 4. Redemption status

Response:

```json
{
  "state": "pending|broadcast|finalized|rejected",
  "l1_txid": "hex32",
  "amount": 100000
}
```

### 5. Redemption state update

Request:

```json
{
  "redemption_batch_id": "opaque-string",
  "state": "rejected",
  "l1_txid": "hex32"
}
```

Authentication:

- Signed operator headers:
  - `X-Selfcoin-Operator-Key`
  - `X-Selfcoin-Timestamp`
  - `X-Selfcoin-Signature`

Notes:

- `broadcast` is not manually set through this endpoint
- `finalized` is not manually set; it is derived from observed lightserver state

### 5a. Automatic redemption settlement

If the external mint is configured with:
- a reserve wallet private key
- a reserve wallet address
- a lightserver RPC URL
- a path to `selfcoin-cli`

then signed operators can call `POST /redemptions/approve_broadcast` to:
1. discover reserve UTXOs via lightserver `get_utxos`
2. build an L1 `build_p2pkh_multi_tx`
3. broadcast that tx via lightserver `broadcast_tx`
4. transition the redemption to `broadcast`

Later `POST /redemptions/status` and the reserve/audit views reconcile `broadcast -> finalized` via observed L1 confirmation depth.

Signed operators may also call `POST /reserves/consolidate` to:
1. select a bounded set of small reserve UTXOs using the consolidation policy
2. build a self-transfer consolidation transaction back to the reserve address
3. broadcast it through lightserver
4. persist the consolidation record for later audit/finalization reporting

Signed operators may call `GET /reserves/consolidate_plan` to inspect the
selected reserve UTXOs, fee, output value, and estimated post-action fragmentation
without broadcasting.

Signed operators may call `POST /policy/redemptions` to pause or resume new
redemption creation. `GET /policy/redemptions` exposes the current policy plus
auto-pause recommendations and threshold metadata.

`GET /monitoring/reserve_health` returns a compact monitoring/export summary with:
- status: `healthy|warn|critical`
- reserve exhaustion / fragmentation / max-input alerts
- current auto-pause recommendation
- live reserve inventory counters

### 6. Reserve and accounting views

`GET /reserves` returns the mint's deposit-backed reserve summary.
When reserve wallet discovery is configured, it also returns live reserve-wallet inventory:
- `wallet_utxo_count`
- `wallet_utxo_value`
- `wallet_locked_utxo_count`
- `wallet_locked_utxo_value`
- `wallet_fragment_smallest`
- `wallet_fragment_largest`
- `wallet_fragment_below_min_change`
- `wallet_synced_at`

Broadcasted redemption inputs are removed from spendable reserve inventory. The in-flight commitment is reported explicitly through `pending_spend_commitment_count` and `pending_spend_input_count` during the `broadcast -> finalized` window.
When the lightserver no longer reports the selected reserve outpoints, the
service records that network-side spend observation and reports it via
`pending_spend_network_observed_count` and `pending_consolidation_network_observed_count`.

Recommended coin-selection policy for the external mint:
- smallest sufficient input set
- explicit max-input budget
- reject selections that would create change below `min_change`
- report the chosen policy and resulting `change_value` in audit exports
- expose reserve exhaustion / fragmentation alerts in reserve and audit views

`GET /accounting/summary` returns:
- deposit totals
- issuance totals
- pending/broadcast/finalized redemption totals
- available reserve estimate
- active note locks

`GET /attestations/reserves` returns:
- current reserve summary
- a timestamped signed reserve snapshot suitable for audit/audit-log export

`GET /operator/key` returns the operator attestation public key used to verify signed reserve and audit snapshots.

`GET /audit/export` returns a full export of deposits, issuances, redemptions, note records, and summary views.
This should be authenticated with signed operator requests outside development.

## Core repo scope

In `selfcoin-core`, the relevant user-facing primitive is:

```bash
selfcoin-cli mint_deposit_create \
  --prev-txid <hex32> \
  --prev-index <u32> \
  --prev-value <u64> \
  --from-privkey <hex32> \
  --mint-id <hex32> \
  --recipient-address <sc...> \
  --amount <u64> \
  [--fee <u64>] \
  [--change-address <sc...>]
```

This creates a normal signed L1 transaction with one `SCMINTDEP` output.

Related operator commands:

```bash
selfcoin-cli mint_redemptions_policy --url http://host:port/policy/redemptions
selfcoin-cli mint_redemptions_pause --url http://host:port/policy/redemptions --operator-key-id <id> --operator-secret-hex <hex> --reason "reserve low"
selfcoin-cli mint_redemptions_resume --url http://host:port/policy/redemptions --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_reserve_consolidation_plan --url http://host:port/reserves/consolidate_plan --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_reserve_health --url http://host:port/monitoring/reserve_health
```

To call the external mint boundary from this repo:

```bash
selfcoin-cli mint_deposit_register \
  --url http://127.0.0.1:8080/deposits/register \
  --deposit-txid <hex32> \
  --deposit-vout <u32> \
  --mint-id <hex32> \
  --recipient-address <sc...> \
  --amount <u64>
```

```bash
selfcoin-cli mint_redeem_status \
  --url http://127.0.0.1:8080/redemptions/status \
  --batch-id <opaque-id>
```

```bash
selfcoin-cli mint_redeem_approve_broadcast \
  --url http://127.0.0.1:8080/redemptions/approve_broadcast \
  --batch-id <opaque-id> \
  --operator-key-id <id> \
  --operator-secret-hex <hex>
```

```bash
curl http://127.0.0.1:8080/accounting/summary
curl http://127.0.0.1:8080/reserves
curl http://127.0.0.1:8080/operator/key
curl http://127.0.0.1:8080/attestations/reserves
selfcoin-cli mint_audit_export \
  --url http://127.0.0.1:8080/audit/export \
  --operator-key-id <id> \
  --operator-secret-hex <hex>
```

## Non-goals

- no blind-signature logic in consensus
- no on-chain private transfer verification
- no mint solvency proof in block validation
- no mint federation logic in the node
