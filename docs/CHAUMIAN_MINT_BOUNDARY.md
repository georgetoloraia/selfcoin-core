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
- redemption batching back to L1

## Suggested service API

Suggested example HTTP endpoints:

- `POST /deposits/register`
- `POST /issuance/blind`
- `POST /redemptions/create`
- `POST /redemptions/status`

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
  "blinded_messages": ["hex", "hex"]
}
```

Response:

```json
{
  "signed_blinds": ["hex", "hex"],
  "mint_epoch": 42
}
```

### 3. Redemption

Request:

```json
{
  "notes": ["opaque-note-1", "opaque-note-2"],
  "redeem_address": "sc1..."
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
  "l1_txid": "hex32"
}
```

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

## Non-goals

- no blind-signature logic in consensus
- no on-chain private transfer verification
- no mint solvency proof in block validation
- no mint federation logic in the node
