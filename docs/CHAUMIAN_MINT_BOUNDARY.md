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
- `GET /monitoring/alerts/history`
- `GET /monitoring/events/policy`
- `GET /monitoring/events/silences`
- `GET /monitoring/notifiers`
- `GET /monitoring/dead_letters`
- `GET /monitoring/incidents/export`
- `GET /monitoring/metrics`
- `GET /monitoring/worker`
- `GET /dashboard`
- `GET /dashboard/incidents`
- `POST /monitoring/dead_letters/replay`
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

`GET /monitoring/alerts/history` returns the recent persisted alert/policy event log.

Signed operators may call:
- `POST /monitoring/events/ack` to acknowledge an event
- `POST /monitoring/events/silence` to silence an event type until a timestamp
- `POST /monitoring/events/policy` to update retention/export policy
- `POST /monitoring/notifiers` to upsert notifier hooks

The service also exposes:
- `GET /monitoring/events/policy`
- `GET /monitoring/events/silences`
- `GET /monitoring/notifiers`
- `GET /monitoring/dead_letters`
- `GET /monitoring/incidents/export`
- `POST /monitoring/dead_letters/replay`

`GET /monitoring/metrics` returns Prometheus-style counters/gauges for:
- available reserve
- reserve balance
- wallet UTXO counts
- pending spends / consolidations
- alert booleans
- redemptions paused / auto-pause enabled
- current health status
- event log size
- dead-letter count
- pending notifier delivery count
- worker leader owned

Supported notifier hooks:
- `webhook`: POST `{ "event": ... }` JSON to a target URL
- `alertmanager`: POST alert-style JSON to a target URL
- `email_spool`: write `.eml` files into a configured spool directory

Notifier configuration includes:
- `retry_max_attempts`
- `retry_backoff_seconds`
- `auth_type=none|bearer|basic`
- `auth_token_secret_ref`
- `auth_user_secret_ref`
- `auth_pass_secret_ref`
- `tls_verify`
- `tls_ca_file`
- `tls_client_cert_file`
- `tls_client_key_file`

When a notifier fails:
- the event stores per-notifier delivery status, attempt count, error text, and next retry time
- a persisted delivery job queue tracks pending/running/done/dead-letter work
- a background retry worker drains that queue on a fixed interval
- once the retry budget is exhausted, the delivery is moved into `dead_letters`

Operationally:
- the worker may use a leader/lock file so only one process drains notifier jobs
- the lock is a renewable lease with stale-timeout takeover policy
- notifier secrets should come from OS-managed files or environment policy first, not the persisted mint state
- a secret backend adapter can also resolve refs from a helper command for external secret managers
- TLS contexts are rebuilt per delivery so CA/client certificate file rotation is picked up without restart

Recommended process split:
- `server` mode: HTTP API only
- `worker` mode: delivery queue worker only
- `all` mode: combined development convenience

Deployment helpers:
- systemd-ready split units live under [services/selfcoin-mint/systemd](/home/greendragon/Desktop/selfcoin-core/services/selfcoin-mint/systemd)

Dead-letter entries may be replayed explicitly through `POST /monitoring/dead_letters/replay`.

`GET /monitoring/incidents/export` returns a signed incident timeline suitable for audit/ops review.
`GET /dashboard` and `GET /dashboard/incidents` provide a minimal operator HTML view over the same exported state.

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
selfcoin-cli mint_redemptions_auto_pause_enable --url http://host:port/policy/redemptions --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_redemptions_auto_pause_disable --url http://host:port/policy/redemptions --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_alert_ack --url http://host:port/monitoring/events/ack --event-id <id> --operator-key-id <id> --operator-secret-hex <hex> [--note <text>]
selfcoin-cli mint_alert_silence --url http://host:port/monitoring/events/silence --event-type <type> --until <unix> --operator-key-id <id> --operator-secret-hex <hex> [--reason <text>]
selfcoin-cli mint_alert_silences --url http://host:port/monitoring/events/silences
selfcoin-cli mint_event_policy --url http://host:port/monitoring/events/policy
selfcoin-cli mint_event_policy_update --url http://host:port/monitoring/events/policy --operator-key-id <id> --operator-secret-hex <hex> [--retention-limit <n>] [--export-include-acknowledged true|false]
selfcoin-cli mint_notifier_list --url http://host:port/monitoring/notifiers
selfcoin-cli mint_notifier_upsert --url http://host:port/monitoring/notifiers --operator-key-id <id> --operator-secret-hex <hex> --notifier-id <id> --kind webhook|alertmanager|email_spool --target <value> [--retry-max-attempts <n>] [--retry-backoff-seconds <n>]
selfcoin-cli mint_dead_letters --url http://host:port/monitoring/dead_letters
selfcoin-cli mint_dead_letter_replay --url http://host:port/monitoring/dead_letters/replay --dead-letter-id <id> --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_incident_timeline_export --url http://host:port/monitoring/incidents/export
selfcoin-cli mint_reserve_consolidation_plan --url http://host:port/reserves/consolidate_plan --operator-key-id <id> --operator-secret-hex <hex>
selfcoin-cli mint_reserve_health --url http://host:port/monitoring/reserve_health
selfcoin-cli mint_reserve_metrics --url http://host:port/monitoring/metrics
selfcoin-cli mint_alert_history --url http://host:port/monitoring/alerts/history
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
