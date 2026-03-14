# selfcoin-mint

Minimal standalone Chaumian mint boundary service for local development and integration work.

This service is intentionally outside consensus. It consumes the JSON contracts described in:

- [docs/CHAUMIAN_MINT_BOUNDARY.md](/home/greendragon/Desktop/selfcoin-core/docs/CHAUMIAN_MINT_BOUNDARY.md)

It is a narrow scaffold, not a production mint:

- file-backed state
- deterministic RSA blind-signing for development/testing
- persistent issuance ledger
- reserve and accounting summary endpoints
- reserve wallet inventory / fragmentation reporting
- max-input coin selection policy and reserve alerts
- automatic redemption settlement using a configured reserve wallet
- lightserver-backed redemption finalization (`pending -> broadcast -> finalized/rejected`)
- HMAC-signed operator admin requests
- signed reserve attestations / audit exports
- no federation
- no multi-operator quorum custody

## Endpoints

- `POST /deposits/register`
- `POST /issuance/blind`
- `POST /redemptions/create`
- `POST /redemptions/approve_broadcast`
- `POST /reserves/consolidate`
- `POST /redemptions/status`
- `POST /redemptions/update`
- `POST /policy/redemptions`
- `GET /healthz`
- `GET /mint/key`
- `GET /reserves`
- `GET /reserves/consolidate_plan`
- `GET /policy/redemptions`
- `GET /monitoring/reserve_health`
- `GET /monitoring/alerts/history`
- `GET /monitoring/metrics`
- `GET /accounting/summary`
- `GET /operator/key`
- `GET /attestations/reserves`
- `GET /audit/export` (operator-signed request required)

## Run

```bash
python3 services/selfcoin-mint/server.py \
  --host 127.0.0.1 \
  --port 8080 \
  --state-file /tmp/selfcoin-mint-state.json \
  --confirmations-required 1 \
  --operator-key dev-operator:1111111111111111111111111111111111111111111111111111111111111111 \
  --lightserver-url http://127.0.0.1:19444/rpc \
  --reserve-privkey 5555555555555555555555555555555555555555555555555555555555555555 \
  --reserve-address sc1... \
  --reserve-fee 1000 \
  --cli-path ./build/selfcoin-cli
```

## Example with selfcoin-cli

```bash
./build/selfcoin-cli mint_deposit_register \
  --url http://127.0.0.1:8080/deposits/register \
  --deposit-txid 1111111111111111111111111111111111111111111111111111111111111111 \
  --deposit-vout 0 \
  --mint-id 2222222222222222222222222222222222222222222222222222222222222222 \
  --recipient-address sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy \
  --amount 100000
```

```bash
./build/selfcoin-cli mint_redeem_status \
  --url http://127.0.0.1:8080/redemptions/status \
  --batch-id <opaque-id>
```

```bash
./build/selfcoin-cli mint_issue_blinds \
  --url http://127.0.0.1:8080/issuance/blind \
  --mint-deposit-ref <opaque-id> \
  --blind blind-msg-1 --note-amount 40000 \
  --blind blind-msg-2 --note-amount 60000
```

```bash
./build/selfcoin-cli mint_redeem_create \
  --url http://127.0.0.1:8080/redemptions/create \
  --redeem-address sc1... \
  --amount 100000 \
  --note <note-ref-1> \
  --note <note-ref-2>
```

```bash
./build/selfcoin-cli mint_redeem_approve_broadcast \
  --url http://127.0.0.1:8080/redemptions/approve_broadcast \
  --batch-id <opaque-id> \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/selfcoin-cli mint_reserve_consolidate \
  --url http://127.0.0.1:8080/reserves/consolidate \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/selfcoin-cli mint_reserve_consolidation_plan \
  --url http://127.0.0.1:8080/reserves/consolidate_plan \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/selfcoin-cli mint_reserve_health \
  --url http://127.0.0.1:8080/monitoring/reserve_health
```

```bash
./build/selfcoin-cli mint_reserve_metrics \
  --url http://127.0.0.1:8080/monitoring/metrics

./build/selfcoin-cli mint_alert_history \
  --url http://127.0.0.1:8080/monitoring/alerts/history
```

```bash
./build/selfcoin-cli mint_redemptions_pause \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --reason "reserve low"

./build/selfcoin-cli mint_redemptions_resume \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111

./build/selfcoin-cli mint_redemptions_auto_pause_enable \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111

./build/selfcoin-cli mint_redemptions_auto_pause_disable \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
curl http://127.0.0.1:8080/accounting/summary
curl http://127.0.0.1:8080/reserves
curl http://127.0.0.1:8080/operator/key
curl http://127.0.0.1:8080/attestations/reserves
./build/selfcoin-cli mint_audit_export \
  --url http://127.0.0.1:8080/audit/export \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

## Notes

- Deposit references are deterministic hashes of `(txid, vout, mint_id)`.
- Blind issuance responses are deterministic RSA blind signatures derived from a local seed.
- Each issuance creates persistent `note_ref` entries with explicit denominations.
- If a reserve wallet and lightserver are configured, signed operators can approve pending redemptions for automatic L1 tx construction and broadcast.
- Broadcasted reserve inputs are excluded from spendable reserve inventory. Pending in-flight reserve usage is tracked separately via `pending_spend_commitment_count` and `pending_spend_input_count`.
- Coin selection uses `smallest-sufficient-non-dust-change` with `min_change=1000` and `max_inputs=8`; if no non-dust change set can be formed within the max-input budget, the redemption stays `pending`.
- Redemption batches that cannot yet be funded stay `pending`; operators may reject them, but `broadcast` must go through `/redemptions/approve_broadcast`.
- `finalized` is derived from observed L1 tx status via the configured lightserver.
- `/reserves` includes live reserve-wallet UTXO count/value, locked UTXO count/value, simple fragmentation metrics, operator-facing alert fields such as reserve exhaustion risk, max-input pressure, and fragmentation threshold breach, and the active coin-selection thresholds when lightserver + reserve address are configured.
- `/policy/redemptions` now includes auto-pause recommendations and threshold metadata derived from the current reserve state.
- `/reserves/consolidate_plan` includes an `estimated_post_action` section so operators can see expected post-consolidation fragmentation before broadcasting.
- `/monitoring/reserve_health` provides a compact monitoring/export summary with `healthy|warn|critical` status, current alert booleans, and the current auto-pause recommendation.
- `/monitoring/alerts/history` provides the recent persisted operator/auto-pause event log.
- `/monitoring/metrics` exports Prometheus-style reserve, pause, and alert counters.
- Signed operators can explicitly trigger reserve consolidation; the service persists consolidation records and includes them in audit export.
- Signed operators can pause new redemptions and inspect a dry-run consolidation plan before broadcasting reserve actions.
- `POST /redemptions/update` and `GET /audit/export` require signed operator headers:
  - `X-Selfcoin-Operator-Key`
  - `X-Selfcoin-Timestamp`
  - `X-Selfcoin-Signature`
- Reserve/accounting/attestation endpoints are derived from persisted deposits, issuances, note records, and redemption state.

## Service tests

```bash
python3 -m unittest services/selfcoin-mint/test_state.py
python3 -m unittest services/selfcoin-mint/test_integration.py
```
