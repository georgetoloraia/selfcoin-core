# selfcoin-mint

Minimal standalone Chaumian mint boundary service for local development and integration work.

This service is intentionally outside consensus. It consumes the JSON contracts described in:

- [docs/CHAUMIAN_MINT_BOUNDARY.md](/home/greendragon/Desktop/selfcoin-core/docs/CHAUMIAN_MINT_BOUNDARY.md)

It is a narrow scaffold, not a production mint:

- file-backed state
- deterministic RSA blind-signing for development/testing
- persistent issuance ledger
- reserve and accounting summary endpoints
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
- `POST /redemptions/status`
- `POST /redemptions/update`
- `GET /healthz`
- `GET /mint/key`
- `GET /reserves`
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
- If a reserve wallet and lightserver are configured, redemption batches are automatically built and broadcast as L1 transactions.
- Redemption batches that cannot yet be funded stay `pending`; operators may still reject them or manually mark them `broadcast`.
- `finalized` is derived from observed L1 tx status via the configured lightserver.
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
