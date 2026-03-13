# selfcoin-mint

Minimal standalone Chaumian mint boundary service for local development and integration work.

This service is intentionally outside consensus. It consumes the JSON contracts described in:

- [docs/CHAUMIAN_MINT_BOUNDARY.md](/home/greendragon/Desktop/selfcoin-core/docs/CHAUMIAN_MINT_BOUNDARY.md)

It is a narrow scaffold, not a production mint:

- file-backed state
- deterministic placeholder blind-signing
- simple redemption batch tracking
- no real reserve management
- no federation
- no real Chaumian cryptography yet

## Endpoints

- `POST /deposits/register`
- `POST /issuance/blind`
- `POST /redemptions/create`
- `POST /redemptions/status`
- `GET /healthz`
- `GET /mint/key`

## Run

```bash
python3 services/selfcoin-mint/server.py \
  --host 127.0.0.1 \
  --port 8080 \
  --state-file /tmp/selfcoin-mint-state.json \
  --confirmations-required 1
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
  --blind blind-msg-1 \
  --blind blind-msg-2
```

```bash
./build/selfcoin-cli mint_redeem_create \
  --url http://127.0.0.1:8080/redemptions/create \
  --redeem-address sc1... \
  --note note-1 \
  --note note-2
```

## Notes

- Deposit references are deterministic hashes of `(txid, vout, mint_id)`.
- Blind issuance responses are deterministic placeholder signatures derived from a local seed.
- Redemption batches are created immediately with `state=pending`.
- You can edit the JSON state file or extend the server to simulate finalization.

## Service tests

```bash
python3 -m unittest services/selfcoin-mint/test_state.py
python3 -m unittest services/selfcoin-mint/test_integration.py
```
