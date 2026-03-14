# selfcoin-mint Operator Runbook

## First boot

1. Build the binaries:
```bash
cmake --build build --target selfcoin-cli -j1
```

2. Install the split service assets:
```bash
sudo bash services/selfcoin-mint/systemd/install_selfcoin_mint.sh
```

3. Edit `/etc/selfcoin-mint/selfcoin-mint.env`:
- set `SELFCOIN_MINT_OPERATOR_KEY`
- set `SELFCOIN_MINT_LIGHTSERVER_URL`
- set `SELFCOIN_MINT_RESERVE_PRIVKEY`
- set `SELFCOIN_MINT_RESERVE_ADDRESS`
- choose `SELFCOIN_MINT_SECRET_BACKEND`

4. Create secrets if using file-backed refs:
```bash
sudo install -d -m 0750 /etc/selfcoin-mint/secrets.d
echo -n 'secret-token' | sudo tee /etc/selfcoin-mint/secrets.d/ops_webhook_bearer >/dev/null
sudo chmod 0640 /etc/selfcoin-mint/secrets.d/ops_webhook_bearer
```

5. Reload and enable the units:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now selfcoin-mint-server
sudo systemctl enable --now selfcoin-mint-worker
```

## Secret helper usage

If you want the `command` backend, point:
```bash
SELFCOIN_MINT_SECRET_BACKEND=command
SELFCOIN_MINT_NOTIFIER_SECRET_HELPER_CMD=/usr/local/libexec/selfcoin-mint-secret-helper --dir /etc/selfcoin-mint/secrets.d --env-prefix SELFCOIN_MINT_SECRET_
```

This helper resolves a secret ref by:
- checking `/etc/selfcoin-mint/secrets.d/<ref>`
- then checking `SELFCOIN_MINT_SECRET_<REF>`

## Worker failover

The worker lease is stored in the configured lock file.

Monitor:
```bash
./build/selfcoin-cli mint_worker_status --url http://127.0.0.1:8080/monitoring/worker
```

Important fields:
- `owned`
- `owner_pid`
- `heartbeat_at`
- `stale`
- `takeover_policy`

If the worker dies and the lease becomes stale:
- a replacement worker can take over after `SELFCOIN_MINT_WORKER_STALE_TIMEOUT_SECONDS`
- the service records `worker.lease_takeover` in the event log

Check alerts:
```bash
./build/selfcoin-cli mint_alert_history --url http://127.0.0.1:8080/monitoring/alerts/history
```

## Basic recovery

If the worker is not advancing queue deliveries:

1. Check lock status:
```bash
./build/selfcoin-cli mint_worker_status --url http://127.0.0.1:8080/monitoring/worker
```

2. Check worker logs:
```bash
sudo journalctl -u selfcoin-mint-worker -n 200 --no-pager
```

3. Restart only the worker first:
```bash
sudo systemctl restart selfcoin-mint-worker
```

4. If configuration changed, restart both:
```bash
sudo systemctl restart selfcoin-mint-server selfcoin-mint-worker
```
