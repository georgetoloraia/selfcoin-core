#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PORT="${PORT:-18080}"
STATE_FILE="$(mktemp /tmp/selfcoin-mint-state.XXXXXX.json)"
LOCK_FILE="$(mktemp /tmp/selfcoin-mint-worker.XXXXXX.lock)"
SECRETS_DIR="$(mktemp -d /tmp/selfcoin-mint-secrets.XXXXXX)"
ENV_FILE="$(mktemp /tmp/selfcoin-mint-env.XXXXXX)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${WORKER_PID:-}" ]]; then kill "$WORKER_PID" >/dev/null 2>&1 || true; fi
  wait "${SERVER_PID:-}" "${WORKER_PID:-}" 2>/dev/null || true
  rm -f "$STATE_FILE" "$LOCK_FILE" "$ENV_FILE"
  rm -rf "$SECRETS_DIR"
}
trap cleanup EXIT

cat >"$ENV_FILE" <<EOF
SELFCOIN_MINT_HOST=127.0.0.1
SELFCOIN_MINT_PORT=$PORT
SELFCOIN_MINT_STATE_FILE=$STATE_FILE
SELFCOIN_MINT_MINT_ID=
SELFCOIN_MINT_SIGNING_SEED=selfcoin-mint-smoke-seed
SELFCOIN_MINT_OPERATOR_KEY=dev-operator:1111111111111111111111111111111111111111111111111111111111111111
SELFCOIN_MINT_LIGHTSERVER_URL=
SELFCOIN_MINT_RESERVE_PRIVKEY=
SELFCOIN_MINT_RESERVE_ADDRESS=
SELFCOIN_MINT_RESERVE_FEE=1000
SELFCOIN_MINT_CLI_PATH=$ROOT/build/selfcoin-cli
SELFCOIN_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS=1
SELFCOIN_MINT_SECRET_BACKEND=auto
SELFCOIN_MINT_NOTIFIER_SECRETS_FILE=
SELFCOIN_MINT_NOTIFIER_SECRET_DIR=$SECRETS_DIR
SELFCOIN_MINT_NOTIFIER_SECRET_ENV_PREFIX=SELFCOIN_MINT_SECRET_
SELFCOIN_MINT_NOTIFIER_SECRET_HELPER_CMD=$ROOT/services/selfcoin-mint/secret_helper.py --dir $SECRETS_DIR --env-prefix SELFCOIN_MINT_SECRET_
SELFCOIN_MINT_WORKER_LOCK_FILE=$LOCK_FILE
SELFCOIN_MINT_WORKER_STALE_TIMEOUT_SECONDS=5
EOF

set -a
source "$ENV_FILE"
set +a

python3 "$ROOT/services/selfcoin-mint/server.py" \
  --mode server \
  --host "$SELFCOIN_MINT_HOST" \
  --port "$SELFCOIN_MINT_PORT" \
  --state-file "$SELFCOIN_MINT_STATE_FILE" \
  --signing-seed "$SELFCOIN_MINT_SIGNING_SEED" \
  --operator-key "$SELFCOIN_MINT_OPERATOR_KEY" \
  --notifier-secret-backend "$SELFCOIN_MINT_SECRET_BACKEND" \
  --notifier-secret-dir "$SELFCOIN_MINT_NOTIFIER_SECRET_DIR" \
  --notifier-secret-helper-cmd "$SELFCOIN_MINT_NOTIFIER_SECRET_HELPER_CMD" \
  --worker-lock-file "$SELFCOIN_MINT_WORKER_LOCK_FILE" \
  --worker-stale-timeout-seconds "$SELFCOIN_MINT_WORKER_STALE_TIMEOUT_SECONDS" \
  --notifier-retry-interval-seconds "$SELFCOIN_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS" \
  >/tmp/selfcoin-mint-server-smoke.log 2>&1 &
SERVER_PID=$!

python3 "$ROOT/services/selfcoin-mint/server.py" \
  --mode worker \
  --state-file "$SELFCOIN_MINT_STATE_FILE" \
  --signing-seed "$SELFCOIN_MINT_SIGNING_SEED" \
  --operator-key "$SELFCOIN_MINT_OPERATOR_KEY" \
  --notifier-secret-backend "$SELFCOIN_MINT_SECRET_BACKEND" \
  --notifier-secret-dir "$SELFCOIN_MINT_NOTIFIER_SECRET_DIR" \
  --notifier-secret-helper-cmd "$SELFCOIN_MINT_NOTIFIER_SECRET_HELPER_CMD" \
  --worker-lock-file "$SELFCOIN_MINT_WORKER_LOCK_FILE" \
  --worker-stale-timeout-seconds "$SELFCOIN_MINT_WORKER_STALE_TIMEOUT_SECONDS" \
  --notifier-retry-interval-seconds "$SELFCOIN_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS" \
  >/tmp/selfcoin-mint-worker-smoke.log 2>&1 &
WORKER_PID=$!

python3 - <<PY
import json, time, urllib.request
url = "http://127.0.0.1:${PORT}/healthz"
for _ in range(50):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            if data.get("ok"):
                break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("server did not become healthy")
with urllib.request.urlopen("http://127.0.0.1:${PORT}/monitoring/worker", timeout=2) as resp:
    worker = json.loads(resp.read().decode())
if worker.get("takeover_policy") != "allow-after-stale-timeout":
    raise SystemExit("unexpected worker status")
PY

echo "selfcoin-mint smoke deployment passed"
