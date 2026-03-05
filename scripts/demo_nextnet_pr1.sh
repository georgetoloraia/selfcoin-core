#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/selfcoin-node"
BASE="${1:-/tmp/selfcoin-nextnet-pr1}"

if [[ ! -x "${BIN}" ]]; then
  echo "missing binary: ${BIN}"
  echo "build first: cmake -S . -B build -G Ninja && cmake --build build -j"
  exit 1
fi

rm -rf "${BASE}"
mkdir -p "${BASE}"

BASE_PORT=$((42000 + (RANDOM % 1000)))
P0=$((BASE_PORT + 0))
P1=$((BASE_PORT + 1))
P2=$((BASE_PORT + 2))
P3=$((BASE_PORT + 3))
PEERS="127.0.0.1:${P0},127.0.0.1:${P1},127.0.0.1:${P2},127.0.0.1:${P3}"

cleanup() {
  pkill -P $$ || true
}
trap cleanup EXIT

echo "[demo] starting 4 nextnet nodes under ${BASE}"
for i in 0 1 2 3; do
  port_var="P${i}"
  port="${!port_var}"
  "${BIN}" \
    --nextnet \
    --node-id "${i}" \
    --db "${BASE}/node${i}" \
    --listen \
    --bind 127.0.0.1 \
    --port "${port}" \
    --peers "${PEERS}" \
    --no-dns-seeds \
    > "${BASE}/node${i}.log" 2>&1 &
done

echo "[demo] waiting for progress..."
sleep 15

for i in 0 1 2 3; do
  echo "----- node${i} tail -----"
  tail -n 10 "${BASE}/node${i}.log" || true
done

echo "[demo] done. logs at ${BASE}/node*.log"
