#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/selfcoin-tests"

if [[ ! -x "${BIN}" ]]; then
  echo "missing binary: ${BIN}" >&2
  exit 1
fi

echo "running restart determinism regression (50 runs)"
for i in $(seq 1 50); do
  echo "[${i}/50]"
  SELFCOIN_TEST_FILTER=test_restart_determinism_and_continued_finalization \
  SELFCOIN_RESTART_DEBUG=1 \
    "${BIN}" >/tmp/selfcoin-restart-regression-${i}.log 2>&1
done
echo "restart determinism regression passed (50/50)"
