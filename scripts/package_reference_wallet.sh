#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
STAGE_DIR="${STAGE_DIR:-/tmp/selfcoin-wallet-stage}"

cmake -S "$ROOT" -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target selfcoin-wallet -j1
cmake --install "$BUILD_DIR" --prefix "$STAGE_DIR"

(
  cd "$BUILD_DIR"
  cpack -G TGZ
  cpack -G ZIP
)

echo "staged wallet install: $STAGE_DIR"
