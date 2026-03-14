#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-/opt/selfcoin-core}"
SYSTEMD_DIR="${2:-/etc/systemd/system}"
ETC_DIR="${3:-/etc/selfcoin-mint}"

install -d "$SYSTEMD_DIR" "$ETC_DIR" "$ETC_DIR/secrets.d" /var/lib/selfcoin-mint /run/selfcoin-mint
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint-server.service "$SYSTEMD_DIR/selfcoin-mint-server.service"
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint-worker.service "$SYSTEMD_DIR/selfcoin-mint-worker.service"
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint.env.example "$ETC_DIR/selfcoin-mint.env"
echo "Installed unit files into $SYSTEMD_DIR and env template into $ETC_DIR/selfcoin-mint.env"
