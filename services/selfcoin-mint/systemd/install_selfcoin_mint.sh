#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-/opt/selfcoin-core}"
SYSTEMD_DIR="${2:-/etc/systemd/system}"
ETC_DIR="${3:-/etc/selfcoin-mint}"
LIBEXEC_DIR="${4:-/usr/local/libexec}"

install -d "$SYSTEMD_DIR" "$ETC_DIR" "$ETC_DIR/secrets.d" "$LIBEXEC_DIR" /var/lib/selfcoin-mint /run/selfcoin-mint
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint-server.service "$SYSTEMD_DIR/selfcoin-mint-server.service"
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint-worker.service "$SYSTEMD_DIR/selfcoin-mint-worker.service"
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint.env.example "$ETC_DIR/selfcoin-mint.env"
install -m 0644 services/selfcoin-mint/systemd/selfcoin-mint.tmpfiles.conf "$ETC_DIR/selfcoin-mint.tmpfiles.conf"
install -m 0755 services/selfcoin-mint/secret_helper.py "$LIBEXEC_DIR/selfcoin-mint-secret-helper"
echo "Installed unit files into $SYSTEMD_DIR, helper into $LIBEXEC_DIR/selfcoin-mint-secret-helper, and env template into $ETC_DIR/selfcoin-mint.env"
