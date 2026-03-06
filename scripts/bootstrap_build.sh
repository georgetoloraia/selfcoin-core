#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
GENERATOR="${GENERATOR:-}"
BUILD_JOBS="${BUILD_JOBS:-}"
RUN_TESTS="${RUN_TESTS:-0}"
CLEAN_ON_GENERATOR_MISMATCH="${CLEAN_ON_GENERATOR_MISMATCH:-1}"
SETUP_NODE_SERVICE="${SETUP_NODE_SERVICE:-1}"
OPEN_FIREWALL_PORTS="${OPEN_FIREWALL_PORTS:-1}"
RESET_CHAIN_DATA="${RESET_CHAIN_DATA:-0}"
SERVICE_NAME="${SERVICE_NAME:-selfcoin}"
DB_DIR="${DB_DIR:-$HOME/.selfcoin/mainnet}"
P2P_PORT="${P2P_PORT:-19440}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19444}"
OUTBOUND_TARGET="${OUTBOUND_TARGET:-2}"
NODE_PUBLIC="${NODE_PUBLIC:-1}"
NODE_EXTRA_ARGS="${NODE_EXTRA_ARGS:-}"
USE_SEEDS_JSON="${USE_SEEDS_JSON:-0}"

log() { printf '[bootstrap] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_build_jobs() {
  if [[ -n "${BUILD_JOBS}" ]]; then
    echo "${BUILD_JOBS}"
    return
  fi

  # Conservative default for small-memory hosts.
  if [[ -r /proc/meminfo ]]; then
    local mem_kb
    mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
    if [[ -n "${mem_kb}" ]]; then
      # <= 2 GiB -> single job to avoid cc1plus OOM kills.
      if (( mem_kb <= 2097152 )); then
        echo "1"
        return
      fi
    fi
  fi

  if have nproc; then
    nproc
    return
  fi
  if have sysctl; then
    sysctl -n hw.ncpu 2>/dev/null || echo "1"
    return
  fi
  echo "1"
}

clear_build_dir() {
  local dir="$1"
  rm -rf "${dir}/CMakeCache.txt" "${dir}/CMakeFiles"
}

configure_cmake() {
  local args=("$@")
  local output
  if output="$(cmake "${args[@]}" 2>&1)"; then
    printf '%s\n' "${output}"
    return 0
  fi
  printf '%s\n' "${output}" >&2

  if [[ "${CLEAN_ON_GENERATOR_MISMATCH}" == "1" ]] && grep -q "Does not match the generator used previously" <<<"${output}"; then
    log "Detected CMake generator mismatch in ${BUILD_DIR}. Cleaning cache and retrying..."
    clear_build_dir "${BUILD_DIR}"
    cmake "${args[@]}"
    return $?
  fi
  return 1
}

need_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    if have sudo; then
      echo "sudo"
    else
      log "Need root privileges but 'sudo' is not installed."
      exit 1
    fi
  else
    echo ""
  fi
}

install_apt() {
  local s; s="$(need_sudo)"
  ${s} apt-get update
  ${s} apt-get install -y \
    build-essential cmake pkg-config ninja-build \
    libssl-dev libsodium-dev librocksdb-dev python3
}

install_dnf() {
  local s; s="$(need_sudo)"
  ${s} dnf install -y \
    gcc-c++ make cmake pkgconf-pkg-config ninja-build \
    openssl-devel libsodium-devel rocksdb-devel python3
}

install_pacman() {
  local s; s="$(need_sudo)"
  ${s} pacman -Sy --noconfirm \
    base-devel cmake pkgconf ninja \
    openssl libsodium rocksdb python
}

install_brew() {
  if ! have brew; then
    log "Homebrew not found. Install Homebrew first: https://brew.sh"
    exit 1
  fi
  brew install cmake pkg-config ninja openssl libsodium rocksdb
}

install_deps() {
  local os
  os="$(uname -s)"
  case "$os" in
    Linux)
      if have apt-get; then
        install_apt
      elif have dnf; then
        install_dnf
      elif have pacman; then
        install_pacman
      else
        log "Unsupported Linux package manager. Install manually:"
        log "  C++20 compiler, cmake>=3.20, pkg-config, OpenSSL dev, libsodium dev, RocksDB dev (optional)"
        exit 1
      fi
      ;;
    Darwin)
      install_brew
      ;;
    *)
      log "Unsupported OS: $os"
      exit 1
      ;;
  esac
}

configure_and_build() {
  cd "${ROOT_DIR}"
  local args=(-S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}")
  local jobs
  jobs="$(detect_build_jobs)"
  if [[ -n "${GENERATOR}" ]]; then
    args+=(-G "${GENERATOR}")
  elif have ninja; then
    args+=(-G Ninja)
  fi
  configure_cmake "${args[@]}"

  if ! cmake --build "${BUILD_DIR}" -j"${jobs}"; then
    log "Build failed."
    log "Hint: if this is an OOM failure (cc1plus killed), retry with BUILD_JOBS=1"
    exit 1
  fi

  if [[ "${RUN_TESTS}" == "1" ]]; then
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
  fi
}

systemd_available() {
  have systemctl && [[ -d /run/systemd/system ]]
}

read_seed_list() {
  local seeds_file="${ROOT_DIR}/mainnet/SEEDS.json"
  if [[ ! -f "${seeds_file}" ]]; then
    return 0
  fi
  python3 - "${seeds_file}" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, "r", encoding="utf-8"))
    seeds = data.get("seeds_p2p", [])
    for s in seeds:
        if isinstance(s, str) and s.strip():
            print(s.strip())
except Exception:
    pass
PY
}

build_execstart_args() {
  local node_bin="${ROOT_DIR}/${BUILD_DIR}/selfcoin-node"
  local key_file="${DB_DIR}/keystore/validator.json"
  local -a args
  args=("${node_bin}" "--db" "${DB_DIR}" "--outbound-target" "${OUTBOUND_TARGET}")
  if [[ "${NODE_PUBLIC}" == "1" ]]; then
    args+=("--public")
  fi

  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
    if (( ${#seeds[@]} > 0 )); then
      args+=("--no-dns-seeds")
      for s in "${seeds[@]}"; do
        args+=("--seeds" "${s}")
      done
    fi
  fi

  args+=("--validator-key-file" "${key_file}")

  if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${NODE_EXTRA_ARGS} )
    args+=("${extra[@]}")
  fi

  printf '%q ' "${args[@]}"
}

reset_chain_data_if_requested() {
  if [[ "${RESET_CHAIN_DATA}" != "1" ]]; then
    return 0
  fi

  log "RESET_CHAIN_DATA=1: resetting ${DB_DIR} (keeping validator key if present)."
  local key="${DB_DIR}/keystore/validator.json"
  local tmp_key="/tmp/selfcoin.validator.$$.json"
  if [[ -f "${key}" ]]; then
    cp -f "${key}" "${tmp_key}"
  fi
  rm -rf "${DB_DIR}"
  mkdir -p "${DB_DIR}/keystore"
  if [[ -f "${tmp_key}" ]]; then
    mv -f "${tmp_key}" "${key}"
    chmod 600 "${key}" || true
  fi
  chmod 700 "${DB_DIR}/keystore" || true
}

open_firewall_ports() {
  if [[ "${OPEN_FIREWALL_PORTS}" != "1" ]]; then
    log "Skipping firewall changes (OPEN_FIREWALL_PORTS=0)."
    return 0
  fi
  local s; s="$(need_sudo)"

  if have ufw; then
    log "Opening firewall ports with ufw: ${P2P_PORT}/tcp and ${LIGHTSERVER_PORT}/tcp."
    ${s} ufw allow "${P2P_PORT}/tcp" >/dev/null || true
    ${s} ufw allow "${LIGHTSERVER_PORT}/tcp" >/dev/null || true
    return 0
  fi

  if have firewall-cmd; then
    log "Opening firewall ports with firewalld: ${P2P_PORT}/tcp and ${LIGHTSERVER_PORT}/tcp."
    ${s} firewall-cmd --permanent --add-port="${P2P_PORT}/tcp" >/dev/null || true
    ${s} firewall-cmd --permanent --add-port="${LIGHTSERVER_PORT}/tcp" >/dev/null || true
    ${s} firewall-cmd --reload >/dev/null || true
    return 0
  fi

  log "No managed firewall command found (ufw/firewalld). Skipping firewall changes."
}

install_and_restart_service() {
  if [[ "${SETUP_NODE_SERVICE}" != "1" ]]; then
    log "Skipping systemd service setup (SETUP_NODE_SERVICE=0)."
    return 0
  fi
  if ! systemd_available; then
    log "systemd not detected; skipping service setup."
    return 0
  fi

  local s; s="$(need_sudo)"
  local service_path="/etc/systemd/system/${SERVICE_NAME}.service"
  local exec_line
  exec_line="$(build_execstart_args)"
  local tmp_unit="/tmp/${SERVICE_NAME}.service.$$"

  cat > "${tmp_unit}" <<EOF
[Unit]
Description=SelfCoin Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${ROOT_DIR}
ExecStart=${exec_line}
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  ${s} install -m 0644 "${tmp_unit}" "${service_path}"
  rm -f "${tmp_unit}"

  ${s} systemctl daemon-reload
  ${s} systemctl enable "${SERVICE_NAME}" >/dev/null || true
  ${s} systemctl restart "${SERVICE_NAME}"
  log "Service ${SERVICE_NAME} installed/restarted: ${service_path}"
}

post_build_setup() {
  reset_chain_data_if_requested
  open_firewall_ports
  install_and_restart_service

  log "Post-build setup summary:"
  log "  DB_DIR=${DB_DIR}"
  log "  P2P_PORT=${P2P_PORT} LIGHTSERVER_PORT=${LIGHTSERVER_PORT}"
  if systemd_available && [[ "${SETUP_NODE_SERVICE}" == "1" ]]; then
    local s; s="$(need_sudo)"
    ${s} systemctl status "${SERVICE_NAME}" --no-pager || true
  fi
}

log "Installing build dependencies (if missing)..."
install_deps
log "Configuring and building SelfCoin Core..."
configure_and_build
log "Applying post-build node bootstrap setup..."
post_build_setup
log "Done. Binaries are in ${BUILD_DIR}/"
