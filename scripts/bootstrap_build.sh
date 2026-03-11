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
FOLLOWER_P2P_PORT="${FOLLOWER_P2P_PORT:-19440}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19444}"
OUTBOUND_TARGET="${OUTBOUND_TARGET:-2}"
NODE_PUBLIC="${NODE_PUBLIC:-1}"
NODE_EXTRA_ARGS="${NODE_EXTRA_ARGS:-}"
USE_SEEDS_JSON="${USE_SEEDS_JSON:-1}"
GENESIS_BIN="${GENESIS_BIN:-}"
GENESIS_PATH="${GENESIS_PATH:-${GENESIS_BIN}}"
ALLOW_UNSAFE_GENESIS_OVERRIDE="${ALLOW_UNSAFE_GENESIS_OVERRIDE:-0}"
NODE_ROLE="${NODE_ROLE:-bootstrap}"
BOOTSTRAP_IP="${BOOTSTRAP_IP:-}"
BOOTSTRAP_HOST="${BOOTSTRAP_HOST:-}"
FOLLOWER_DB_DIR="${FOLLOWER_DB_DIR:-$HOME/.selfcoin/mainnet-follower}"
CONFIG_OUTPUT_DIR="${CONFIG_OUTPUT_DIR:-${ROOT_DIR}/deploy/generated}"
BOOTSTRAP_LAUNCHER="${CONFIG_OUTPUT_DIR}/bootstrap-node.sh"
FOLLOWER_LAUNCHER="${CONFIG_OUTPUT_DIR}/follower-node.sh"
BOOTSTRAP_UNIT_TEMPLATE="${CONFIG_OUTPUT_DIR}/systemd/selfcoin-bootstrap.service"
FOLLOWER_UNIT_TEMPLATE="${CONFIG_OUTPUT_DIR}/systemd/selfcoin-follower.service"

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

resolve_genesis_source() {
  local default_genesis_bin="${ROOT_DIR}/mainnet/genesis.bin"
  local default_genesis_json="${ROOT_DIR}/mainnet/genesis.json"
  if [[ -n "${GENESIS_PATH}" ]]; then
    echo "${GENESIS_PATH}"
  elif [[ -f "${default_genesis_bin}" ]]; then
    echo "${default_genesis_bin}"
  elif [[ -f "${default_genesis_json}" ]]; then
    echo "${default_genesis_json}"
  else
    log "No genesis artifact found. Set GENESIS_PATH or provide mainnet/genesis.bin."
    exit 1
  fi
}

sha256_file() {
  local path="$1"
  if have sha256sum; then
    sha256sum "${path}" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "${path}" | awk '{print $1}'
  elif have openssl; then
    openssl dgst -sha256 "${path}" | awk '{print $NF}'
  else
    echo "sha256-unavailable"
  fi
}

join_csv() {
  local IFS=,
  printf '%s' "$*"
}

seed_csv() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  if (( ${#seeds[@]} > 0 )); then
    join_csv "${seeds[@]}"
  fi
}

detect_local_ip() {
  if have hostname; then
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -n "${ip}" ]]; then
      echo "${ip}"
      return
    fi
  fi
  if have ip; then
    local ip_route
    ip_route="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
    if [[ -n "${ip_route}" ]]; then
      echo "${ip_route}"
      return
    fi
  fi
}

bootstrap_host_value() {
  if [[ -n "${BOOTSTRAP_IP}" ]]; then
    echo "${BOOTSTRAP_IP}"
  elif [[ -n "${BOOTSTRAP_HOST}" ]]; then
    echo "${BOOTSTRAP_HOST}"
  elif [[ "${NODE_ROLE}" == "bootstrap" ]]; then
    detect_local_ip || true
  fi
}

bootstrap_peer_endpoint() {
  local host
  if [[ -n "${BOOTSTRAP_IP}" ]]; then
    host="${BOOTSTRAP_IP}"
  elif [[ -n "${BOOTSTRAP_HOST}" ]]; then
    host="${BOOTSTRAP_HOST}"
  elif [[ "${NODE_ROLE}" == "bootstrap" ]]; then
    host="$(detect_local_ip || true)"
  else
    host=""
  fi
  if [[ -z "${host}" ]]; then
    host="REPLACE_WITH_BOOTSTRAP_IP"
  fi
  echo "${host}:${P2P_PORT}"
}

require_follower_bootstrap_peer() {
  if [[ "${NODE_ROLE}" != "follower" ]]; then
    return 0
  fi
  local peer
  peer="$(bootstrap_peer_endpoint)"
  if [[ "${peer}" == REPLACE_WITH_BOOTSTRAP_IP:* ]]; then
    log "Follower role requires an explicit bootstrap address."
    log "Set BOOTSTRAP_IP=<public-bootstrap-ip> (or BOOTSTRAP_HOST=<host>)."
    exit 1
  fi
}

package_genesis_artifact() {
  local src="$1"
  local dst_dir="${CONFIG_OUTPUT_DIR}/artifacts"
  mkdir -p "${dst_dir}"
  # Package the exact genesis artifact we built against so operators can copy one
  # deterministic file to every node and verify it by sha256 before starting.
  local dst="${dst_dir}/$(basename "${src}")"
  install -m 0644 "${src}" "${dst}"
  echo "${dst}"
}

dir_has_chain_state() {
  local dir="$1"
  [[ -d "${dir}" ]] || return 1
  find "${dir}" -mindepth 1 -maxdepth 1 \
    ! -name 'keystore' \
    ! -name 'LOCK' \
    -print -quit 2>/dev/null | grep -q .
}

is_bootstrap_template_json() {
  local genesis_json="${ROOT_DIR}/mainnet/genesis.json"
  [[ -f "${genesis_json}" ]] || return 1
  python3 - "${genesis_json}" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, "r", encoding="utf-8"))
    vals = data.get("initial_validators", [])
    sys.exit(0 if isinstance(vals, list) and len(vals) == 0 else 1)
except Exception:
    sys.exit(1)
PY
}

bootstrap_preflight() {
  local genesis_bin
  genesis_bin="$(resolve_genesis_source)"

  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi

  local template_mode=0
  if [[ -n "${genesis_bin}" && -f "${genesis_bin}" ]] && is_bootstrap_template_json; then
    template_mode=1
  fi

  if [[ "${template_mode}" != "1" ]]; then
    return 0
  fi

  if (( ${#seeds[@]} == 0 )); then
    log "Bootstrap mode: first-node bootstrap (no configured seeds)."
    return 0
  fi

  log "Bootstrap mode: follower join via configured seeds."
  if dir_has_chain_state "${DB_DIR}"; then
    if [[ "${RESET_CHAIN_DATA}" != "1" ]]; then
      log "Refusing to start follower join with existing chain state in ${DB_DIR}."
      log "This usually means the node could keep an old fork instead of joining the live bootstrap chain."
      log "Use RESET_CHAIN_DATA=1 ./scripts/bootstrap_build.sh after confirming the correct seeds/genesis."
      exit 1
    fi
  fi
}

build_bootstrap_args() {
  local node_bin="$1"
  local db_dir="$2"
  local genesis_path="$3"
  local key_file="${db_dir}/keystore/validator.json"
  local seeds
  seeds="$(seed_csv)"
  local -a args
  args=(
    "${node_bin}"
    "--db" "${db_dir}"
    "--genesis" "${genesis_path}"
    "--public"
    "--listen"
    "--bind" "0.0.0.0"
    "--port" "${P2P_PORT}"
    "--outbound-target" "${OUTBOUND_TARGET}"
    "--validator-key-file" "${key_file}"
    "--no-dns-seeds"
  )

  # Public bootstrap nodes must listen on a routable interface so that followers
  # can complete VERSION/VERACK and start bootstrap adoption/sync from a known peer.
  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    args+=("--allow-unsafe-genesis-override")
  fi
  if [[ -n "${seeds}" ]]; then
    args+=("--seeds" "${seeds}")
  fi
  if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${NODE_EXTRA_ARGS} )
    args+=("${extra[@]}")
  fi

  printf '%q ' "${args[@]}"
}

build_follower_args() {
  local node_bin="$1"
  local db_dir="$2"
  local genesis_path="$3"
  local bootstrap_peer="$4"
  local key_file="${db_dir}/keystore/validator.json"
  local seeds
  seeds="$(seed_csv)"
  local -a args
  args=(
    "${node_bin}"
    "--db" "${db_dir}"
    "--genesis" "${genesis_path}"
    "--port" "${FOLLOWER_P2P_PORT}"
    "--outbound-target" "${OUTBOUND_TARGET}"
    "--validator-key-file" "${key_file}"
    "--no-dns-seeds"
    "--peers" "${bootstrap_peer}"
  )

  # Followers should use a direct bootstrap peer for first sync instead of
  # depending only on DNS seeds or ambient peer discovery.
  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    args+=("--allow-unsafe-genesis-override")
  fi
  if [[ -n "${seeds}" ]]; then
    args+=("--seeds" "${seeds}")
  fi
  if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${NODE_EXTRA_ARGS} )
    args+=("${extra[@]}")
  fi

  printf '%q ' "${args[@]}"
}

write_launcher() {
  local path="$1"
  local command_line="$2"
  cat > "${path}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec ${command_line}
EOF
  chmod +x "${path}"
}

write_unit_template() {
  local path="$1"
  local description="$2"
  local launcher="$3"
  cat > "${path}" <<EOF
[Unit]
Description=${description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${ROOT_DIR}
ExecStart=${launcher}
Restart=on-failure
RestartSec=2
TimeoutStopSec=90
KillSignal=SIGINT
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

generate_runtime_artifacts() {
  local node_bin="${ROOT_DIR}/${BUILD_DIR}/selfcoin-node"
  local genesis_source
  genesis_source="$(resolve_genesis_source)"
  require_follower_bootstrap_peer
  local packaged_genesis
  packaged_genesis="$(package_genesis_artifact "${genesis_source}")"
  local bootstrap_peer
  bootstrap_peer="$(bootstrap_peer_endpoint)"
  mkdir -p "${CONFIG_OUTPUT_DIR}" "${CONFIG_OUTPUT_DIR}/systemd"

  write_launcher "${BOOTSTRAP_LAUNCHER}" "$(build_bootstrap_args "${node_bin}" "${DB_DIR}" "${packaged_genesis}")"
  write_launcher "${FOLLOWER_LAUNCHER}" "$(build_follower_args "${node_bin}" "${FOLLOWER_DB_DIR}" "${packaged_genesis}" "${bootstrap_peer}")"
  write_unit_template "${BOOTSTRAP_UNIT_TEMPLATE}" "SelfCoin Bootstrap Node" "${BOOTSTRAP_LAUNCHER}"
  write_unit_template "${FOLLOWER_UNIT_TEMPLATE}" "SelfCoin Follower Node" "${FOLLOWER_LAUNCHER}"

  printf '%s\n' "${packaged_genesis}"
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
  if [[ "${NODE_ROLE}" == "follower" ]]; then
    log "Skipping firewall changes for follower role."
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
  local template_path
  if [[ "${NODE_ROLE}" == "follower" ]]; then
    local bootstrap_peer
    bootstrap_peer="$(bootstrap_peer_endpoint)"
    if [[ "${bootstrap_peer}" == REPLACE_WITH_BOOTSTRAP_IP:* ]]; then
      log "Skipping systemd install for follower role: set BOOTSTRAP_IP to generate a usable direct peer."
      log "Generated example follower launcher still exists at ${FOLLOWER_LAUNCHER}"
      return 0
    fi
    template_path="${FOLLOWER_UNIT_TEMPLATE}"
  else
    template_path="${BOOTSTRAP_UNIT_TEMPLATE}"
  fi

  ${s} install -m 0644 "${template_path}" "${service_path}"

  ${s} systemctl daemon-reload
  ${s} systemctl enable "${SERVICE_NAME}" >/dev/null || true
  ${s} systemctl restart "${SERVICE_NAME}"
  log "Service ${SERVICE_NAME} installed/restarted: ${service_path}"
}

post_build_setup() {
  bootstrap_preflight
  require_follower_bootstrap_peer
  reset_chain_data_if_requested
  open_firewall_ports
  local packaged_genesis
  packaged_genesis="$(generate_runtime_artifacts)"
  install_and_restart_service

  local bootstrap_peer
  bootstrap_peer="$(bootstrap_peer_endpoint)"
  local genesis_sha
  genesis_sha="$(sha256_file "${packaged_genesis}")"
  local verify_host
  verify_host="$(bootstrap_host_value)"
  if [[ -z "${verify_host}" ]]; then
    verify_host="<bootstrap-ip>"
  fi

  log "Post-build setup summary:"
  log "  NODE_ROLE=${NODE_ROLE}"
  log "  Bootstrap DB=${DB_DIR}"
  log "  Follower DB=${FOLLOWER_DB_DIR}"
  log "  P2P_PORT=${P2P_PORT} FOLLOWER_P2P_PORT=${FOLLOWER_P2P_PORT} LIGHTSERVER_PORT=${LIGHTSERVER_PORT}"
  log "  Packaged genesis=${packaged_genesis}"
  log "  Packaged genesis sha256=${genesis_sha}"
  log "  All nodes must use this exact genesis artifact or VERSION handshake will be rejected."
  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    log "  Unsafe genesis override is ENABLED for generated commands."
  else
    log "  Unsafe genesis override is DISABLED by default."
  fi
  log "  Bootstrap peer endpoint for followers=${bootstrap_peer}"
  log "Generated runtime files:"
  log "  ${BOOTSTRAP_LAUNCHER}"
  log "  ${FOLLOWER_LAUNCHER}"
  log "  ${BOOTSTRAP_UNIT_TEMPLATE}"
  log "  ${FOLLOWER_UNIT_TEMPLATE}"
  log "Bootstrap node command:"
  log "  ${BOOTSTRAP_LAUNCHER}"
  log "Follower node command:"
  log "  ${FOLLOWER_LAUNCHER}"
  log "Bootstrap verification:"
  log "  Listener check: ss -ltnp | rg ${P2P_PORT}"
  log "  Reachability check: nc -vz ${verify_host} ${P2P_PORT}"
  log "Follower verification:"
  log "  Peer/sync log check: journalctl -u ${SERVICE_NAME} -n 100 --no-pager | rg 'peer-connected|recv VERSION|recv VERACK|request-finalized-tip|recv BLOCK|buffered-sync-applied'"
  log "  Runtime status check: journalctl -u ${SERVICE_NAME} -n 100 --no-pager | rg 'established=|height='"
  log "If logs show 'genesis-fingerprint-mismatch', stop the node, replace the genesis artifact, and reset the follower DB before retrying."
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
