#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
GENERATOR="${GENERATOR:-}"
BUILD_JOBS="${BUILD_JOBS:-}"
RUN_TESTS="${RUN_TESTS:-0}"
CLEAN_ON_GENERATOR_MISMATCH="${CLEAN_ON_GENERATOR_MISMATCH:-1}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
RESET_CHAIN_DATA="${RESET_CHAIN_DATA:-0}"
SETUP_NODE_SERVICE="${SETUP_NODE_SERVICE:-1}"
SERVICE_NAME="${SERVICE_NAME:-selfcoin}"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$USER}}"
DB_DIR="${DB_DIR:-$HOME/.selfcoin/mainnet}"
P2P_PORT="${P2P_PORT:-19440}"
OUTBOUND_TARGET="${OUTBOUND_TARGET:-1}"
HANDSHAKE_TIMEOUT_MS="${HANDSHAKE_TIMEOUT_MS:-30000}"
FRAME_TIMEOUT_MS="${FRAME_TIMEOUT_MS:-30000}"
IDLE_TIMEOUT_MS="${IDLE_TIMEOUT_MS:-120000}"
NODE_EXTRA_ARGS="${NODE_EXTRA_ARGS:-}"
USE_SEEDS_JSON="${USE_SEEDS_JSON:-1}"
GENESIS_BIN="${GENESIS_BIN:-}"
GENESIS_PATH="${GENESIS_PATH:-${GENESIS_BIN}}"
ALLOW_UNSAFE_GENESIS_OVERRIDE="${ALLOW_UNSAFE_GENESIS_OVERRIDE:-1}"
NODE_ROLE="${NODE_ROLE:-auto}"

log() { printf '[bootstrap] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

listener_pids_on_port() {
  local port="$1"
  if have ss; then
    ss -ltnp "sport = :${port}" 2>/dev/null | grep -o "pid=[0-9]\+" | cut -d= -f2 | awk '!seen[$0]++'
    return 0
  fi
  if have lsof; then
    lsof -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null | awk '!seen[$0]++'
    return 0
  fi
}

detect_build_jobs() {
  if [[ -n "${BUILD_JOBS}" ]]; then
    echo "${BUILD_JOBS}"
    return
  fi

  if [[ -r /proc/meminfo ]]; then
    local mem_kb
    mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
    if [[ -n "${mem_kb}" ]] && (( mem_kb <= 2097152 )); then
      echo "1"
      return
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

systemd_available() {
  have systemctl && [[ -d /run/systemd/system ]]
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
  if [[ "${INSTALL_DEPS}" != "1" ]]; then
    log "Skipping dependency installation (INSTALL_DEPS=0)."
    return 0
  fi

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
    for seed in data.get("seeds_p2p", []):
        if isinstance(seed, str):
            seed = seed.strip()
            if seed:
                print(seed)
except Exception:
    pass
PY
}

seed_count() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  echo "${#seeds[@]}"
}

seed_csv() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  if (( ${#seeds[@]} == 0 )); then
    return 0
  fi
  local IFS=,
  printf '%s' "${seeds[*]}"
}

requested_mode() {
  case "${NODE_ROLE}" in
    auto|"")
      echo "auto"
      ;;
    bootstrap)
      echo "bootstrap"
      ;;
    joiner|follower)
      echo "joiner"
      ;;
    *)
      log "Unsupported NODE_ROLE=${NODE_ROLE}. Use auto, bootstrap, or joiner."
      exit 1
      ;;
  esac
}

detect_mode() {
  local requested
  requested="$(requested_mode)"
  if [[ "${requested}" != "auto" ]]; then
    echo "${requested}"
    return
  fi

  if [[ "$(seed_count)" -gt 0 ]]; then
    echo "joiner"
  else
    echo "bootstrap"
  fi
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

reset_chain_data_if_requested() {
  if [[ "${RESET_CHAIN_DATA}" != "1" ]]; then
    return 0
  fi

  local -a pids=()
  mapfile -t pids < <(listener_pids_on_port "${P2P_PORT}" || true)
  if (( ${#pids[@]} > 0 )); then
    local pid
    for pid in "${pids[@]}"; do
      local comm
      comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]')"
      if [[ "${comm}" != "selfcoin-node" ]]; then
        log "Port ${P2P_PORT} is already in use by pid=${pid} (${comm:-unknown})."
        log "Stop that process manually, then retry."
        exit 1
      fi
      log "Stopping existing selfcoin-node pid=${pid} on port ${P2P_PORT}."
      kill "${pid}" 2>/dev/null || true
    done

    sleep 1
    local -a stubborn_pids=()
    mapfile -t stubborn_pids < <(listener_pids_on_port "${P2P_PORT}" || true)
    if (( ${#stubborn_pids[@]} > 0 )); then
      for pid in "${stubborn_pids[@]}"; do
        local comm
        comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]')"
        if [[ "${comm}" == "selfcoin-node" ]]; then
          log "Force stopping selfcoin-node pid=${pid} on port ${P2P_PORT}."
          kill -9 "${pid}" 2>/dev/null || true
        fi
      done
      sleep 1
    fi

    if listener_pids_on_port "${P2P_PORT}" | grep -q .; then
      log "Port ${P2P_PORT} is still busy after cleanup."
      log "Run: ss -ltnp | rg ${P2P_PORT}"
      exit 1
    fi
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

build_node_command() {
  local node_bin="${ROOT_DIR}/${BUILD_DIR}/selfcoin-node"
  local genesis_path="$1"
  local mode="$2"
  local -a args=(
    "${node_bin}"
    "--db" "${DB_DIR}"
    "--genesis" "${genesis_path}"
    "--port" "${P2P_PORT}"
    "--handshake-timeout-ms" "${HANDSHAKE_TIMEOUT_MS}"
    "--frame-timeout-ms" "${FRAME_TIMEOUT_MS}"
    "--idle-timeout-ms" "${IDLE_TIMEOUT_MS}"
  )

  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    args+=("--allow-unsafe-genesis-override")
  fi

  if [[ "${mode}" == "bootstrap" ]]; then
    args+=(
      "--public"
      "--listen"
      "--bind" "0.0.0.0"
      "--no-dns-seeds"
      "--outbound-target" "0"
    )
  else
    local peers
    peers="$(seed_csv)"
    if [[ -z "${peers}" ]]; then
      log "Joiner mode requires one or more peers in mainnet/SEEDS.json."
      exit 1
    fi
    args+=(
      "--no-dns-seeds"
      "--outbound-target" "${OUTBOUND_TARGET}"
      "--peers" "${peers}"
    )
  fi

  if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${NODE_EXTRA_ARGS} )
    args+=("${extra[@]}")
  fi

  printf '%q ' "${args[@]}"
}

print_summary() {
  local mode="$1"
  local genesis_path="$2"
  local command_line="$3"
  local genesis_sha
  genesis_sha="$(sha256_file "${genesis_path}")"
  local peers
  peers="$(seed_csv)"

  log "Detected mode=${mode}"
  log "Seed count=$(seed_count)"
  log "DB_DIR=${DB_DIR}"
  log "Genesis=${genesis_path}"
  log "Genesis sha256=${genesis_sha}"
  log "All nodes must use this exact genesis artifact or VERSION handshake will be rejected."
  if [[ "${mode}" == "bootstrap" ]]; then
    log "Peers=<none; SEEDS.json is empty>"
  else
    log "Peers=${peers}"
  fi
  log "Command:"
  printf '%s\n' "${command_line}"
  if [[ "${mode}" == "bootstrap" ]]; then
    log "Bootstrap verification:"
    log "  ss -ltnp | rg ${P2P_PORT}"
    log "  nc -vz <this-public-ip> ${P2P_PORT}"
  else
    log "Joiner verification:"
    log "  rg 'peer-connected|recv VERSION|recv VERACK|request-finalized-tip|recv BLOCK|buffered-sync-applied'"
  fi
  log "If logs show 'genesis-fingerprint-mismatch', stop the node and reset ${DB_DIR} before retrying."
}

run_node() {
  local command_line="$1"
  log "Starting selfcoin-node..."
  # Intentional direct exec: this script is the one command operators run.
  eval "exec ${command_line}"
}

install_and_restart_service() {
  local command_line="$1"
  if [[ "${SETUP_NODE_SERVICE}" != "1" ]]; then
    return 1
  fi
  if ! systemd_available; then
    return 1
  fi

  local service_path="/etc/systemd/system/${SERVICE_NAME}.service"
  local launcher_path="${ROOT_DIR}/deploy/generated/${SERVICE_NAME}.service.sh"
  local s; s="$(need_sudo)"
  mkdir -p "${ROOT_DIR}/deploy/generated"
  cat > "${launcher_path}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec ${command_line}
EOF
  chmod +x "${launcher_path}"
  ${s} tee "${service_path}" >/dev/null <<EOF
[Unit]
Description=SelfCoin Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${ROOT_DIR}
ExecStart=${launcher_path}
Restart=on-failure
RestartSec=2
TimeoutStopSec=90
KillSignal=SIGINT
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  ${s} systemctl daemon-reload
  ${s} systemctl enable "${SERVICE_NAME}" >/dev/null || true
  ${s} systemctl restart "${SERVICE_NAME}"
  log "Installed and restarted ${SERVICE_NAME}.service"
  ${s} systemctl status "${SERVICE_NAME}" --no-pager || true
  return 0
}

main() {
  log "Installing build dependencies (if missing)..."
  install_deps
  log "Configuring and building SelfCoin Core..."
  configure_and_build
  reset_chain_data_if_requested

  local mode
  mode="$(detect_mode)"
  local genesis_path
  genesis_path="$(resolve_genesis_source)"
  local command_line
  command_line="$(build_node_command "${genesis_path}" "${mode}")"

  print_summary "${mode}" "${genesis_path}" "${command_line}"
  if install_and_restart_service "${command_line}"; then
    exit 0
  fi
  run_node "${command_line}"
}

main "$@"
