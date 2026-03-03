#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
GENERATOR="${GENERATOR:-}"

log() { printf '[bootstrap] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

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
  if [[ -n "${GENERATOR}" ]]; then
    args+=(-G "${GENERATOR}")
  elif have ninja; then
    args+=(-G Ninja)
  fi
  cmake "${args[@]}"
  cmake --build "${BUILD_DIR}" -j
}

log "Installing build dependencies (if missing)..."
install_deps
log "Configuring and building SelfCoin Core..."
configure_and_build
log "Done. Binaries are in ${BUILD_DIR}/"
