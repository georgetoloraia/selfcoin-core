#include <csignal>
#include <iostream>
#include <thread>

#include "node/node.hpp"

using selfcoin::node::Node;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_sigint(int) { g_stop = 1; }
}  // namespace

int main(int argc, char** argv) {
  auto cfg = selfcoin::node::parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr << "usage: selfcoin-node [--node-id <id>] [--db <dir>] [--genesis <path>] [--allow-unsafe-genesis-override] [--port <p>] "
                 "[--validator-key-file <path>] [--validator-passphrase <pass>] [--validator-passphrase-env <ENV>] "
                 "[--public] [--listen] [--bind <ip>] [--outbound-target <n>] [--dns-seeds|--no-dns-seeds] "
                 "[--peers host:port,...] [--seeds host:port,...] [--disable-p2p] [--log-json] "
                 "[--handshake-timeout-ms <ms>] [--frame-timeout-ms <ms>] [--idle-timeout-ms <ms>] "
                 "[--peer-queue-max-bytes <n>] [--peer-queue-max-msgs <n>] [--max-inbound <n>] [--ban-seconds <s>] "
                 "[--invalid-frame-ban-threshold <n>] [--invalid-frame-window-seconds <s>] "
                 "[--min-relay-fee <sats>] [--activation-enabled] [--activation-max-version <n>] "
                 "[--activation-window-blocks <n>] [--activation-threshold-percent <n>] "
                 "[--activation-delay-blocks <n>] "
                 "[--validator-min-bond <u64>] [--validator-warmup-blocks <n>] [--validator-cooldown-blocks <n>] "
                 "[--validator-join-limit-window-blocks <n>] [--validator-join-limit-max-new <n>] "
                 "[--liveness-window-blocks <n>] [--miss-rate-suspend-threshold-percent <n>] "
                 "[--miss-rate-exit-threshold-percent <n>] [--suspend-duration-blocks <n>]\n";
    return 1;
  }

  Node node(*cfg);
  if (!node.init()) {
    std::cerr << "node init failed\n";
    return 1;
  }
  node.start();

  std::signal(SIGINT, on_sigint);
  std::signal(SIGTERM, on_sigint);

  while (!g_stop) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  node.stop();
  return 0;
}
