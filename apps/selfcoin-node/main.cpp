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
    std::cerr << "usage: selfcoin-node --devnet --node-id <0..3> --port <p> --db <dir> [--peers host:port,...] [--disable-p2p]\n";
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
