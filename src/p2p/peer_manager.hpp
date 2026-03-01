#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "p2p/framing.hpp"

namespace selfcoin::p2p {

struct PeerInfo {
  int id{0};
  std::string endpoint;
  bool version_rx{false};
  bool verack_rx{false};
  bool version_tx{false};
  bool verack_tx{false};

  bool established() const { return version_rx && verack_rx && version_tx && verack_tx; }
};

class PeerManager {
 public:
  using MessageHandler = std::function<void(int peer_id, std::uint16_t msg_type, const Bytes& payload)>;

  void configure_network(std::uint32_t magic, std::uint16_t proto_version, std::size_t max_payload_len);
  bool start_listener(const std::string& bind_ip, std::uint16_t port);
  bool connect_to(const std::string& host, std::uint16_t port);
  void stop();

  void set_on_message(MessageHandler fn) { on_message_ = std::move(fn); }
  void send_to(int peer_id, std::uint16_t msg_type, const Bytes& payload);
  void broadcast(std::uint16_t msg_type, const Bytes& payload);

  std::vector<int> peer_ids() const;
  PeerInfo get_peer_info(int peer_id) const;
  bool mark_handshake_tx(int peer_id, bool version, bool verack);
  bool mark_handshake_rx(int peer_id, bool version, bool verack);

 private:
  struct PeerConn {
    int fd{-1};
    PeerInfo info;
    std::thread reader;
    mutable std::mutex write_mu;
  };

  void accept_loop();
  void start_peer(int fd, const std::string& endpoint);
  void read_loop(int peer_id);

  int listen_fd_{-1};
  std::thread accept_thread_;
  std::atomic<bool> running_{false};

  mutable std::mutex mu_;
  int next_peer_id_{1};
  std::map<int, std::shared_ptr<PeerConn>> peers_;

  MessageHandler on_message_;
  std::uint32_t magic_{MAGIC};
  std::uint16_t proto_version_{PROTOCOL_VERSION};
  std::size_t max_payload_len_{8 * 1024 * 1024};
};

}  // namespace selfcoin::p2p
