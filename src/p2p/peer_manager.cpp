#include "p2p/peer_manager.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "p2p/messages.hpp"

namespace selfcoin::p2p {

void PeerManager::configure_network(std::uint32_t magic, std::uint16_t proto_version, std::size_t max_payload_len) {
  magic_ = magic;
  proto_version_ = proto_version;
  max_payload_len_ = max_payload_len;
}

bool PeerManager::start_listener(const std::string& bind_ip, std::uint16_t port) {
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) return false;

  int one = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }

  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    listen_port_ = ntohs(bound.sin_port);
  } else {
    listen_port_ = port;
  }
  if (listen(listen_fd_, 64) != 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }

  running_ = true;
  accept_thread_ = std::thread([this]() { accept_loop(); });
  return true;
}

bool PeerManager::connect_to(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return false;

  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return false;

  start_peer(fd, host + ":" + std::to_string(port), host);
  return true;
}

void PeerManager::stop() {
  if (!running_.exchange(false)) return;

  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
    listen_port_ = 0;
  }

  if (accept_thread_.joinable()) accept_thread_.join();

  std::vector<std::shared_ptr<PeerConn>> peers;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [_, p] : peers_) peers.push_back(p);
    peers_.clear();
  }

  for (auto& p : peers) {
    if (p->fd >= 0) {
      ::shutdown(p->fd, SHUT_RDWR);
      ::close(p->fd);
      p->fd = -1;
    }
    if (p->reader.joinable()) p->reader.join();
  }
}

bool PeerManager::send_to(int peer_id, std::uint16_t msg_type, const Bytes& payload, bool low_priority) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return false;
    p = it->second;
  }

  if (p->queued_msgs.load() >= limits_.max_outbound_queue_msgs ||
      p->queued_bytes.load() + payload.size() > limits_.max_outbound_queue_bytes) {
    if (low_priority) {
      emit_event(peer_id, PeerEventType::QUEUE_OVERFLOW, "drop-low-priority");
      return false;
    }
    emit_event(peer_id, PeerEventType::QUEUE_OVERFLOW, "disconnect");
    disconnect_peer(peer_id);
    return false;
  }

  p->queued_msgs.fetch_add(1);
  p->queued_bytes.fetch_add(payload.size());
  std::lock_guard<std::mutex> wl(p->write_mu);
  const bool ok = write_frame_fd(p->fd, Frame{msg_type, payload}, magic_, proto_version_);
  p->queued_msgs.fetch_sub(1);
  p->queued_bytes.fetch_sub(payload.size());
  if (!ok) {
    emit_event(peer_id, PeerEventType::DISCONNECTED, "send-failed");
    disconnect_peer(peer_id);
  }
  return ok;
}

void PeerManager::broadcast(std::uint16_t msg_type, const Bytes& payload) {
  const bool low_priority = (msg_type == MsgType::TX);
  for (int id : peer_ids()) {
    (void)send_to(id, msg_type, payload, low_priority);
  }
}

void PeerManager::disconnect_peer(int peer_id) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return;
    p = it->second;
  }
  if (p->fd >= 0) {
    ::shutdown(p->fd, SHUT_RDWR);
    ::close(p->fd);
    p->fd = -1;
  }
}

std::vector<int> PeerManager::peer_ids() const {
  std::vector<int> ids;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [id, _] : peers_) ids.push_back(id);
  return ids;
}

PeerInfo PeerManager::get_peer_info(int peer_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return {};
  return it->second->info;
}

bool PeerManager::mark_handshake_tx(int peer_id, bool version, bool verack) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  if (version) it->second->info.version_tx = true;
  if (verack) it->second->info.verack_tx = true;
  return true;
}

bool PeerManager::mark_handshake_rx(int peer_id, bool version, bool verack) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  if (version) it->second->info.version_rx = true;
  if (verack) it->second->info.verack_rx = true;
  return true;
}

bool PeerManager::set_peer_handshake_meta(int peer_id, std::uint32_t proto_version,
                                          const std::array<std::uint8_t, 16>& network_id, std::uint64_t feature_flags) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = peers_.find(peer_id);
  if (it == peers_.end()) return false;
  it->second->info.proto_version = proto_version;
  it->second->info.network_id = network_id;
  it->second->info.feature_flags = feature_flags;
  return true;
}

void PeerManager::accept_loop() {
  while (running_) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    if (fd < 0) {
      if (!running_) break;
      continue;
    }
    char ipbuf[64]{};
    inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
    start_peer(fd, std::string(ipbuf) + ":" + std::to_string(ntohs(addr.sin_port)), ipbuf);
  }
}

void PeerManager::start_peer(int fd, const std::string& endpoint, const std::string& ip) {
  auto p = std::make_shared<PeerConn>();
  p->fd = fd;
  {
    std::lock_guard<std::mutex> lk(mu_);
    p->info.id = next_peer_id_++;
    p->info.endpoint = endpoint;
    p->info.ip = ip;
    peers_[p->info.id] = p;
  }
  emit_event(p->info.id, PeerEventType::CONNECTED, endpoint);

  p->reader = std::thread([this, peer_id = p->info.id]() { read_loop(peer_id); });
}

void PeerManager::read_loop(int peer_id) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return;
    p = it->second;
  }

  while (running_) {
    const auto info = get_peer_info(peer_id);
    const std::uint32_t header_timeout = info.established() ? limits_.idle_timeout_ms : limits_.handshake_timeout_ms;
    FrameReadError ferr = FrameReadError::NONE;
    auto frame = read_frame_fd_timed(p->fd, max_payload_len_, magic_, proto_version_, header_timeout, limits_.frame_timeout_ms,
                                     &ferr);
    if (!frame.has_value()) {
      if (ferr == FrameReadError::TIMEOUT_HEADER) {
        emit_event(peer_id, info.established() ? PeerEventType::FRAME_TIMEOUT : PeerEventType::HANDSHAKE_TIMEOUT, "header-timeout");
      } else if (ferr == FrameReadError::TIMEOUT_BODY) {
        emit_event(peer_id, PeerEventType::FRAME_TIMEOUT, "body-timeout");
      } else if (ferr != FrameReadError::NONE && ferr != FrameReadError::IO_EOF) {
        emit_event(peer_id, PeerEventType::FRAME_INVALID, "invalid-frame");
      }
      break;
    }
    if (on_message_) on_message_(peer_id, frame->msg_type, frame->payload);
  }

  ::shutdown(p->fd, SHUT_RDWR);
  ::close(p->fd);
  p->fd = -1;
  std::lock_guard<std::mutex> lk(mu_);
  peers_.erase(peer_id);
  emit_event(peer_id, PeerEventType::DISCONNECTED, "read-loop-end");
}

void PeerManager::emit_event(int peer_id, PeerEventType type, const std::string& detail) const {
  if (on_event_) on_event_(peer_id, type, detail);
}

}  // namespace selfcoin::p2p
