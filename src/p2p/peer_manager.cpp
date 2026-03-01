#include "p2p/peer_manager.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace selfcoin::p2p {

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

  start_peer(fd, host + ":" + std::to_string(port));
  return true;
}

void PeerManager::stop() {
  if (!running_.exchange(false)) return;

  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
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

void PeerManager::send_to(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  std::shared_ptr<PeerConn> p;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return;
    p = it->second;
  }
  std::lock_guard<std::mutex> wl(p->write_mu);
  write_frame_fd(p->fd, Frame{msg_type, payload});
}

void PeerManager::broadcast(std::uint16_t msg_type, const Bytes& payload) {
  for (int id : peer_ids()) {
    send_to(id, msg_type, payload);
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
    start_peer(fd, std::string(ipbuf) + ":" + std::to_string(ntohs(addr.sin_port)));
  }
}

void PeerManager::start_peer(int fd, const std::string& endpoint) {
  auto p = std::make_shared<PeerConn>();
  p->fd = fd;
  {
    std::lock_guard<std::mutex> lk(mu_);
    p->info.id = next_peer_id_++;
    p->info.endpoint = endpoint;
    peers_[p->info.id] = p;
  }

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
    auto frame = read_frame_fd(p->fd);
    if (!frame.has_value()) break;
    if (on_message_) on_message_(peer_id, frame->msg_type, frame->payload);
  }

  ::shutdown(p->fd, SHUT_RDWR);
  ::close(p->fd);
  p->fd = -1;
  std::lock_guard<std::mutex> lk(mu_);
  peers_.erase(peer_id);
}

}  // namespace selfcoin::p2p
