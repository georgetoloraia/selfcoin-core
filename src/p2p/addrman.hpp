#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace selfcoin::p2p {

struct NetAddress {
  std::string ip;
  std::uint16_t port{0};

  std::string key() const;
  bool operator<(const NetAddress& o) const { return std::tie(ip, port) < std::tie(o.ip, o.port); }
  bool operator==(const NetAddress& o) const { return ip == o.ip && port == o.port; }
};

struct AddrEntry {
  NetAddress addr;
  std::uint64_t last_seen{0};
  std::uint64_t last_attempt{0};
  std::uint32_t success_count{0};
  std::uint32_t fail_count{0};
  std::string last_error;
  int score{0};
};

class AddrMan {
 public:
  explicit AddrMan(std::size_t max_entries = 10'000) : max_entries_(max_entries) {}

  void add_or_update(const NetAddress& addr, std::uint64_t last_seen);
  void mark_attempt(const NetAddress& addr, std::uint64_t now);
  void mark_success(const NetAddress& addr, std::uint64_t now);
  void mark_fail(const NetAddress& addr, std::uint64_t now, const std::string& err = {});

  std::vector<NetAddress> select_candidates(std::size_t n, std::uint64_t now) const;
  std::size_t size() const { return entries_.size(); }

  bool save(const std::string& path) const;
  bool load(const std::string& path);

  std::vector<AddrEntry> all() const;

 private:
  void enforce_limit();
  static std::uint64_t backoff_seconds(const AddrEntry& e);

  std::size_t max_entries_{10'000};
  std::map<std::string, AddrEntry> entries_;
};

std::optional<NetAddress> parse_endpoint(const std::string& endpoint);

}  // namespace selfcoin::p2p
