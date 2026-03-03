#include "p2p/addrman.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace selfcoin::p2p {

std::string NetAddress::key() const { return ip + ":" + std::to_string(port); }

std::optional<NetAddress> parse_endpoint(const std::string& endpoint) {
  const auto pos = endpoint.rfind(':');
  if (pos == std::string::npos) return std::nullopt;
  const std::string host = endpoint.substr(0, pos);
  const std::string port_s = endpoint.substr(pos + 1);
  if (host.empty() || port_s.empty()) return std::nullopt;
  try {
    const auto p = static_cast<std::uint16_t>(std::stoul(port_s));
    return NetAddress{host, p};
  } catch (...) {
    return std::nullopt;
  }
}

void AddrMan::add_or_update(const NetAddress& addr, std::uint64_t last_seen) {
  if (addr.ip.empty() || addr.port == 0) return;
  auto& e = entries_[addr.key()];
  if (e.addr.ip.empty()) e.addr = addr;
  e.last_seen = std::max(e.last_seen, last_seen);
  enforce_limit();
}

void AddrMan::mark_attempt(const NetAddress& addr, std::uint64_t now) {
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_attempt = now;
}

void AddrMan::mark_success(const NetAddress& addr, std::uint64_t now) {
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_seen = std::max(e.last_seen, now);
  e.last_attempt = now;
  e.success_count += 1;
  if (e.score < 1000) e.score += 10;
  if (e.fail_count > 0) e.fail_count -= 1;
}

void AddrMan::mark_fail(const NetAddress& addr, std::uint64_t now, const std::string& err) {
  auto& e = entries_[addr.key()];
  e.addr = addr;
  e.last_attempt = now;
  e.fail_count += 1;
  e.last_error = err;
  if (e.score > -1000) e.score -= 20;
}

std::uint64_t AddrMan::backoff_seconds(const AddrEntry& e) {
  const std::uint32_t exp = std::min<std::uint32_t>(e.fail_count, 10U);
  const std::uint64_t base = (1ULL << exp) * 5ULL;
  return std::min<std::uint64_t>(base, 3600ULL);
}

std::vector<NetAddress> AddrMan::select_candidates(std::size_t n, std::uint64_t now) const {
  std::vector<const AddrEntry*> all;
  all.reserve(entries_.size());
  for (const auto& [_, e] : entries_) {
    if (e.addr.port == 0 || e.addr.ip.empty()) continue;
    const auto bo = backoff_seconds(e);
    if (e.last_attempt > 0 && now < e.last_attempt + bo) continue;
    all.push_back(&e);
  }

  std::sort(all.begin(), all.end(), [](const AddrEntry* a, const AddrEntry* b) {
    if (a->score != b->score) return a->score > b->score;
    if (a->last_seen != b->last_seen) return a->last_seen > b->last_seen;
    return a->addr.key() < b->addr.key();
  });

  std::vector<NetAddress> out;
  out.reserve(std::min(n, all.size()));
  for (std::size_t i = 0; i < all.size() && out.size() < n; ++i) out.push_back(all[i]->addr);
  return out;
}

void AddrMan::enforce_limit() {
  if (entries_.size() <= max_entries_) return;
  std::vector<std::reference_wrapper<const AddrEntry>> vals;
  vals.reserve(entries_.size());
  for (const auto& [_, e] : entries_) vals.emplace_back(e);
  std::sort(vals.begin(), vals.end(), [](const AddrEntry& a, const AddrEntry& b) {
    if (a.score != b.score) return a.score < b.score;
    if (a.last_seen != b.last_seen) return a.last_seen < b.last_seen;
    return a.addr.key() < b.addr.key();
  });
  const std::size_t drop = entries_.size() - max_entries_;
  for (std::size_t i = 0; i < drop; ++i) {
    entries_.erase(vals[i].get().addr.key());
  }
}

bool AddrMan::save(const std::string& path) const {
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  for (const auto& [_, e] : entries_) {
    out << e.addr.ip << '\t' << e.addr.port << '\t' << e.last_seen << '\t' << e.last_attempt << '\t'
        << e.success_count << '\t' << e.fail_count << '\t' << e.score << '\t' << e.last_error << '\n';
  }
  return out.good();
}

bool AddrMan::load(const std::string& path) {
  entries_.clear();
  std::ifstream in(path);
  if (!in.good()) return true;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    AddrEntry e;
    std::string port, last_seen, last_attempt, succ, fail, score;
    if (!std::getline(ss, e.addr.ip, '\t')) continue;
    if (!std::getline(ss, port, '\t')) continue;
    if (!std::getline(ss, last_seen, '\t')) continue;
    if (!std::getline(ss, last_attempt, '\t')) continue;
    if (!std::getline(ss, succ, '\t')) continue;
    if (!std::getline(ss, fail, '\t')) continue;
    if (!std::getline(ss, score, '\t')) continue;
    std::getline(ss, e.last_error);
    try {
      e.addr.port = static_cast<std::uint16_t>(std::stoul(port));
      e.last_seen = std::stoull(last_seen);
      e.last_attempt = std::stoull(last_attempt);
      e.success_count = static_cast<std::uint32_t>(std::stoul(succ));
      e.fail_count = static_cast<std::uint32_t>(std::stoul(fail));
      e.score = std::stoi(score);
    } catch (...) {
      continue;
    }
    if (e.addr.ip.empty() || e.addr.port == 0) continue;
    entries_[e.addr.key()] = std::move(e);
  }
  enforce_limit();
  return true;
}

std::vector<AddrEntry> AddrMan::all() const {
  std::vector<AddrEntry> out;
  out.reserve(entries_.size());
  for (const auto& [_, e] : entries_) out.push_back(e);
  return out;
}

}  // namespace selfcoin::p2p
