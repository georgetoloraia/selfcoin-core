#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <tuple>

#include "common/types.hpp"

namespace selfcoin::p2p {

class TokenBucket {
 public:
  TokenBucket() = default;
  TokenBucket(double capacity, double refill_per_sec);

  void configure(double capacity, double refill_per_sec);
  bool consume(double tokens, std::uint64_t now_ms);
  double available(std::uint64_t now_ms) const;

 private:
  void refill(std::uint64_t now_ms);

  double capacity_{0.0};
  double refill_per_sec_{0.0};
  mutable double tokens_{0.0};
  mutable std::uint64_t last_refill_ms_{0};
  mutable bool initialized_{false};
};

enum class MisbehaviorReason {
  INVALID_FRAME,
  PRE_HANDSHAKE_CONSENSUS,
  INVALID_PAYLOAD,
  INVALID_VOTE_SIGNATURE,
  INVALID_PROPOSE,
  DUPLICATE_SPAM,
  RATE_LIMIT,
};

struct PeerScoreStatus {
  int score{0};
  bool soft_muted{false};
  bool banned{false};
  std::uint64_t ban_until{0};
};

class PeerDiscipline {
 public:
  PeerDiscipline(int soft_mute_score, int ban_score, std::uint64_t ban_seconds);

  PeerScoreStatus add_score(const std::string& ip, MisbehaviorReason reason, std::uint64_t now_unix);
  PeerScoreStatus status(const std::string& ip, std::uint64_t now_unix) const;
  bool is_banned(const std::string& ip, std::uint64_t now_unix) const;
  void decay(std::uint64_t now_unix);

 private:
  struct Entry {
    int score{0};
    std::uint64_t ban_until{0};
    std::uint64_t last_update{0};
  };

  int reason_score(MisbehaviorReason reason) const;

  int soft_mute_score_{30};
  int ban_score_{100};
  std::uint64_t ban_seconds_{600};
  std::map<std::string, Entry> entries_;
};

class VoteVerifyCache {
 public:
  using Key = std::tuple<std::uint64_t, std::uint32_t, Hash32, PubKey32>;

  explicit VoteVerifyCache(std::size_t capacity = 20'000);

  bool contains(const Key& key) const;
  void insert(const Key& key);
  void clear_height(std::uint64_t height);

 private:
  std::size_t capacity_{20'000};
  std::map<Key, bool> seen_;
  std::deque<Key> order_;
};

}  // namespace selfcoin::p2p
