#include "consensus/validators.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::consensus {

void ValidatorRegistry::upsert(PubKey32 pub, ValidatorInfo info) { validators_[pub] = info; }

void ValidatorRegistry::register_pending(const PubKey32& pub, std::uint64_t joined_height) {
  auto& v = validators_[pub];
  if (v.status == ValidatorStatus::BANNED) return;
  v.status = ValidatorStatus::PENDING;
  v.joined_height = joined_height;
}

void ValidatorRegistry::ban(const PubKey32& pub) {
  auto it = validators_.find(pub);
  if (it != validators_.end()) {
    it->second.status = ValidatorStatus::BANNED;
  }
}

void ValidatorRegistry::advance_height(std::uint64_t height) {
  for (auto& [_, info] : validators_) {
    if (info.status == ValidatorStatus::PENDING && height >= info.joined_height + WARMUP_BLOCKS) {
      info.status = ValidatorStatus::ACTIVE;
    }
  }
}

std::vector<PubKey32> ValidatorRegistry::active_sorted(std::uint64_t height) const {
  std::vector<PubKey32> out;
  for (const auto& [pub, info] : validators_) {
    if (info.status == ValidatorStatus::ACTIVE ||
        (info.status == ValidatorStatus::PENDING && height >= info.joined_height + WARMUP_BLOCKS)) {
      out.push_back(pub);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool ValidatorRegistry::is_active_for_height(const PubKey32& pub, std::uint64_t height) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  if (it->second.status == ValidatorStatus::BANNED) return false;
  if (it->second.status == ValidatorStatus::ACTIVE) return true;
  return height >= it->second.joined_height + WARMUP_BLOCKS;
}

std::optional<ValidatorInfo> ValidatorRegistry::get(const PubKey32& pub) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return std::nullopt;
  return it->second;
}

std::size_t quorum_threshold(std::size_t n_active) { return (2 * n_active) / 3 + 1; }

std::optional<PubKey32> select_leader(const Hash32& prev_finalized_hash, std::uint64_t height,
                                      std::uint32_t round, const std::vector<PubKey32>& active_sorted) {
  if (active_sorted.empty()) return std::nullopt;
  codec::ByteWriter w;
  w.bytes_fixed(prev_finalized_hash);
  w.u64le(height);
  w.u32le(round);
  const Hash32 h = crypto::sha256d(w.data());

  std::uint64_t pick = 0;
  for (int i = 0; i < 8; ++i) {
    pick |= static_cast<std::uint64_t>(h[i]) << (8 * i);
  }
  return active_sorted[pick % active_sorted.size()];
}

}  // namespace selfcoin::consensus
