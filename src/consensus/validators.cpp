#include "consensus/validators.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::consensus {

void ValidatorRegistry::upsert(PubKey32 pub, ValidatorInfo info) { validators_[pub] = info; }

void ValidatorRegistry::register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height) {
  auto& v = validators_[pub];
  v.status = ValidatorStatus::PENDING;
  v.joined_height = joined_height;
  v.has_bond = true;
  v.bond_outpoint = bond_outpoint;
  v.unbond_height = 0;
}

bool ValidatorRegistry::request_unbond(const PubKey32& pub, std::uint64_t height) {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return false;
  if (it->second.status == ValidatorStatus::BANNED) return false;
  if (!it->second.has_bond) return false;
  it->second.status = ValidatorStatus::EXITING;
  it->second.unbond_height = height;
  return true;
}

void ValidatorRegistry::ban(const PubKey32& pub) {
  auto it = validators_.find(pub);
  if (it != validators_.end()) {
    it->second.status = ValidatorStatus::BANNED;
    it->second.has_bond = false;
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
    if ((info.status == ValidatorStatus::ACTIVE && info.has_bond) ||
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
  if (!it->second.has_bond) return false;
  if (it->second.status == ValidatorStatus::BANNED || it->second.status == ValidatorStatus::EXITING) return false;
  if (it->second.status == ValidatorStatus::ACTIVE && it->second.has_bond) return true;
  return height >= it->second.joined_height + WARMUP_BLOCKS;
}

std::optional<ValidatorInfo> ValidatorRegistry::get(const PubKey32& pub) const {
  auto it = validators_.find(pub);
  if (it == validators_.end()) return std::nullopt;
  return it->second;
}

std::optional<PubKey32> ValidatorRegistry::pubkey_by_bond_outpoint(const OutPoint& op) const {
  for (const auto& [pub, info] : validators_) {
    if (!info.has_bond) continue;
    if (info.bond_outpoint.txid == op.txid && info.bond_outpoint.index == op.index) return pub;
  }
  return std::nullopt;
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

std::vector<PubKey32> select_committee(const Hash32& prev_finalized_hash, std::uint64_t height,
                                       const std::vector<PubKey32>& active_sorted, std::size_t max_committee) {
  if (active_sorted.empty()) return {};
  const std::size_t committee_size = std::min(max_committee, active_sorted.size());

  codec::ByteWriter seed_w;
  seed_w.bytes(Bytes{'S', 'C', '-', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'E', '-', 'V', '0'});
  seed_w.bytes_fixed(prev_finalized_hash);
  seed_w.u64le(height);
  const Hash32 seed = crypto::sha256d(seed_w.data());

  std::vector<std::pair<Hash32, PubKey32>> scored;
  scored.reserve(active_sorted.size());
  for (const auto& pub : active_sorted) {
    codec::ByteWriter sw;
    sw.bytes_fixed(seed);
    sw.bytes_fixed(pub);
    scored.push_back({crypto::sha256d(sw.data()), pub});
  }

  std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) return a.first < b.first;
    return a.second < b.second;
  });

  std::vector<PubKey32> out;
  out.reserve(committee_size);
  for (std::size_t i = 0; i < committee_size; ++i) out.push_back(scored[i].second);
  return out;
}

Hash32 compute_finality_entropy_v2(const Hash32& prev_block_id, const FinalityProof& prev_finality_proof) {
  std::vector<FinalitySig> canon = prev_finality_proof.sigs;
  std::sort(canon.begin(), canon.end(), [](const FinalitySig& a, const FinalitySig& b) {
    if (a.validator_pubkey != b.validator_pubkey) return a.validator_pubkey < b.validator_pubkey;
    return a.signature < b.signature;
  });

  // Deterministic duplicate handling: keep the lexicographically smallest
  // signature per validator_pubkey, drop the rest.
  std::vector<FinalitySig> deduped;
  deduped.reserve(canon.size());
  for (const auto& fs : canon) {
    if (!deduped.empty() && deduped.back().validator_pubkey == fs.validator_pubkey) continue;
    deduped.push_back(fs);
  }

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'E', 'N', 'T', 'R', 'O', 'P', 'Y', '-', 'V', '2'});
  w.bytes_fixed(prev_block_id);
  for (const auto& fs : deduped) {
    w.bytes_fixed(fs.validator_pubkey);
    w.bytes_fixed(fs.signature);
  }
  return crypto::sha256d(w.data());
}

Hash32 make_sortition_seed_v2(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'E', 'E', 'D', '-', 'V', '2'});
  w.bytes_fixed(prev_entropy);
  w.u64le(height);
  w.u32le(round);
  return crypto::sha256d(w.data());
}

std::size_t committee_size_v2(std::size_t active_count, std::size_t configured_max_committee) {
  if (active_count <= 2) return active_count;
  const std::size_t k = std::min(active_count, configured_max_committee);
  return std::max<std::size_t>(2, k);
}

std::size_t committee_size_for_round_v2(std::size_t active_count, std::size_t configured_max_committee,
                                        std::uint32_t round) {
  std::size_t k = committee_size_v2(active_count, configured_max_committee);
  if (round == 0 || active_count <= 2) return k;

  if (k == 0) k = 1;  // Defensive, preserves deterministic finite progression.

  std::uint32_t needed = 0;
  std::size_t k_tmp = k;
  while (k_tmp < active_count && needed < 64) {
    if (k_tmp > (active_count / 2)) {
      k_tmp = active_count;
    } else {
      k_tmp *= 2;
    }
    ++needed;
  }

  const std::uint32_t shift = std::min(round, needed);
  for (std::uint32_t i = 0; i < shift && k < active_count; ++i) {
    if (k > (active_count / 2)) {
      k = active_count;
      break;
    }
    k *= 2;
  }
  return std::max<std::size_t>(2, std::min(active_count, k));
}

std::vector<PubKey32> select_committee_v2(const std::vector<PubKey32>& active_sorted, const Hash32& seed,
                                          std::size_t committee_size) {
  if (active_sorted.empty() || committee_size == 0) return {};
  const std::size_t take = std::min(committee_size, active_sorted.size());

  std::vector<std::pair<Hash32, PubKey32>> scored;
  scored.reserve(active_sorted.size());
  for (const auto& pub : active_sorted) {
    codec::ByteWriter sw;
    sw.bytes(Bytes{'S', 'C', '-', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'E', '-', 'V', '2'});
    sw.bytes_fixed(seed);
    sw.bytes_fixed(pub);
    scored.push_back({crypto::sha256d(sw.data()), pub});
  }
  std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) return a.first < b.first;
    return a.second < b.second;
  });

  std::vector<PubKey32> out;
  out.reserve(take);
  for (std::size_t i = 0; i < take; ++i) out.push_back(scored[i].second);
  return out;
}

std::optional<PubKey32> select_leader_v2(const std::vector<PubKey32>& committee) {
  if (committee.empty()) return std::nullopt;
  return committee.front();
}

}  // namespace selfcoin::consensus
