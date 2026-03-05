#pragma once

#include <map>
#include <optional>
#include <set>
#include <vector>

#include "common/types.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::consensus {

enum class ValidatorStatus : std::uint8_t {
  PENDING = 0,
  ACTIVE = 1,
  EXITING = 2,
  BANNED = 3,
};

struct ValidatorInfo {
  ValidatorStatus status{ValidatorStatus::PENDING};
  std::uint64_t joined_height{0};
  bool has_bond{false};
  OutPoint bond_outpoint{};
  std::uint64_t unbond_height{0};
};

class ValidatorRegistry {
 public:
  void upsert(PubKey32 pub, ValidatorInfo info);
  void register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height);
  bool request_unbond(const PubKey32& pub, std::uint64_t height);
  void ban(const PubKey32& pub);
  void advance_height(std::uint64_t height);

  std::vector<PubKey32> active_sorted(std::uint64_t height) const;
  bool is_active_for_height(const PubKey32& pub, std::uint64_t height) const;
  std::optional<ValidatorInfo> get(const PubKey32& pub) const;
  std::optional<PubKey32> pubkey_by_bond_outpoint(const OutPoint& op) const;
  const std::map<PubKey32, ValidatorInfo>& all() const { return validators_; }

 private:
  std::map<PubKey32, ValidatorInfo> validators_;
};

std::size_t quorum_threshold(std::size_t n_active);
std::optional<PubKey32> select_leader(const Hash32& prev_finalized_hash, std::uint64_t height,
                                      std::uint32_t round, const std::vector<PubKey32>& active_sorted);
std::vector<PubKey32> select_committee(const Hash32& prev_finalized_hash, std::uint64_t height,
                                       const std::vector<PubKey32>& active_sorted,
                                       std::size_t max_committee = MAX_COMMITTEE);
Hash32 compute_finality_entropy_v2(const Hash32& prev_block_id, const FinalityProof& prev_finality_proof);
Hash32 make_sortition_seed_v2(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round);
std::size_t committee_size_v2(std::size_t active_count, std::size_t configured_max_committee = 128);
std::size_t committee_size_for_round_v2(std::size_t active_count, std::size_t configured_max_committee,
                                        std::uint32_t round);
std::vector<PubKey32> select_committee_v2(const std::vector<PubKey32>& active_sorted, const Hash32& seed,
                                          std::size_t committee_size);
std::optional<PubKey32> select_leader_v2(const std::vector<PubKey32>& committee);

}  // namespace selfcoin::consensus
