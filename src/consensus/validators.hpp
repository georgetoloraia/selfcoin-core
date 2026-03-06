#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::consensus {

enum class ValidatorStatus : std::uint8_t {
  PENDING = 0,
  ACTIVE = 1,
  EXITING = 2,
  BANNED = 3,
  SUSPENDED = 4,
};

struct ValidatorInfo {
  ValidatorStatus status{ValidatorStatus::PENDING};
  std::uint64_t joined_height{0};
  std::uint64_t bonded_amount{BOND_AMOUNT};
  bool has_bond{false};
  OutPoint bond_outpoint{};
  std::uint64_t unbond_height{0};
  std::uint64_t eligible_count_window{0};
  std::uint64_t participated_count_window{0};
  std::uint64_t liveness_window_start{0};
  std::uint64_t suspended_until_height{0};
  std::uint64_t last_join_height{0};
  std::uint64_t last_exit_height{0};
  std::uint32_t penalty_strikes{0};
};

struct ValidatorRules {
  std::uint64_t min_bond{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t cooldown_blocks{0};
};

class ValidatorRegistry {
 public:
  void set_rules(ValidatorRules rules) { rules_ = rules; }
  const ValidatorRules& rules() const { return rules_; }
  void upsert(PubKey32 pub, ValidatorInfo info);
  bool can_register_bond(const PubKey32& pub, std::uint64_t height, std::uint64_t bond_amount, std::string* err = nullptr) const;
  void register_bond_legacy(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height);
  bool register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height) {
    register_bond_legacy(pub, bond_outpoint, joined_height);
    return true;
  }
  bool register_bond(const PubKey32& pub, const OutPoint& bond_outpoint, std::uint64_t joined_height, std::uint64_t bond_amount,
                     std::string* err = nullptr);
  bool request_unbond(const PubKey32& pub, std::uint64_t height);
  void ban(const PubKey32& pub);
  void advance_height(std::uint64_t height);

  std::vector<PubKey32> active_sorted(std::uint64_t height) const;
  bool is_active_for_height(const PubKey32& pub, std::uint64_t height) const;
  std::optional<ValidatorInfo> get(const PubKey32& pub) const;
  std::optional<PubKey32> pubkey_by_bond_outpoint(const OutPoint& op) const;
  std::map<PubKey32, ValidatorInfo>& mutable_all() { return validators_; }
  const std::map<PubKey32, ValidatorInfo>& all() const { return validators_; }

 private:
  bool is_effectively_active(const ValidatorInfo& info, std::uint64_t height) const;

  std::map<PubKey32, ValidatorInfo> validators_;
  ValidatorRules rules_{};
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
std::vector<PubKey32> committee_participants_from_finality(const std::vector<PubKey32>& committee,
                                                           const std::vector<FinalitySig>& sigs);
bool v4_liveness_should_rollover(std::uint64_t height, std::uint64_t epoch_start_height,
                                 std::uint64_t window_blocks);
std::uint64_t v4_liveness_next_epoch_start(std::uint64_t height, std::uint64_t epoch_start_height,
                                           std::uint64_t window_blocks);
void v4_advance_join_window(std::uint64_t height, std::uint64_t window_blocks, std::uint64_t* window_start_height,
                            std::uint32_t* window_count);

}  // namespace selfcoin::consensus
