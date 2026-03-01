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

}  // namespace selfcoin::consensus
