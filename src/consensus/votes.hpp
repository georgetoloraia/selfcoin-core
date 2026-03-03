#pragma once

#include <map>
#include <optional>
#include <set>
#include <vector>

#include "consensus/validators.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::consensus {

struct VoteTallyResult {
  bool accepted{false};
  bool duplicate{false};
  bool equivocation{false};
  std::optional<EquivocationEvidence> evidence;
  std::size_t votes_for_block{0};
};

class VoteTracker {
 public:
  struct Limits {
    std::size_t max_blocks_per_height_round{256};
    std::size_t max_votes_global{50'000};
  };

  VoteTracker() = default;
  explicit VoteTracker(Limits limits) : limits_(limits) {}
  VoteTallyResult add_vote(const Vote& vote);
  std::vector<FinalitySig> signatures_for(std::uint64_t height, std::uint32_t round, const Hash32& block_id) const;
  std::set<PubKey32> participants_for(std::uint64_t height, std::uint32_t round) const;
  void clear_height(std::uint64_t height);

 private:
  struct Key {
    std::uint64_t height;
    std::uint32_t round;
    Hash32 block_id;

    bool operator<(const Key& o) const {
      return std::tie(height, round, block_id) < std::tie(o.height, o.round, o.block_id);
    }
  };

  std::map<Key, std::map<PubKey32, Sig64>> by_block_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, std::map<PubKey32, Hash32>> seen_by_validator_;
  std::map<std::tuple<std::uint64_t, std::uint32_t, PubKey32>, Vote> stored_votes_;
  Limits limits_{};
};

}  // namespace selfcoin::consensus
