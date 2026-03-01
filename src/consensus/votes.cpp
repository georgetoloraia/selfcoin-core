#include "consensus/votes.hpp"

namespace selfcoin::consensus {

VoteTallyResult VoteTracker::add_vote(const Vote& vote) {
  VoteTallyResult out;
  const auto hr = std::make_pair(vote.height, vote.round);
  auto& seen = seen_by_validator_[hr];

  const auto it = seen.find(vote.validator_pubkey);
  if (it != seen.end()) {
    if (it->second == vote.block_id) {
      out.accepted = false;
      out.duplicate = true;
      return out;
    }

    out.accepted = false;
    out.equivocation = true;
    const auto key_a = std::make_tuple(vote.height, vote.round, vote.validator_pubkey);
    const auto old_it = stored_votes_.find(key_a);
    if (old_it != stored_votes_.end()) {
      out.evidence = EquivocationEvidence{old_it->second, vote};
    }
    return out;
  }

  seen[vote.validator_pubkey] = vote.block_id;
  stored_votes_[std::make_tuple(vote.height, vote.round, vote.validator_pubkey)] = vote;

  const Key key{vote.height, vote.round, vote.block_id};
  by_block_[key][vote.validator_pubkey] = vote.signature;
  out.accepted = true;
  out.votes_for_block = by_block_[key].size();
  return out;
}

std::vector<FinalitySig> VoteTracker::signatures_for(std::uint64_t height, std::uint32_t round,
                                                      const Hash32& block_id) const {
  const Key key{height, round, block_id};
  auto it = by_block_.find(key);
  if (it == by_block_.end()) return {};
  std::vector<FinalitySig> out;
  out.reserve(it->second.size());
  for (const auto& [pub, sig] : it->second) {
    out.push_back(FinalitySig{pub, sig});
  }
  return out;
}

void VoteTracker::clear_height(std::uint64_t height) {
  for (auto it = by_block_.begin(); it != by_block_.end();) {
    if (it->first.height == height) {
      it = by_block_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = seen_by_validator_.begin(); it != seen_by_validator_.end();) {
    if (it->first.first == height) {
      it = seen_by_validator_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = stored_votes_.begin(); it != stored_votes_.end();) {
    if (std::get<0>(it->first) == height) {
      it = stored_votes_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace selfcoin::consensus
