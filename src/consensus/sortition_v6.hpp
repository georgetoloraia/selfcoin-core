#pragma once

#include "common/types.hpp"
#include "consensus/validators.hpp"

namespace selfcoin::consensus {

struct V6Params {
  ValidatorWeightParamsV6 weight{};
  std::uint64_t proposer_expected_num{1};
  std::uint64_t proposer_expected_den{1};
  std::uint32_t voter_target_k{100};
  std::uint32_t round_expand_cap{8};
  std::uint32_t round_expand_factor{2};
};

struct WeightedThresholdV6 {
  std::uint64_t num{0};
  std::uint64_t den{1};
};

std::size_t voter_target_k_v6(std::size_t active_count, std::uint32_t round, const V6Params& params);
WeightedThresholdV6 threshold_weighted_v6(std::uint64_t total_weight, std::uint64_t validator_weight,
                                          std::uint64_t expected_num, std::uint64_t expected_den);
bool eligible_weighted_v6(const Hash32& output, const WeightedThresholdV6& threshold);

}  // namespace selfcoin::consensus
