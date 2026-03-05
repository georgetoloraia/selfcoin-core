#include "consensus/sortition_v6.hpp"

#include <algorithm>
#include <limits>

#include "consensus/sortition_v5.hpp"

namespace selfcoin::consensus {

namespace {

WeightedThresholdV6 normalize_ratio(__uint128_t num, __uint128_t den) {
  if (den == 0) return {};
  if (num == 0) return {.num = 0, .den = 1};
  if (num >= den) return {.num = 1, .den = 1};

  while (num > std::numeric_limits<std::uint64_t>::max() || den > std::numeric_limits<std::uint64_t>::max()) {
    num = (num + 1) / 2;
    den = (den + 1) / 2;
  }

  return {.num = static_cast<std::uint64_t>(num), .den = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(den))};
}

}  // namespace

std::size_t voter_target_k_v6(std::size_t active_count, std::uint32_t round, const V6Params& params) {
  if (active_count == 0) return 0;
  std::size_t k = std::min<std::size_t>(active_count, std::max<std::size_t>(2, params.voter_target_k));
  const std::uint32_t steps = std::min(round, params.round_expand_cap);
  for (std::uint32_t i = 0; i < steps && k < active_count; ++i) {
    const std::uint32_t factor = std::max<std::uint32_t>(2, params.round_expand_factor);
    if (k > active_count / factor) k = active_count;
    else k *= factor;
  }
  return std::min(k, active_count);
}

WeightedThresholdV6 threshold_weighted_v6(std::uint64_t total_weight, std::uint64_t validator_weight,
                                          std::uint64_t expected_num, std::uint64_t expected_den) {
  if (total_weight == 0 || validator_weight == 0 || expected_den == 0) return {.num = 0, .den = 1};

  const __uint128_t num = static_cast<__uint128_t>(expected_num) * static_cast<__uint128_t>(validator_weight);
  const __uint128_t den = static_cast<__uint128_t>(expected_den) * static_cast<__uint128_t>(total_weight);
  return normalize_ratio(num, den);
}

bool eligible_weighted_v6(const Hash32& output, const WeightedThresholdV6& threshold) {
  if (threshold.den == 0 || threshold.num == 0) return false;
  if (threshold.num >= threshold.den) return true;
  return is_output_below_probability_threshold(output, threshold.num, threshold.den);
}

}  // namespace selfcoin::consensus
