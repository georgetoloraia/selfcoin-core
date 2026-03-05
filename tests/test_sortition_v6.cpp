#include "test_framework.hpp"

#include <limits>

#include "codec/bytes.hpp"
#include "consensus/sortition_v6.hpp"
#include "consensus/validators.hpp"
#include "crypto/hash.hpp"

using namespace selfcoin;

namespace {

Hash32 deterministic_output(std::uint64_t i) {
  codec::ByteWriter w;
  w.u64le(i);
  return crypto::sha256d(w.data());
}

consensus::ValidatorInfo make_active_validator(std::uint64_t bonded_amount) {
  consensus::ValidatorInfo vi;
  vi.status = consensus::ValidatorStatus::ACTIVE;
  vi.has_bond = true;
  vi.bonded_amount = bonded_amount;
  return vi;
}

}  // namespace

TEST(test_v6_weight_zero_never_eligible) {
  const auto t = consensus::threshold_weighted_v6(100, 0, 10, 1);
  ASSERT_EQ(t.num, 0u);
  ASSERT_EQ(t.den, 1u);
  ASSERT_TRUE(!consensus::eligible_weighted_v6(deterministic_output(1), t));
}

TEST(test_v6_heavier_weight_higher_selection_rate) {
  constexpr std::uint64_t total_weight = 100;
  const auto light_t = consensus::threshold_weighted_v6(total_weight, 1, 10, 1);
  const auto heavy_t = consensus::threshold_weighted_v6(total_weight, 10, 10, 1);
  std::size_t light_hits = 0;
  std::size_t heavy_hits = 0;
  for (std::uint64_t i = 0; i < 2000; ++i) {
    const auto out = deterministic_output(i);
    if (consensus::eligible_weighted_v6(out, light_t)) ++light_hits;
    if (consensus::eligible_weighted_v6(out, heavy_t)) ++heavy_hits;
  }
  ASSERT_TRUE(heavy_hits >= light_hits);
}

TEST(test_v6_threshold_clamps_no_overflow) {
  const auto t = consensus::threshold_weighted_v6(std::numeric_limits<std::uint64_t>::max(),
                                                  std::numeric_limits<std::uint64_t>::max(),
                                                  std::numeric_limits<std::uint64_t>::max(), 1);
  ASSERT_TRUE(t.den >= 1);
  ASSERT_TRUE(t.num >= 1);
  ASSERT_TRUE(t.num <= t.den);
}

TEST(test_v6_total_weight_deterministic) {
  consensus::ValidatorRegistry vr;
  consensus::ValidatorWeightParamsV6 p;
  p.bond_unit = 10;
  p.units_max = 1'000'000;

  PubKey32 a{};
  a[0] = 1;
  PubKey32 b{};
  b[0] = 2;
  PubKey32 c{};
  c[0] = 3;

  vr.upsert(a, make_active_validator(100));   // 10 units
  vr.upsert(b, make_active_validator(250));   // 25 units
  auto ci = make_active_validator(700);
  ci.status = consensus::ValidatorStatus::SUSPENDED;
  vr.upsert(c, ci);  // excluded by active filter

  const auto w1 = consensus::total_active_weight_units_v6(vr, 100, p);
  const auto w2 = consensus::total_active_weight_units_v6(vr, 100, p);
  ASSERT_EQ(w1, 35u);
  ASSERT_EQ(w1, w2);
}

TEST(test_v6_round_expansion_increases_expected_and_eligibility) {
  consensus::V6Params p;
  p.voter_target_k = 4;
  p.round_expand_cap = 4;
  p.round_expand_factor = 2;
  ASSERT_EQ(consensus::voter_target_k_v6(64, 0, p), 4u);
  ASSERT_EQ(consensus::voter_target_k_v6(64, 1, p), 8u);
  ASSERT_EQ(consensus::voter_target_k_v6(64, 2, p), 16u);
  ASSERT_EQ(consensus::voter_target_k_v6(64, 3, p), 32u);
}

void register_sortition_v6_tests() {}
