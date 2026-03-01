#include "test_framework.hpp"

#include "consensus/monetary.hpp"

using namespace selfcoin;

namespace {

PubKey32 pub(std::uint8_t b) {
  PubKey32 p{};
  p.fill(b);
  return p;
}

}  // namespace

TEST(test_reward_schedule_boundaries) {
  using namespace selfcoin::consensus;
  ASSERT_EQ(reward_units(0), EMISSION_Q + 1);
  ASSERT_EQ(reward_units(EMISSION_R - 1), EMISSION_Q + 1);
  ASSERT_EQ(reward_units(EMISSION_R), EMISSION_Q);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS - 1), EMISSION_Q);
  ASSERT_EQ(reward_units(EMISSION_BLOCKS), 0ULL);
}

TEST(test_reward_schedule_exact_total_supply) {
  using namespace selfcoin::consensus;
  std::uint64_t total = 0;
  for (std::uint64_t h = 0; h < EMISSION_BLOCKS; ++h) total += reward_units(h);
  ASSERT_EQ(total, TOTAL_SUPPLY_UNITS);
}

TEST(test_payout_split_deterministic_with_remainder) {
  using namespace selfcoin::consensus;
  const std::uint64_t h = 0;
  const std::vector<PubKey32> signers = {pub(0xAA), pub(0x10), pub(0x55)};
  const auto p = compute_payout(h, 0, pub(0xEE), signers);

  const std::uint64_t R = reward_units(h);
  const std::uint64_t leader = (R * 20ULL) / 100ULL;
  ASSERT_EQ(p.leader, leader);
  ASSERT_EQ(p.total, R);
  ASSERT_EQ(p.signers.size(), 3u);

  std::uint64_t signer_sum = 0;
  for (const auto& it : p.signers) signer_sum += it.second;
  ASSERT_EQ(signer_sum, R - leader);

  // Sorted lexicographically by pubkey bytes.
  ASSERT_TRUE(p.signers[0].first < p.signers[1].first);
  ASSERT_TRUE(p.signers[1].first < p.signers[2].first);

  const std::uint64_t pool = R - leader;
  const std::uint64_t base = pool / 3ULL;
  const std::uint64_t rem = pool % 3ULL;
  ASSERT_EQ(p.signers[0].second, base + (rem > 0 ? 1ULL : 0ULL));
  ASSERT_EQ(p.signers[1].second, base + (rem > 1 ? 1ULL : 0ULL));
  ASSERT_EQ(p.signers[2].second, base + (rem > 2 ? 1ULL : 0ULL));
}

TEST(test_payout_after_emission_fees_only) {
  using namespace selfcoin::consensus;
  const std::uint64_t fees = 12345;
  const auto p = compute_payout(EMISSION_BLOCKS, fees, pub(0x01), {pub(0x02), pub(0x03)});
  ASSERT_EQ(reward_units(EMISSION_BLOCKS), 0ULL);
  ASSERT_EQ(p.total, fees);
  std::uint64_t sum = p.leader;
  for (const auto& it : p.signers) sum += it.second;
  ASSERT_EQ(sum, fees);
}

void register_monetary_tests() {}
