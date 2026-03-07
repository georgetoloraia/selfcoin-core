#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <stdexcept>
#include <string>
#include <set>
#include <vector>

#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"

using namespace selfcoin;

namespace {

std::vector<PubKey32> make_active_set(std::size_t n) {
  std::vector<PubKey32> out;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(static_cast<std::uint8_t>(i + 1));
    auto kp = crypto::keypair_from_seed32(seed);
    if (!kp.has_value()) throw std::runtime_error("keypair generation failed");
    out.push_back(kp->public_key);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::string committee_key(const std::vector<PubKey32>& c) {
  std::string out;
  for (const auto& p : c) {
    out.append(reinterpret_cast<const char*>(p.data()), p.size());
  }
  return out;
}

}  // namespace

TEST(test_research_v2_committee_size_small_active) {
  ASSERT_EQ(consensus::committee_size_v2(0, 100), 0u);
  ASSERT_EQ(consensus::committee_size_v2(1, 100), 1u);
  ASSERT_EQ(consensus::committee_size_v2(2, 100), 2u);
  const auto k3 = consensus::committee_size_v2(3, 100);
  ASSERT_TRUE(k3 >= 2u);
  ASSERT_TRUE(k3 <= 3u);
}

TEST(test_research_v2_committee_size_round_expansion_progression) {
  ASSERT_EQ(consensus::committee_size_for_round_v2(2, 100, 0), 2u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(4, 100, 0), 4u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(8, 2, 0), 2u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(8, 2, 1), 4u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(8, 2, 2), 8u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(32, 3, 1), 6u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(32, 3, 2), 12u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(32, 3, 3), 24u);
  ASSERT_EQ(consensus::committee_size_for_round_v2(32, 3, 4), 32u);
}

TEST(test_research_v2_committee_size_reaches_active_count_when_round_sufficient) {
  constexpr std::size_t active_count = 1'000'000;
  constexpr std::size_t configured_max = 2;
  ASSERT_EQ(consensus::committee_size_for_round_v2(active_count, configured_max, 0), 2u);

  std::size_t k_tmp = 2;
  std::uint32_t needed = 0;
  while (k_tmp < active_count) {
    k_tmp = (k_tmp > (active_count / 2)) ? active_count : (k_tmp * 2);
    ++needed;
    ASSERT_TRUE(needed < 64u);
  }

  ASSERT_EQ(consensus::committee_size_for_round_v2(active_count, configured_max, needed), active_count);
  ASSERT_EQ(consensus::committee_size_for_round_v2(active_count, configured_max, needed + 5), active_count);
}

TEST(test_research_v2_committee_size_monotonic_non_decreasing_with_round) {
  const std::size_t active_count = 4096;
  const std::size_t configured_max = 3;
  std::size_t prev = consensus::committee_size_for_round_v2(active_count, configured_max, 0);
  for (std::uint32_t round = 1; round <= 32; ++round) {
    const std::size_t cur = consensus::committee_size_for_round_v2(active_count, configured_max, round);
    ASSERT_TRUE(cur >= prev);
    prev = cur;
  }
  ASSERT_EQ(prev, active_count);
}

TEST(test_research_v2_selection_deterministic) {
  const auto active = make_active_set(12);
  Hash32 entropy{};
  entropy.fill(0x42);
  const Hash32 seed = consensus::make_sortition_seed_v2(entropy, 123, 7);
  const auto c1 = consensus::select_committee_v2(active, seed, 5);
  const auto c2 = consensus::select_committee_v2(active, seed, 5);
  ASSERT_EQ(c1, c2);
  ASSERT_EQ(consensus::select_leader_v2(c1), consensus::select_leader_v2(c2));
}

TEST(test_research_v2_round_changes_selection) {
  const auto active = make_active_set(16);
  Hash32 entropy{};
  entropy.fill(0x55);
  std::set<std::string> committees;
  for (std::uint32_t round = 0; round < 10; ++round) {
    const Hash32 seed = consensus::make_sortition_seed_v2(entropy, 500, round);
    const auto c = consensus::select_committee_v2(active, seed, 5);
    committees.insert(committee_key(c));
  }
  ASSERT_TRUE(committees.size() >= 2u);
}

TEST(test_research_v2_entropy_order_independent) {
  FinalityProof fp_a;
  FinalityProof fp_b;
  for (int i = 0; i < 5; ++i) {
    FinalitySig fs;
    fs.validator_pubkey.fill(static_cast<std::uint8_t>(i + 1));
    fs.signature.fill(static_cast<std::uint8_t>(0xA0 + i));
    fp_a.sigs.push_back(fs);
  }
  fp_b.sigs = fp_a.sigs;
  std::reverse(fp_b.sigs.begin(), fp_b.sigs.end());

  Hash32 prev{};
  prev.fill(0x33);
  const auto e1 = consensus::compute_finality_entropy_v2(prev, fp_a);
  const auto e2 = consensus::compute_finality_entropy_v2(prev, fp_b);
  ASSERT_EQ(e1, e2);
}

TEST(test_research_v2_entropy_replay_stable_and_pubkey_sensitive) {
  FinalityProof fp_a;
  for (int i = 0; i < 4; ++i) {
    FinalitySig fs;
    fs.validator_pubkey.fill(static_cast<std::uint8_t>(i + 1));
    fs.signature.fill(static_cast<std::uint8_t>(0xD0 + i));
    fp_a.sigs.push_back(fs);
  }
  FinalityProof fp_b = fp_a;
  std::reverse(fp_b.sigs.begin(), fp_b.sigs.end());

  Hash32 prev{};
  prev.fill(0x7C);
  const auto r1 = consensus::compute_finality_entropy_v2(prev, fp_a);
  const auto r2 = consensus::compute_finality_entropy_v2(prev, fp_a);
  const auto r3 = consensus::compute_finality_entropy_v2(prev, fp_b);
  ASSERT_EQ(r1, r2);
  ASSERT_EQ(r1, r3);

  FinalityProof fp_changed = fp_a;
  fp_changed.sigs[0].validator_pubkey[0] ^= 0x01;
  const auto r_changed = consensus::compute_finality_entropy_v2(prev, fp_changed);
  ASSERT_TRUE(r_changed != r1);
}

TEST(test_research_v2_entropy_dedups_duplicate_pubkey) {
  Hash32 prev{};
  prev.fill(0x5A);

  FinalitySig keep;
  keep.validator_pubkey.fill(0x22);
  keep.signature.fill(0x10);

  FinalitySig drop = keep;
  drop.signature.fill(0xF0);  // lexicographically larger than keep.signature

  FinalityProof with_dups;
  with_dups.sigs.push_back(drop);
  with_dups.sigs.push_back(keep);

  FinalityProof deduped;
  deduped.sigs.push_back(keep);

  const auto e_with_dups = consensus::compute_finality_entropy_v2(prev, with_dups);
  const auto e_deduped = consensus::compute_finality_entropy_v2(prev, deduped);
  ASSERT_EQ(e_with_dups, e_deduped);
}

TEST(test_research_v2_fairness_sanity) {
  const std::size_t n = 20;
  const auto active = make_active_set(n);
  Hash32 entropy{};
  entropy.fill(0x11);

  std::map<PubKey32, std::size_t> appearances;
  std::set<PubKey32> unique_leaders;
  for (std::uint32_t round = 0; round < 500; ++round) {
    const Hash32 seed = consensus::make_sortition_seed_v2(entropy, 777, round);
    const auto c = consensus::select_committee_v2(active, seed, 5);
    for (const auto& p : c) appearances[p] += 1;
    auto leader = consensus::select_leader_v2(c);
    if (leader.has_value()) unique_leaders.insert(*leader);
  }

  std::size_t appeared = 0;
  for (const auto& p : active) {
    if (appearances[p] > 0) ++appeared;
  }
  ASSERT_TRUE(appeared >= 15u);
  ASSERT_TRUE(unique_leaders.size() >= 5u);
}

void register_research_sortition_v2_tests() {}
