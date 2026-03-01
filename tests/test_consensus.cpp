#include "test_framework.hpp"

#include "consensus/validators.hpp"
#include "consensus/votes.hpp"

using namespace selfcoin;

TEST(test_leader_selection_determinism) {
  std::vector<PubKey32> vals(4);
  for (size_t i = 0; i < vals.size(); ++i) vals[i].fill(static_cast<std::uint8_t>(10 + i));
  std::sort(vals.begin(), vals.end());

  Hash32 prev{};
  prev.fill(7);

  auto l1 = consensus::select_leader(prev, 10, 2, vals);
  auto l2 = consensus::select_leader(prev, 10, 2, vals);
  ASSERT_TRUE(l1.has_value());
  ASSERT_TRUE(l2.has_value());
  ASSERT_EQ(*l1, *l2);
}

TEST(test_committee_selection_determinism) {
  std::vector<PubKey32> vals(10);
  for (size_t i = 0; i < vals.size(); ++i) vals[i].fill(static_cast<std::uint8_t>(20 + i));
  std::sort(vals.begin(), vals.end());

  Hash32 prev{};
  prev.fill(0x42);

  auto c1 = consensus::select_committee(prev, 50, vals, 6);
  auto c2 = consensus::select_committee(prev, 50, vals, 6);
  ASSERT_EQ(c1, c2);
  ASSERT_EQ(c1.size(), 6u);
}

TEST(test_committee_selection_changes_with_seed_inputs) {
  std::vector<PubKey32> vals(12);
  for (size_t i = 0; i < vals.size(); ++i) vals[i].fill(static_cast<std::uint8_t>(80 + i));
  std::sort(vals.begin(), vals.end());

  Hash32 prev_a{};
  prev_a.fill(0x11);
  Hash32 prev_b{};
  prev_b.fill(0x22);

  auto c1 = consensus::select_committee(prev_a, 100, vals, 8);
  auto c2 = consensus::select_committee(prev_a, 101, vals, 8);
  auto c3 = consensus::select_committee(prev_b, 100, vals, 8);
  ASSERT_TRUE(c1 != c2);
  ASSERT_TRUE(c1 != c3);
}

TEST(test_quorum_formula_1_to_20) {
  for (size_t n = 1; n <= 20; ++n) {
    const size_t q = consensus::quorum_threshold(n);
    ASSERT_EQ(q, (2 * n) / 3 + 1);
  }
}

TEST(test_vote_dedup_quorum_and_equivocation) {
  consensus::VoteTracker vt;
  Vote v;
  v.height = 1;
  v.round = 0;
  v.block_id.fill(1);
  v.validator_pubkey.fill(9);
  v.signature.fill(3);

  auto r1 = vt.add_vote(v);
  ASSERT_TRUE(r1.accepted);
  ASSERT_EQ(r1.votes_for_block, 1u);

  auto r2 = vt.add_vote(v);
  ASSERT_TRUE(r2.duplicate);

  Vote v2 = v;
  v2.block_id.fill(2);
  auto r3 = vt.add_vote(v2);
  ASSERT_TRUE(r3.equivocation);
  ASSERT_TRUE(r3.evidence.has_value());
}

void register_consensus_tests() {}
