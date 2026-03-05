#include "test_framework.hpp"

#include <array>
#include <stdexcept>

#include "consensus/sortition_v5.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/vrf.hpp"

using namespace selfcoin;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("keygen failed");
  return *kp;
}

}  // namespace

TEST(test_v5_seed_derivation_deterministic) {
  Hash32 prev{};
  prev.fill(0x11);
  const auto s1 = consensus::make_vrf_seed_v5(prev, 100, 2);
  const auto s2 = consensus::make_vrf_seed_v5(prev, 100, 2);
  ASSERT_EQ(s1, s2);
  ASSERT_TRUE(consensus::make_vrf_seed_v5(prev, 100, 3) != s1);
}

TEST(test_v5_round_expansion_increases_voter_target) {
  consensus::V5Params p;
  p.voter_target_k = 4;
  p.round_expand_cap = 4;
  p.round_expand_factor = 2;
  ASSERT_EQ(consensus::voter_target_k_v5(64, 0, p), 4u);
  ASSERT_EQ(consensus::voter_target_k_v5(64, 1, p), 8u);
  ASSERT_EQ(consensus::voter_target_k_v5(64, 2, p), 16u);
  ASSERT_EQ(consensus::voter_target_k_v5(64, 3, p), 32u);
}

TEST(test_v5_eligibility_deterministic_fixed_inputs) {
  auto kp = key_from_byte(21);
  Hash32 prev{};
  prev.fill(0x22);
  const auto seed = consensus::make_vrf_seed_v5(prev, 50, 1);
  const auto voter_seed = consensus::role_seed_v5(seed, consensus::SortitionRole::VOTER);
  const auto proposer_seed = consensus::role_seed_v5(seed, consensus::SortitionRole::PROPOSER);
  auto voter_proof = crypto::vrf_prove(kp.private_key, Bytes(voter_seed.begin(), voter_seed.end()));
  auto proposer_proof = crypto::vrf_prove(kp.private_key, Bytes(proposer_seed.begin(), proposer_seed.end()));
  ASSERT_TRUE(voter_proof.has_value());
  ASSERT_TRUE(proposer_proof.has_value());
  const bool e1 = consensus::is_v5_eligible(kp.public_key, voter_seed, 1, 4, *voter_proof);
  const bool e2 = consensus::is_v5_eligible(kp.public_key, voter_seed, 1, 4, *voter_proof);
  ASSERT_EQ(e1, e2);
  ASSERT_TRUE(!consensus::is_v5_eligible(kp.public_key, proposer_seed, 1, 4, *voter_proof));
}

void register_sortition_v5_tests() {}
