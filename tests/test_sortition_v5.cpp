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
  constexpr std::uint64_t height = 50;
  constexpr std::uint32_t round = 1;
  const auto seed = consensus::make_vrf_seed_v5(prev, height, round);
  const auto voter_seed = consensus::role_seed_v5(seed, consensus::V5Role::VOTER);
  const auto proposer_seed = consensus::role_seed_v5(seed, consensus::V5Role::PROPOSER);
  const auto voter_transcript =
      consensus::make_v5_vrf_transcript(consensus::V5Role::VOTER, height, round, voter_seed, std::nullopt);
  const auto proposer_transcript =
      consensus::make_v5_vrf_transcript(consensus::V5Role::PROPOSER, height, round, proposer_seed, std::nullopt);
  auto voter_proof = crypto::vrf_prove(kp.private_key, kp.public_key, voter_transcript);
  auto proposer_proof = crypto::vrf_prove(kp.private_key, kp.public_key, proposer_transcript);
  ASSERT_TRUE(voter_proof.has_value());
  ASSERT_TRUE(proposer_proof.has_value());
  const bool e1 = consensus::is_v5_eligible(kp.public_key, consensus::V5Role::VOTER, height, round, voter_seed,
                                            std::nullopt, 1, 4, *voter_proof);
  const bool e2 = consensus::is_v5_eligible(kp.public_key, consensus::V5Role::VOTER, height, round, voter_seed,
                                            std::nullopt, 1, 4, *voter_proof);
  ASSERT_EQ(e1, e2);
  ASSERT_TRUE(!consensus::is_v5_eligible(kp.public_key, consensus::V5Role::PROPOSER, height, round, proposer_seed,
                                         std::nullopt, 1, 4, *voter_proof));
}

TEST(test_v5_threshold_fail_rejected) {
  auto kp = key_from_byte(31);
  Hash32 prev{};
  prev.fill(0x99);
  constexpr std::uint64_t height = 120;
  constexpr std::uint32_t round = 4;
  const auto seed = consensus::make_vrf_seed_v5(prev, height, round);
  const auto voter_seed = consensus::role_seed_v5(seed, consensus::V5Role::VOTER);
  const auto transcript =
      consensus::make_v5_vrf_transcript(consensus::V5Role::VOTER, height, round, voter_seed, std::nullopt);
  auto proof = crypto::vrf_prove(kp.private_key, kp.public_key, transcript);
  ASSERT_TRUE(proof.has_value());

  // A valid signature/proof still fails eligibility when the probability threshold is tiny.
  ASSERT_TRUE(!consensus::is_v5_eligible(kp.public_key, consensus::V5Role::VOTER, height, round, voter_seed,
                                         std::nullopt, 0, 1'000'000, *proof));
}

TEST(test_v5_transcript_encoding_stability) {
  Hash32 seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
  std::array<std::uint8_t, 16> network_id{};
  for (std::size_t i = 0; i < network_id.size(); ++i) network_id[i] = static_cast<std::uint8_t>(0xA0 + i);
  const auto transcript =
      consensus::make_v5_vrf_transcript(consensus::V5Role::PROPOSER, 0x0102030405060708ULL, 0x0A0B0C0D, seed, network_id);
  ASSERT_EQ(transcript.size(), 81u);
  const Bytes prefix(transcript.begin(), transcript.begin() + 15);
  const Bytes expected_prefix{'S', 'C', '-', 'V', 'R', 'F', '-', 'P', 'R', 'O', 'O', 'F', '-', 'V', '5'};
  ASSERT_EQ(prefix, expected_prefix);
  ASSERT_EQ(transcript[15], static_cast<std::uint8_t>(consensus::V5Role::PROPOSER));
}

void register_sortition_v5_tests() {}
