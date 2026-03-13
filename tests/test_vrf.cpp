#include "test_framework.hpp"

#include <array>
#include <stdexcept>

#include "codec/bytes.hpp"
#include "common/chain_id.hpp"
#include "consensus/randomness.hpp"
#include "consensus/vrf_sortition.hpp"
#include "common/network.hpp"
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

Bytes transcript_for(std::uint8_t domain, std::uint64_t height, std::uint32_t round, const Hash32& seed) {
  codec::ByteWriter w;
  w.u8(domain);
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(seed);
  return w.take();
}

}  // namespace

TEST(test_research_vrf_prove_verify_roundtrip) {
  auto kp = key_from_byte(7);
  Hash32 seed{};
  seed.fill(0xA1);
  const auto transcript = transcript_for(1, 5, 2, seed);
  auto p = crypto::vrf_prove(kp.private_key, kp.public_key, transcript);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, transcript, *p));
}

TEST(test_research_vrf_wrong_seed_fails) {
  auto kp = key_from_byte(8);
  Hash32 s1{};
  s1.fill(0x0B);
  Hash32 s2{};
  s2.fill(0x0C);
  const auto t1 = transcript_for(1, 9, 1, s1);
  const auto t2 = transcript_for(1, 9, 1, s2);
  auto p = crypto::vrf_prove(kp.private_key, kp.public_key, t1);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, t2, *p));
}

TEST(test_research_vrf_wrong_pubkey_fails) {
  auto kp1 = key_from_byte(9);
  auto kp2 = key_from_byte(10);
  Hash32 seed{};
  seed.fill(0x33);
  const auto transcript = transcript_for(2, 10, 7, seed);
  auto p = crypto::vrf_prove(kp1.private_key, kp1.public_key, transcript);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(!crypto::vrf_verify(kp2.public_key, transcript, *p));
}

TEST(test_research_vrf_replay_across_domain_fails) {
  auto kp = key_from_byte(11);
  Hash32 seed{};
  seed.fill(0x44);
  const auto proposer = transcript_for(2, 100, 3, seed);
  const auto voter = transcript_for(1, 100, 3, seed);
  auto p = crypto::vrf_prove(kp.private_key, kp.public_key, proposer);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, proposer, *p));
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, voter, *p));
}

TEST(test_research_vrf_replay_across_round_fails) {
  auto kp = key_from_byte(12);
  Hash32 seed{};
  seed.fill(0x55);
  const auto round7 = transcript_for(1, 100, 7, seed);
  const auto round8 = transcript_for(1, 100, 8, seed);
  auto p = crypto::vrf_prove(kp.private_key, kp.public_key, round7);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, round8, *p));
}

TEST(test_research_vrf_output_mismatch_fails) {
  auto kp = key_from_byte(13);
  Hash32 seed{};
  seed.fill(0x66);
  const auto transcript = transcript_for(1, 11, 2, seed);
  auto p = crypto::vrf_prove(kp.private_key, kp.public_key, transcript);
  ASSERT_TRUE(p.has_value());
  auto tampered = *p;
  tampered.output[0] ^= 0x01;
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, transcript, tampered));
}

TEST(test_proposer_vrf_threshold_expands_with_round) {
  const auto t0 = consensus::proposer_vrf_threshold_u64(8, 0, 1, 1);
  const auto t1 = consensus::proposer_vrf_threshold_u64(8, 1, 1, 1);
  const auto t2 = consensus::proposer_vrf_threshold_u64(8, 2, 1, 1);
  ASSERT_TRUE(t1 > t0);
  ASSERT_TRUE(t2 > t1);
}

TEST(test_proposer_vrf_verify_roundtrip_and_eligibility) {
  auto kp = key_from_byte(14);
  Hash32 prev{};
  prev.fill(0x7A);
  const auto transcript = consensus::proposer_vrf_transcript(mainnet_network(), prev, 11, 0);
  auto proof = crypto::vrf_prove(kp.private_key, kp.public_key, transcript);
  ASSERT_TRUE(proof.has_value());

  const bool direct_ok = crypto::vrf_verify(kp.public_key, transcript, *proof);
  ASSERT_TRUE(direct_ok);

  const bool eligible = consensus::verify_proposer_vrf(mainnet_network(), kp.public_key, prev, 11, 0, *proof, 1, 1, 1);
  ASSERT_TRUE(eligible);
}

TEST(test_finalized_randomness_accumulator_is_deterministic) {
  ChainId cid;
  cid.genesis_hash_hex = hex_encode(Bytes(32, 0x11));
  auto r0 = consensus::initial_finalized_randomness(mainnet_network(), cid);

  BlockHeader h1;
  h1.prev_finalized_hash.fill(0x01);
  h1.height = 1;
  h1.timestamp = 100;
  h1.merkle_root.fill(0x02);
  h1.leader_pubkey.fill(0x03);
  h1.leader_signature.fill(0x04);
  h1.round = 0;
  h1.vrf_output.fill(0x05);

  BlockHeader h2 = h1;
  h2.height = 2;
  h2.prev_finalized_hash = h1.block_id();
  h2.timestamp = 200;
  h2.merkle_root.fill(0x06);
  h2.vrf_output.fill(0x07);

  auto a1 = consensus::advance_finalized_randomness(r0, h1);
  auto a2 = consensus::advance_finalized_randomness(a1, h2);

  auto b1 = consensus::advance_finalized_randomness(
      consensus::initial_finalized_randomness(mainnet_network(), cid), h1);
  auto b2 = consensus::advance_finalized_randomness(b1, h2);

  ASSERT_EQ(a1, b1);
  ASSERT_EQ(a2, b2);
  ASSERT_TRUE(a2 != r0);
}

void register_research_vrf_tests() {}
