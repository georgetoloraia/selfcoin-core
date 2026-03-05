#include "test_framework.hpp"

#include <array>
#include <stdexcept>

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

TEST(test_vrf_prove_verify_roundtrip) {
  auto kp = key_from_byte(7);
  Bytes msg{1, 2, 3, 4, 5};
  auto p = crypto::vrf_prove(kp.private_key, msg);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(crypto::vrf_verify(kp.public_key, msg, *p));
}

TEST(test_vrf_wrong_seed_fails) {
  auto kp = key_from_byte(8);
  auto p = crypto::vrf_prove(kp.private_key, Bytes{9});
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(!crypto::vrf_verify(kp.public_key, Bytes{10}, *p));
}

TEST(test_vrf_wrong_pubkey_fails) {
  auto kp1 = key_from_byte(9);
  auto kp2 = key_from_byte(10);
  auto p = crypto::vrf_prove(kp1.private_key, Bytes{4, 4, 4});
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(!crypto::vrf_verify(kp2.public_key, Bytes{4, 4, 4}, *p));
}

void register_vrf_tests() {}
