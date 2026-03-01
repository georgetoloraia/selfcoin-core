#include "test_framework.hpp"

#include "address/address.hpp"

using namespace selfcoin;

TEST(test_address_encode_decode_checksum) {
  std::array<std::uint8_t, 20> pkh{};
  for (size_t i = 0; i < pkh.size(); ++i) pkh[i] = static_cast<std::uint8_t>(i);

  auto addr = address::encode_p2pkh("tsc", pkh);
  ASSERT_TRUE(addr.has_value());

  auto dec = address::decode(*addr);
  ASSERT_TRUE(dec.has_value());
  ASSERT_EQ(dec->hrp, "tsc");
  ASSERT_EQ(dec->addr_type, 0x00);
  ASSERT_EQ(dec->pubkey_hash, pkh);

  std::string bad = *addr;
  bad.back() = (bad.back() == 'a') ? 'b' : 'a';
  ASSERT_TRUE(!address::decode(bad).has_value());
}

void register_address_tests() {}
