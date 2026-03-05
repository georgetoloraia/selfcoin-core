#include "test_framework.hpp"

#include "common/network.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"

using namespace selfcoin;

TEST(test_version_message_v07_roundtrip) {
  p2p::VersionMsg v;
  v.proto_version = 7;
  v.network_id = mainnet_network().network_id;
  v.feature_flags = 0xA5A5;
  v.services = 11;
  v.timestamp = 22;
  v.nonce = 33;
  v.node_software_version = "selfcoin-tests/0.7";
  v.start_height = 44;
  v.start_hash.fill(0x55);

  const Bytes b = p2p::ser_version(v);
  auto d = p2p::de_version(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->proto_version, v.proto_version);
  ASSERT_EQ(d->network_id, v.network_id);
  ASSERT_EQ(d->feature_flags, v.feature_flags);
  ASSERT_EQ(d->services, v.services);
  ASSERT_EQ(d->timestamp, v.timestamp);
  ASSERT_EQ(d->nonce, v.nonce);
  ASSERT_EQ(d->node_software_version, v.node_software_version);
  ASSERT_EQ(d->start_height, v.start_height);
  ASSERT_EQ(d->start_hash, v.start_hash);
}

TEST(test_prefix_classification) {
  ASSERT_EQ(p2p::classify_prefix(Bytes{'H', 'T', 'T', 'P'}), p2p::PrefixKind::HTTP);
  ASSERT_EQ(p2p::classify_prefix(Bytes{'{', '"', 'a'}), p2p::PrefixKind::JSON);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x16, 0x03, 0x01, 0x00}), p2p::PrefixKind::TLS);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x01, 0x02, 0x03}), p2p::PrefixKind::UNKNOWN);
}

void register_p2p_tests() {}
