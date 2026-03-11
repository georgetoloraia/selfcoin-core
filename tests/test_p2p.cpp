#include "test_framework.hpp"

#include "common/network.hpp"
#include "codec/bytes.hpp"
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

TEST(test_version_message_accepts_bootstrap_fingerprint_length) {
  p2p::VersionMsg v;
  v.proto_version = PROTOCOL_VERSION;
  v.network_id = mainnet_network().network_id;
  v.feature_flags = 0;
  v.services = 0;
  v.timestamp = 1;
  v.nonce = 2;
  v.node_software_version =
      "selfcoin-node/0.7;genesis=ad1eb4a5a0b1ee0e2f062539542b972d35bd216edd702e345fae76475a759a77;"
      "network_id=192d26a3e3decbc1919afbbe9d849149;cv=7;"
      "bootstrap_validator=f7b672871002c9286fab332251a82e2c7339dbf21fc8e8350ed1bcbeb671775f;"
      "validator_pubkey=be71f29a6c3fa5f32cff5a2977ca38394a386183e48046190a52bcaaca5b1090";
  v.start_height = 3;
  v.start_hash.fill(0x44);

  const Bytes b = p2p::ser_version(v);
  auto d = p2p::de_version(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->node_software_version, v.node_software_version);
}

TEST(test_prefix_classification) {
  ASSERT_EQ(p2p::classify_prefix(Bytes{'H', 'T', 'T', 'P'}), p2p::PrefixKind::HTTP);
  ASSERT_EQ(p2p::classify_prefix(Bytes{'{', '"', 'a'}), p2p::PrefixKind::JSON);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x16, 0x03, 0x01, 0x00}), p2p::PrefixKind::TLS);
  ASSERT_EQ(p2p::classify_prefix(Bytes{0x01, 0x02, 0x03}), p2p::PrefixKind::UNKNOWN);
}

TEST(test_propose_codec_roundtrip_with_vrf_extensions) {
  p2p::ProposeMsg p;
  p.height = 10;
  p.round = 3;
  p.prev_finalized_hash.fill(0x11);
  p.block_bytes = Bytes{0xAA, 0xBB, 0xCC};
  p.vrf_proof = Bytes{1, 2, 3, 4};
  p.vrf_output.fill(0x22);

  const Bytes b = p2p::ser_propose(p, true);
  auto d = p2p::de_propose(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->height, p.height);
  ASSERT_EQ(d->round, p.round);
  ASSERT_EQ(d->prev_finalized_hash, p.prev_finalized_hash);
  ASSERT_EQ(d->block_bytes, p.block_bytes);
  ASSERT_EQ(d->vrf_proof, p.vrf_proof);
  ASSERT_EQ(d->vrf_output, p.vrf_output);
}

TEST(test_vote_codec_roundtrip_with_vrf_extensions) {
  p2p::VoteMsg m;
  m.vote.height = 7;
  m.vote.round = 2;
  m.vote.block_id.fill(0x31);
  m.vote.validator_pubkey.fill(0x41);
  m.vote.signature.fill(0x51);
  m.vrf_proof = Bytes{9, 8, 7};
  m.vrf_output.fill(0x61);

  const Bytes b = p2p::ser_vote(m, true);
  auto d = p2p::de_vote(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->vote.height, m.vote.height);
  ASSERT_EQ(d->vote.round, m.vote.round);
  ASSERT_EQ(d->vote.block_id, m.vote.block_id);
  ASSERT_EQ(d->vote.validator_pubkey, m.vote.validator_pubkey);
  ASSERT_EQ(d->vote.signature, m.vote.signature);
  ASSERT_EQ(d->vrf_proof, m.vrf_proof);
  ASSERT_EQ(d->vrf_output, m.vrf_output);
}

TEST(test_version_message_rejects_oversized_software_string) {
  codec::ByteWriter w;
  w.u32le(PROTOCOL_VERSION);
  w.bytes_fixed(mainnet_network().network_id);
  w.u64le(0);
  w.u64le(0);
  w.u64le(0);
  w.u32le(0);
  Bytes sw(600, 'x');
  w.varbytes(sw);
  w.u64le(0);
  Hash32 zero{};
  w.bytes_fixed(zero);
  ASSERT_TRUE(!p2p::de_version(w.take()).has_value());
}

TEST(test_tx_message_rejects_oversized_payload) {
  codec::ByteWriter w;
  Bytes tx_bytes(300 * 1024, 0xAA);
  w.varbytes(tx_bytes);
  ASSERT_TRUE(!p2p::de_tx(w.take()).has_value());
}

void register_p2p_tests() {}
