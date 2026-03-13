#include "test_framework.hpp"

#include "codec/bytes.hpp"
#include "codec/varint.hpp"
#include "utxo/tx.hpp"

using namespace selfcoin;

TEST(test_varint_roundtrip_and_minimality) {
  const std::vector<std::uint64_t> values = {0, 1, 2, 127, 128, 255, 300, 16384, (1ULL << 32), UINT64_MAX};
  for (auto v : values) {
    auto enc = codec::encode_uleb128(v);
    ASSERT_TRUE(codec::is_minimal_uleb128_encoding(enc));
    size_t off = 0;
    auto dec = codec::decode_uleb128(enc, off, true);
    ASSERT_TRUE(dec.has_value());
    ASSERT_EQ(dec.value(), v);
    ASSERT_EQ(off, enc.size());
  }

  Bytes non_minimal = {0x80, 0x00};
  size_t off = 0;
  ASSERT_TRUE(!codec::decode_uleb128(non_minimal, off, true).has_value());
}

TEST(test_tx_and_blockheader_roundtrip) {
  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{zero_hash(), 7, Bytes{0x40}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{123, Bytes{0x76, 0xA9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xAC}});

  auto ser = tx.serialize();
  auto parsed = Tx::parse(ser);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->serialize(), ser);

  BlockHeader h;
  h.prev_finalized_hash = tx.txid();
  h.height = 5;
  h.timestamp = 123456;
  h.merkle_root = tx.txid();
  h.leader_pubkey.fill(9);
  h.round = 3;
  h.vrf_proof = Bytes(64, 0x42);
  h.vrf_output.fill(0xA1);

  auto hser = h.serialize();
  auto hparsed = BlockHeader::parse(hser);
  ASSERT_TRUE(hparsed.has_value());
  ASSERT_EQ(hparsed->serialize(), hser);
}

void register_codec_tests() {}
