#include "test_framework.hpp"

#include <filesystem>

#include "codec/bytes.hpp"
#include "codec/varint.hpp"
#include "storage/db.hpp"
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
  h.leader_signature.fill(7);
  h.round = 3;
  h.vrf_proof = Bytes(64, 0x42);
  h.vrf_output.fill(0xA1);

  auto hser = h.serialize();
  auto hparsed = BlockHeader::parse(hser);
  ASSERT_TRUE(hparsed.has_value());
  ASSERT_EQ(hparsed->serialize(), hser);
}

TEST(test_slashing_record_db_roundtrip) {
  const std::string path = "/tmp/selfcoin_test_slashing_record_db";
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::SlashingRecord rec;
  rec.record_id.fill(0x11);
  rec.kind = storage::SlashingRecordKind::PROPOSER_EQUIVOCATION;
  rec.validator_pubkey.fill(0x22);
  rec.height = 55;
  rec.round = 3;
  rec.observed_height = 54;
  rec.object_a.fill(0x33);
  rec.object_b.fill(0x44);
  rec.txid.fill(0x55);

  ASSERT_TRUE(db.put_slashing_record(rec));
  const auto records = db.load_slashing_records();
  auto it = records.find(rec.record_id);
  ASSERT_TRUE(it != records.end());
  ASSERT_EQ(it->second.kind, rec.kind);
  ASSERT_EQ(it->second.validator_pubkey, rec.validator_pubkey);
  ASSERT_EQ(it->second.height, rec.height);
  ASSERT_EQ(it->second.round, rec.round);
  ASSERT_EQ(it->second.observed_height, rec.observed_height);
  ASSERT_EQ(it->second.object_a, rec.object_a);
  ASSERT_EQ(it->second.object_b, rec.object_b);
  ASSERT_EQ(it->second.txid, rec.txid);
}

TEST(test_committee_epoch_snapshot_db_roundtrip) {
  const std::string path = "/tmp/selfcoin_test_committee_epoch_snapshot_db";
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  storage::CommitteeEpochSnapshot snapshot;
  snapshot.epoch_start_height = 33;
  snapshot.epoch_seed.fill(0x44);
  PubKey32 a{};
  PubKey32 b{};
  a.fill(0x11);
  b.fill(0x22);
  snapshot.ordered_members = {a, b};

  ASSERT_TRUE(db.put_committee_epoch_snapshot(snapshot));
  const auto loaded = db.get_committee_epoch_snapshot(snapshot.epoch_start_height);
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(loaded->epoch_start_height, snapshot.epoch_start_height);
  ASSERT_EQ(loaded->epoch_seed, snapshot.epoch_seed);
  ASSERT_EQ(loaded->ordered_members, snapshot.ordered_members);

  const auto all = db.load_committee_epoch_snapshots();
  auto it = all.find(snapshot.epoch_start_height);
  ASSERT_TRUE(it != all.end());
  ASSERT_EQ(it->second.ordered_members, snapshot.ordered_members);
}

void register_codec_tests() {}
