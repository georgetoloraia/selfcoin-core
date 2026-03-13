#include "test_framework.hpp"

#include <ctime>

#include "address/address.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "mempool/mempool.hpp"
#include "policy/hashcash.hpp"
#include "utxo/signing.hpp"

using namespace selfcoin;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

TxOut p2pkh_out_for_pub(const PubKey32& pub, std::uint64_t value) {
  const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
  return TxOut{value, address::p2pkh_script_pubkey(pkh)};
}

std::optional<Tx> spend_one(const OutPoint& op, const TxOut& prev, const crypto::KeyPair& from,
                            const PubKey32& to_pub, std::uint64_t value_out) {
  std::vector<TxOut> outs;
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  outs.push_back(TxOut{value_out, address::p2pkh_script_pubkey(to_pkh)});
  return build_signed_p2pkh_tx_single_input(op, prev, from.private_key, outs);
}

}  // namespace

TEST(test_mempool_accept_reject_rules) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(1);
  const auto k2 = key_from_byte(2);

  OutPoint op1{};
  op1.txid.fill(0x11);
  op1.index = 0;
  TxOut prev1 = p2pkh_out_for_pub(k1.public_key, 1'000'000);
  view[op1] = UtxoEntry{prev1};

  auto tx_ok = spend_one(op1, prev1, k1, k2.public_key, 999'000);
  ASSERT_TRUE(tx_ok.has_value());

  std::string err;
  ASSERT_TRUE(mp.accept_tx(*tx_ok, view, &err));
  ASSERT_EQ(mp.size(), 1u);

  ASSERT_TRUE(!mp.accept_tx(*tx_ok, view, &err));

  auto tx_conflict = spend_one(op1, prev1, k1, k2.public_key, 998'500);
  ASSERT_TRUE(tx_conflict.has_value());
  ASSERT_TRUE(!mp.accept_tx(*tx_conflict, view, &err));

  OutPoint op2{};
  op2.txid.fill(0x22);
  op2.index = 0;
  TxOut prev2 = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op2] = UtxoEntry{prev2};
  auto tx_neg_fee = spend_one(op2, prev2, k1, k2.public_key, 20'000);
  ASSERT_TRUE(tx_neg_fee.has_value());
  ASSERT_TRUE(!mp.accept_tx(*tx_neg_fee, view, &err));

  Tx big;
  big.version = 1;
  big.lock_time = 0;
  big.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  big.outputs.push_back(TxOut{1, Bytes(120 * 1024, 0x01)});
  ASSERT_TRUE(!mp.accept_tx(big, view, &err));
}

TEST(test_mempool_selection_order_fee_then_txid) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(10);
  const auto k2 = key_from_byte(20);

  OutPoint op_a{};
  op_a.txid.fill(0xA1);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0xB1);
  op_b.index = 0;
  OutPoint op_c{};
  op_c.txid.fill(0xC1);
  op_c.index = 0;

  TxOut prev_a = p2pkh_out_for_pub(k1.public_key, 10000);
  TxOut prev_b = p2pkh_out_for_pub(k1.public_key, 10000);
  TxOut prev_c = p2pkh_out_for_pub(k1.public_key, 10000);

  view[op_a] = UtxoEntry{prev_a};
  view[op_b] = UtxoEntry{prev_b};
  view[op_c] = UtxoEntry{prev_c};

  auto tx1 = spend_one(op_a, prev_a, k1, k2.public_key, 9800);  // fee 200
  auto tx2 = spend_one(op_b, prev_b, k1, k2.public_key, 9700);  // fee 300
  auto tx3 = spend_one(op_c, prev_c, k1, k2.public_key, 9800);  // fee 200
  ASSERT_TRUE(tx1 && tx2 && tx3);

  std::string err;
  ASSERT_TRUE(mp.accept_tx(*tx1, view, &err));
  ASSERT_TRUE(mp.accept_tx(*tx2, view, &err));
  ASSERT_TRUE(mp.accept_tx(*tx3, view, &err));

  auto selected = mp.select_for_block(10, 1024 * 1024, view);
  ASSERT_EQ(selected.size(), 3u);

  ASSERT_EQ(selected[0].txid(), tx2->txid());

  const Hash32 t1 = tx1->txid();
  const Hash32 t3 = tx3->txid();
  if (t1 < t3) {
    ASSERT_EQ(selected[1].txid(), t1);
    ASSERT_EQ(selected[2].txid(), t3);
  } else {
    ASSERT_EQ(selected[1].txid(), t3);
    ASSERT_EQ(selected[2].txid(), t1);
  }
}

TEST(test_mempool_hashcash_policy_requires_stamp_for_low_fee_txs) {
  mempool::Mempool mp;
  mp.set_network(mainnet_network());
  mp.set_hashcash_config(policy::HashcashConfig{
      .enabled = true,
      .base_bits = 10,
      .max_bits = 10,
      .epoch_seconds = 60,
      .fee_exempt_min = 500,
      .pressure_tx_threshold = 1000,
      .pressure_step_txs = 500,
      .pressure_bits_per_step = 1,
      .large_tx_bytes = 4096,
      .large_tx_extra_bits = 1,
  });
  mempool::UtxoView view;

  const auto k1 = key_from_byte(3);
  const auto k2 = key_from_byte(4);

  OutPoint op1{};
  op1.txid.fill(0x31);
  op1.index = 0;
  TxOut prev1 = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op1] = UtxoEntry{prev1};

  auto tx = spend_one(op1, prev1, k1, k2.public_key, 9'800);  // fee 200, below exempt min
  ASSERT_TRUE(tx.has_value());

  std::string err;
  ASSERT_TRUE(!mp.accept_tx(*tx, view, &err));
  ASSERT_TRUE(err.find("hashcash stamp required") != std::string::npos);

  const auto now_unix = static_cast<std::uint64_t>(std::time(nullptr));
  ASSERT_TRUE(policy::apply_hashcash_stamp(&*tx, mainnet_network(),
                                           policy::HashcashConfig{
                                               .enabled = true,
                                               .base_bits = 10,
                                               .max_bits = 10,
                                               .epoch_seconds = 60,
                                               .fee_exempt_min = 500,
                                               .pressure_tx_threshold = 1000,
                                               .pressure_step_txs = 500,
                                               .pressure_bits_per_step = 1,
                                               .large_tx_bytes = 4096,
                                               .large_tx_extra_bits = 1,
                                           },
                                           10, now_unix, 500'000, &err));
  auto reparsed = Tx::parse(tx->serialize());
  ASSERT_TRUE(reparsed.has_value());
  ASSERT_TRUE(reparsed->hashcash.has_value());
  ASSERT_EQ(reparsed->hashcash->bits, 10u);
  ASSERT_TRUE(mp.accept_tx(*reparsed, view, &err));
}

void register_mempool_tests() {}
