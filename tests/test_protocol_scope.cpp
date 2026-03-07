#include "test_framework.hpp"

#include "address/address.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

using namespace selfcoin;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("keygen failed");
  return *kp;
}

Bytes make_p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

Bytes reg_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

Bytes unbond_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

Bytes burn_script(const Hash32& h) {
  Bytes s{'S', 'C', 'B', 'U', 'R', 'N'};
  s.insert(s.end(), h.begin(), h.end());
  return s;
}

Tx make_spend_tx(const OutPoint& op, const TxOut& prev_out, const crypto::KeyPair& kp, const std::vector<TxOut>& outputs) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{op.txid, op.index, Bytes{}, 0xFFFFFFFF});
  tx.outputs = outputs;
  auto msg = signing_message_for_input(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("sighash failed");
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  if (!sig.has_value()) throw std::runtime_error("sign failed");
  tx.inputs[0].script_sig = make_p2pkh_script_sig(*sig, kp.public_key);
  (void)prev_out;
  return tx;
}

}  // namespace

TEST(test_protocol_scope_rejects_non_v1_tx) {
  Tx tx;
  tx.version = 2;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{zero_hash(), 0xFFFFFFFF, Bytes{}, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{1, Bytes{0x51}});
  auto r = validate_tx(tx, 0, {});
  ASSERT_TRUE(!r.ok);
}

TEST(test_protocol_scope_rejects_nonzero_lock_time) {
  const auto kp = key_from_byte(21);
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  OutPoint op{};
  op.txid.fill(0xA1);
  op.index = 0;
  TxOut prev_out{50'000, address::p2pkh_script_pubkey(pkh)};
  UtxoSet view;
  view[op] = UtxoEntry{prev_out};

  auto tx = make_spend_tx(op, prev_out, kp, {TxOut{49'000, address::p2pkh_script_pubkey(pkh)}});
  tx.lock_time = 1;
  auto r = validate_tx(tx, 1, view, nullptr);
  ASSERT_TRUE(!r.ok);
}

TEST(test_protocol_scope_rejects_unsupported_output_script) {
  const auto kp = key_from_byte(22);
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  OutPoint op{};
  op.txid.fill(0xA2);
  op.index = 0;
  TxOut prev_out{50'000, address::p2pkh_script_pubkey(pkh)};
  UtxoSet view;
  view[op] = UtxoEntry{prev_out};

  auto tx = make_spend_tx(op, prev_out, kp, {TxOut{49'000, Bytes{0x51}}});
  auto r = validate_tx(tx, 1, view, nullptr);
  ASSERT_TRUE(!r.ok);
  ASSERT_TRUE(r.error.find("unsupported script_pubkey") != std::string::npos);
}

TEST(test_protocol_scope_allows_settlement_output_scripts) {
  const auto kp = key_from_byte(23);
  const auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));

  ASSERT_TRUE(is_supported_base_layer_output_script(address::p2pkh_script_pubkey(pkh)));
  ASSERT_TRUE(is_supported_base_layer_output_script(reg_script(kp.public_key)));
  ASSERT_TRUE(is_supported_base_layer_output_script(unbond_script(kp.public_key)));

  Hash32 h{};
  h.fill(0x42);
  ASSERT_TRUE(is_supported_base_layer_output_script(burn_script(h)));
}

void register_protocol_scope_tests() {}
