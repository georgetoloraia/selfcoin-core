#include "test_framework.hpp"

#include "address/address.hpp"
#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace selfcoin;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp) throw std::runtime_error("key gen failed");
  return *kp;
}

Bytes reg_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

Bytes unb_script(const PubKey32& pub) {
  Bytes s{'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  s.insert(s.end(), pub.begin(), pub.end());
  return s;
}

}  // namespace

TEST(test_scval_scripts_detection) {
  const auto kp = key_from_byte(9);
  Bytes reg = reg_script(kp.public_key);
  Bytes unb = unb_script(kp.public_key);
  PubKey32 out{};
  ASSERT_TRUE(is_validator_register_script(reg, &out));
  ASSERT_EQ(out, kp.public_key);
  ASSERT_TRUE(is_validator_unbond_script(unb, &out));
  ASSERT_EQ(out, kp.public_key);
}

TEST(test_unbond_signature_and_rule_validation) {
  const auto kp = key_from_byte(10);
  OutPoint bond_op{};
  bond_op.txid.fill(0xA0);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.advance_height(WARMUP_BLOCKS + 2);

  std::string err;
  auto tx = build_unbond_tx(bond_op, kp.public_key, BOND_AMOUNT, 1000, kp.private_key, &err);
  ASSERT_TRUE(tx.has_value());

  SpecialValidationContext ctx{&vr, WARMUP_BLOCKS + 5};
  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

TEST(test_unbond_delay_enforced) {
  const auto kp = key_from_byte(11);
  OutPoint unb_op{};
  unb_op.txid.fill(0xB0);
  unb_op.index = 0;

  UtxoSet view;
  view[unb_op] = UtxoEntry{TxOut{BOND_AMOUNT - 1000, unb_script(kp.public_key)}};

  consensus::ValidatorRegistry vr;
  OutPoint bond_op{};
  bond_op.txid.fill(0xA1);
  bond_op.index = 0;
  vr.register_bond(kp.public_key, bond_op, 1);
  vr.request_unbond(kp.public_key, 50);

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{unb_op.txid, unb_op.index, Bytes{}, 0xFFFFFFFF});
  auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 2000, address::p2pkh_script_pubkey(pkh)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  SpecialValidationContext early{&vr, 50 + UNBOND_DELAY_BLOCKS - 1};
  auto r1 = validate_tx(tx, 1, view, &early);
  ASSERT_TRUE(!r1.ok);

  SpecialValidationContext late{&vr, 50 + UNBOND_DELAY_BLOCKS};
  auto r2 = validate_tx(tx, 1, view, &late);
  ASSERT_TRUE(r2.ok);
}

TEST(test_slash_evidence_parsing_and_validation) {
  const auto kp = key_from_byte(12);
  OutPoint bond_op{};
  bond_op.txid.fill(0xC0);
  bond_op.index = 1;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  Vote a;
  a.height = 100;
  a.round = 2;
  a.block_id.fill(0x11);
  a.validator_pubkey = kp.public_key;
  auto siga = crypto::ed25519_sign(Bytes(a.block_id.begin(), a.block_id.end()), kp.private_key);
  ASSERT_TRUE(siga.has_value());
  a.signature = *siga;

  Vote b = a;
  b.block_id.fill(0x22);
  auto sigb = crypto::ed25519_sign(Bytes(b.block_id.begin(), b.block_id.end()), kp.private_key);
  ASSERT_TRUE(sigb.has_value());
  b.signature = *sigb;

  std::string err;
  auto tx = build_slash_tx(bond_op, BOND_AMOUNT, a, b, 0, &err);
  ASSERT_TRUE(tx.has_value());

  SlashEvidence e;
  ASSERT_TRUE(parse_slash_script_sig(tx->inputs[0].script_sig, &e));

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 10);
  vr.advance_height(200);
  SpecialValidationContext ctx{&vr, 200};

  auto r = validate_tx(*tx, 1, view, &ctx);
  ASSERT_TRUE(r.ok);
}

TEST(test_scvalreg_not_spendable_as_normal_p2pkh) {
  const auto kp = key_from_byte(13);
  OutPoint bond_op{};
  bond_op.txid.fill(0xD0);
  bond_op.index = 0;

  UtxoSet view;
  view[bond_op] = UtxoEntry{TxOut{BOND_AMOUNT, reg_script(kp.public_key)}};

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_op.txid, bond_op.index, Bytes{}, 0xFFFFFFFF});
  auto pkh = crypto::h160(Bytes(kp.public_key.begin(), kp.public_key.end()));
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 1000, address::p2pkh_script_pubkey(pkh)});

  auto msg = signing_message_for_input(tx, 0);
  ASSERT_TRUE(msg.has_value());
  auto sig = crypto::ed25519_sign(*msg, kp.private_key);
  ASSERT_TRUE(sig.has_value());
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig->begin(), sig->end());
  ss.push_back(0x20);
  ss.insert(ss.end(), kp.public_key.begin(), kp.public_key.end());
  tx.inputs[0].script_sig = ss;

  consensus::ValidatorRegistry vr;
  vr.register_bond(kp.public_key, bond_op, 1);
  SpecialValidationContext ctx{&vr, 10};

  auto r = validate_tx(tx, 1, view, &ctx);
  ASSERT_TRUE(!r.ok);
}

void register_bonding_tests() {}
