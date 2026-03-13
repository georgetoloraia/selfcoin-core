#include "utxo/signing.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

namespace selfcoin {

namespace {

std::optional<crypto::KeyPair> keypair_from_private_key(const Bytes& private_key_32, std::string* err) {
  if (private_key_32.size() != 32) {
    if (err) *err = "private key must be 32 bytes";
    return std::nullopt;
  }
  std::array<std::uint8_t, 32> seed{};
  std::copy(private_key_32.begin(), private_key_32.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value() && err) *err = "failed to derive keypair";
  return kp;
}

}  // namespace

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err) {
  auto kp = keypair_from_private_key(private_key_32, err);
  if (!kp.has_value()) {
    return std::nullopt;
  }

  std::array<std::uint8_t, 20> expected_pkh{};
  if (!is_p2pkh_script_pubkey(prev_out.script_pubkey, &expected_pkh)) {
    if (err) *err = "prev output is not P2PKH";
    return std::nullopt;
  }
  const auto got_pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  if (!std::equal(got_pkh.begin(), got_pkh.end(), expected_pkh.begin())) {
    if (err) *err = "private key does not match prev output pubkey hash";
    return std::nullopt;
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{prev_outpoint.txid, prev_outpoint.index, Bytes{}, 0xFFFFFFFF});
  tx.outputs = outputs;

  auto msg = signing_message_for_input(tx, 0);
  if (!msg.has_value()) {
    if (err) *err = "failed to build sighash";
    return std::nullopt;
  }
  auto sig = crypto::ed25519_sign(*msg, private_key_32);
  if (!sig.has_value()) {
    if (err) *err = "failed to sign";
    return std::nullopt;
  }

  Bytes script_sig;
  script_sig.reserve(98);
  script_sig.push_back(0x40);
  script_sig.insert(script_sig.end(), sig->begin(), sig->end());
  script_sig.push_back(0x20);
  script_sig.insert(script_sig.end(), kp->public_key.begin(), kp->public_key.end());
  tx.inputs[0].script_sig = script_sig;

  return tx;
}

std::optional<Tx> build_signed_p2pkh_tx_multi_input(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                    const Bytes& private_key_32,
                                                    const std::vector<TxOut>& outputs,
                                                    std::string* err) {
  if (prevs.empty()) {
    if (err) *err = "at least one prev output is required";
    return std::nullopt;
  }
  auto kp = keypair_from_private_key(private_key_32, err);
  if (!kp.has_value()) {
    return std::nullopt;
  }

  const auto got_pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  for (const auto& [prev_outpoint, prev_out] : prevs) {
    (void)prev_outpoint;
    std::array<std::uint8_t, 20> expected_pkh{};
    if (!is_p2pkh_script_pubkey(prev_out.script_pubkey, &expected_pkh)) {
      if (err) *err = "prev output is not P2PKH";
      return std::nullopt;
    }
    if (!std::equal(got_pkh.begin(), got_pkh.end(), expected_pkh.begin())) {
      if (err) *err = "private key does not match prev output pubkey hash";
      return std::nullopt;
    }
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.outputs = outputs;
  tx.inputs.reserve(prevs.size());
  for (const auto& [prev_outpoint, _] : prevs) {
    tx.inputs.push_back(TxIn{prev_outpoint.txid, prev_outpoint.index, Bytes{}, 0xFFFFFFFF});
  }

  for (std::uint32_t i = 0; i < tx.inputs.size(); ++i) {
    auto msg = signing_message_for_input(tx, i);
    if (!msg.has_value()) {
      if (err) *err = "failed to build sighash";
      return std::nullopt;
    }
    auto sig = crypto::ed25519_sign(*msg, private_key_32);
    if (!sig.has_value()) {
      if (err) *err = "failed to sign";
      return std::nullopt;
    }
    Bytes script_sig;
    script_sig.reserve(98);
    script_sig.push_back(0x40);
    script_sig.insert(script_sig.end(), sig->begin(), sig->end());
    script_sig.push_back(0x20);
    script_sig.insert(script_sig.end(), kp->public_key.begin(), kp->public_key.end());
    tx.inputs[i].script_sig = script_sig;
  }

  return tx;
}

std::optional<Tx> build_unbond_tx(const OutPoint& bond_outpoint, const PubKey32& validator_pubkey,
                                  std::uint64_t bond_value, std::uint64_t fee,
                                  const Bytes& validator_privkey_32, std::string* err) {
  if (bond_value < fee) {
    if (err) *err = "fee exceeds bond value";
    return std::nullopt;
  }
  if (validator_privkey_32.size() != 32) {
    if (err) *err = "private key must be 32 bytes";
    return std::nullopt;
  }
  auto kp = keypair_from_private_key(validator_privkey_32, err);
  if (!kp.has_value() || kp->public_key != validator_pubkey) {
    if (err) *err = "private key/pubkey mismatch";
    return std::nullopt;
  }

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_outpoint.txid, bond_outpoint.index, Bytes{}, 0xFFFFFFFF});
  Bytes spk{'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  spk.insert(spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  tx.outputs.push_back(TxOut{bond_value - fee, spk});

  auto msg = unbond_message_for_input(tx, 0);
  if (!msg.has_value()) {
    if (err) *err = "unbond sighash failed";
    return std::nullopt;
  }
  auto sig = crypto::ed25519_sign(*msg, validator_privkey_32);
  if (!sig.has_value()) {
    if (err) *err = "unbond sign failed";
    return std::nullopt;
  }
  Bytes script_sig;
  script_sig.reserve(98);
  script_sig.push_back(0x40);
  script_sig.insert(script_sig.end(), sig->begin(), sig->end());
  script_sig.push_back(0x20);
  script_sig.insert(script_sig.end(), validator_pubkey.begin(), validator_pubkey.end());
  tx.inputs[0].script_sig = script_sig;

  return tx;
}

std::optional<Tx> build_validator_join_request_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err) {
  if (prev_out.value < bond_amount + fee) {
    if (err) *err = "insufficient prev value for bond + fee";
    return std::nullopt;
  }
  auto pop = crypto::ed25519_sign(validator_join_request_pop_message(validator_pubkey, payout_pubkey), validator_privkey_32);
  if (!pop.has_value()) {
    if (err) *err = "failed to sign join request proof";
    return std::nullopt;
  }

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  Bytes req_spk{'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  req_spk.insert(req_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  req_spk.insert(req_spk.end(), payout_pubkey.begin(), payout_pubkey.end());
  req_spk.insert(req_spk.end(), pop->begin(), pop->end());

  std::vector<TxOut> outputs{TxOut{bond_amount, reg_spk}, TxOut{0, req_spk}};
  const std::uint64_t change = prev_out.value - bond_amount - fee;
  if (change > 0) outputs.push_back(TxOut{change, change_script_pubkey});
  return build_signed_p2pkh_tx_single_input(prev_outpoint, prev_out, funding_privkey_32, outputs, err);
}

std::optional<Tx> build_validator_join_approval_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                   const Bytes& funding_privkey_32, const Hash32& request_txid,
                                                   const PubKey32& validator_pubkey,
                                                   const Bytes& approver_privkey_32,
                                                   const Bytes& change_script_pubkey, std::uint64_t fee,
                                                   std::string* err) {
  if (prev_out.value < fee) {
    if (err) *err = "fee exceeds prev value";
    return std::nullopt;
  }
  auto kp = keypair_from_private_key(approver_privkey_32, err);
  if (!kp.has_value()) {
    return std::nullopt;
  }
  auto approval_sig = crypto::ed25519_sign(validator_join_approval_message(request_txid, validator_pubkey), approver_privkey_32);
  if (!approval_sig.has_value()) {
    if (err) *err = "failed to sign validator join approval";
    return std::nullopt;
  }

  Bytes approve_spk{'S', 'C', 'V', 'A', 'L', 'J', 'A', 'P'};
  approve_spk.insert(approve_spk.end(), request_txid.begin(), request_txid.end());
  approve_spk.insert(approve_spk.end(), validator_pubkey.begin(), validator_pubkey.end());
  approve_spk.insert(approve_spk.end(), kp->public_key.begin(), kp->public_key.end());
  approve_spk.insert(approve_spk.end(), approval_sig->begin(), approval_sig->end());

  std::vector<TxOut> outputs{TxOut{0, approve_spk}};
  const std::uint64_t change = prev_out.value - fee;
  if (change > 0) outputs.push_back(TxOut{change, change_script_pubkey});
  return build_signed_p2pkh_tx_single_input(prev_outpoint, prev_out, funding_privkey_32, outputs, err);
}

std::optional<Tx> build_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, const Vote& vote_a,
                                 const Vote& vote_b, std::uint64_t fee, std::string* err) {
  if (bond_value < fee) {
    if (err) *err = "fee exceeds bond value";
    return std::nullopt;
  }

  codec::ByteWriter ev;
  ev.u64le(vote_a.height);
  ev.u32le(vote_a.round);
  ev.bytes_fixed(vote_a.block_id);
  ev.bytes_fixed(vote_a.validator_pubkey);
  ev.bytes_fixed(vote_a.signature);
  ev.u64le(vote_b.height);
  ev.u32le(vote_b.round);
  ev.bytes_fixed(vote_b.block_id);
  ev.bytes_fixed(vote_b.validator_pubkey);
  ev.bytes_fixed(vote_b.signature);
  Bytes evidence_blob = ev.take();

  codec::ByteWriter ss;
  ss.bytes(Bytes{'S', 'C', 'S', 'L', 'A', 'S', 'H'});
  ss.varbytes(evidence_blob);
  Bytes script_sig = ss.take();

  const Hash32 evh = crypto::sha256d(evidence_blob);
  Bytes burn{'S', 'C', 'B', 'U', 'R', 'N'};
  burn.insert(burn.end(), evh.begin(), evh.end());

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{bond_outpoint.txid, bond_outpoint.index, script_sig, 0xFFFFFFFF});
  tx.outputs.push_back(TxOut{bond_value - fee, burn});
  return tx;
}

}  // namespace selfcoin
