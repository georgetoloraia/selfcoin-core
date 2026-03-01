#include "utxo/signing.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

namespace selfcoin {

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err) {
  if (private_key_32.size() != 32) {
    if (err) *err = "private key must be 32 bytes";
    return std::nullopt;
  }
  std::array<std::uint8_t, 32> seed{};
  std::copy(private_key_32.begin(), private_key_32.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) {
    if (err) *err = "failed to derive keypair";
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
  std::array<std::uint8_t, 32> seed{};
  std::copy(validator_privkey_32.begin(), validator_privkey_32.end(), seed.begin());
  auto kp = crypto::keypair_from_seed32(seed);
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
