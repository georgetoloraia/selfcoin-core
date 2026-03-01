#include "utxo/signing.hpp"

#include <algorithm>

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

}  // namespace selfcoin
