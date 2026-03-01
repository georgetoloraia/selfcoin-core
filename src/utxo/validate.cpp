#include "utxo/validate.hpp"

#include <algorithm>
#include <set>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace selfcoin {

bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash) {
  if (script_pubkey.size() != 25) return false;
  if (script_pubkey[0] != 0x76 || script_pubkey[1] != 0xA9 || script_pubkey[2] != 0x14 ||
      script_pubkey[23] != 0x88 || script_pubkey[24] != 0xAC) {
    return false;
  }
  if (out_hash) {
    std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23, out_hash->begin());
  }
  return true;
}

bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig, PubKey32* out_pub) {
  if (script_sig.size() != 98) return false;
  if (script_sig[0] != 0x40 || script_sig[65] != 0x20) return false;
  if (out_sig) std::copy(script_sig.begin() + 1, script_sig.begin() + 65, out_sig->begin());
  if (out_pub) std::copy(script_sig.begin() + 66, script_sig.end(), out_pub->begin());
  return true;
}

std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  Tx signing = tx;
  for (auto& in : signing.inputs) {
    in.script_sig.clear();
  }
  const Hash32 txh = crypto::sha256d(signing.serialize());

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'I', 'G', '-', 'V', '0'});
  w.u32le(input_index);
  w.bytes_fixed(txh);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos) {
  if (tx.version != 1) return {false, "unsupported tx version", 0};
  if (tx.lock_time != 0) return {false, "lock_time must be 0 in v0", 0};
  if (tx.inputs.empty() || tx.outputs.empty()) return {false, "tx inputs/outputs empty", 0};

  if (tx_index_in_block == 0) {
    if (tx.inputs.size() != 1) return {false, "coinbase must have one input", 0};
    const auto& in = tx.inputs[0];
    if (in.prev_txid != zero_hash()) return {false, "coinbase prev_txid invalid", 0};
    if (in.prev_index != 0xFFFFFFFF) return {false, "coinbase prev_index invalid", 0};
    if (in.sequence != 0xFFFFFFFF) return {false, "coinbase sequence invalid", 0};
    if (in.script_sig.size() > 100) return {false, "coinbase script_sig > 100", 0};
    return {true, "", 0};
  }

  std::uint64_t in_sum = 0;
  std::uint64_t out_sum = 0;
  std::set<OutPoint> seen_inputs;
  for (const auto& out : tx.outputs) out_sum += out.value;

  for (std::uint32_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    if (in.sequence != 0xFFFFFFFF) return {false, "sequence must be FFFFFFFF", 0};
    OutPoint op{in.prev_txid, in.prev_index};
    if (!seen_inputs.insert(op).second) return {false, "duplicate input outpoint", 0};
    auto it = utxos.find(op);
    if (it == utxos.end()) return {false, "missing utxo", 0};

    std::array<std::uint8_t, 20> pkh{};
    if (!is_p2pkh_script_pubkey(it->second.out.script_pubkey, &pkh)) {
      return {false, "unsupported prev script_pubkey", 0};
    }

    Sig64 sig{};
    PubKey32 pub{};
    if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad script_sig", 0};
    const auto derived = crypto::h160(Bytes(pub.begin(), pub.end()));
    if (!std::equal(derived.begin(), derived.end(), pkh.begin())) {
      return {false, "pubkey hash mismatch", 0};
    }

    const auto msg = signing_message_for_input(tx, i);
    if (!msg.has_value()) return {false, "sighash failed", 0};
    if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "signature invalid", 0};

    in_sum += it->second.out.value;
  }

  if (in_sum < out_sum) return {false, "negative fee", 0};
  return {true, "", in_sum - out_sum};
}

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward) {
  if (block.txs.empty()) return {false, "block has no tx", 0};
  UtxoSet work = base_utxos;

  std::uint64_t fees = 0;
  for (size_t i = 0; i < block.txs.size(); ++i) {
    auto r = validate_tx(block.txs[i], i, work);
    if (!r.ok) return {false, "tx invalid at index " + std::to_string(i) + ": " + r.error, 0};
    fees += r.fee;

    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        work.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      work[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }

  std::uint64_t coinbase_sum = 0;
  for (const auto& out : block.txs[0].outputs) coinbase_sum += out.value;
  if (coinbase_sum != block_reward + fees) {
    return {false, "coinbase sum mismatch", 0};
  }

  return {true, "", fees};
}

void apply_block_to_utxo(const Block& block, UtxoSet& utxos) {
  for (size_t i = 0; i < block.txs.size(); ++i) {
    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        utxos.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      utxos[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }
}

}  // namespace selfcoin
