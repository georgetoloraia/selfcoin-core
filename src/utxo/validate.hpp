#pragma once

#include <optional>
#include <string>

#include "utxo/tx.hpp"

namespace selfcoin {

struct TxValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t fee{0};
};

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos);
std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index);
bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash = nullptr);
bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig = nullptr, PubKey32* out_pub = nullptr);

struct BlockValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t total_fees{0};
};

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward);
void apply_block_to_utxo(const Block& block, UtxoSet& utxos);

}  // namespace selfcoin
