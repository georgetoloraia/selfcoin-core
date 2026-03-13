#pragma once

#include <functional>
#include <optional>
#include <string>

#include "consensus/validators.hpp"
#include "utxo/tx.hpp"

namespace selfcoin {

struct TxValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t fee{0};
};

struct SpecialValidationContext {
  const consensus::ValidatorRegistry* validators{nullptr};
  std::uint64_t current_height{0};
  bool enforce_variable_bond_range{false};
  std::uint64_t min_bond_amount{BOND_AMOUNT};
  std::uint64_t max_bond_amount{BOND_AMOUNT};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  std::function<bool(const PubKey32&, std::uint64_t, std::uint32_t)> is_committee_member;
};

struct SlashEvidence {
  Vote a;
  Vote b;
  Bytes raw_blob;
};

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos,
                               const SpecialValidationContext* ctx = nullptr);
std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index);
std::optional<Bytes> unbond_message_for_input(const Tx& tx, std::uint32_t input_index);
Bytes validator_join_request_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey);
Bytes validator_join_approval_message(const Hash32& request_txid, const PubKey32& validator_pubkey);
bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash = nullptr);
bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig = nullptr, PubKey32* out_pub = nullptr);
bool is_supported_base_layer_output_script(const Bytes& script_pubkey);
bool parse_slash_script_sig(const Bytes& script_sig, SlashEvidence* out);

struct BlockValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t total_fees{0};
};

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward,
                                         const SpecialValidationContext* ctx = nullptr,
                                         const std::vector<PubKey32>* reward_signers = nullptr);
void apply_block_to_utxo(const Block& block, UtxoSet& utxos);

}  // namespace selfcoin
