#pragma once

#include <optional>

#include "utxo/tx.hpp"

namespace selfcoin {

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err = nullptr);
std::optional<Tx> build_unbond_tx(const OutPoint& bond_outpoint, const PubKey32& validator_pubkey,
                                  std::uint64_t bond_value, std::uint64_t fee,
                                  const Bytes& validator_privkey_32, std::string* err = nullptr);
std::optional<Tx> build_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, const Vote& vote_a,
                                 const Vote& vote_b, std::uint64_t fee = 0, std::string* err = nullptr);

}  // namespace selfcoin
