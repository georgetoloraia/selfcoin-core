#pragma once

#include <optional>

#include "utxo/tx.hpp"

namespace selfcoin {

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err = nullptr);

}  // namespace selfcoin
