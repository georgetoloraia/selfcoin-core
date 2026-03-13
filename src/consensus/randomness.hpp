#pragma once

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::consensus {

Hash32 initial_finalized_randomness(const NetworkConfig& network, const ChainId& chain_id);
Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const BlockHeader& header);

}  // namespace selfcoin::consensus
