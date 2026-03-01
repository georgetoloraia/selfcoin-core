#include "common/network.hpp"

namespace selfcoin {
namespace {

const NetworkConfig kDevnet{
    .name = "devnet",
    .magic = MAGIC,
    .protocol_version = PROTOCOL_VERSION,
    .p2p_default_port = 18444,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .default_seeds = {},
};

const NetworkConfig kTestnet{
    .name = "testnet",
    .magic = 0x5343544E,  // "SCTN"
    .protocol_version = PROTOCOL_VERSION,
    .p2p_default_port = 28444,
    .lightserver_default_port = 29444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .default_seeds = {
        "127.0.0.1:28444",
        "seed1.testnet.selfcoin.example:28444",
        "seed2.testnet.selfcoin.example:28444",
    },
};

}  // namespace

const NetworkConfig& devnet_network() { return kDevnet; }

const NetworkConfig& testnet_network() { return kTestnet; }

const NetworkConfig& network_by_name(const std::string& name) {
  if (name == "testnet") return kTestnet;
  return kDevnet;
}

}  // namespace selfcoin

