#include "common/network.hpp"

#include <algorithm>

#include "crypto/hash.hpp"

namespace selfcoin {
namespace {

std::array<std::uint8_t, 16> network_id_for_name(const std::string& name) {
  const std::string s = "selfcoin:" + name;
  const Hash32 h = crypto::sha256(Bytes(s.begin(), s.end()));
  std::array<std::uint8_t, 16> out{};
  std::copy(h.begin(), h.begin() + 16, out.begin());
  return out;
}

const NetworkConfig kDevnet{
    .name = "devnet",
    .network_id = network_id_for_name("devnet"),
    .magic = MAGIC,
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 18444,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .activation_enabled = false,
    .initial_consensus_version = 1,
    .max_consensus_version = 1,
    .activation_window_blocks = 0,
    .activation_threshold_percent = 0,
    .activation_delay_blocks = 0,
    .default_seeds = {},
};

const NetworkConfig kTestnet{
    .name = "testnet",
    .network_id = network_id_for_name("testnet"),
    .magic = 0x5343544E,  // "SCTN"
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 28444,
    .lightserver_default_port = 29444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .activation_enabled = false,
    .initial_consensus_version = 1,
    .max_consensus_version = 1,
    .activation_window_blocks = 0,
    .activation_threshold_percent = 0,
    .activation_delay_blocks = 0,
    .default_seeds = {
        "127.0.0.1:28444",
        "seed1.testnet.selfcoin.example:28444",
        "seed2.testnet.selfcoin.example:28444",
    },
};

const NetworkConfig kMainnet{
    .name = "mainnet",
    .network_id = network_id_for_name("mainnet"),
    .magic = 0x53434D4E,  // "SCMN"
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 19440,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .activation_enabled = false,
    .initial_consensus_version = 1,
    .max_consensus_version = 1,
    .activation_window_blocks = 0,
    .activation_threshold_percent = 0,
    .activation_delay_blocks = 0,
    .default_seeds = {
        "212.58.103.170:19440",
        "seed1.gotdns.ch:19440",
        "138.197.113.69:19440",
        // "seed1.mainnet.selfcoin.example:19440",
        // "seed2.mainnet.selfcoin.example:19440",
    },
};

const NetworkConfig kNextnet{
    .name = "nextnet",
    .network_id = network_id_for_name("nextnet"),
    .magic = 0x53434E58,  // "SCNX"
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,
    .p2p_default_port = 38444,
    .lightserver_default_port = 39444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = ROUND_TIMEOUT_MS,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .activation_enabled = true,
    .initial_consensus_version = 1,
    .max_consensus_version = 2,
    .activation_window_blocks = 100,
    .activation_threshold_percent = 90,
    .activation_delay_blocks = 100,
    .default_seeds = {
        "127.0.0.1:38444",
    },
};

}  // namespace

const NetworkConfig& devnet_network() { return kDevnet; }

const NetworkConfig& testnet_network() { return kTestnet; }

const NetworkConfig& mainnet_network() { return kMainnet; }
const NetworkConfig& nextnet_network() { return kNextnet; }

const NetworkConfig& network_by_name(const std::string& name) {
  if (name == "nextnet") return kNextnet;
  if (name == "mainnet") return kMainnet;
  if (name == "testnet") return kTestnet;
  return kDevnet;
}

}  // namespace selfcoin
