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
    .default_seeds = {
        "212.58.103.170:19440",
        // "seed1.mainnet.selfcoin.example:19440",
        // "seed2.mainnet.selfcoin.example:19440",
    },
};

}  // namespace

const NetworkConfig& devnet_network() { return kDevnet; }

const NetworkConfig& testnet_network() { return kTestnet; }

const NetworkConfig& mainnet_network() { return kMainnet; }

const NetworkConfig& network_by_name(const std::string& name) {
  if (name == "mainnet") return kMainnet;
  if (name == "testnet") return kTestnet;
  return kDevnet;
}

}  // namespace selfcoin
