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

const NetworkConfig kMainnet{
    .name = "mainnet",
    .network_id = network_id_for_name("mainnet"),
    .magic = 0x53434D4E,  // "SCMN"
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 19440,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .round_timeout_ms = 10'000,
    .min_block_interval_ms = 8000,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .validator_min_bond = BOND_AMOUNT,
    .validator_bond_min_amount = BOND_AMOUNT,
    .validator_bond_max_amount = BOND_AMOUNT * 100,
    .validator_warmup_blocks = WARMUP_BLOCKS,
    .validator_cooldown_blocks = 100,
    .validator_join_limit_window_blocks = 1'000,
    .validator_join_limit_max_new = 64,
    .liveness_window_blocks = 10'000,
    .miss_rate_suspend_threshold_percent = 30,
    .miss_rate_exit_threshold_percent = 60,
    .suspend_duration_blocks = 1'000,
    .default_seeds = {
        "167.172.97.180:19440",
        "138.197.113.69:19440",
    },
};

}  // namespace

const NetworkConfig& mainnet_network() { return kMainnet; }

const NetworkConfig& network_by_name(const std::string&) { return kMainnet; }

}  // namespace selfcoin
