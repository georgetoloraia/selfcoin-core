#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

#include "common/types.hpp"

namespace selfcoin {

struct NetworkConfig {
  std::string name;
  std::array<std::uint8_t, 16> network_id{};
  std::uint32_t magic{MAGIC};
  std::uint16_t protocol_version{PROTOCOL_VERSION};
  std::uint64_t feature_flags{0};
  std::uint16_t p2p_default_port{18444};
  std::uint16_t lightserver_default_port{19444};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint32_t round_timeout_ms{ROUND_TIMEOUT_MS};
  std::uint32_t min_block_interval_ms{1000};
  std::size_t max_payload_len{8 * 1024 * 1024};
  std::uint64_t bond_amount{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  std::uint64_t validator_min_bond{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount{BOND_AMOUNT};
  std::uint64_t validator_warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks{0};
  std::uint64_t validator_join_limit_window_blocks{0};
  std::uint32_t validator_join_limit_max_new{0};
  std::uint64_t liveness_window_blocks{10'000};
  std::uint32_t miss_rate_suspend_threshold_percent{30};
  std::uint32_t miss_rate_exit_threshold_percent{60};
  std::uint64_t suspend_duration_blocks{1'000};
  std::vector<std::string> default_seeds;
};

const NetworkConfig& mainnet_network();
const NetworkConfig& network_by_name(const std::string& name);  // mainnet only

}  // namespace selfcoin
