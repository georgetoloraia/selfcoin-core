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
  std::size_t max_payload_len{8 * 1024 * 1024};
  std::uint64_t bond_amount{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  bool activation_enabled{false};
  std::uint32_t initial_consensus_version{1};
  std::uint32_t max_consensus_version{1};
  std::uint64_t activation_window_blocks{0};
  std::uint32_t activation_threshold_percent{0};
  std::uint64_t activation_delay_blocks{0};
  std::uint64_t validator_min_bond{BOND_AMOUNT};
  std::uint64_t validator_warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t validator_cooldown_blocks{0};
  std::uint64_t validator_join_limit_window_blocks{0};
  std::uint32_t validator_join_limit_max_new{0};
  std::uint64_t liveness_window_blocks{10'000};
  std::uint32_t miss_rate_suspend_threshold_percent{30};
  std::uint32_t miss_rate_exit_threshold_percent{60};
  std::uint64_t suspend_duration_blocks{1'000};
  std::uint64_t v5_proposer_expected_num{1};
  std::uint64_t v5_proposer_expected_den{1};
  std::uint32_t v5_voter_target_k{100};
  std::uint32_t v5_round_expand_cap{8};
  std::uint32_t v5_round_expand_factor{2};
  std::uint64_t v6_bond_unit{BOND_AMOUNT};
  std::uint64_t v6_units_max{1'000'000};
  std::uint64_t v6_proposer_expected_num{1};
  std::uint64_t v6_proposer_expected_den{1};
  std::uint32_t v6_voter_target_k{100};
  std::uint32_t v6_round_expand_cap{8};
  std::uint32_t v6_round_expand_factor{2};
  std::uint64_t v7_min_bond_amount{BOND_AMOUNT};
  std::uint64_t v7_max_bond_amount{BOND_AMOUNT};
  std::uint64_t v7_effective_units_cap{10'000};
  std::vector<std::string> default_seeds;
};

const NetworkConfig& mainnet_network();
const NetworkConfig& network_by_name(const std::string& name);  // mainnet only

}  // namespace selfcoin
