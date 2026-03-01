#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace selfcoin {

struct NetworkConfig {
  std::string name;
  std::uint32_t magic{MAGIC};
  std::uint16_t protocol_version{PROTOCOL_VERSION};
  std::uint16_t p2p_default_port{18444};
  std::uint16_t lightserver_default_port{19444};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint32_t round_timeout_ms{ROUND_TIMEOUT_MS};
  std::size_t max_payload_len{8 * 1024 * 1024};
  std::uint64_t bond_amount{BOND_AMOUNT};
  std::uint64_t warmup_blocks{WARMUP_BLOCKS};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  std::vector<std::string> default_seeds;
};

const NetworkConfig& devnet_network();
const NetworkConfig& testnet_network();
const NetworkConfig& network_by_name(const std::string& name);

}  // namespace selfcoin

