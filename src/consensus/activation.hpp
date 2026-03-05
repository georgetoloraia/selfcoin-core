#pragma once

#include <cstdint>
#include <optional>

#include "utxo/tx.hpp"

namespace selfcoin::consensus {

struct ActivationParams {
  bool enabled{false};
  std::uint32_t initial_version{1};
  std::uint32_t max_version{1};
  std::uint64_t window_blocks{0};
  std::uint32_t threshold_percent{0};
  std::uint64_t activation_delay_blocks{0};
};

struct ActivationState {
  std::uint32_t current_version{1};
  std::uint32_t pending_version{0};
  std::uint64_t pending_activation_height{0};
  std::uint64_t last_height{0};
  std::uint64_t window_start_height{0};
  std::uint64_t window_signal_count{0};
  std::uint64_t window_total_count{0};
};

// Parses optional coinbase script marker "cv=<u32>" from script_sig text.
std::optional<std::uint32_t> parse_coinbase_signal_version(const Tx& coinbase);

// Encodes coinbase script as "cb:<height>:<round>[:cv=<version>]".
Bytes make_coinbase_script_sig(std::uint64_t height, std::uint32_t round, std::optional<std::uint32_t> signal_version);

// Applies one finalized-block signal sample and updates activation state.
void apply_signal(ActivationState* state, const ActivationParams& params, std::uint64_t height,
                  std::optional<std::uint32_t> signaled_version);

// Returns version that is active for a given height.
std::uint32_t version_for_height(const ActivationState& state, const ActivationParams& params, std::uint64_t height);

}  // namespace selfcoin::consensus
