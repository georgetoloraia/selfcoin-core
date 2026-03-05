#include "consensus/activation.hpp"

#include <sstream>
#include <string>

namespace selfcoin::consensus {

std::optional<std::uint32_t> parse_coinbase_signal_version(const Tx& coinbase) {
  if (coinbase.inputs.empty()) return std::nullopt;
  const auto& script = coinbase.inputs[0].script_sig;
  if (script.empty()) return std::nullopt;
  const std::string s(script.begin(), script.end());
  const std::string needle = "cv=";
  const auto pos = s.find(needle);
  if (pos == std::string::npos) return std::nullopt;
  auto end = s.find(':', pos + needle.size());
  if (end == std::string::npos) end = s.size();
  const std::string v = s.substr(pos + needle.size(), end - (pos + needle.size()));
  if (v.empty()) return std::nullopt;
  try {
    return static_cast<std::uint32_t>(std::stoul(v));
  } catch (...) {
    return std::nullopt;
  }
}

Bytes make_coinbase_script_sig(std::uint64_t height, std::uint32_t round, std::optional<std::uint32_t> signal_version) {
  std::ostringstream oss;
  oss << "cb:" << height << ":" << round;
  if (signal_version.has_value()) oss << ":cv=" << *signal_version;
  const auto s = oss.str();
  return Bytes(s.begin(), s.end());
}

void apply_signal(ActivationState* state, const ActivationParams& params, std::uint64_t height,
                  std::optional<std::uint32_t> signaled_version) {
  if (!state) return;
  state->last_height = height;
  if (!params.enabled || params.window_blocks == 0 || params.threshold_percent == 0 || params.max_version <= 1) return;

  if (state->window_total_count == 0) {
    state->window_start_height = height;
  }
  if (height >= state->window_start_height + params.window_blocks) {
    state->window_start_height = height;
    state->window_total_count = 0;
    state->window_signal_count = 0;
  }

  state->window_total_count += 1;
  const std::uint32_t target_version = state->current_version + 1;
  if (target_version <= params.max_version && signaled_version.has_value() && *signaled_version >= target_version) {
    state->window_signal_count += 1;
  }

  if (state->pending_version == 0 && target_version <= params.max_version && state->window_total_count >= params.window_blocks) {
    const std::uint64_t required =
        (params.window_blocks * static_cast<std::uint64_t>(params.threshold_percent) + 99ULL) / 100ULL;
    if (state->window_signal_count >= required) {
      state->pending_version = target_version;
      state->pending_activation_height = height + params.activation_delay_blocks;
    }
    state->window_start_height = height + 1;
    state->window_total_count = 0;
    state->window_signal_count = 0;
  }

  if (state->pending_version > 0 && height >= state->pending_activation_height) {
    state->current_version = state->pending_version;
    state->pending_version = 0;
    state->pending_activation_height = 0;
  }
}

std::uint32_t version_for_height(const ActivationState& state, const ActivationParams& params, std::uint64_t height) {
  if (!params.enabled) return params.initial_version;
  if (state.pending_version > 0 && height >= state.pending_activation_height) return state.pending_version;
  return state.current_version;
}

}  // namespace selfcoin::consensus
