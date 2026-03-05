#include "consensus/activation.hpp"

#include <sstream>
#include <string>

namespace selfcoin::consensus {

namespace {
constexpr std::uint32_t kFixedConsensusVersion = 7;
}

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
  (void)params;
  (void)signaled_version;
  if (!state) return;
  state->last_height = height;
  state->current_version = kFixedConsensusVersion;
  state->pending_version = 0;
  state->pending_activation_height = 0;
  state->window_start_height = 0;
  state->window_signal_count = 0;
  state->window_total_count = 0;
}

std::uint32_t version_for_height(const ActivationState& state, const ActivationParams& params, std::uint64_t height) {
  (void)state;
  (void)params;
  (void)height;
  return kFixedConsensusVersion;
}

}  // namespace selfcoin::consensus
