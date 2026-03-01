#include "consensus/monetary.hpp"

#include <algorithm>

namespace selfcoin::consensus {

std::uint64_t reward_units(std::uint64_t height) {
  if (height >= EMISSION_BLOCKS) return 0;
  return EMISSION_Q + ((height < EMISSION_R) ? 1ULL : 0ULL);
}

Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys) {
  Payout out;
  const std::uint64_t reward = reward_units(height);
  out.total = reward + fees_units;

  std::sort(signer_pubkeys.begin(), signer_pubkeys.end());
  signer_pubkeys.erase(std::unique(signer_pubkeys.begin(), signer_pubkeys.end()), signer_pubkeys.end());

  out.leader = (out.total * 20ULL) / 100ULL;
  std::uint64_t pool = out.total - out.leader;
  if (signer_pubkeys.empty()) {
    out.leader = out.total;
    return out;
  }

  const std::uint64_t base = pool / static_cast<std::uint64_t>(signer_pubkeys.size());
  const std::uint64_t rem = pool % static_cast<std::uint64_t>(signer_pubkeys.size());

  out.signers.reserve(signer_pubkeys.size());
  for (std::size_t i = 0; i < signer_pubkeys.size(); ++i) {
    std::uint64_t v = base + (i < rem ? 1ULL : 0ULL);
    out.signers.push_back({signer_pubkeys[i], v});
  }
  (void)leader_pubkey;
  return out;
}

}  // namespace selfcoin::consensus
