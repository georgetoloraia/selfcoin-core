#pragma once

#include <optional>

#include "common/types.hpp"
#include "crypto/vrf.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::consensus {

enum class V5Role : std::uint8_t {
  PROPOSER = 1,
  VOTER = 2,
};

struct V5Params {
  std::uint64_t proposer_expected_num{1};
  std::uint64_t proposer_expected_den{1};
  std::uint32_t voter_target_k{100};
  std::uint32_t round_expand_cap{8};
  std::uint32_t round_expand_factor{2};
};

Hash32 make_vrf_seed_v5(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round);
Hash32 role_seed_v5(const Hash32& seed, V5Role role);
Bytes make_v5_vrf_transcript(V5Role role, std::uint64_t height, std::uint32_t round, const Hash32& role_seed,
                             const std::optional<std::array<std::uint8_t, 16>>& network_id = std::nullopt);
std::size_t voter_target_k_v5(std::size_t active_count, std::uint32_t round, const V5Params& p);
bool is_output_below_probability_threshold(const Hash32& output, std::uint64_t num, std::uint64_t den);
bool is_v5_eligible(const PubKey32& pub, V5Role role, std::uint64_t height, std::uint32_t round, const Hash32& role_seed,
                    const std::optional<std::array<std::uint8_t, 16>>& network_id, std::uint64_t num, std::uint64_t den,
                    const crypto::VrfProof& proof);

}  // namespace selfcoin::consensus
