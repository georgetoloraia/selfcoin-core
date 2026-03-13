#pragma once

#include "common/network.hpp"
#include "crypto/vrf.hpp"

namespace selfcoin::consensus {

Bytes proposer_vrf_transcript(const NetworkConfig& network, const Hash32& prev_finalized_hash, std::uint64_t height,
                              std::uint32_t round);

std::uint64_t proposer_vrf_score_u64(const Hash32& vrf_output);
std::uint64_t proposer_vrf_threshold_u64(std::size_t active_count, std::uint32_t round, std::uint32_t expected_num,
                                         std::uint32_t expected_den);
bool proposer_vrf_output_is_eligible(const Hash32& vrf_output, std::size_t active_count, std::uint32_t round,
                                     std::uint32_t expected_num, std::uint32_t expected_den);
bool verify_proposer_vrf(const NetworkConfig& network, const PubKey32& pubkey, const Hash32& prev_finalized_hash,
                         std::uint64_t height, std::uint32_t round, const crypto::VrfProof& proof,
                         std::size_t active_count, std::uint32_t expected_num, std::uint32_t expected_den);

}  // namespace selfcoin::consensus
