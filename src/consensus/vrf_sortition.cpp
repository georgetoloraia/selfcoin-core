#include "consensus/vrf_sortition.hpp"

#include <algorithm>
#include <limits>

#include "codec/bytes.hpp"

namespace selfcoin::consensus {

Bytes proposer_vrf_transcript(const NetworkConfig& network, const Hash32& prev_finalized_hash, std::uint64_t height,
                              std::uint32_t round) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'P', 'R', 'O', 'P', '-', 'V', '1'});
  w.bytes_fixed(network.network_id);
  w.bytes_fixed(prev_finalized_hash);
  w.u64le(height);
  w.u32le(round);
  return w.take();
}

std::uint64_t proposer_vrf_score_u64(const Hash32& vrf_output) {
  std::uint64_t out = 0;
  for (int i = 0; i < 8; ++i) out = (out << 8) | static_cast<std::uint64_t>(vrf_output[i]);
  return out;
}

std::uint64_t proposer_vrf_threshold_u64(std::size_t active_count, std::uint32_t round, std::uint32_t expected_num,
                                         std::uint32_t expected_den) {
  if (active_count == 0) return 0;
  if (expected_den == 0) expected_den = 1;

  const std::uint32_t shift = std::min<std::uint32_t>(round, 32);
  const long double round_multiplier = static_cast<long double>(std::uint64_t{1} << shift);
  const long double base_expected = static_cast<long double>(expected_num) / static_cast<long double>(expected_den);
  const long double expected =
      std::min<long double>(static_cast<long double>(active_count), base_expected * round_multiplier);
  if (expected >= static_cast<long double>(active_count)) return std::numeric_limits<std::uint64_t>::max();

  const long double p = expected / static_cast<long double>(active_count);
  if (p <= 0.0L) return 0;
  const long double max_u64 = static_cast<long double>(std::numeric_limits<std::uint64_t>::max());
  return static_cast<std::uint64_t>(p * max_u64);
}

bool proposer_vrf_output_is_eligible(const Hash32& vrf_output, std::size_t active_count, std::uint32_t round,
                                     std::uint32_t expected_num, std::uint32_t expected_den) {
  if (active_count == 0) return false;
  return proposer_vrf_score_u64(vrf_output) <=
         proposer_vrf_threshold_u64(active_count, round, expected_num, expected_den);
}

bool verify_proposer_vrf(const NetworkConfig& network, const PubKey32& pubkey, const Hash32& prev_finalized_hash,
                         std::uint64_t height, std::uint32_t round, const crypto::VrfProof& proof,
                         std::size_t active_count, std::uint32_t expected_num, std::uint32_t expected_den) {
  const auto transcript = proposer_vrf_transcript(network, prev_finalized_hash, height, round);
  if (!crypto::vrf_verify(pubkey, transcript, proof)) return false;
  return proposer_vrf_output_is_eligible(proof.output, active_count, round, expected_num, expected_den);
}

}  // namespace selfcoin::consensus
