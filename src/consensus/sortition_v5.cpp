#include "consensus/sortition_v5.hpp"

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::consensus {

Hash32 make_vrf_seed_v5(const Hash32& prev_entropy, std::uint64_t height, std::uint32_t round) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'S', 'E', 'E', 'D', '-', 'V', '5'});
  w.bytes_fixed(prev_entropy);
  w.u64le(height);
  w.u32le(round);
  return crypto::sha256d(w.data());
}

Hash32 role_seed_v5(const Hash32& seed, V5Role role) {
  codec::ByteWriter w;
  if (role == V5Role::PROPOSER) {
    w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'R', 'O', 'L', 'E', '-', 'P', 'R', 'O', 'P', 'O', 'S', 'E', 'R'});
  } else {
    w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'R', 'O', 'L', 'E', '-', 'V', 'O', 'T', 'E', 'R'});
  }
  w.bytes_fixed(seed);
  return crypto::sha256d(w.data());
}

Bytes make_v5_vrf_transcript(V5Role role, std::uint64_t height, std::uint32_t round, const Hash32& role_seed,
                             const std::optional<std::array<std::uint8_t, 16>>& network_id) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'P', 'R', 'O', 'O', 'F', '-', 'V', '5'});
  w.u8(static_cast<std::uint8_t>(role));
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(role_seed);
  if (network_id.has_value()) {
    w.bytes(Bytes{'N', 'E', 'T', 'I', 'D'});
    w.bytes_fixed(*network_id);
  }
  return w.take();
}

std::size_t voter_target_k_v5(std::size_t active_count, std::uint32_t round, const V5Params& p) {
  if (active_count == 0) return 0;
  std::size_t k = std::min<std::size_t>(active_count, std::max<std::size_t>(2, p.voter_target_k));
  const std::uint32_t steps = std::min(round, p.round_expand_cap);
  for (std::uint32_t i = 0; i < steps && k < active_count; ++i) {
    const std::uint32_t factor = std::max<std::uint32_t>(2, p.round_expand_factor);
    if (k > active_count / factor) k = active_count;
    else k *= factor;
  }
  return std::min(k, active_count);
}

bool is_output_below_probability_threshold(const Hash32& output, std::uint64_t num, std::uint64_t den) {
  if (den == 0) return false;
  if (num >= den) return true;

  // Deterministic probability check on top 64 bits.
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<std::uint64_t>(output[i]);
  const __uint128_t space = (static_cast<__uint128_t>(1) << 64);
  const __uint128_t threshold = (space * static_cast<__uint128_t>(num)) / static_cast<__uint128_t>(den);
  return static_cast<__uint128_t>(v) < threshold;
}

bool is_v5_eligible(const PubKey32& pub, V5Role role, std::uint64_t height, std::uint32_t round, const Hash32& role_seed,
                    const std::optional<std::array<std::uint8_t, 16>>& network_id, std::uint64_t num, std::uint64_t den,
                    const crypto::VrfProof& proof) {
  const Bytes transcript = make_v5_vrf_transcript(role, height, round, role_seed, network_id);
  if (!crypto::vrf_verify(pub, transcript, proof)) return false;
  return is_output_below_probability_threshold(proof.output, num, den);
}

}  // namespace selfcoin::consensus
