#include "consensus/randomness.hpp"

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::consensus {

Hash32 initial_finalized_randomness(const NetworkConfig& network, const ChainId& chain_id) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'A', 'N', 'D', '-', 'G', 'E', 'N', '-', 'V', '1'});
  w.bytes_fixed(network.network_id);
  const auto gh = hex_decode(chain_id.genesis_hash_hex);
  if (gh && gh->size() == 32) w.bytes(*gh);
  return crypto::sha256d(w.data());
}

Hash32 advance_finalized_randomness(const Hash32& prev_randomness, const BlockHeader& header) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'R', 'A', 'N', 'D', '-', 'A', 'C', 'C', '-', 'V', '1'});
  w.bytes_fixed(prev_randomness);
  w.bytes_fixed(header.block_id());
  w.bytes_fixed(header.leader_pubkey);
  w.u64le(header.height);
  w.u32le(header.round);
  w.bytes_fixed(header.vrf_output);
  return crypto::sha256d(w.data());
}

}  // namespace selfcoin::consensus
