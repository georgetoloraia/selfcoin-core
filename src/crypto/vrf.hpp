#pragma once

#include "common/types.hpp"

namespace selfcoin::crypto {

struct VrfProof {
  Bytes proof;
  Hash32 output{};
};

// Signature-based VRF-like primitive:
// proof = Ed25519Sign(sk, transcript)
// output = sha256d("SC-VRF-OUT-V5" || pubkey || proof)
std::optional<VrfProof> vrf_prove(const Bytes& private_key_32, const PubKey32& pubkey, const Bytes& transcript);
bool vrf_verify(const PubKey32& pubkey, const Bytes& msg, const VrfProof& p);

}  // namespace selfcoin::crypto
