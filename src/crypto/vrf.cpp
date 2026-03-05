#include "crypto/vrf.hpp"

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::crypto {

std::optional<VrfProof> vrf_prove(const Bytes& private_key_32, const Bytes& msg) {
  auto sig = ed25519_sign(msg, private_key_32);
  if (!sig.has_value()) return std::nullopt;
  VrfProof p;
  p.proof.assign(sig->begin(), sig->end());
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'O', 'U', 'T', '-', 'V', '0'});
  w.bytes(p.proof);
  p.output = sha256d(w.data());
  return p;
}

bool vrf_verify(const PubKey32& pubkey, const Bytes& msg, const VrfProof& p) {
  if (p.proof.size() != 64) return false;
  Sig64 sig{};
  std::copy(p.proof.begin(), p.proof.end(), sig.begin());
  if (!ed25519_verify(msg, sig, pubkey)) return false;
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'V', 'R', 'F', '-', 'O', 'U', 'T', '-', 'V', '0'});
  w.bytes(p.proof);
  return sha256d(w.data()) == p.output;
}

}  // namespace selfcoin::crypto
