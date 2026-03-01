#include "crypto/hash.hpp"

#include <openssl/ripemd.h>
#include <openssl/sha.h>

namespace selfcoin::crypto {

Hash32 sha256d(const Bytes& data) {
  unsigned char first[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), first);
  Hash32 out{};
  SHA256(first, SHA256_DIGEST_LENGTH, out.data());
  return out;
}

std::array<std::uint8_t, 20> h160(const Bytes& data) {
  unsigned char sha[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), sha);
  std::array<std::uint8_t, 20> out{};
  RIPEMD160(sha, SHA256_DIGEST_LENGTH, out.data());
  return out;
}

}  // namespace selfcoin::crypto
