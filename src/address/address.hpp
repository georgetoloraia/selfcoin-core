#pragma once

#include <array>
#include <optional>
#include <string>

#include "common/types.hpp"

namespace selfcoin::address {

struct DecodedAddress {
  std::string hrp;
  std::uint8_t addr_type;
  std::array<std::uint8_t, 20> pubkey_hash;
};

std::optional<std::string> encode_p2pkh(const std::string& hrp, const std::array<std::uint8_t, 20>& pubkey_hash);
std::optional<DecodedAddress> decode(const std::string& addr);
Bytes p2pkh_script_pubkey(const std::array<std::uint8_t, 20>& pubkey_hash);

}  // namespace selfcoin::address
