#pragma once

#include <array>
#include <optional>
#include <string>

#include "utxo/tx.hpp"

namespace selfcoin::p2p {

enum MsgType : std::uint16_t {
  VERSION = 1,
  VERACK = 2,
  GET_FINALIZED_TIP = 3,
  FINALIZED_TIP = 4,
  PROPOSE = 5,
  VOTE = 6,
  GET_BLOCK = 7,
  BLOCK = 8,
  TX = 9,
  GETADDR = 10,
  ADDR = 11,
  PING = 12,
  PONG = 13,
};

struct VersionMsg {
  std::uint32_t proto_version{PROTOCOL_VERSION};
  std::array<std::uint8_t, 16> network_id{};
  std::uint64_t feature_flags{0};
  std::uint64_t services{0};
  std::uint64_t timestamp{0};
  std::uint32_t nonce{0};
  std::string node_software_version{"selfcoin-core/0.7"};
  std::uint64_t start_height{0};
  Hash32 start_hash{};
};

struct FinalizedTipMsg {
  std::uint64_t height{0};
  Hash32 hash{};
};

struct ProposeMsg {
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 prev_finalized_hash{};
  Bytes block_bytes;
  Bytes vrf_proof;
  Hash32 vrf_output{};
};

struct VoteMsg {
  Vote vote;
  Bytes vrf_proof;
  Hash32 vrf_output{};
};

struct GetBlockMsg {
  Hash32 hash{};
};

struct BlockMsg {
  Bytes block_bytes;
};

struct TxMsg {
  Bytes tx_bytes;
};

struct GetAddrMsg {};

struct AddrEntryMsg {
  std::uint8_t ip_version{4};  // 4 or 6
  std::array<std::uint8_t, 16> ip{};
  std::uint16_t port{0};
  std::uint64_t last_seen_unix{0};
};

struct AddrMsg {
  std::vector<AddrEntryMsg> entries;
};

struct PingMsg {
  std::uint64_t nonce{0};
};

bool is_known_message_type(std::uint16_t msg_type);

Bytes ser_version(const VersionMsg& m);
std::optional<VersionMsg> de_version(const Bytes& b);
Bytes ser_finalized_tip(const FinalizedTipMsg& m);
std::optional<FinalizedTipMsg> de_finalized_tip(const Bytes& b);
Bytes ser_propose(const ProposeMsg& m, bool include_vrf_extensions = false);
std::optional<ProposeMsg> de_propose(const Bytes& b);
Bytes ser_vote(const VoteMsg& m, bool include_vrf_extensions = false);
std::optional<VoteMsg> de_vote(const Bytes& b);
Bytes ser_get_block(const GetBlockMsg& m);
std::optional<GetBlockMsg> de_get_block(const Bytes& b);
Bytes ser_block(const BlockMsg& m);
std::optional<BlockMsg> de_block(const Bytes& b);
Bytes ser_tx(const TxMsg& m);
std::optional<TxMsg> de_tx(const Bytes& b);
Bytes ser_getaddr(const GetAddrMsg& m);
std::optional<GetAddrMsg> de_getaddr(const Bytes& b);
Bytes ser_addr(const AddrMsg& m);
std::optional<AddrMsg> de_addr(const Bytes& b);
Bytes ser_ping(const PingMsg& m);
std::optional<PingMsg> de_ping(const Bytes& b);

}  // namespace selfcoin::p2p
