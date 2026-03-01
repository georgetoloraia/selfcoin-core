#pragma once

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
};

struct VersionMsg {
  std::uint16_t proto_version{PROTOCOL_VERSION};
  std::uint64_t services{0};
  std::uint64_t timestamp{0};
  std::uint32_t nonce{0};
  std::string user_agent{"selfcoin-core/0.1"};
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
};

struct VoteMsg {
  Vote vote;
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

Bytes ser_version(const VersionMsg& m);
std::optional<VersionMsg> de_version(const Bytes& b);
Bytes ser_finalized_tip(const FinalizedTipMsg& m);
std::optional<FinalizedTipMsg> de_finalized_tip(const Bytes& b);
Bytes ser_propose(const ProposeMsg& m);
std::optional<ProposeMsg> de_propose(const Bytes& b);
Bytes ser_vote(const VoteMsg& m);
std::optional<VoteMsg> de_vote(const Bytes& b);
Bytes ser_get_block(const GetBlockMsg& m);
std::optional<GetBlockMsg> de_get_block(const Bytes& b);
Bytes ser_block(const BlockMsg& m);
std::optional<BlockMsg> de_block(const Bytes& b);
Bytes ser_tx(const TxMsg& m);
std::optional<TxMsg> de_tx(const Bytes& b);

}  // namespace selfcoin::p2p
