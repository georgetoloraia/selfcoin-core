#include "p2p/messages.hpp"

#include "codec/bytes.hpp"

namespace selfcoin::p2p {
namespace {

// The VERSION fingerprint currently carries chain-id plus bootstrap/runtime
// metadata, so the cap must comfortably exceed the minimal local fingerprint.
constexpr std::size_t kMaxSoftwareVersionBytes = 512;
constexpr std::size_t kMaxProposalBlockBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxVoteProofBytes = 256;
constexpr std::size_t kMaxBlockMessageBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxTxMessageBytes = 256 * 1024;
constexpr std::uint64_t kMaxAddrEntries = 256;

}  // namespace

bool is_known_message_type(std::uint16_t msg_type) {
  switch (msg_type) {
    case MsgType::VERSION:
    case MsgType::VERACK:
    case MsgType::GET_FINALIZED_TIP:
    case MsgType::FINALIZED_TIP:
    case MsgType::PROPOSE:
    case MsgType::VOTE:
    case MsgType::GET_BLOCK:
    case MsgType::BLOCK:
    case MsgType::TX:
    case MsgType::GETADDR:
    case MsgType::ADDR:
      return true;
    default:
      return false;
  }
}

Bytes ser_version(const VersionMsg& m) {
  codec::ByteWriter w;
  w.u32le(m.proto_version);
  w.bytes_fixed(m.network_id);
  w.u64le(m.feature_flags);
  w.u64le(m.services);
  w.u64le(m.timestamp);
  w.u32le(m.nonce);
  w.varbytes(Bytes(m.node_software_version.begin(), m.node_software_version.end()));
  w.u64le(m.start_height);
  w.bytes_fixed(m.start_hash);
  return w.take();
}

std::optional<VersionMsg> de_version(const Bytes& b) {
  VersionMsg m;
  // v0.7 format
  if (codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto pv = r.u32le();
        auto nid = r.bytes_fixed<16>();
        auto ff = r.u64le();
        auto s = r.u64le();
        auto ts = r.u64le();
        auto n = r.u32le();
        auto sw = r.varbytes();
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!pv || !nid || !ff || !s || !ts || !n || !sw || !h || !hash) return false;
        if (sw->size() > kMaxSoftwareVersionBytes) return false;
        m.proto_version = *pv;
        m.network_id = *nid;
        m.feature_flags = *ff;
        m.services = *s;
        m.timestamp = *ts;
        m.nonce = *n;
        m.node_software_version = std::string(sw->begin(), sw->end());
        m.start_height = *h;
        m.start_hash = *hash;
        return true;
      })) return m;

  // Backward-aware parse for pre-v0.7 payloads in this repo line.
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto pv16 = r.u16le();
        auto s = r.u64le();
        auto ts = r.u64le();
        auto n = r.u32le();
        auto ua = r.varbytes();
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!pv16 || !s || !ts || !n || !ua || !h || !hash) return false;
        if (ua->size() > kMaxSoftwareVersionBytes) return false;
        m.proto_version = *pv16;
        m.network_id.fill(0);
        m.feature_flags = 0;
        m.services = *s;
        m.timestamp = *ts;
        m.nonce = *n;
        m.node_software_version = std::string(ua->begin(), ua->end());
        m.start_height = *h;
        m.start_hash = *hash;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_finalized_tip(const FinalizedTipMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.height);
  w.bytes_fixed(m.hash);
  return w.take();
}

std::optional<FinalizedTipMsg> de_finalized_tip(const Bytes& b) {
  FinalizedTipMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!h || !hash) return false;
        m.height = *h;
        m.hash = *hash;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_propose(const ProposeMsg& m, bool include_vrf_extensions) {
  codec::ByteWriter w;
  w.u64le(m.height);
  w.u32le(m.round);
  w.bytes_fixed(m.prev_finalized_hash);
  w.varbytes(m.block_bytes);
  if (include_vrf_extensions) {
    w.varbytes(m.vrf_proof);
    w.bytes_fixed(m.vrf_output);
  }
  return w.take();
}

std::optional<ProposeMsg> de_propose(const Bytes& b) {
  ProposeMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto prev = r.bytes_fixed<32>();
        auto blk = r.varbytes();
        if (!h || !round || !prev || !blk) return false;
        if (blk->size() > kMaxProposalBlockBytes) return false;
        m.height = *h;
        m.round = *round;
        m.prev_finalized_hash = *prev;
        m.block_bytes = *blk;
        if (r.remaining() > 0) {
          auto proof = r.varbytes();
          auto out = r.bytes_fixed<32>();
          if (!proof || !out) return false;
          if (proof->size() > kMaxVoteProofBytes) return false;
          m.vrf_proof = *proof;
          m.vrf_output = *out;
        }
        return true;
      }))
    return std::nullopt;
  return m;
}

Bytes ser_vote(const VoteMsg& m, bool include_vrf_extensions) {
  codec::ByteWriter w;
  w.u64le(m.vote.height);
  w.u32le(m.vote.round);
  w.bytes_fixed(m.vote.block_id);
  w.bytes_fixed(m.vote.validator_pubkey);
  w.bytes_fixed(m.vote.signature);
  if (include_vrf_extensions) {
    w.varbytes(m.vrf_proof);
    w.bytes_fixed(m.vrf_output);
  }
  return w.take();
}

std::optional<VoteMsg> de_vote(const Bytes& b) {
  VoteMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto block = r.bytes_fixed<32>();
        auto pub = r.bytes_fixed<32>();
        auto sig = r.bytes_fixed<64>();
        if (!h || !round || !block || !pub || !sig) return false;
        m.vote.height = *h;
        m.vote.round = *round;
        m.vote.block_id = *block;
        m.vote.validator_pubkey = *pub;
        m.vote.signature = *sig;
        if (r.remaining() > 0) {
          auto proof = r.varbytes();
          auto out = r.bytes_fixed<32>();
          if (!proof || !out) return false;
          if (proof->size() > kMaxVoteProofBytes) return false;
          m.vrf_proof = *proof;
          m.vrf_output = *out;
        }
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_get_block(const GetBlockMsg& m) {
  codec::ByteWriter w;
  w.bytes_fixed(m.hash);
  return w.take();
}

std::optional<GetBlockMsg> de_get_block(const Bytes& b) {
  if (b.size() != 32) return std::nullopt;
  GetBlockMsg m;
  std::copy(b.begin(), b.end(), m.hash.begin());
  return m;
}

Bytes ser_block(const BlockMsg& m) {
  codec::ByteWriter w;
  w.varbytes(m.block_bytes);
  return w.take();
}

std::optional<BlockMsg> de_block(const Bytes& b) {
  BlockMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto blk = r.varbytes();
        if (!blk) return false;
        if (blk->size() > kMaxBlockMessageBytes) return false;
        m.block_bytes = *blk;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_tx(const TxMsg& m) {
  codec::ByteWriter w;
  w.varbytes(m.tx_bytes);
  return w.take();
}

std::optional<TxMsg> de_tx(const Bytes& b) {
  TxMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto tx = r.varbytes();
        if (!tx) return false;
        if (tx->size() > kMaxTxMessageBytes) return false;
        m.tx_bytes = *tx;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_getaddr(const GetAddrMsg&) { return {}; }

std::optional<GetAddrMsg> de_getaddr(const Bytes& b) {
  if (!b.empty()) return std::nullopt;
  return GetAddrMsg{};
}

Bytes ser_addr(const AddrMsg& m) {
  codec::ByteWriter w;
  w.varint(m.entries.size());
  for (const auto& e : m.entries) {
    w.u8(e.ip_version);
    if (e.ip_version == 4) {
      Bytes ip4{e.ip[0], e.ip[1], e.ip[2], e.ip[3]};
      w.bytes(ip4);
    } else {
      w.bytes_fixed(e.ip);
    }
    w.u16le(e.port);
    w.u64le(e.last_seen_unix);
  }
  return w.take();
}

std::optional<AddrMsg> de_addr(const Bytes& b) {
  AddrMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto n = r.varint();
        if (!n || *n > kMaxAddrEntries) return false;
        m.entries.clear();
        m.entries.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          AddrEntryMsg e;
          auto ver = r.u8();
          if (!ver || (*ver != 4 && *ver != 6)) return false;
          e.ip_version = *ver;
          if (*ver == 4) {
            auto ip4 = r.bytes(4);
            if (!ip4) return false;
            e.ip.fill(0);
            e.ip[0] = (*ip4)[0];
            e.ip[1] = (*ip4)[1];
            e.ip[2] = (*ip4)[2];
            e.ip[3] = (*ip4)[3];
          } else {
            auto ip6 = r.bytes_fixed<16>();
            if (!ip6) return false;
            e.ip = *ip6;
          }
          auto p = r.u16le();
          auto seen = r.u64le();
          if (!p || !seen) return false;
          e.port = *p;
          e.last_seen_unix = *seen;
          m.entries.push_back(e);
        }
        return true;
      })) return std::nullopt;
  return m;
}

}  // namespace selfcoin::p2p
