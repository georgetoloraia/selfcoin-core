#include "p2p/messages.hpp"

#include "codec/bytes.hpp"

namespace selfcoin::p2p {

Bytes ser_version(const VersionMsg& m) {
  codec::ByteWriter w;
  w.u16le(m.proto_version);
  w.u64le(m.services);
  w.u64le(m.timestamp);
  w.u32le(m.nonce);
  w.varbytes(Bytes(m.user_agent.begin(), m.user_agent.end()));
  w.u64le(m.start_height);
  w.bytes_fixed(m.start_hash);
  return w.take();
}

std::optional<VersionMsg> de_version(const Bytes& b) {
  VersionMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto pv = r.u16le();
        auto s = r.u64le();
        auto ts = r.u64le();
        auto n = r.u32le();
        auto ua = r.varbytes();
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!pv || !s || !ts || !n || !ua || !h || !hash) return false;
        m.proto_version = *pv;
        m.services = *s;
        m.timestamp = *ts;
        m.nonce = *n;
        m.user_agent = std::string(ua->begin(), ua->end());
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

Bytes ser_propose(const ProposeMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.height);
  w.u32le(m.round);
  w.bytes_fixed(m.prev_finalized_hash);
  w.varbytes(m.block_bytes);
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
        m.height = *h;
        m.round = *round;
        m.prev_finalized_hash = *prev;
        m.block_bytes = *blk;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_vote(const VoteMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.vote.height);
  w.u32le(m.vote.round);
  w.bytes_fixed(m.vote.block_id);
  w.bytes_fixed(m.vote.validator_pubkey);
  w.bytes_fixed(m.vote.signature);
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
        m.block_bytes = *blk;
        return true;
      })) return std::nullopt;
  return m;
}

}  // namespace selfcoin::p2p
