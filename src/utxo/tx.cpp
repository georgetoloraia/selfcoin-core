#include "utxo/tx.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin {

Bytes Tx::serialize() const {
  codec::ByteWriter w;
  w.u32le(version);
  w.varint(inputs.size());
  for (const auto& in : inputs) {
    w.bytes_fixed(in.prev_txid);
    w.u32le(in.prev_index);
    w.varbytes(in.script_sig);
    w.u32le(in.sequence);
  }
  w.varint(outputs.size());
  for (const auto& out : outputs) {
    w.u64le(out.value);
    w.varbytes(out.script_pubkey);
  }
  w.u32le(lock_time);
  return w.take();
}

std::optional<Tx> Tx::parse(const Bytes& b) {
  Tx tx;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto in_count = r.varint();
        if (!version || !in_count) return false;
        tx.version = *version;

        tx.inputs.clear();
        tx.inputs.reserve(*in_count);
        for (std::uint64_t i = 0; i < *in_count; ++i) {
          TxIn in;
          auto prev = r.bytes_fixed<32>();
          auto idx = r.u32le();
          auto script = r.varbytes();
          auto seq = r.u32le();
          if (!prev || !idx || !script || !seq) return false;
          in.prev_txid = *prev;
          in.prev_index = *idx;
          in.script_sig = *script;
          in.sequence = *seq;
          tx.inputs.push_back(std::move(in));
        }

        auto out_count = r.varint();
        if (!out_count) return false;
        tx.outputs.clear();
        tx.outputs.reserve(*out_count);
        for (std::uint64_t i = 0; i < *out_count; ++i) {
          TxOut out;
          auto value = r.u64le();
          auto script = r.varbytes();
          if (!value || !script) return false;
          out.value = *value;
          out.script_pubkey = *script;
          tx.outputs.push_back(std::move(out));
        }

        auto lock = r.u32le();
        if (!lock) return false;
        tx.lock_time = *lock;
        return true;
      })) {
    return std::nullopt;
  }
  return tx;
}

Hash32 Tx::txid() const { return crypto::sha256d(serialize()); }

Bytes BlockHeader::serialize() const {
  codec::ByteWriter w;
  w.bytes_fixed(prev_finalized_hash);
  w.u64le(height);
  w.u64le(timestamp);
  w.bytes_fixed(merkle_root);
  w.bytes_fixed(leader_pubkey);
  w.u32le(round);
  return w.take();
}

std::optional<BlockHeader> BlockHeader::parse(const Bytes& b) {
  BlockHeader h;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto prev = r.bytes_fixed<32>();
        auto height = r.u64le();
        auto ts = r.u64le();
        auto merkle = r.bytes_fixed<32>();
        auto leader = r.bytes_fixed<32>();
        auto round = r.u32le();
        if (!prev || !height || !ts || !merkle || !leader || !round) return false;
        h.prev_finalized_hash = *prev;
        h.height = *height;
        h.timestamp = *ts;
        h.merkle_root = *merkle;
        h.leader_pubkey = *leader;
        h.round = *round;
        return true;
      })) {
    return std::nullopt;
  }
  return h;
}

Hash32 BlockHeader::block_id() const {
  Bytes pre{'S', 'C', '-', 'B', 'L', 'O', 'C', 'K', '-', 'V', '0'};
  const Bytes hbytes = serialize();
  pre.insert(pre.end(), hbytes.begin(), hbytes.end());
  return crypto::sha256d(pre);
}

Bytes FinalityProof::serialize() const {
  codec::ByteWriter w;
  w.varint(sigs.size());
  for (const auto& s : sigs) {
    w.bytes_fixed(s.validator_pubkey);
    w.bytes_fixed(s.signature);
  }
  return w.take();
}

std::optional<FinalityProof> FinalityProof::parse(const Bytes& b) {
  FinalityProof p;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto n = r.varint();
        if (!n) return false;
        p.sigs.clear();
        p.sigs.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          p.sigs.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return p;
}

Bytes Block::serialize() const {
  codec::ByteWriter w;
  const Bytes h = header.serialize();
  w.bytes(h);
  w.varint(txs.size());
  for (const auto& tx : txs) {
    w.bytes(tx.serialize());
  }
  w.bytes(finality_proof.serialize());
  return w.take();
}

std::optional<Block> Block::parse(const Bytes& b) {
  Block blk;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto prev = r.bytes_fixed<32>();
        auto height = r.u64le();
        auto ts = r.u64le();
        auto merkle = r.bytes_fixed<32>();
        auto leader = r.bytes_fixed<32>();
        auto round = r.u32le();
        if (!prev || !height || !ts || !merkle || !leader || !round) return false;
        blk.header.prev_finalized_hash = *prev;
        blk.header.height = *height;
        blk.header.timestamp = *ts;
        blk.header.merkle_root = *merkle;
        blk.header.leader_pubkey = *leader;
        blk.header.round = *round;

        auto n = r.varint();
        if (!n || *n < 1) return false;
        blk.txs.clear();
        blk.txs.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          auto version = r.u32le();
          auto in_count = r.varint();
          if (!version || !in_count) return false;
          Tx tx;
          tx.version = *version;
          for (std::uint64_t j = 0; j < *in_count; ++j) {
            auto prev_t = r.bytes_fixed<32>();
            auto prev_i = r.u32le();
            auto sig = r.varbytes();
            auto seq = r.u32le();
            if (!prev_t || !prev_i || !sig || !seq) return false;
            tx.inputs.push_back(TxIn{*prev_t, *prev_i, *sig, *seq});
          }
          auto out_count = r.varint();
          if (!out_count) return false;
          for (std::uint64_t j = 0; j < *out_count; ++j) {
            auto v = r.u64le();
            auto spk = r.varbytes();
            if (!v || !spk) return false;
            tx.outputs.push_back(TxOut{*v, *spk});
          }
          auto lock = r.u32le();
          if (!lock) return false;
          tx.lock_time = *lock;
          blk.txs.push_back(std::move(tx));
        }

        auto sig_count = r.varint();
        if (!sig_count) return false;
        blk.finality_proof.sigs.clear();
        blk.finality_proof.sigs.reserve(*sig_count);
        for (std::uint64_t i = 0; i < *sig_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          blk.finality_proof.sigs.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return blk;
}

bool is_validator_register_script(const Bytes& script, PubKey32* out_pubkey) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  if (script.size() != 40) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_pubkey) {
    std::copy(script.begin() + 8, script.end(), out_pubkey->begin());
  }
  return true;
}

}  // namespace selfcoin
