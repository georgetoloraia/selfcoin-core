#include "utxo/tx.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin {
namespace {
constexpr std::uint64_t kMaxTxInputs = 10'000;
constexpr std::uint64_t kMaxTxOutputs = 10'000;
constexpr std::size_t kMaxScriptBytes = 256 * 1024;
}  // namespace

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
  try {
    if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
          auto version = r.u32le();
          auto in_count = r.varint();
          if (!version || !in_count) return false;
          if (*in_count > kMaxTxInputs) return false;
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
            if (script->size() > kMaxScriptBytes) return false;
            in.prev_txid = *prev;
            in.prev_index = *idx;
            in.script_sig = *script;
            in.sequence = *seq;
            tx.inputs.push_back(std::move(in));
          }

          auto out_count = r.varint();
          if (!out_count) return false;
          if (*out_count > kMaxTxOutputs) return false;
          tx.outputs.clear();
          tx.outputs.reserve(*out_count);
          for (std::uint64_t i = 0; i < *out_count; ++i) {
            TxOut out;
            auto value = r.u64le();
            auto script = r.varbytes();
            if (!value || !script) return false;
            if (script->size() > kMaxScriptBytes) return false;
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
  } catch (...) {
    return std::nullopt;
  }
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

Bytes FinalityCertificate::serialize() const {
  codec::ByteWriter w;
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(block_id);
  w.u32le(quorum_threshold);
  w.varint(committee_members.size());
  for (const auto& member : committee_members) w.bytes_fixed(member);
  w.varint(signatures.size());
  for (const auto& s : signatures) {
    w.bytes_fixed(s.validator_pubkey);
    w.bytes_fixed(s.signature);
  }
  return w.take();
}

std::optional<FinalityCertificate> FinalityCertificate::parse(const Bytes& b) {
  FinalityCertificate cert;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto block = r.bytes_fixed<32>();
        auto quorum = r.u32le();
        auto committee_count = r.varint();
        if (!h || !round || !block || !quorum || !committee_count) return false;
        cert.height = *h;
        cert.round = *round;
        cert.block_id = *block;
        cert.quorum_threshold = *quorum;
        cert.committee_members.clear();
        cert.committee_members.reserve(*committee_count);
        for (std::uint64_t i = 0; i < *committee_count; ++i) {
          auto member = r.bytes_fixed<32>();
          if (!member) return false;
          cert.committee_members.push_back(*member);
        }
        auto sig_count = r.varint();
        if (!sig_count) return false;
        cert.signatures.clear();
        cert.signatures.reserve(*sig_count);
        for (std::uint64_t i = 0; i < *sig_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          cert.signatures.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return cert;
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

bool is_validator_unbond_script(const Bytes& script, PubKey32* out_pubkey) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  if (script.size() != 40) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_pubkey) {
    std::copy(script.begin() + 8, script.end(), out_pubkey->begin());
  }
  return true;
}

bool is_burn_script(const Bytes& script, Hash32* out_evidence_hash) {
  static const std::array<std::uint8_t, 6> prefix = {'S', 'C', 'B', 'U', 'R', 'N'};
  if (script.size() != 38) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_evidence_hash) {
    std::copy(script.begin() + 6, script.end(), out_evidence_hash->begin());
  }
  return true;
}

}  // namespace selfcoin
