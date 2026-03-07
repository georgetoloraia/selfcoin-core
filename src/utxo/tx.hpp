#pragma once

#include <map>
#include <optional>
#include <string>
#include <tuple>

#include "common/types.hpp"

namespace selfcoin {

struct TxIn {
  Hash32 prev_txid;
  std::uint32_t prev_index{0};
  Bytes script_sig;
  std::uint32_t sequence{0xFFFFFFFF};
};

struct TxOut {
  std::uint64_t value{0};
  Bytes script_pubkey;
};

struct Tx {
  std::uint32_t version{1};
  std::vector<TxIn> inputs;
  std::vector<TxOut> outputs;
  std::uint32_t lock_time{0};

  Bytes serialize() const;
  static std::optional<Tx> parse(const Bytes& b);
  Hash32 txid() const;
};

struct BlockHeader {
  Hash32 prev_finalized_hash;
  std::uint64_t height{0};
  std::uint64_t timestamp{0};
  Hash32 merkle_root;
  PubKey32 leader_pubkey;
  std::uint32_t round{0};

  Bytes serialize() const;
  static std::optional<BlockHeader> parse(const Bytes& b);
  Hash32 block_id() const;
};

struct FinalitySig {
  PubKey32 validator_pubkey;
  Sig64 signature;
};

struct FinalityProof {
  std::vector<FinalitySig> sigs;

  Bytes serialize() const;
  static std::optional<FinalityProof> parse(const Bytes& b);
};

struct FinalityCertificate {
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 block_id{};
  std::uint32_t quorum_threshold{0};
  // The conservative certificate slice stores explicit committee members rather
  // than a separate committee commitment so readers can reconstruct the finalized
  // quorum context without introducing new protocol assumptions.
  std::vector<PubKey32> committee_members;
  // Raw signatures are preserved as-is. Aggregated signatures are intentionally
  // deferred and not implied by this object.
  std::vector<FinalitySig> signatures;

  Bytes serialize() const;
  static std::optional<FinalityCertificate> parse(const Bytes& b);
};

struct Block {
  BlockHeader header;
  std::vector<Tx> txs;
  FinalityProof finality_proof;

  Bytes serialize() const;
  static std::optional<Block> parse(const Bytes& b);
};

struct Vote {
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 block_id;
  PubKey32 validator_pubkey;
  Sig64 signature;
};

struct EquivocationEvidence {
  Vote a;
  Vote b;
};

struct OutPoint {
  Hash32 txid;
  std::uint32_t index{0};

  bool operator<(const OutPoint& o) const {
    return std::tie(txid, index) < std::tie(o.txid, o.index);
  }
};

struct UtxoEntry {
  TxOut out;
};

using UtxoSet = std::map<OutPoint, UtxoEntry>;

bool is_validator_register_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
bool is_validator_unbond_script(const Bytes& script, PubKey32* out_pubkey = nullptr);
bool is_burn_script(const Bytes& script, Hash32* out_evidence_hash = nullptr);

}  // namespace selfcoin
