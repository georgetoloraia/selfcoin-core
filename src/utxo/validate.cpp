#include "utxo/validate.hpp"

#include <algorithm>
#include <set>

#include "codec/bytes.hpp"
#include "consensus/monetary.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "address/address.hpp"

namespace selfcoin {

namespace {

std::optional<Vote> read_vote_fixed(codec::ByteReader& r) {
  Vote v;
  auto h = r.u64le();
  auto round = r.u32le();
  auto bid = r.bytes_fixed<32>();
  auto pub = r.bytes_fixed<32>();
  auto sig = r.bytes_fixed<64>();
  if (!h || !round || !bid || !pub || !sig) return std::nullopt;
  v.height = *h;
  v.round = *round;
  v.block_id = *bid;
  v.validator_pubkey = *pub;
  v.signature = *sig;
  return v;
}

}  // namespace

bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash) {
  if (script_pubkey.size() != 25) return false;
  if (script_pubkey[0] != 0x76 || script_pubkey[1] != 0xA9 || script_pubkey[2] != 0x14 ||
      script_pubkey[23] != 0x88 || script_pubkey[24] != 0xAC) {
    return false;
  }
  if (out_hash) {
    std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23, out_hash->begin());
  }
  return true;
}

bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig, PubKey32* out_pub) {
  if (script_sig.size() != 98) return false;
  if (script_sig[0] != 0x40 || script_sig[65] != 0x20) return false;
  if (out_sig) std::copy(script_sig.begin() + 1, script_sig.begin() + 65, out_sig->begin());
  if (out_pub) std::copy(script_sig.begin() + 66, script_sig.end(), out_pub->begin());
  return true;
}

std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  Tx signing = tx;
  for (auto& in : signing.inputs) {
    in.script_sig.clear();
  }
  const Hash32 txh = crypto::sha256d(signing.serialize());

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'I', 'G', '-', 'V', '0'});
  w.u32le(input_index);
  w.bytes_fixed(txh);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

std::optional<Bytes> unbond_message_for_input(const Tx& tx, std::uint32_t input_index) {
  if (input_index >= tx.inputs.size()) return std::nullopt;
  Tx signing = tx;
  for (auto& in : signing.inputs) {
    in.script_sig.clear();
  }
  const Hash32 txh = crypto::sha256d(signing.serialize());

  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'U', 'N', 'B', 'O', 'N', 'D', '-', 'V', '0'});
  w.bytes_fixed(txh);
  w.u32le(input_index);
  const Hash32 msg = crypto::sha256d(w.data());
  return Bytes(msg.begin(), msg.end());
}

bool parse_slash_script_sig(const Bytes& script_sig, SlashEvidence* out) {
  static const Bytes marker{'S', 'C', 'S', 'L', 'A', 'S', 'H'};
  if (script_sig.size() < marker.size()) return false;
  if (!std::equal(marker.begin(), marker.end(), script_sig.begin())) return false;

  Bytes tail(script_sig.begin() + static_cast<long>(marker.size()), script_sig.end());
  Bytes blob;
  if (!codec::parse_exact(tail, [&](codec::ByteReader& r) {
        auto b = r.varbytes();
        if (!b) return false;
        blob = *b;
        return true;
      })) {
    return false;
  }

  Vote a;
  Vote b;
  if (!codec::parse_exact(blob, [&](codec::ByteReader& r) {
        auto v1 = read_vote_fixed(r);
        auto v2 = read_vote_fixed(r);
        if (!v1 || !v2) return false;
        a = *v1;
        b = *v2;
        return true;
      })) {
    return false;
  }

  if (out) {
    out->a = a;
    out->b = b;
    out->raw_blob = blob;
  }
  return true;
}

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos,
                               const SpecialValidationContext* ctx) {
  if (tx.version != 1) return {false, "unsupported tx version", 0};
  if (tx.lock_time != 0) return {false, "lock_time must be 0 in v0", 0};
  if (tx.inputs.empty() || tx.outputs.empty()) return {false, "tx inputs/outputs empty", 0};

  if (tx_index_in_block == 0) {
    if (tx.inputs.size() != 1) return {false, "coinbase must have one input", 0};
    const auto& in = tx.inputs[0];
    if (in.prev_txid != zero_hash()) return {false, "coinbase prev_txid invalid", 0};
    if (in.prev_index != 0xFFFFFFFF) return {false, "coinbase prev_index invalid", 0};
    if (in.sequence != 0xFFFFFFFF) return {false, "coinbase sequence invalid", 0};
    if (in.script_sig.size() > 100) return {false, "coinbase script_sig > 100", 0};
    return {true, "", 0};
  }

  for (const auto& out : tx.outputs) {
    PubKey32 pub{};
    if (is_validator_register_script(out.script_pubkey, &pub)) {
      (void)pub;
      if (ctx && ctx->consensus_version >= 7) {
        if (out.value < ctx->v7_min_bond_amount || out.value > ctx->v7_max_bond_amount) {
          return {false, "SCVALREG output out of v7 bond range", 0};
        }
      } else if (out.value != BOND_AMOUNT) {
        return {false, "SCVALREG output must equal BOND_AMOUNT", 0};
      }
    }
  }

  std::uint64_t in_sum = 0;
  std::uint64_t out_sum = 0;
  std::set<OutPoint> seen_inputs;
  for (const auto& out : tx.outputs) out_sum += out.value;

  for (std::uint32_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    if (in.sequence != 0xFFFFFFFF) return {false, "sequence must be FFFFFFFF", 0};
    OutPoint op{in.prev_txid, in.prev_index};
    if (!seen_inputs.insert(op).second) return {false, "duplicate input outpoint", 0};
    auto it = utxos.find(op);
    if (it == utxos.end()) return {false, "missing utxo", 0};

    const TxOut& prev_out = it->second.out;

    std::array<std::uint8_t, 20> pkh{};
    if (is_p2pkh_script_pubkey(prev_out.script_pubkey, &pkh)) {
      Sig64 sig{};
      PubKey32 pub{};
      if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad script_sig", 0};
      const auto derived = crypto::h160(Bytes(pub.begin(), pub.end()));
      if (!std::equal(derived.begin(), derived.end(), pkh.begin())) {
        return {false, "pubkey hash mismatch", 0};
      }

      const auto msg = signing_message_for_input(tx, i);
      if (!msg.has_value()) return {false, "sighash failed", 0};
      if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "signature invalid", 0};
      in_sum += prev_out.value;
      continue;
    }

    PubKey32 bond_pub{};
    if (is_validator_register_script(prev_out.script_pubkey, &bond_pub)) {
      if (!ctx || !ctx->validators) return {false, "bond spend requires validator context", 0};

      SlashEvidence evidence;
      if (parse_slash_script_sig(in.script_sig, &evidence)) {
        if (tx.outputs.size() != 1) return {false, "slash tx must have exactly one output", 0};
        Hash32 burn_hash{};
        if (!is_burn_script(tx.outputs[0].script_pubkey, &burn_hash)) return {false, "slash output must be SCBURN", 0};
        const Hash32 evh = crypto::sha256d(evidence.raw_blob);
        if (burn_hash != evh) return {false, "slash evidence hash mismatch", 0};

        if (evidence.a.height != evidence.b.height || evidence.a.round != evidence.b.round) {
          return {false, "invalid equivocation evidence height/round", 0};
        }
        if (evidence.a.block_id == evidence.b.block_id) return {false, "invalid equivocation evidence block_id", 0};
        if (evidence.a.validator_pubkey != evidence.b.validator_pubkey) return {false, "evidence pubkey mismatch", 0};
        if (evidence.a.validator_pubkey != bond_pub) return {false, "evidence pubkey must match bond", 0};

        Bytes a_bid(evidence.a.block_id.begin(), evidence.a.block_id.end());
        Bytes b_bid(evidence.b.block_id.begin(), evidence.b.block_id.end());
        if (!crypto::ed25519_verify(a_bid, evidence.a.signature, evidence.a.validator_pubkey)) {
          return {false, "invalid evidence signature a", 0};
        }
        if (!crypto::ed25519_verify(b_bid, evidence.b.signature, evidence.b.validator_pubkey)) {
          return {false, "invalid evidence signature b", 0};
        }
        if (!ctx->is_committee_member) return {false, "slash spend requires committee context", 0};
        if (!ctx->is_committee_member(evidence.a.validator_pubkey, evidence.a.height, evidence.a.round)) {
          return {false, "slash evidence validator not in committee", 0};
        }
      } else {
        // UNBOND path
        if (tx.outputs.size() != 1) return {false, "unbond tx must have exactly one output", 0};
        PubKey32 out_pub{};
        if (!is_validator_unbond_script(tx.outputs[0].script_pubkey, &out_pub)) {
          return {false, "unbond tx must output SCVALUNB", 0};
        }
        if (out_pub != bond_pub) return {false, "unbond pubkey mismatch", 0};

        Sig64 sig{};
        PubKey32 pub{};
        if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad unbond auth script_sig", 0};
        if (pub != bond_pub) return {false, "unbond auth pubkey mismatch", 0};
        const auto msg = unbond_message_for_input(tx, i);
        if (!msg.has_value()) return {false, "unbond sighash failed", 0};
        if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "unbond signature invalid", 0};
      }

      in_sum += prev_out.value;
      continue;
    }

    PubKey32 unbond_pub{};
    if (is_validator_unbond_script(prev_out.script_pubkey, &unbond_pub)) {
      if (!ctx || !ctx->validators) return {false, "unbond spend requires validator context", 0};
      auto info = ctx->validators->get(unbond_pub);
      if (!info.has_value()) return {false, "unknown validator for unbond output", 0};
      if (ctx->current_height < info->unbond_height + UNBOND_DELAY_BLOCKS) {
        return {false, "unbond delay not reached", 0};
      }

      Sig64 sig{};
      PubKey32 pub{};
      if (!is_p2pkh_script_sig(in.script_sig, &sig, &pub)) return {false, "bad unbond-spend script_sig", 0};
      if (pub != unbond_pub) return {false, "unbond-spend pubkey mismatch", 0};
      const auto msg = signing_message_for_input(tx, i);
      if (!msg.has_value()) return {false, "unbond-spend sighash failed", 0};
      if (!crypto::ed25519_verify(*msg, sig, pub)) return {false, "unbond-spend signature invalid", 0};

      for (const auto& o : tx.outputs) {
        if (!is_p2pkh_script_pubkey(o.script_pubkey, nullptr)) {
          return {false, "unbond output spend must go to P2PKH", 0};
        }
      }

      in_sum += prev_out.value;
      continue;
    }

    return {false, "unsupported prev script_pubkey", 0};
  }

  if (in_sum < out_sum) return {false, "negative fee", 0};
  return {true, "", in_sum - out_sum};
}

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward,
                                         const SpecialValidationContext* ctx,
                                         const std::vector<PubKey32>* reward_signers) {
  if (block.txs.empty()) return {false, "block has no tx", 0};
  UtxoSet work = base_utxos;

  std::uint64_t fees = 0;
  for (size_t i = 0; i < block.txs.size(); ++i) {
    auto r = validate_tx(block.txs[i], i, work, ctx);
    if (!r.ok) return {false, "tx invalid at index " + std::to_string(i) + ": " + r.error, 0};
    fees += r.fee;

    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        work.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      work[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }

  (void)block_reward;
  std::uint64_t coinbase_sum = 0;
  for (const auto& out : block.txs[0].outputs) coinbase_sum += out.value;
  const std::uint64_t reward = consensus::reward_units(block.header.height);
  if (coinbase_sum != reward + fees) {
    return {false, "coinbase sum mismatch", 0};
  }

  if (reward_signers) {
    const auto payout = consensus::compute_payout(block.header.height, fees, block.header.leader_pubkey, *reward_signers);
    std::vector<TxOut> expected;
    expected.reserve(1 + payout.signers.size());
    const auto leader_pkh = crypto::h160(Bytes(block.header.leader_pubkey.begin(), block.header.leader_pubkey.end()));
    expected.push_back(TxOut{payout.leader, address::p2pkh_script_pubkey(leader_pkh)});
    for (const auto& [pub, units] : payout.signers) {
      const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
      expected.push_back(TxOut{units, address::p2pkh_script_pubkey(pkh)});
    }
    if (block.txs[0].outputs.size() != expected.size()) return {false, "coinbase payout distribution mismatch", 0};
    for (std::size_t i = 0; i < expected.size(); ++i) {
      if (block.txs[0].outputs[i].value != expected[i].value ||
          block.txs[0].outputs[i].script_pubkey != expected[i].script_pubkey) {
        return {false, "coinbase payout distribution mismatch", 0};
      }
    }
  }

  return {true, "", fees};
}

void apply_block_to_utxo(const Block& block, UtxoSet& utxos) {
  for (size_t i = 0; i < block.txs.size(); ++i) {
    if (i > 0) {
      for (const auto& in : block.txs[i].inputs) {
        utxos.erase(OutPoint{in.prev_txid, in.prev_index});
      }
    }
    const Hash32 txid = block.txs[i].txid();
    for (std::uint32_t out_i = 0; out_i < block.txs[i].outputs.size(); ++out_i) {
      utxos[OutPoint{txid, out_i}] = UtxoEntry{block.txs[i].outputs[out_i]};
    }
  }
}

}  // namespace selfcoin
