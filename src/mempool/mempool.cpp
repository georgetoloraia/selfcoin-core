#include "mempool/mempool.hpp"

#include <algorithm>

#include "utxo/validate.hpp"

namespace selfcoin::mempool {

namespace {

bool outpoint_exists(const UtxoView& view, const OutPoint& op) {
  return view.find(op) != view.end();
}

}  // namespace

bool Mempool::accept_tx(const Tx& tx, const UtxoView& view, std::string* err, std::uint64_t min_fee,
                        std::uint64_t* accepted_fee) {
  const Bytes raw = tx.serialize();
  if (raw.size() > kMaxTxBytes) {
    if (err) *err = "tx too large";
    return false;
  }
  if (by_txid_.size() >= kMaxTxCount) {
    if (err) *err = "mempool count limit reached";
    return false;
  }
  if (total_bytes_ + raw.size() > kMaxPoolBytes) {
    if (err) *err = "mempool bytes limit reached";
    return false;
  }

  const Hash32 txid = tx.txid();
  if (by_txid_.find(txid) != by_txid_.end()) {
    if (err) *err = "tx already exists";
    return false;
  }

  // v0: no unconfirmed parents. Every input must reference confirmed UTXO view.
  for (const auto& in : tx.inputs) {
    OutPoint op{in.prev_txid, in.prev_index};
    if (!outpoint_exists(view, op)) {
      if (err) *err = "input depends on unconfirmed or missing utxo";
      return false;
    }
    if (spent_outpoints_.find(op) != spent_outpoints_.end()) {
      if (err) *err = "double spend in mempool";
      return false;
    }
  }

  const auto vr = validate_tx(tx, 1, view, ctx_ ? &*ctx_ : nullptr);
  if (!vr.ok) {
    if (err) *err = "tx invalid: " + vr.error;
    return false;
  }
  if (vr.fee < min_fee) {
    if (err) *err = "fee below min relay fee";
    return false;
  }

  TxMeta meta;
  meta.entry = MempoolEntry{tx, txid, vr.fee, raw.size()};
  meta.spent.reserve(tx.inputs.size());
  for (const auto& in : tx.inputs) {
    OutPoint op{in.prev_txid, in.prev_index};
    meta.spent.push_back(op);
    spent_outpoints_[op] = txid;
  }

  total_bytes_ += raw.size();
  by_txid_[txid] = std::move(meta);
  if (accepted_fee) *accepted_fee = vr.fee;
  return true;
}

std::vector<Tx> Mempool::select_for_block(std::size_t max_txs, std::size_t max_bytes, const UtxoView& view) const {
  std::vector<const TxMeta*> candidates;
  candidates.reserve(by_txid_.size());
  for (const auto& [_, meta] : by_txid_) {
    candidates.push_back(&meta);
  }

  std::sort(candidates.begin(), candidates.end(), [](const TxMeta* a, const TxMeta* b) {
    if (a->entry.fee != b->entry.fee) return a->entry.fee > b->entry.fee;
    return a->entry.txid < b->entry.txid;
  });

  std::vector<Tx> out;
  out.reserve(std::min(max_txs, candidates.size()));
  std::size_t used_bytes = 0;
  UtxoView work = view;

  for (const TxMeta* m : candidates) {
    if (out.size() >= max_txs) break;
    if (used_bytes + m->entry.size_bytes > max_bytes) continue;

    const auto vr = validate_tx(m->entry.tx, 1, work, ctx_ ? &*ctx_ : nullptr);
    if (!vr.ok) continue;

    for (const auto& in : m->entry.tx.inputs) {
      work.erase(OutPoint{in.prev_txid, in.prev_index});
    }
    const Hash32 txid = m->entry.txid;
    for (std::uint32_t i = 0; i < m->entry.tx.outputs.size(); ++i) {
      work[OutPoint{txid, i}] = UtxoEntry{m->entry.tx.outputs[i]};
    }

    out.push_back(m->entry.tx);
    used_bytes += m->entry.size_bytes;
  }
  return out;
}

void Mempool::remove_confirmed(const std::vector<Hash32>& txids) {
  std::set<Hash32> to_remove(txids.begin(), txids.end());

  for (auto it = by_txid_.begin(); it != by_txid_.end();) {
    bool remove = to_remove.find(it->first) != to_remove.end();
    if (!remove) {
      ++it;
      continue;
    }

    for (const auto& op : it->second.spent) {
      auto sit = spent_outpoints_.find(op);
      if (sit != spent_outpoints_.end() && sit->second == it->first) {
        spent_outpoints_.erase(sit);
      }
    }
    total_bytes_ -= it->second.entry.size_bytes;
    it = by_txid_.erase(it);
  }
}

void Mempool::prune_against_utxo(const UtxoView& view) {
  for (auto it = by_txid_.begin(); it != by_txid_.end();) {
    bool ok = true;
    for (const auto& in : it->second.entry.tx.inputs) {
      if (!outpoint_exists(view, OutPoint{in.prev_txid, in.prev_index})) {
        ok = false;
        break;
      }
    }
    if (ok) {
      ++it;
      continue;
    }

    for (const auto& op : it->second.spent) {
      auto sit = spent_outpoints_.find(op);
      if (sit != spent_outpoints_.end() && sit->second == it->first) {
        spent_outpoints_.erase(sit);
      }
    }
    total_bytes_ -= it->second.entry.size_bytes;
    it = by_txid_.erase(it);
  }
}

std::size_t Mempool::size() const { return by_txid_.size(); }

bool Mempool::contains(const Hash32& txid) const { return by_txid_.find(txid) != by_txid_.end(); }

}  // namespace selfcoin::mempool
