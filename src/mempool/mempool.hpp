#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/network.hpp"
#include "policy/hashcash.hpp"
#include "utxo/validate.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::mempool {

using UtxoView = UtxoSet;

struct MempoolEntry {
  Tx tx;
  Hash32 txid;
  std::uint64_t fee{0};
  std::size_t size_bytes{0};
};

class Mempool {
 public:
  static constexpr std::size_t kMaxTxBytes = 100 * 1024;
  static constexpr std::size_t kMaxTxCount = 10'000;
  static constexpr std::size_t kMaxPoolBytes = 10 * 1024 * 1024;

  bool accept_tx(const Tx& tx, const UtxoView& view, std::string* err, std::uint64_t min_fee = 0,
                 std::uint64_t* accepted_fee = nullptr);
  std::vector<Tx> select_for_block(std::size_t max_txs, std::size_t max_bytes, const UtxoView& view) const;
  void remove_confirmed(const std::vector<Hash32>& txids);
  void prune_against_utxo(const UtxoView& view);
  std::size_t size() const;
  bool contains(const Hash32& txid) const;
  void set_validation_context(SpecialValidationContext ctx) { ctx_ = ctx; }
  void set_hashcash_config(policy::HashcashConfig cfg) { hashcash_cfg_ = std::move(cfg); }
  void set_network(NetworkConfig cfg) { network_ = std::move(cfg); }

 private:
  struct TxMeta {
    MempoolEntry entry;
    std::vector<OutPoint> spent;
  };

  std::map<Hash32, TxMeta> by_txid_;
  std::map<OutPoint, Hash32> spent_outpoints_;
  std::size_t total_bytes_{0};
  std::optional<SpecialValidationContext> ctx_;
  policy::HashcashConfig hashcash_cfg_{};
  NetworkConfig network_{mainnet_network()};
};

}  // namespace selfcoin::mempool
