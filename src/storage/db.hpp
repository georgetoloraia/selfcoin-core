#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "consensus/validators.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::storage {

struct TipState {
  std::uint64_t height{0};
  Hash32 hash{};
};

class DB {
 public:
  DB();
  ~DB();

  DB(const DB&) = delete;
  DB& operator=(const DB&) = delete;
  DB(DB&&) noexcept = default;
  DB& operator=(DB&&) noexcept = default;

  bool open(const std::string& path);
  bool open_readonly(const std::string& path);
  bool flush();
  void close();

  bool put(const std::string& key, const Bytes& value);
  std::optional<Bytes> get(const std::string& key) const;
  std::map<std::string, Bytes> scan_prefix(const std::string& prefix) const;

  bool set_tip(const TipState& tip);
  std::optional<TipState> get_tip() const;

  bool put_block(const Hash32& hash, const Bytes& block_bytes);
  std::optional<Bytes> get_block(const Hash32& hash) const;
  // Certificates are indexed both by finalized height and finalized block hash.
  // This keeps the new first-class certificate surface separate from the legacy
  // embedded Block.finality_proof compatibility path.
  bool put_finality_certificate(const FinalityCertificate& cert);
  std::optional<FinalityCertificate> get_finality_certificate_by_height(std::uint64_t height) const;
  std::optional<FinalityCertificate> get_finality_certificate_by_block(const Hash32& hash) const;

  bool set_height_hash(std::uint64_t height, const Hash32& hash);
  std::optional<Hash32> get_height_hash(std::uint64_t height) const;

  bool put_utxo(const OutPoint& op, const TxOut& out);
  bool erase_utxo(const OutPoint& op);
  std::map<OutPoint, UtxoEntry> load_utxos() const;

  bool put_validator(const PubKey32& pub, const consensus::ValidatorInfo& info);
  std::map<PubKey32, consensus::ValidatorInfo> load_validators() const;
  bool put_validator_join_request(const Hash32& request_txid, const ValidatorJoinRequest& req);
  std::map<Hash32, ValidatorJoinRequest> load_validator_join_requests() const;

  struct TxLocation {
    std::uint64_t height{0};
    std::uint32_t tx_index{0};
    Bytes tx_bytes;
  };
  bool put_tx_index(const Hash32& txid, std::uint64_t height, std::uint32_t tx_index, const Bytes& tx_bytes);
  std::optional<TxLocation> get_tx_index(const Hash32& txid) const;

  struct ScriptUtxoEntry {
    OutPoint outpoint;
    std::uint64_t value{0};
    Bytes script_pubkey;
    std::uint64_t height{0};
  };
  bool put_script_utxo(const Hash32& scripthash, const OutPoint& op, const TxOut& out, std::uint64_t height);
  bool erase_script_utxo(const Hash32& scripthash, const OutPoint& op);
  std::vector<ScriptUtxoEntry> get_script_utxos(const Hash32& scripthash) const;

  struct ScriptHistoryEntry {
    Hash32 txid{};
    std::uint64_t height{0};
  };
  bool add_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid);
  std::vector<ScriptHistoryEntry> get_script_history(const Hash32& scripthash) const;

 private:
  std::string path_;
  bool readonly_{false};

#ifdef SC_HAS_ROCKSDB
  class RocksImpl;
  std::unique_ptr<RocksImpl> rocks_;
#else
  std::map<std::string, Bytes> mem_;
  bool flush_file() const;
  bool load_file();
#endif
};

std::string key_block(const Hash32& hash);
std::string key_height(std::uint64_t height);
std::string key_utxo(const OutPoint& op);
std::string key_validator(const PubKey32& pub);

}  // namespace selfcoin::storage
