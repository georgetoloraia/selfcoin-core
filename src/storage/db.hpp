#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "consensus/validators.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::storage {

struct TipState {
  std::uint64_t height{0};
  Hash32 hash{};
};

class DB {
 public:
  bool open(const std::string& path);

  bool put(const std::string& key, const Bytes& value);
  std::optional<Bytes> get(const std::string& key) const;
  std::map<std::string, Bytes> scan_prefix(const std::string& prefix) const;

  bool set_tip(const TipState& tip);
  std::optional<TipState> get_tip() const;

  bool put_block(const Hash32& hash, const Bytes& block_bytes);
  std::optional<Bytes> get_block(const Hash32& hash) const;

  bool set_height_hash(std::uint64_t height, const Hash32& hash);
  std::optional<Hash32> get_height_hash(std::uint64_t height) const;

  bool put_utxo(const OutPoint& op, const TxOut& out);
  bool erase_utxo(const OutPoint& op);
  std::map<OutPoint, UtxoEntry> load_utxos() const;

  bool put_validator(const PubKey32& pub, const consensus::ValidatorInfo& info);
  std::map<PubKey32, consensus::ValidatorInfo> load_validators() const;

 private:
  std::string path_;

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
