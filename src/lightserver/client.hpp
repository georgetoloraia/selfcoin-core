#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/chain_id.hpp"
#include "common/types.hpp"

namespace selfcoin::lightserver {

struct RpcStatusView {
  selfcoin::ChainId chain;
  std::uint64_t tip_height{0};
  std::string tip_hash;
};

struct UtxoView {
  Hash32 txid{};
  std::uint32_t vout{0};
  std::uint64_t value{0};
  std::uint64_t height{0};
  Bytes script_pubkey;
};

struct HistoryEntry {
  Hash32 txid{};
  std::uint64_t height{0};
};

struct TxView {
  std::uint64_t height{0};
  Bytes tx_bytes;
};

struct BroadcastResult {
  bool accepted{false};
  std::string txid_hex;
  std::string error;
};

std::optional<RpcStatusView> rpc_get_status(const std::string& rpc_url, std::string* err);
std::optional<std::vector<UtxoView>> rpc_get_utxos(const std::string& rpc_url, const Hash32& scripthash, std::string* err);
std::optional<std::vector<HistoryEntry>> rpc_get_history(const std::string& rpc_url, const Hash32& scripthash,
                                                         std::string* err);
std::optional<TxView> rpc_get_tx(const std::string& rpc_url, const Hash32& txid, std::string* err);
std::optional<BroadcastResult> rpc_broadcast_tx(const std::string& rpc_url, const Bytes& tx_bytes, std::string* err);
std::optional<std::string> http_post_json_raw(const std::string& url, const std::string& body, std::string* err);

}  // namespace selfcoin::lightserver
