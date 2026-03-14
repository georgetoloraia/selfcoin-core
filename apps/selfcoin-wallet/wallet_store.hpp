#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "storage/db.hpp"

namespace selfcoin::wallet {

class WalletStore {
 public:
  struct MintNoteRecord {
    std::string note_ref;
    std::uint64_t amount{0};
    bool active{true};
  };

  struct State {
    std::vector<std::string> sent_txids;
    std::vector<std::string> local_events;
    std::vector<MintNoteRecord> mint_notes;
    std::string mint_deposit_ref;
    std::string mint_last_deposit_txid;
    std::uint32_t mint_last_deposit_vout{0};
    std::string mint_last_redemption_batch_id;
  };

  bool open(const std::string& wallet_file_path);
  bool load(State* out) const;

  bool add_sent_txid(const std::string& txid);
  bool append_local_event(const std::string& line);
  bool upsert_mint_note(const std::string& note_ref, std::uint64_t amount, bool active);
  bool set_mint_deposit_ref(const std::string& value);
  bool set_mint_last_deposit_txid(const std::string& value);
  bool set_mint_last_deposit_vout(std::uint32_t value);
  bool set_mint_last_redemption_batch_id(const std::string& value);

 private:
  bool set_string(const std::string& key, const std::string& value);
  bool set_u32(const std::string& key, std::uint32_t value);
  std::optional<std::string> get_string(const std::string& key) const;
  std::optional<std::uint32_t> get_u32(const std::string& key) const;
  std::uint64_t next_event_seq() const;

  storage::DB db_;
  std::string path_;
};

}  // namespace selfcoin::wallet
