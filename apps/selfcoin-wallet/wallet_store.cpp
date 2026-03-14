#include "wallet_store.hpp"

#include <cstdio>
#include <algorithm>
#include <filesystem>

#include "codec/bytes.hpp"

namespace selfcoin::wallet {
namespace {

Bytes to_bytes(const std::string& value) { return Bytes(value.begin(), value.end()); }

std::string from_bytes(const Bytes& value) { return std::string(value.begin(), value.end()); }

std::string key_sent(const std::string& txid) { return "SENT:" + txid; }
std::string key_event_seq() { return "EVT:SEQ"; }
std::string key_event(std::uint64_t seq) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "EVT:%020llu", static_cast<unsigned long long>(seq));
  return std::string(buf);
}
std::string key_note(const std::string& note_ref) { return "NOTE:" + note_ref; }
std::string key_meta(const std::string& name) { return "META:" + name; }

Bytes serialize_note(std::uint64_t amount, bool active) {
  codec::ByteWriter w;
  w.u64le(amount);
  w.u8(active ? 1 : 0);
  return w.take();
}

std::optional<std::pair<std::uint64_t, bool>> parse_note(const Bytes& value) {
  std::pair<std::uint64_t, bool> out{};
  if (!codec::parse_exact(value, [&](codec::ByteReader& r) {
        auto amount = r.u64le();
        auto active = r.u8();
        if (!amount || !active) return false;
        out.first = *amount;
        out.second = (*active != 0);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

}  // namespace

bool WalletStore::open(const std::string& wallet_file_path) {
  path_ = wallet_file_path + ".walletdb";
  std::filesystem::create_directories(path_);
  return db_.open(path_);
}

bool WalletStore::load(State* out) const {
  if (!out) return false;
  out->sent_txids.clear();
  out->local_events.clear();
  out->mint_notes.clear();

  for (const auto& [key, _] : db_.scan_prefix("SENT:")) out->sent_txids.push_back(key.substr(5));
  std::sort(out->sent_txids.begin(), out->sent_txids.end());

  for (const auto& [key, value] : db_.scan_prefix("EVT:")) {
    if (key == key_event_seq()) continue;
    out->local_events.push_back(from_bytes(value));
  }

  for (const auto& [key, value] : db_.scan_prefix("NOTE:")) {
    auto parsed = parse_note(value);
    if (!parsed) continue;
    out->mint_notes.push_back(MintNoteRecord{key.substr(5), parsed->first, parsed->second});
  }
  std::sort(out->mint_notes.begin(), out->mint_notes.end(),
            [](const auto& a, const auto& b) { return a.note_ref < b.note_ref; });

  out->mint_deposit_ref = get_string(key_meta("mint_deposit_ref")).value_or("");
  out->mint_last_deposit_txid = get_string(key_meta("mint_last_deposit_txid")).value_or("");
  out->mint_last_deposit_vout = get_u32(key_meta("mint_last_deposit_vout")).value_or(0);
  out->mint_last_redemption_batch_id = get_string(key_meta("mint_last_redemption_batch_id")).value_or("");
  return true;
}

bool WalletStore::add_sent_txid(const std::string& txid) { return db_.put(key_sent(txid), Bytes{}); }

bool WalletStore::append_local_event(const std::string& line) {
  const std::uint64_t seq = next_event_seq() + 1;
  if (!db_.put(key_event(seq), to_bytes(line))) return false;
  codec::ByteWriter w;
  w.u64le(seq);
  return db_.put(key_event_seq(), w.take());
}

bool WalletStore::upsert_mint_note(const std::string& note_ref, std::uint64_t amount, bool active) {
  return db_.put(key_note(note_ref), serialize_note(amount, active));
}

bool WalletStore::set_mint_deposit_ref(const std::string& value) { return set_string(key_meta("mint_deposit_ref"), value); }

bool WalletStore::set_mint_last_deposit_txid(const std::string& value) {
  return set_string(key_meta("mint_last_deposit_txid"), value);
}

bool WalletStore::set_mint_last_deposit_vout(std::uint32_t value) { return set_u32(key_meta("mint_last_deposit_vout"), value); }

bool WalletStore::set_mint_last_redemption_batch_id(const std::string& value) {
  return set_string(key_meta("mint_last_redemption_batch_id"), value);
}

bool WalletStore::set_string(const std::string& key, const std::string& value) { return db_.put(key, to_bytes(value)); }

bool WalletStore::set_u32(const std::string& key, std::uint32_t value) {
  codec::ByteWriter w;
  w.u32le(value);
  return db_.put(key, w.take());
}

std::optional<std::string> WalletStore::get_string(const std::string& key) const {
  auto value = db_.get(key);
  if (!value) return std::nullopt;
  return from_bytes(*value);
}

std::optional<std::uint32_t> WalletStore::get_u32(const std::string& key) const {
  auto value = db_.get(key);
  if (!value) return std::nullopt;
  std::uint32_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u32le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

std::uint64_t WalletStore::next_event_seq() const {
  auto value = db_.get(key_event_seq());
  if (!value) return 0;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*value, [&](codec::ByteReader& r) {
        auto parsed = r.u64le();
        if (!parsed) return false;
        out = *parsed;
        return true;
      })) {
    return 0;
  }
  return out;
}

}  // namespace selfcoin::wallet
