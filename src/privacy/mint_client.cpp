#include "privacy/mint_client.hpp"

#include <regex>
#include <sstream>

#include "codec/bytes.hpp"

namespace selfcoin::privacy {
namespace {

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string hex20(const std::array<std::uint8_t, 20>& v) {
  return hex_encode(Bytes(v.begin(), v.end()));
}

std::optional<std::string> find_json_string(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return m[1].str();
}

std::optional<std::uint64_t> find_json_u64(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return static_cast<std::uint64_t>(std::stoull(m[1].str()));
}

std::optional<bool> find_json_bool(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*(true|false)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return std::nullopt;
  return m[1].str() == "true";
}

std::vector<std::string> find_json_string_array(const std::string& json, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return {};
  std::vector<std::string> out;
  std::regex item_re("\"([^\"]*)\"");
  std::string body = m[1].str();
  auto begin = std::sregex_iterator(body.begin(), body.end(), item_re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) out.push_back((*it)[1].str());
  return out;
}

std::string json_string_array(const std::vector<std::string>& items) {
  std::ostringstream oss;
  oss << "[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << json_escape(items[i]) << "\"";
  }
  oss << "]";
  return oss.str();
}

}  // namespace

std::string to_json(const MintDepositRegistrationRequest& req) {
  std::ostringstream oss;
  oss << "{"
      << "\"chain\":\"" << json_escape(req.chain) << "\","
      << "\"deposit_txid\":\"" << hex_encode32(req.deposit_txid) << "\","
      << "\"deposit_vout\":" << req.deposit_vout << ","
      << "\"mint_id\":\"" << hex_encode32(req.mint_id) << "\","
      << "\"recipient_pubkey_hash\":\"" << hex20(req.recipient_pubkey_hash) << "\","
      << "\"amount\":" << req.amount
      << "}";
  return oss.str();
}

std::string to_json(const MintBlindIssueRequest& req) {
  std::ostringstream oss;
  oss << "{"
      << "\"mint_deposit_ref\":\"" << json_escape(req.mint_deposit_ref) << "\","
      << "\"blinded_messages\":" << json_string_array(req.blinded_messages)
      << "}";
  return oss.str();
}

std::string to_json(const MintRedemptionRequest& req) {
  std::ostringstream oss;
  oss << "{"
      << "\"notes\":" << json_string_array(req.notes) << ","
      << "\"redeem_address\":\"" << json_escape(req.redeem_address) << "\""
      << "}";
  return oss.str();
}

std::optional<MintDepositRegistrationResponse> parse_mint_deposit_registration_response(const std::string& json) {
  auto accepted = find_json_bool(json, "accepted");
  auto confirmations = find_json_u64(json, "confirmations_required");
  auto ref = find_json_string(json, "mint_deposit_ref");
  if (!accepted || !confirmations || !ref) return std::nullopt;
  MintDepositRegistrationResponse out;
  out.accepted = *accepted;
  out.confirmations_required = *confirmations;
  out.mint_deposit_ref = *ref;
  return out;
}

std::optional<MintBlindIssueResponse> parse_mint_blind_issue_response(const std::string& json) {
  auto epoch = find_json_u64(json, "mint_epoch");
  if (!epoch) return std::nullopt;
  MintBlindIssueResponse out;
  out.signed_blinds = find_json_string_array(json, "signed_blinds");
  out.mint_epoch = *epoch;
  return out;
}

std::optional<MintRedemptionResponse> parse_mint_redemption_response(const std::string& json) {
  auto accepted = find_json_bool(json, "accepted");
  auto batch = find_json_string(json, "redemption_batch_id");
  if (!accepted || !batch) return std::nullopt;
  MintRedemptionResponse out;
  out.accepted = *accepted;
  out.redemption_batch_id = *batch;
  return out;
}

std::optional<MintRedemptionStatusResponse> parse_mint_redemption_status_response(const std::string& json) {
  auto state = find_json_string(json, "state");
  auto txid = find_json_string(json, "l1_txid");
  if (!state || !txid) return std::nullopt;
  MintRedemptionStatusResponse out;
  out.state = *state;
  out.l1_txid = *txid;
  return out;
}

}  // namespace selfcoin::privacy
