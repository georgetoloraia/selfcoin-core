#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <ctime>
#include <regex>
#include <fstream>
#include <iostream>
#include <sstream>
#include <optional>
#include <random>
#include <string>
#include <algorithm>
#include <vector>
#include <filesystem>
#include <cstdio>

#include "address/address.hpp"
#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "common/paths.hpp"
#include "consensus/randomness.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "policy/hashcash.hpp"
#include "privacy/mint_client.hpp"
#include "privacy/mint_scripts.hpp"
#include "storage/db.hpp"
#include "storage/snapshot.hpp"
#include "utxo/signing.hpp"

namespace {

std::string short_pub_hex(const selfcoin::PubKey32& pub) {
  return selfcoin::hex_encode(selfcoin::Bytes(pub.begin(), pub.begin() + 4));
}

std::optional<int> connect_tcp(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return std::nullopt;

  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return std::nullopt;
  return fd;
}

bool do_handshake_v0(int fd) {
  selfcoin::p2p::VersionMsg v;
  v.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
  v.nonce = 0xC011CAFE;
  v.start_height = 0;
  v.start_hash = selfcoin::zero_hash();

  if (!selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::VERSION, selfcoin::p2p::ser_version(v)})) {
    return false;
  }

  bool got_version = false;
  bool got_verack = false;
  bool sent_verack = false;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline && (!got_version || !got_verack)) {
    auto f = selfcoin::p2p::read_frame_fd(fd);
    if (!f.has_value()) return false;
    if (f->msg_type == selfcoin::p2p::MsgType::VERSION) {
      auto pv = selfcoin::p2p::de_version(f->payload);
      if (!pv.has_value()) return false;
      got_version = true;
      if (!sent_verack) {
        if (!selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::VERACK, {}})) {
          return false;
        }
        sent_verack = true;
      }
    } else if (f->msg_type == selfcoin::p2p::MsgType::VERACK) {
      got_verack = true;
    }
  }

  return got_version && got_verack;
}

std::optional<std::array<std::uint8_t, 32>> decode_hex32(const std::string& hex) {
  auto b = selfcoin::hex_decode(hex);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  std::array<std::uint8_t, 32> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::optional<std::array<std::uint8_t, 64>> decode_hex64(const std::string& hex) {
  auto b = selfcoin::hex_decode(hex);
  if (!b.has_value() || b->size() != 64) return std::nullopt;
  std::array<std::uint8_t, 64> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

struct ParsedHttpUrl {
  std::string host;
  std::uint16_t port{0};
  std::string path;
};

std::optional<ParsedHttpUrl> parse_http_url(const std::string& url) {
  std::regex re(R"(^http://([^/:]+):([0-9]+)(/[^ ]*)$)");
  std::smatch m;
  if (!std::regex_match(url, m, re)) return std::nullopt;
  ParsedHttpUrl out;
  out.host = m[1].str();
  out.port = static_cast<std::uint16_t>(std::stoul(m[2].str()));
  out.path = m[3].str();
  return out;
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body,
                                          const std::string& bearer_token, std::string* err);
std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err);
std::optional<std::string> http_get_json(const std::string& url, const std::string& bearer_token, std::string* err);
std::optional<std::string> http_get_json(const std::string& url, std::string* err);

std::optional<std::string> http_post_json(const std::string& url, const std::string& body,
                                          const std::string& bearer_token, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "url must be http://host:port/path";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt.has_value()) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const int fd = *fd_opt;
  std::ostringstream req;
  req << "POST " << parsed->path << " HTTP/1.1\r\nHost: " << parsed->host << ":" << parsed->port
      << "\r\nContent-Type: application/json\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  req << "Content-Length: " << body.size()
      << "\r\nConnection: close\r\n\r\n" << body;
  const auto req_s = req.str();
  if (!selfcoin::p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req_s.data()), req_s.size())) {
    ::close(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) {
    if (err) *err = "bad http response";
    return std::nullopt;
  }
  return resp.substr(pos + 4);
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err) {
  return http_post_json(url, body, "", err);
}

std::optional<std::string> http_get_json(const std::string& url, const std::string& bearer_token, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "url must be http://host:port/path";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt.has_value()) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const int fd = *fd_opt;
  std::ostringstream req;
  req << "GET " << parsed->path << " HTTP/1.1\r\nHost: " << parsed->host << ":" << parsed->port << "\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  req << "Connection: close\r\n\r\n";
  const auto req_s = req.str();
  if (!selfcoin::p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req_s.data()), req_s.size())) {
    ::close(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) {
    if (err) *err = "bad http response";
    return std::nullopt;
  }
  return resp.substr(pos + 4);
}

std::optional<std::string> http_get_json(const std::string& url, std::string* err) {
  return http_get_json(url, "", err);
}

std::optional<std::string> rpc_http_post(const std::string& url, const std::string& body, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed || parsed->path != "/rpc") {
    if (err) *err = "url must be http://host:port/rpc";
    return std::nullopt;
  }
  return http_post_json(url, body, err);
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

struct RpcStatusView {
  selfcoin::ChainId chain;
  std::uint64_t tip_height{0};
  std::string tip_hash;
};

std::optional<RpcStatusView> parse_get_status_result(const std::string& body, std::string* err) {
  if (body.find("\"error\"") != std::string::npos) {
    if (err) *err = "rpc returned error";
    return std::nullopt;
  }
  RpcStatusView out;
  auto network_name = find_json_string(body, "network_name");
  auto network_id = find_json_string(body, "network_id");
  auto genesis_hash = find_json_string(body, "genesis_hash");
  auto genesis_source = find_json_string(body, "genesis_source");
  auto proto = find_json_u64(body, "protocol_version");
  auto magic = find_json_u64(body, "magic");
  auto tip_height = find_json_u64(body, "height");
  auto tip_hash = find_json_string(body, "hash");
  if (!network_name || !network_id || !genesis_hash || !genesis_source || !proto || !magic || !tip_height || !tip_hash) {
    if (err) *err = "missing status fields";
    return std::nullopt;
  }
  out.chain.network_name = *network_name;
  out.chain.network_id_hex = *network_id;
  out.chain.genesis_hash_hex = *genesis_hash;
  out.chain.genesis_source = *genesis_source;
  out.chain.protocol_version = static_cast<std::uint32_t>(*proto);
  out.chain.magic = static_cast<std::uint32_t>(*magic);
  out.tip_height = *tip_height;
  out.tip_hash = *tip_hash;
  return out;
}

std::string expand_user(const std::string& path) {
  return selfcoin::expand_user_home(path);
}

std::vector<std::string> read_lines(const std::string& path) {
  std::ifstream in(path);
  std::vector<std::string> out;
  std::string line;
  while (std::getline(in, line)) out.push_back(line);
  return out;
}

std::vector<std::string> tail_lines(const std::string& path, std::size_t count) {
  auto lines = read_lines(path);
  if (lines.size() <= count) return lines;
  return std::vector<std::string>(lines.end() - static_cast<std::ptrdiff_t>(count), lines.end());
}

std::string trim_copy(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
  std::size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) ++start;
  return s.substr(start);
}

std::string slashing_kind_name(selfcoin::storage::SlashingRecordKind kind) {
  switch (kind) {
    case selfcoin::storage::SlashingRecordKind::VOTE_EQUIVOCATION:
      return "vote-equivocation";
    case selfcoin::storage::SlashingRecordKind::PROPOSER_EQUIVOCATION:
      return "proposer-equivocation";
    case selfcoin::storage::SlashingRecordKind::ONCHAIN_SLASH:
      return "onchain-slash";
  }
  return "unknown";
}

std::vector<std::string> run_command_lines(const std::string& cmd) {
  std::vector<std::string> out;
  FILE* fp = ::popen(cmd.c_str(), "r");
  if (!fp) return out;
  char buf[4096];
  while (std::fgets(buf, sizeof(buf), fp)) out.push_back(trim_copy(buf));
  (void)::pclose(fp);
  return out;
}

bool contains_any(const std::string& s, const std::vector<std::string>& needles) {
  for (const auto& n : needles) {
    if (s.find(n) != std::string::npos) return true;
  }
  return false;
}

void print_section(const std::string& title) {
  std::cout << "\n== " << title << " ==\n";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage:\n"
              << "  selfcoin-cli tip --db <dir>\n"
              << "  selfcoin-cli --print-logs [--db <dir>] [--service <name>] [--tail <n>]\n"
              << "  selfcoin-cli print_logs [--db <dir>] [--service <name>] [--tail <n>]\n"
              << "  selfcoin-cli snapshot_export --db <dir> --out <snapshot.bin>   # stopped/quiescent db expected\n"
              << "  selfcoin-cli snapshot_import --db <dir> --in <snapshot.bin>    # empty db only\n"
              << "  selfcoin-cli create_keypair [--seed-hex <32b-hex>] [--hrp sc]\n"
              << "  selfcoin-cli wallet_create --out <path> [--pass <pass>] [--network mainnet] [--seed-hex <32b-hex>]\n"
              << "  selfcoin-cli wallet_address --file <path> [--pass <pass>]\n"
              << "  selfcoin-cli wallet_export --file <path> [--pass <pass>]\n"
              << "  selfcoin-cli wallet_import --out <path> --privkey <hex32> [--pass <pass>] [--network mainnet]\n"
              << "  selfcoin-cli address_from_pubkey --hrp <sc> --pubkey <hex32>\n"
              << "  selfcoin-cli build_p2pkh_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> --to-address <addr> --amount <u64> --fee <u64> [--change-address <addr>]\n"
              << "  selfcoin-cli create_validator_bond_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> [--fee <u64>] [--change-address <addr>]\n"
              << "  selfcoin-cli create_validator_join_request_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --funding-privkey <hex32> --validator-privkey <hex32> [--payout-pubkey <hex32>] [--bond-amount <u64>] [--fee <u64>] [--change-address <addr>]\n"
              << "  selfcoin-cli create_validator_join_approval_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --funding-privkey <hex32> --approver-privkey <hex32> --request-txid <hex32> --validator-pubkey <hex32> [--fee <u64>] [--change-address <addr>]\n"
              << "  selfcoin-cli mint_deposit_create --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> --mint-id <hex32> --recipient-address <addr> --amount <u64> [--fee <u64>] [--change-address <addr>]\n"
              << "  selfcoin-cli mint_deposit_status [--db <dir>] [--mint-id <hex32>] [--recipient-address <addr>] [--tail <n>]\n"
              << "  selfcoin-cli mint_deposit_register --url http://host:port/path --deposit-txid <hex32> --deposit-vout <u32> --mint-id <hex32> --recipient-address <addr> --amount <u64> [--chain mainnet]\n"
              << "  selfcoin-cli mint_issue_blinds --url http://host:port/path --mint-deposit-ref <id> --blind <msg> --note-amount <u64> [--blind <msg> --note-amount <u64> ...]\n"
              << "  selfcoin-cli mint_redeem_create --url http://host:port/path --redeem-address <addr> --amount <u64> --note <opaque> [--note <opaque> ...]\n"
              << "  selfcoin-cli mint_redeem_status --url http://host:port/path --batch-id <id>\n"
              << "  selfcoin-cli mint_redeem_update --url http://host:port/path --batch-id <id> --state <pending|broadcast|finalized|rejected> [--l1-txid <hex32>] --admin-token <token>\n"
              << "  selfcoin-cli mint_reserves --url http://host:port/path\n"
              << "  selfcoin-cli mint_accounting_summary --url http://host:port/path\n"
              << "  selfcoin-cli mint_audit_export --url http://host:port/path --admin-token <token>\n"
              << "  selfcoin-cli mint_api_example\n"
              << "  selfcoin-cli hashcash_stamp_tx --tx-hex <hex> [--bits <n>] [--network mainnet] [--epoch-seconds <n>] [--now <unix>] [--max-nonce <n>]\n"
              << "  selfcoin-cli create_unbond_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --validator-pubkey <hex32> --validator-privkey <hex32> [--fee <u64>]\n"
              << "  selfcoin-cli create_slash_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --a-height <u64> --a-round <u32> --a-block <hex32> --a-pub <hex32> --a-sig <hex64> --b-height <u64> --b-round <u32> --b-block <hex32> --b-pub <hex32> --b-sig <hex64> [--fee <u64>]\n"
              << "  selfcoin-cli slash_records [--db <dir>] [--tail <n>]\n"
              << "  selfcoin-cli genesis_build --in <genesis.json> --out <genesis.bin>\n"
              << "  selfcoin-cli genesis_hash --in <genesis.bin>\n"
              << "  selfcoin-cli genesis_verify --json <genesis.json> --bin <genesis.bin>\n"
              << "  selfcoin-cli genesis_print_embedded\n"
              << "  selfcoin-cli rpc_status --url http://host:port/rpc\n"
              << "  selfcoin-cli rpc_compare --urls http://a:19444/rpc,http://b:19444/rpc\n"
              << "  selfcoin-cli broadcast_tx --host <ip> --port <p> --tx-hex <hex>\n";
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "--print-logs" || cmd == "print_logs") {
    std::string db_path = "./data/node";
    std::string service_name = "selfcoin";
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--service" && i + 1 < argc) service_name = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }

    db_path = expand_user(db_path);
    const auto db_dir = std::filesystem::path(db_path);
    const auto mining_log = (db_dir / "MiningLOG").string();
    const auto peers_path = (db_dir / "peers.dat").string();
    const auto addrman_path = (db_dir / "addrman.dat").string();
    const auto key_path = (db_dir / "keystore" / "validator.json").string();

    selfcoin::storage::DB db;
    const bool opened = db.open_readonly(db_path) || db.open(db_path);

    print_section("Node");
    std::cout << "db=" << db_path << "\n";
    std::cout << "service=" << service_name << "\n";
    std::cout << "opened_db=" << (opened ? "yes" : "no") << "\n";

    if (opened) {
      const auto tip = db.get_tip();
      if (tip) {
        std::cout << "height=" << tip->height << "\n";
        std::cout << "tip_hash=" << selfcoin::hex_encode32(tip->hash) << "\n";
        const auto cert = db.get_finality_certificate_by_height(tip->height);
        if (cert) {
          std::cout << "finality_quorum=" << cert->quorum_threshold << "\n";
          std::cout << "finality_signatures=" << cert->signatures.size() << "\n";
          std::cout << "committee_members=" << cert->committee_members.size() << "\n";
        }
        const auto net = selfcoin::mainnet_network();
        const auto epoch_start =
            selfcoin::consensus::committee_epoch_start(tip->height + 1, net.vrf_committee_epoch_blocks);
        const auto snapshot = db.get_committee_epoch_snapshot(epoch_start);
        if (snapshot) {
          std::cout << "committee_epoch_start=" << snapshot->epoch_start_height << "\n";
          std::cout << "committee_epoch_seed=" << selfcoin::hex_encode32(snapshot->epoch_seed) << "\n";
          std::cout << "committee_epoch_ordered_members=" << snapshot->ordered_members.size() << "\n";
          std::ostringstream members;
          for (std::size_t i = 0; i < snapshot->ordered_members.size(); ++i) {
            if (i) members << ",";
            members << short_pub_hex(snapshot->ordered_members[i]);
          }
          std::cout << "committee_epoch_members_short=" << members.str() << "\n";
        }
      } else {
        std::cout << "height=unknown\n";
      }

      const auto validators = db.load_validators();
      std::size_t active = 0;
      std::size_t pending = 0;
      std::size_t exiting = 0;
      std::size_t suspended = 0;
      std::size_t banned = 0;
      for (const auto& [_, info] : validators) {
        switch (info.status) {
          case selfcoin::consensus::ValidatorStatus::ACTIVE: ++active; break;
          case selfcoin::consensus::ValidatorStatus::PENDING: ++pending; break;
          case selfcoin::consensus::ValidatorStatus::EXITING: ++exiting; break;
          case selfcoin::consensus::ValidatorStatus::SUSPENDED: ++suspended; break;
          case selfcoin::consensus::ValidatorStatus::BANNED: ++banned; break;
        }
      }
      std::cout << "validators_total=" << validators.size() << "\n";
      std::cout << "validators_active=" << active << "\n";
      std::cout << "validators_pending=" << pending << "\n";
      std::cout << "validators_exiting=" << exiting << "\n";
      std::cout << "validators_suspended=" << suspended << "\n";
      std::cout << "validators_banned=" << banned << "\n";
    }

    std::string kerr;
    selfcoin::keystore::ValidatorKey vk;
    if (selfcoin::keystore::keystore_exists(key_path) &&
        selfcoin::keystore::load_validator_keystore(key_path, "", &vk, &kerr)) {
      std::cout << "local_validator_pubkey=" << selfcoin::hex_encode(selfcoin::Bytes(vk.pubkey.begin(), vk.pubkey.end()))
                << "\n";
      std::cout << "local_validator_address=" << vk.address << "\n";
    }

    print_section("Peers");
    if (std::filesystem::exists(peers_path)) {
      const auto peers = tail_lines(peers_path, tail);
      std::cout << "persisted_peers=" << peers.size() << "\n";
      for (const auto& line : peers) std::cout << line << "\n";
    } else {
      std::cout << "persisted_peers=0\n";
    }
    if (std::filesystem::exists(addrman_path)) {
      const auto addrman = tail_lines(addrman_path, tail);
      std::cout << "addrman_entries=" << addrman.size() << "\n";
      for (const auto& line : addrman) std::cout << line << "\n";
    } else {
      std::cout << "addrman_entries=0\n";
    }

    print_section("Mining");
    if (std::filesystem::exists(mining_log)) {
      const auto mining = tail_lines(mining_log, tail);
      std::cout << "mined_blocks_logged=" << mining.size() << "\n";
      for (const auto& line : mining) std::cout << line << "\n";
    } else {
      std::cout << "MiningLOG not found\n";
    }

    print_section("Security");
    const std::string journal_cmd =
        "journalctl -u " + service_name + " -n " + std::to_string(tail * 10) + " --no-pager -l -q 2>/dev/null";
    const auto journal_lines = run_command_lines(journal_cmd);
    const std::vector<std::string> security_needles = {
        "peer-banned", "peer-soft-muted", "reject-version", "drop-addr", "pre-handshake", "timeout",
        "adopted bootstrap validator", "bootstrap single-node genesis", "pending_joiners"};
    std::size_t emitted = 0;
    for (const auto& line : journal_lines) {
      if (!contains_any(line, security_needles)) continue;
      std::cout << line << "\n";
      ++emitted;
      if (emitted >= tail) break;
    }
    if (emitted == 0) {
      std::cout << "no recent security/runtime events found via journalctl\n";
    }

    print_section("Slashing");
    if (opened) {
      auto records = db.load_slashing_records();
      std::cout << "slashing_records=" << records.size() << "\n";
      std::vector<selfcoin::storage::SlashingRecord> ordered;
      ordered.reserve(records.size());
      for (const auto& [_, rec] : records) ordered.push_back(rec);
      std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        if (a.observed_height != b.observed_height) return a.observed_height > b.observed_height;
        return a.record_id > b.record_id;
      });
      const std::size_t limit = std::min<std::size_t>(tail, ordered.size());
      for (std::size_t i = 0; i < limit; ++i) {
        const auto& rec = ordered[i];
        std::cout << slashing_kind_name(rec.kind)
                  << " validator=" << selfcoin::hex_encode(selfcoin::Bytes(rec.validator_pubkey.begin(), rec.validator_pubkey.end()))
                  << " height=" << rec.height
                  << " round=" << rec.round
                  << " observed_height=" << rec.observed_height
                  << " a=" << selfcoin::hex_encode32(rec.object_a)
                  << " b=" << selfcoin::hex_encode32(rec.object_b);
        if (rec.txid != selfcoin::zero_hash()) {
          std::cout << " txid=" << selfcoin::hex_encode32(rec.txid);
        }
        std::cout << "\n";
      }
    } else {
      std::cout << "slashing_records=unknown\n";
    }
    return 0;
  }

  if (cmd == "slash_records") {
    std::string db_path = "./data/node";
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }
    selfcoin::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    auto records = db.load_slashing_records();
    std::vector<selfcoin::storage::SlashingRecord> ordered;
    ordered.reserve(records.size());
    for (const auto& [_, rec] : records) ordered.push_back(rec);
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
      if (a.observed_height != b.observed_height) return a.observed_height > b.observed_height;
      return a.record_id > b.record_id;
    });
    std::cout << "slashing_records=" << ordered.size() << "\n";
    const std::size_t limit = std::min<std::size_t>(tail, ordered.size());
    for (std::size_t i = 0; i < limit; ++i) {
      const auto& rec = ordered[i];
      std::cout << slashing_kind_name(rec.kind)
                << " validator=" << selfcoin::hex_encode(selfcoin::Bytes(rec.validator_pubkey.begin(), rec.validator_pubkey.end()))
                << " height=" << rec.height
                << " round=" << rec.round
                << " observed_height=" << rec.observed_height
                << " a=" << selfcoin::hex_encode32(rec.object_a)
                << " b=" << selfcoin::hex_encode32(rec.object_b);
      if (rec.txid != selfcoin::zero_hash()) {
        std::cout << " txid=" << selfcoin::hex_encode32(rec.txid);
      }
      std::cout << "\n";
    }
    return 0;
  }

  if (cmd == "tip") {
    std::string db_path = "./data/node";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
    }

    selfcoin::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    auto tip = db.get_tip();
    if (!tip) {
      std::cout << "no tip\n";
      return 0;
    }
    std::cout << "height=" << tip->height << " hash=" << selfcoin::hex_encode32(tip->hash) << "\n";
    return 0;
  }

  if (cmd == "snapshot_export") {
    std::string db_path = "./data/node";
    std::string out_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
    }
    if (out_path.empty()) {
      std::cerr << "snapshot_export requires --out\n";
      return 1;
    }
    selfcoin::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    selfcoin::storage::SnapshotManifest manifest;
    std::string err;
    if (!selfcoin::storage::export_snapshot_bundle(db, out_path, &manifest, &err)) {
      std::cerr << "snapshot_export failed: " << err << "\n";
      return 1;
    }
    std::cout << "snapshot=" << out_path << "\n";
    std::cout << "finalized_height=" << manifest.finalized_height << "\n";
    std::cout << "finalized_hash=" << selfcoin::hex_encode32(manifest.finalized_hash) << "\n";
    std::cout << "utxo_root=" << selfcoin::hex_encode32(manifest.utxo_root) << "\n";
    std::cout << "validators_root=" << selfcoin::hex_encode32(manifest.validators_root) << "\n";
    std::cout << "entry_count=" << manifest.entry_count << "\n";
    return 0;
  }

  if (cmd == "snapshot_import") {
    std::string db_path = "./data/node";
    std::string in_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--in" && i + 1 < argc) in_path = argv[++i];
    }
    if (in_path.empty()) {
      std::cerr << "snapshot_import requires --in\n";
      return 1;
    }
    selfcoin::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    selfcoin::storage::SnapshotManifest manifest;
    std::string err;
    if (!selfcoin::storage::import_snapshot_bundle(db, in_path, &manifest, &err)) {
      std::cerr << "snapshot_import failed: " << err << "\n";
      return 1;
    }
    std::cout << "db=" << db_path << "\n";
    std::cout << "finalized_height=" << manifest.finalized_height << "\n";
    std::cout << "finalized_hash=" << selfcoin::hex_encode32(manifest.finalized_hash) << "\n";
    std::cout << "entry_count=" << manifest.entry_count << "\n";
    return 0;
  }

  if (cmd == "genesis_build") {
    std::string in_path;
    std::string out_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
      else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
    }
    if (in_path.empty() || out_path.empty()) {
      std::cerr << "genesis_build requires --in and --out\n";
      return 1;
    }
    std::string err;
    auto doc = selfcoin::genesis::load_from_path(in_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!selfcoin::genesis::validate_document(*doc, selfcoin::mainnet_network(), &err, 0)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    const auto bin = selfcoin::genesis::encode_bin(*doc);
    if (!selfcoin::genesis::write_bin_to_path(out_path, bin, &err)) {
      std::cerr << "failed to write genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(bin);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "network_id=" << selfcoin::hex_encode(selfcoin::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_hash") {
    std::string in_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
    }
    if (in_path.empty()) {
      std::cerr << "genesis_hash requires --in\n";
      return 1;
    }
    std::string err;
    auto bin = selfcoin::genesis::load_bin_from_path(in_path, &err);
    if (!bin) {
      std::cerr << "failed to load genesis bin: " << err << "\n";
      return 1;
    }
    auto doc = selfcoin::genesis::decode_bin(*bin, &err);
    if (!doc) {
      std::cerr << "failed to decode genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(*bin);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "network_id=" << selfcoin::hex_encode(selfcoin::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_verify") {
    std::string json_path;
    std::string bin_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--json" && i + 1 < argc) json_path = argv[++i];
      else if (a == "--bin" && i + 1 < argc) bin_path = argv[++i];
    }
    if (json_path.empty() || bin_path.empty()) {
      std::cerr << "genesis_verify requires --json and --bin\n";
      return 1;
    }
    std::string err;
    auto doc = selfcoin::genesis::load_from_path(json_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!selfcoin::genesis::validate_document(*doc, selfcoin::mainnet_network(), &err, 0)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    auto existing = selfcoin::genesis::load_bin_from_path(bin_path, &err);
    if (!existing) {
      std::cerr << "failed to read genesis bin: " << err << "\n";
      return 1;
    }
    const auto rebuilt = selfcoin::genesis::encode_bin(*doc);
    if (*existing != rebuilt) {
      std::cerr << "genesis verify failed: binary mismatch\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(rebuilt);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "verified=1\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_print_embedded") {
    std::cout << "embedded_mainnet_genesis_len=" << selfcoin::genesis::MAINNET_GENESIS_BIN_LEN << "\n";
    std::cout << "embedded_mainnet_genesis_hash=" << selfcoin::hex_encode32(selfcoin::genesis::MAINNET_GENESIS_HASH)
              << "\n";
    return 0;
  }

  if (cmd == "rpc_status") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "rpc_status requires --url\n";
      return 1;
    }
    std::string err;
    auto body = rpc_http_post(url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", &err);
    if (!body.has_value()) {
      std::cerr << "rpc_status failed: " << err << "\n";
      return 1;
    }
    auto status = parse_get_status_result(*body, &err);
    if (!status.has_value()) {
      std::cerr << "rpc_status parse failed: " << err << "\n";
      return 1;
    }
    std::cout << "url=" << url << "\n";
    std::cout << "network_name=" << status->chain.network_name << "\n";
    std::cout << "network_id=" << status->chain.network_id_hex << "\n";
    std::cout << "protocol_version=" << status->chain.protocol_version << "\n";
    std::cout << "magic=" << status->chain.magic << "\n";
    std::cout << "genesis_hash=" << status->chain.genesis_hash_hex << "\n";
    std::cout << "genesis_source=" << status->chain.genesis_source << "\n";
    std::cout << "tip_height=" << status->tip_height << "\n";
    std::cout << "tip_hash=" << status->tip_hash << "\n";
    return 0;
  }

  if (cmd == "rpc_compare") {
    std::string urls_csv;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--urls" && i + 1 < argc) urls_csv = argv[++i];
    }
    if (urls_csv.empty()) {
      std::cerr << "rpc_compare requires --urls\n";
      return 1;
    }
    std::vector<std::string> urls;
    {
      std::stringstream ss(urls_csv);
      std::string item;
      while (std::getline(ss, item, ',')) {
        if (!item.empty()) urls.push_back(item);
      }
    }
    if (urls.size() < 2) {
      std::cerr << "rpc_compare requires at least 2 urls\n";
      return 1;
    }

    std::vector<RpcStatusView> statuses;
    statuses.reserve(urls.size());
    bool had_error = false;

    std::cout << "url\tnetwork_id\tgenesis_hash\tproto\tmagic\theight\ttip\n";
    for (const auto& url : urls) {
      std::string err;
      auto body = rpc_http_post(url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", &err);
      if (!body.has_value()) {
        std::cout << url << "\tERR\tERR\tERR\tERR\tERR\t" << err << "\n";
        had_error = true;
        continue;
      }
      auto st = parse_get_status_result(*body, &err);
      if (!st.has_value()) {
        std::cout << url << "\tERR\tERR\tERR\tERR\tERR\t" << err << "\n";
        had_error = true;
        continue;
      }
      statuses.push_back(*st);
      std::cout << url << "\t" << st->chain.network_id_hex.substr(0, 8) << "...\t" << st->chain.genesis_hash_hex.substr(0, 8)
                << "...\t" << st->chain.protocol_version << "\t" << st->chain.magic << "\t" << st->tip_height << "\t"
                << st->tip_hash.substr(0, 8) << "...\n";
    }

    if (had_error || statuses.size() < 2) return 2;

    bool mismatch = false;
    const auto& ref = statuses.front().chain;
    for (std::size_t i = 1; i < statuses.size(); ++i) {
      const auto mm = selfcoin::compare_chain_identity(ref, statuses[i].chain);
      if (!mm.match) {
        mismatch = true;
        std::cout << "MISMATCH[" << i << "]:";
        if (mm.network_id_differs) std::cout << " network_id";
        if (mm.genesis_hash_differs) std::cout << " genesis_hash";
        if (mm.protocol_version_differs) std::cout << " protocol_version";
        if (mm.magic_differs) std::cout << " magic";
        std::cout << "\n";
      }
    }
    if (mismatch) return 2;
    std::cout << "all chain identities match\n";
    return 0;
  }

  if (cmd == "create_keypair") {
    std::string seed_hex;
    std::string hrp = "sc";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
    }

    std::array<std::uint8_t, 32> seed{};
    if (!seed_hex.empty()) {
      auto s = decode_hex32(seed_hex);
      if (!s.has_value()) {
        std::cerr << "--seed-hex must be 32 bytes hex\n";
        return 1;
      }
      seed = *s;
    } else {
      std::random_device rd;
      for (auto& b : seed) b = static_cast<std::uint8_t>(rd());
    }

    auto kp = selfcoin::crypto::keypair_from_seed32(seed);
    if (!kp.has_value()) {
      std::cerr << "failed to create keypair\n";
      return 1;
    }
    auto pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    auto addr = selfcoin::address::encode_p2pkh(hrp, pkh);

    std::cout << "privkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(seed.begin(), seed.end())) << "\n";
    std::cout << "pubkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end())) << "\n";
    if (addr.has_value()) std::cout << "address=" << *addr << "\n";
    return 0;
  }

  if (cmd == "wallet_create") {
    std::string out_path;
    std::string passphrase;
    std::string network_name = "mainnet";
    std::string seed_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--out" && i + 1 < argc) out_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
    }
    if (out_path.empty()) {
      std::cerr << "--out is required\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only --network mainnet is supported\n";
      return 1;
    }
    std::optional<std::array<std::uint8_t, 32>> seed_override;
    if (!seed_hex.empty()) {
      seed_override = decode_hex32(seed_hex);
      if (!seed_override) {
        std::cerr << "--seed-hex must be 32-byte hex\n";
        return 1;
      }
    }
    selfcoin::keystore::ValidatorKey vk;
    std::string err;
    if (!selfcoin::keystore::create_validator_keystore(out_path, passphrase, network_name,
                                                        selfcoin::keystore::hrp_for_network(network_name),
                                                        seed_override, &vk, &err)) {
      std::cerr << "wallet_create failed: " << err << "\n";
      return 1;
    }
    std::cout << "file=" << out_path << "\n";
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "pubkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "wallet_address") {
    std::string file_path;
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    if (file_path.empty()) {
      std::cerr << "--file is required\n";
      return 1;
    }
    selfcoin::keystore::ValidatorKey vk;
    std::string err;
    if (!selfcoin::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "wallet_address failed: " << err << "\n";
      return 1;
    }
    std::cout << vk.address << "\n";
    return 0;
  }

  if (cmd == "wallet_export") {
    std::string file_path;
    std::string passphrase;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--file" && i + 1 < argc) file_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
    }
    if (file_path.empty()) {
      std::cerr << "--file is required\n";
      return 1;
    }
    selfcoin::keystore::ValidatorKey vk;
    std::string err;
    if (!selfcoin::keystore::load_validator_keystore(file_path, passphrase, &vk, &err)) {
      std::cerr << "wallet_export failed: " << err << "\n";
      return 1;
    }
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "privkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(vk.privkey.begin(), vk.privkey.end())) << "\n";
    std::cout << "pubkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "wallet_import") {
    std::string out_path;
    std::string passphrase;
    std::string network_name = "mainnet";
    std::string privkey_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--out" && i + 1 < argc) out_path = argv[++i];
      else if (a == "--pass" && i + 1 < argc) passphrase = argv[++i];
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--privkey" && i + 1 < argc) privkey_hex = argv[++i];
    }
    auto priv = decode_hex32(privkey_hex);
    if (out_path.empty() || !priv) {
      std::cerr << "--out and --privkey(32-byte hex) are required\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only --network mainnet is supported\n";
      return 1;
    }
    selfcoin::keystore::ValidatorKey vk;
    std::string err;
    const std::optional<std::array<std::uint8_t, 32>> seed_override = *priv;
    if (!selfcoin::keystore::create_validator_keystore(out_path, passphrase, network_name,
                                                        selfcoin::keystore::hrp_for_network(network_name),
                                                        seed_override, &vk, &err)) {
      std::cerr << "wallet_import failed: " << err << "\n";
      return 1;
    }
    std::cout << "file=" << out_path << "\n";
    std::cout << "network=" << vk.network_name << "\n";
    std::cout << "pubkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(vk.pubkey.begin(), vk.pubkey.end())) << "\n";
    std::cout << "address=" << vk.address << "\n";
    return 0;
  }

  if (cmd == "address_from_pubkey" || cmd == "addr") {
    std::string hrp = "sc";
    std::string pub_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
      if (a == "--pubkey" && i + 1 < argc) pub_hex = argv[++i];
    }
    if (pub_hex.empty()) {
      std::cerr << "--pubkey is required\n";
      return 1;
    }

    auto b = selfcoin::hex_decode(pub_hex);
    if (!b || b->size() != 32) {
      std::cerr << "pubkey must be 32 bytes hex\n";
      return 1;
    }
    auto pkh = selfcoin::crypto::h160(*b);
    auto addr = selfcoin::address::encode_p2pkh(hrp, pkh);
    if (!addr) {
      std::cerr << "address encoding failed\n";
      return 1;
    }
    std::cout << *addr << "\n";
    return 0;
  }

  if (cmd == "build_p2pkh_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string to_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--to-address" && i + 1 < argc) to_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    auto to = selfcoin::address::decode(to_addr);
    if (!prev_txid.has_value() || !priv.has_value() || !to.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    selfcoin::OutPoint op{*prev_txid, prev_index};

    auto kp = selfcoin::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(from_pkh)};

    std::vector<selfcoin::TxOut> outputs;
    outputs.push_back(selfcoin::TxOut{amount, selfcoin::address::p2pkh_script_pubkey(to->pubkey_hash)});

    const std::uint64_t change = prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = selfcoin::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = selfcoin::build_signed_p2pkh_tx_single_input(op, prev_out, selfcoin::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "build tx failed: " << err << "\n";
      return 1;
    }

    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_validator_bond_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string change_addr;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    if (!prev_txid || !priv) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < selfcoin::BOND_AMOUNT + fee) {
      std::cerr << "insufficient prev value for bond + fee\n";
      return 1;
    }

    auto kp = selfcoin::crypto::keypair_from_seed32(*priv);
    if (!kp) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    selfcoin::OutPoint op{*prev_txid, prev_index};
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(from_pkh)};

    selfcoin::Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
    reg_spk.insert(reg_spk.end(), kp->public_key.begin(), kp->public_key.end());
    std::vector<selfcoin::TxOut> outputs{selfcoin::TxOut{selfcoin::BOND_AMOUNT, reg_spk}};

    const std::uint64_t change = prev_value - selfcoin::BOND_AMOUNT - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = selfcoin::address::decode(change_addr);
        if (!ch) {
          std::cerr << "invalid change address\n";
          return 1;
        }
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = selfcoin::build_signed_p2pkh_tx_single_input(op, prev_out, selfcoin::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx) {
      std::cerr << "create bond tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_validator_join_request_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string funding_priv_hex;
    std::string validator_priv_hex;
    std::string payout_pub_hex;
    std::string change_addr;
    std::uint64_t bond_amount = selfcoin::BOND_AMOUNT;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--funding-privkey" && i + 1 < argc) funding_priv_hex = argv[++i];
      else if (a == "--validator-privkey" && i + 1 < argc) validator_priv_hex = argv[++i];
      else if (a == "--payout-pubkey" && i + 1 < argc) payout_pub_hex = argv[++i];
      else if (a == "--bond-amount" && i + 1 < argc) bond_amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto funding_priv = decode_hex32(funding_priv_hex);
    auto validator_priv = decode_hex32(validator_priv_hex);
    if (!prev_txid || !funding_priv || !validator_priv) {
      std::cerr << "invalid required args\n";
      return 1;
    }

    auto funding_kp = selfcoin::crypto::keypair_from_seed32(*funding_priv);
    auto validator_kp = selfcoin::crypto::keypair_from_seed32(*validator_priv);
    if (!funding_kp || !validator_kp) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    selfcoin::PubKey32 payout_pub = validator_kp->public_key;
    if (!payout_pub_hex.empty()) {
      auto payout = decode_hex32(payout_pub_hex);
      if (!payout) {
        std::cerr << "invalid payout pubkey\n";
        return 1;
      }
      payout_pub = *payout;
    }

    auto funding_pkh = selfcoin::crypto::h160(selfcoin::Bytes(funding_kp->public_key.begin(), funding_kp->public_key.end()));
    selfcoin::OutPoint op{*prev_txid, prev_index};
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(funding_pkh)};
    selfcoin::Bytes change_spk = selfcoin::address::p2pkh_script_pubkey(funding_pkh);
    if (!change_addr.empty()) {
      auto ch = selfcoin::address::decode(change_addr);
      if (!ch) {
        std::cerr << "invalid change address\n";
        return 1;
      }
      change_spk = selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash);
    }

    std::string err;
    auto tx = selfcoin::build_validator_join_request_tx(
        op, prev_out, selfcoin::Bytes(funding_priv->begin(), funding_priv->end()), validator_kp->public_key,
        selfcoin::Bytes(validator_priv->begin(), validator_priv->end()), payout_pub, bond_amount, fee, change_spk, &err);
    if (!tx) {
      std::cerr << "create join request tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "mint_deposit_create") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string mint_id_hex;
    std::string recipient_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    auto mint_id = decode_hex32(mint_id_hex);
    auto recipient = selfcoin::address::decode(recipient_addr);
    if (!prev_txid.has_value() || !priv.has_value() || !mint_id.has_value() || !recipient.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    auto kp = selfcoin::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    selfcoin::OutPoint op{*prev_txid, prev_index};
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(from_pkh)};

    std::vector<selfcoin::TxOut> outputs;
    outputs.push_back(selfcoin::TxOut{
        amount, selfcoin::privacy::mint_deposit_script_pubkey(*mint_id, recipient->pubkey_hash)});

    const std::uint64_t change = prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = selfcoin::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = selfcoin::build_signed_p2pkh_tx_single_input(op, prev_out, selfcoin::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "mint deposit tx build failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "mint_deposit_status") {
    std::string db_path = "./data/node";
    std::string mint_id_hex;
    std::string recipient_addr;
    std::size_t tail = 20;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--tail" && i + 1 < argc) tail = static_cast<std::size_t>(std::stoull(argv[++i]));
    }

    std::optional<selfcoin::Hash32> mint_filter;
    if (!mint_id_hex.empty()) {
      auto id = decode_hex32(mint_id_hex);
      if (!id) {
        std::cerr << "invalid --mint-id\n";
        return 1;
      }
      mint_filter = *id;
    }
    std::optional<std::array<std::uint8_t, 20>> recipient_filter;
    if (!recipient_addr.empty()) {
      auto addr = selfcoin::address::decode(recipient_addr);
      if (!addr) {
        std::cerr << "invalid --recipient-address\n";
        return 1;
      }
      recipient_filter = addr->pubkey_hash;
    }

    selfcoin::storage::DB db;
    if (!db.open_readonly(db_path) && !db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }

    struct MintDepositRow {
      selfcoin::OutPoint outpoint;
      selfcoin::Hash32 mint_id{};
      std::array<std::uint8_t, 20> recipient{};
      std::uint64_t value{0};
      std::uint64_t height{0};
      selfcoin::Hash32 txid{};
    };

    std::vector<MintDepositRow> rows;
    const auto utxos = db.load_utxos();
    for (const auto& [op, entry] : utxos) {
      selfcoin::Hash32 mint_id{};
      std::array<std::uint8_t, 20> recipient{};
      if (!selfcoin::privacy::is_mint_deposit_script(entry.out.script_pubkey, &mint_id, &recipient)) continue;
      if (mint_filter.has_value() && mint_id != *mint_filter) continue;
      if (recipient_filter.has_value() && recipient != *recipient_filter) continue;
      MintDepositRow row;
      row.outpoint = op;
      row.mint_id = mint_id;
      row.recipient = recipient;
      row.value = entry.out.value;
      row.txid = op.txid;
      auto loc = db.get_tx_index(op.txid);
      if (loc) row.height = loc->height;
      rows.push_back(row);
    }

    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
      if (a.height != b.height) return a.height > b.height;
      return a.outpoint.index < b.outpoint.index;
    });

    std::cout << "mint_deposits=" << rows.size() << "\n";
    const std::size_t limit = std::min<std::size_t>(tail, rows.size());
    for (std::size_t i = 0; i < limit; ++i) {
      const auto& row = rows[i];
      std::cout << "txid=" << selfcoin::hex_encode32(row.txid)
                << " vout=" << row.outpoint.index
                << " value=" << row.value
                << " height=" << row.height
                << " mint_id=" << selfcoin::hex_encode32(row.mint_id)
                << " recipient_pkh=" << selfcoin::hex_encode(selfcoin::Bytes(row.recipient.begin(), row.recipient.end()))
                << "\n";
    }
    return 0;
  }

  if (cmd == "mint_deposit_register") {
    std::string url;
    std::string chain = "mainnet";
    std::string deposit_txid_hex;
    std::uint32_t deposit_vout = 0;
    std::string mint_id_hex;
    std::string recipient_addr;
    std::uint64_t amount = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--chain" && i + 1 < argc) chain = argv[++i];
      else if (a == "--deposit-txid" && i + 1 < argc) deposit_txid_hex = argv[++i];
      else if (a == "--deposit-vout" && i + 1 < argc) deposit_vout = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--mint-id" && i + 1 < argc) mint_id_hex = argv[++i];
      else if (a == "--recipient-address" && i + 1 < argc) recipient_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto deposit_txid = decode_hex32(deposit_txid_hex);
    auto mint_id = decode_hex32(mint_id_hex);
    auto recipient = selfcoin::address::decode(recipient_addr);
    if (url.empty() || !deposit_txid || !mint_id || !recipient) {
      std::cerr << "invalid required args\n";
      return 1;
    }

    selfcoin::privacy::MintDepositRegistrationRequest req;
    req.chain = chain;
    req.deposit_txid = *deposit_txid;
    req.deposit_vout = deposit_vout;
    req.mint_id = *mint_id;
    req.recipient_pubkey_hash = recipient->pubkey_hash;
    req.amount = amount;

    std::string err;
    auto body = http_post_json(url, selfcoin::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_deposit_register failed: " << err << "\n";
      return 1;
    }
    auto resp = selfcoin::privacy::parse_mint_deposit_registration_response(*body);
    if (!resp) {
      std::cerr << "mint_deposit_register parse failed\n";
      return 1;
    }
    std::cout << "accepted=" << (resp->accepted ? "true" : "false") << "\n";
    std::cout << "confirmations_required=" << resp->confirmations_required << "\n";
    std::cout << "mint_deposit_ref=" << resp->mint_deposit_ref << "\n";
    return 0;
  }

  if (cmd == "mint_issue_blinds") {
    std::string url;
    std::string mint_deposit_ref;
    std::vector<std::string> blinds;
    std::vector<std::uint64_t> note_amounts;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--mint-deposit-ref" && i + 1 < argc) mint_deposit_ref = argv[++i];
      else if (a == "--blind" && i + 1 < argc) blinds.push_back(argv[++i]);
      else if (a == "--note-amount" && i + 1 < argc) {
        note_amounts.push_back(static_cast<std::uint64_t>(std::stoull(argv[++i])));
      }
    }
    if (url.empty() || mint_deposit_ref.empty() || blinds.empty() || blinds.size() != note_amounts.size()) {
      std::cerr << "mint_issue_blinds requires --url, --mint-deposit-ref, and matching --blind/--note-amount pairs\n";
      return 1;
    }
    selfcoin::privacy::MintBlindIssueRequest req;
    req.mint_deposit_ref = mint_deposit_ref;
    req.blinded_messages = blinds;
    req.note_amounts = note_amounts;

    std::string err;
    auto body = http_post_json(url, selfcoin::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_issue_blinds failed: " << err << "\n";
      return 1;
    }
    auto resp = selfcoin::privacy::parse_mint_blind_issue_response(*body);
    if (!resp) {
      std::cerr << "mint_issue_blinds parse failed\n";
      return 1;
    }
    std::cout << "issuance_id=" << resp->issuance_id << "\n";
    std::cout << "mint_epoch=" << resp->mint_epoch << "\n";
    std::cout << "signed_blinds=" << resp->signed_blinds.size() << "\n";
    for (std::size_t i = 0; i < resp->signed_blinds.size(); ++i) {
      std::cout << "signed_blind[" << i << "]=" << resp->signed_blinds[i] << "\n";
      if (i < resp->note_refs.size()) {
        std::cout << "note_ref[" << i << "]=" << resp->note_refs[i] << "\n";
      }
      if (i < resp->note_amounts.size()) {
        std::cout << "note_amount[" << i << "]=" << resp->note_amounts[i] << "\n";
      }
    }
    return 0;
  }

  if (cmd == "mint_redeem_create") {
    std::string url;
    std::string redeem_address;
    std::vector<std::string> notes;
    std::uint64_t amount = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--redeem-address" && i + 1 < argc) redeem_address = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--note" && i + 1 < argc) notes.push_back(argv[++i]);
    }
    if (url.empty() || redeem_address.empty() || amount == 0 || notes.empty()) {
      std::cerr << "mint_redeem_create requires --url, --redeem-address, --amount, and at least one --note\n";
      return 1;
    }
    selfcoin::privacy::MintRedemptionRequest req;
    req.notes = notes;
    req.redeem_address = redeem_address;
    req.amount = amount;

    std::string err;
    auto body = http_post_json(url, selfcoin::privacy::to_json(req), &err);
    if (!body) {
      std::cerr << "mint_redeem_create failed: " << err << "\n";
      return 1;
    }
    auto resp = selfcoin::privacy::parse_mint_redemption_response(*body);
    if (!resp) {
      std::cerr << "mint_redeem_create parse failed\n";
      return 1;
    }
    std::cout << "accepted=" << (resp->accepted ? "true" : "false") << "\n";
    std::cout << "redemption_batch_id=" << resp->redemption_batch_id << "\n";
    return 0;
  }

  if (cmd == "mint_redeem_status") {
    std::string url;
    std::string batch_id;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--batch-id" && i + 1 < argc) batch_id = argv[++i];
    }
    if (url.empty() || batch_id.empty()) {
      std::cerr << "mint_redeem_status requires --url and --batch-id\n";
      return 1;
    }

    std::ostringstream body_json;
    body_json << "{\"redemption_batch_id\":\"" << batch_id << "\"}";

    std::string err;
    auto body = http_post_json(url, body_json.str(), &err);
    if (!body) {
      std::cerr << "mint_redeem_status failed: " << err << "\n";
      return 1;
    }
    auto resp = selfcoin::privacy::parse_mint_redemption_status_response(*body);
    if (!resp) {
      std::cerr << "mint_redeem_status parse failed\n";
      return 1;
    }
    std::cout << "state=" << resp->state << "\n";
    std::cout << "l1_txid=" << resp->l1_txid << "\n";
    std::cout << "amount=" << resp->amount << "\n";
    return 0;
  }

  if (cmd == "mint_redeem_update") {
    std::string url;
    std::string batch_id;
    std::string state;
    std::string l1_txid;
    std::string admin_token;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--batch-id" && i + 1 < argc) batch_id = argv[++i];
      else if (a == "--state" && i + 1 < argc) state = argv[++i];
      else if (a == "--l1-txid" && i + 1 < argc) l1_txid = argv[++i];
      else if (a == "--admin-token" && i + 1 < argc) admin_token = argv[++i];
    }
    if (url.empty() || batch_id.empty() || state.empty() || admin_token.empty()) {
      std::cerr << "mint_redeem_update requires --url, --batch-id, --state, and --admin-token\n";
      return 1;
    }
    std::ostringstream body_json;
    body_json << "{\"redemption_batch_id\":\"" << batch_id << "\",\"state\":\"" << state << "\"";
    if (!l1_txid.empty()) body_json << ",\"l1_txid\":\"" << l1_txid << "\"";
    body_json << "}";
    std::string err;
    auto body = http_post_json(url, body_json.str(), admin_token, &err);
    if (!body) {
      std::cerr << "mint_redeem_update failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_reserves") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_reserves requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_reserves failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_accounting_summary") {
    std::string url;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
    }
    if (url.empty()) {
      std::cerr << "mint_accounting_summary requires --url\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, &err);
    if (!body) {
      std::cerr << "mint_accounting_summary failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_audit_export") {
    std::string url;
    std::string admin_token;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--url" && i + 1 < argc) url = argv[++i];
      else if (a == "--admin-token" && i + 1 < argc) admin_token = argv[++i];
    }
    if (url.empty() || admin_token.empty()) {
      std::cerr << "mint_audit_export requires --url and --admin-token\n";
      return 1;
    }
    std::string err;
    auto body = http_get_json(url, admin_token, &err);
    if (!body) {
      std::cerr << "mint_audit_export failed: " << err << "\n";
      return 1;
    }
    std::cout << *body << "\n";
    return 0;
  }

  if (cmd == "mint_api_example") {
    selfcoin::privacy::MintDepositRegistrationRequest deposit_req;
    deposit_req.chain = "mainnet";
    deposit_req.deposit_txid.fill(0x11);
    deposit_req.deposit_vout = 0;
    deposit_req.mint_id.fill(0x22);
    deposit_req.recipient_pubkey_hash.fill(0x33);
    deposit_req.amount = 100000;

    selfcoin::privacy::MintBlindIssueRequest issue_req;
    issue_req.mint_deposit_ref = "example-ref";
    issue_req.blinded_messages = {"blind-msg-1", "blind-msg-2"};
    issue_req.note_amounts = {40000, 60000};

    selfcoin::privacy::MintRedemptionRequest redeem_req;
    redeem_req.notes = {"note-1", "note-2"};
    redeem_req.redeem_address = "sc1example";
    redeem_req.amount = 100000;

    std::cout << "deposit_registration=" << selfcoin::privacy::to_json(deposit_req) << "\n";
    std::cout << "blind_issue=" << selfcoin::privacy::to_json(issue_req) << "\n";
    std::cout << "redemption=" << selfcoin::privacy::to_json(redeem_req) << "\n";
    return 0;
  }

  if (cmd == "hashcash_stamp_tx") {
    std::string tx_hex;
    std::string network_name = "mainnet";
    std::uint32_t bits = 18;
    std::uint64_t epoch_seconds = 60;
    std::uint64_t now_unix = static_cast<std::uint64_t>(std::time(nullptr));
    std::uint64_t max_nonce = 0;
    for (int i = 2; i < argc; ++i) {
      const std::string a = argv[i];
      if (a == "--tx-hex" && i + 1 < argc) tx_hex = argv[++i];
      else if (a == "--bits" && i + 1 < argc) bits = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--network" && i + 1 < argc) network_name = argv[++i];
      else if (a == "--epoch-seconds" && i + 1 < argc) epoch_seconds = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--now" && i + 1 < argc) now_unix = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--max-nonce" && i + 1 < argc) max_nonce = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    if (tx_hex.empty()) {
      std::cerr << "hashcash_stamp_tx requires --tx-hex\n";
      return 1;
    }
    if (network_name != "mainnet") {
      std::cerr << "only mainnet network is currently supported\n";
      return 1;
    }
    auto raw = selfcoin::hex_decode(tx_hex);
    if (!raw.has_value()) {
      std::cerr << "invalid tx hex\n";
      return 1;
    }
    auto tx = selfcoin::Tx::parse(*raw);
    if (!tx.has_value()) {
      std::cerr << "invalid tx bytes\n";
      return 1;
    }
    selfcoin::policy::HashcashConfig cfg;
    cfg.enabled = true;
    cfg.base_bits = bits;
    cfg.max_bits = bits;
    cfg.epoch_seconds = std::max<std::uint64_t>(1, epoch_seconds);
    std::string err;
    if (!selfcoin::policy::apply_hashcash_stamp(&*tx, selfcoin::mainnet_network(), cfg, bits, now_unix, max_nonce, &err)) {
      std::cerr << "hashcash stamping failed: " << err << "\n";
      return 1;
    }
    std::cout << "bits=" << bits << "\n";
    std::cout << "epoch_bucket=" << tx->hashcash->epoch_bucket << "\n";
    std::cout << "nonce=" << tx->hashcash->nonce << "\n";
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_validator_join_approval_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string funding_priv_hex;
    std::string approver_priv_hex;
    std::string request_txid_hex;
    std::string validator_pub_hex;
    std::string change_addr;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--funding-privkey" && i + 1 < argc) funding_priv_hex = argv[++i];
      else if (a == "--approver-privkey" && i + 1 < argc) approver_priv_hex = argv[++i];
      else if (a == "--request-txid" && i + 1 < argc) request_txid_hex = argv[++i];
      else if (a == "--validator-pubkey" && i + 1 < argc) validator_pub_hex = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto funding_priv = decode_hex32(funding_priv_hex);
    auto approver_priv = decode_hex32(approver_priv_hex);
    auto request_txid = decode_hex32(request_txid_hex);
    auto validator_pub = decode_hex32(validator_pub_hex);
    if (!prev_txid || !funding_priv || !approver_priv || !request_txid || !validator_pub) {
      std::cerr << "invalid required args\n";
      return 1;
    }

    auto funding_kp = selfcoin::crypto::keypair_from_seed32(*funding_priv);
    if (!funding_kp) {
      std::cerr << "invalid funding private key\n";
      return 1;
    }
    auto funding_pkh = selfcoin::crypto::h160(selfcoin::Bytes(funding_kp->public_key.begin(), funding_kp->public_key.end()));
    selfcoin::OutPoint op{*prev_txid, prev_index};
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(funding_pkh)};
    selfcoin::Bytes change_spk = selfcoin::address::p2pkh_script_pubkey(funding_pkh);
    if (!change_addr.empty()) {
      auto ch = selfcoin::address::decode(change_addr);
      if (!ch) {
        std::cerr << "invalid change address\n";
        return 1;
      }
      change_spk = selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash);
    }

    std::string err;
    auto tx = selfcoin::build_validator_join_approval_tx(
        op, prev_out, selfcoin::Bytes(funding_priv->begin(), funding_priv->end()), *request_txid, *validator_pub,
        selfcoin::Bytes(approver_priv->begin(), approver_priv->end()), change_spk, fee, &err);
    if (!tx) {
      std::cerr << "create join approval tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_unbond_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = selfcoin::BOND_AMOUNT;
    std::string validator_pub_hex;
    std::string validator_priv_hex;
    std::uint64_t fee = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (a == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--validator-pubkey" && i + 1 < argc) validator_pub_hex = argv[++i];
      else if (a == "--validator-privkey" && i + 1 < argc) validator_priv_hex = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    auto bond_txid = decode_hex32(bond_txid_hex);
    auto pub = decode_hex32(validator_pub_hex);
    auto priv = decode_hex32(validator_priv_hex);
    if (!bond_txid || !pub || !priv) {
      std::cerr << "invalid args\n";
      return 1;
    }

    selfcoin::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = selfcoin::build_unbond_tx(op, *pub, bond_value, fee, selfcoin::Bytes(priv->begin(), priv->end()), &err);
    if (!tx) {
      std::cerr << "create unbond tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_slash_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = selfcoin::BOND_AMOUNT;
    selfcoin::Vote a, b;
    std::string a_block_hex, a_pub_hex, a_sig_hex, b_block_hex, b_pub_hex, b_sig_hex;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string k = argv[i];
      if (k == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (k == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-height" && i + 1 < argc) a.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-round" && i + 1 < argc) a.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--a-block" && i + 1 < argc) a_block_hex = argv[++i];
      else if (k == "--a-pub" && i + 1 < argc) a_pub_hex = argv[++i];
      else if (k == "--a-sig" && i + 1 < argc) a_sig_hex = argv[++i];
      else if (k == "--b-height" && i + 1 < argc) b.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--b-round" && i + 1 < argc) b.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--b-block" && i + 1 < argc) b_block_hex = argv[++i];
      else if (k == "--b-pub" && i + 1 < argc) b_pub_hex = argv[++i];
      else if (k == "--b-sig" && i + 1 < argc) b_sig_hex = argv[++i];
      else if (k == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto bond_txid = decode_hex32(bond_txid_hex);
    auto a_block = decode_hex32(a_block_hex);
    auto a_pub = decode_hex32(a_pub_hex);
    auto a_sig = decode_hex64(a_sig_hex);
    auto b_block = decode_hex32(b_block_hex);
    auto b_pub = decode_hex32(b_pub_hex);
    auto b_sig = decode_hex64(b_sig_hex);
    if (!bond_txid || !a_block || !a_pub || !a_sig || !b_block || !b_pub || !b_sig) {
      std::cerr << "invalid slash args\n";
      return 1;
    }
    a.block_id = *a_block;
    a.validator_pubkey = *a_pub;
    a.signature = *a_sig;
    b.block_id = *b_block;
    b.validator_pubkey = *b_pub;
    b.signature = *b_sig;

    selfcoin::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = selfcoin::build_slash_tx(op, bond_value, a, b, fee, &err);
    if (!tx) {
      std::cerr << "create slash tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "broadcast_tx") {
    std::string host = "127.0.0.1";
    std::uint16_t port = 18444;
    std::string tx_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--host" && i + 1 < argc) host = argv[++i];
      else if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
      else if (a == "--tx-hex" && i + 1 < argc) tx_hex = argv[++i];
    }
    if (tx_hex.empty()) {
      std::cerr << "--tx-hex is required\n";
      return 1;
    }

    auto raw = selfcoin::hex_decode(tx_hex);
    if (!raw.has_value() || !selfcoin::Tx::parse(*raw).has_value()) {
      std::cerr << "invalid tx hex\n";
      return 1;
    }

    auto fd_opt = connect_tcp(host, port);
    if (!fd_opt.has_value()) {
      std::cerr << "connect failed\n";
      return 1;
    }
    const int fd = *fd_opt;

    bool ok = do_handshake_v0(fd);
    if (!ok) {
      ::close(fd);
      std::cerr << "handshake failed\n";
      return 1;
    }

    ok = selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::TX, selfcoin::p2p::ser_tx(selfcoin::p2p::TxMsg{*raw})});
    ::close(fd);
    if (!ok) {
      std::cerr << "send tx failed\n";
      return 1;
    }
    std::cout << "broadcasted tx\n";
    return 0;
  }

  std::cerr << "unknown command\n";
  return 1;
}
