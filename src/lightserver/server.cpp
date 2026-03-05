#include "lightserver/server.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstring>
#include <map>
#include <regex>
#include <set>
#include <sstream>

#include "codec/bytes.hpp"
#include "common/paths.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/validators.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "genesis/genesis.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "utxo/validate.hpp"

namespace selfcoin::lightserver {
namespace {

std::string json_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<Hash32> parse_hex32(const std::string& s) {
  auto b = hex_decode(s);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::optional<PubKey32> parse_pubkey32(const std::string& s) {
  auto b = hex_decode(s);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  PubKey32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::string root_index_key(const std::string& kind, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "ROOT:" + kind + ":" + hex_encode(w.data());
}

std::optional<std::uint64_t> find_u64(const std::string& body, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(body, m, re)) return std::nullopt;
  return static_cast<std::uint64_t>(std::stoull(m[1].str()));
}

std::optional<std::string> find_string(const std::string& body, const std::string& key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(body, m, re)) return std::nullopt;
  return m[1].str();
}

std::string find_id_token(const std::string& body) {
  std::regex re("\"id\"\\s*:\\s*([^,}\\s][^,}]*)");
  std::smatch m;
  if (!std::regex_search(body, m, re)) return "null";
  std::string t = m[1].str();
  while (!t.empty() && std::isspace(static_cast<unsigned char>(t.back()))) t.pop_back();
  return t.empty() ? "null" : t;
}

bool read_http_request(int fd, std::string* out_req) {
  std::string req;
  std::array<char, 4096> buf{};
  while (req.find("\r\n\r\n") == std::string::npos) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return false;
    req.append(buf.data(), static_cast<size_t>(n));
    if (req.size() > 2 * 1024 * 1024) return false;
  }

  const auto hdr_end = req.find("\r\n\r\n");
  const std::string headers = req.substr(0, hdr_end);
  std::regex cl_re("Content-Length:\\s*([0-9]+)", std::regex_constants::icase);
  std::smatch m;
  size_t content_len = 0;
  if (std::regex_search(headers, m, cl_re)) {
    content_len = static_cast<size_t>(std::stoull(m[1].str()));
  }
  while (req.size() < hdr_end + 4 + content_len) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return false;
    req.append(buf.data(), static_cast<size_t>(n));
  }
  *out_req = req;
  return true;
}

std::string http_response_json(const std::string& body, int status = 200) {
  const char* status_text = (status == 200) ? "OK" : "Bad Request";
  std::ostringstream oss;
  oss << "HTTP/1.1 " << status << " " << status_text << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  return oss.str();
}

}  // namespace

Server::Server(Config cfg) : cfg_(std::move(cfg)) {}
Server::~Server() { stop(); }

bool Server::init() {
  cfg_.db_path = expand_user_home(cfg_.db_path);
  if (!db_.open_readonly(cfg_.db_path)) {
    if (!db_.open(cfg_.db_path)) return false;
  }
  chain_id_ = ChainId::from_config_and_db(cfg_.network, db_);
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  if (cfg_.tx_relay_port == 0) cfg_.tx_relay_port = cfg_.network.p2p_default_port;
  started_at_unix_ = static_cast<std::uint64_t>(::time(nullptr));
  return true;
}

bool Server::start() {
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) return false;
  int one = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.port);
  if (inet_pton(AF_INET, cfg_.bind_ip.c_str(), &addr.sin_addr) != 1) return false;
  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    bound_port_ = ntohs(bound.sin_port);
  } else {
    bound_port_ = cfg_.port;
  }
  cfg_.port = bound_port_;
  if (listen(listen_fd_, 64) != 0) return false;
  running_ = true;
  accept_thread_ = std::thread([this]() { accept_loop(); });
  return true;
}

void Server::stop() {
  if (!running_.exchange(false)) return;
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
    bound_port_ = 0;
  }
  if (accept_thread_.joinable()) accept_thread_.join();
}

std::string Server::handle_rpc_for_test(const std::string& body) { return handle_rpc_body(body); }

void Server::accept_loop() {
  while (running_) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
    if (fd < 0) {
      if (!running_) break;
      continue;
    }
    handle_client(fd);
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
  }
}

void Server::handle_client(int fd) {
  std::string req;
  if (!read_http_request(fd, &req)) return;
  const auto first_line_end = req.find("\r\n");
  if (first_line_end == std::string::npos) return;
  const std::string first = req.substr(0, first_line_end);
  if (first.rfind("POST /rpc ", 0) != 0) {
    const std::string body = R"({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid endpoint"}})";
    const auto resp = http_response_json(body, 400);
    (void)p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(resp.data()), resp.size());
    return;
  }
  const auto hdr_end = req.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return;
  const std::string body = req.substr(hdr_end + 4);
  const std::string out = handle_rpc_body(body);
  const auto resp = http_response_json(out, 200);
  (void)p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(resp.data()), resp.size());
}

std::string Server::make_error(const std::string& id_token, int code, const std::string& msg) const {
  std::ostringstream oss;
  oss << "{\"jsonrpc\":\"2.0\",\"id\":" << id_token << ",\"error\":{\"code\":" << code << ",\"message\":\""
      << json_escape(msg) << "\"}}";
  return oss.str();
}

std::string Server::make_result(const std::string& id_token, const std::string& result_json) const {
  std::ostringstream oss;
  oss << "{\"jsonrpc\":\"2.0\",\"id\":" << id_token << ",\"result\":" << result_json << "}";
  return oss.str();
}

std::optional<std::vector<PubKey32>> Server::committee_for_height(std::uint64_t height) {
  auto tip = db_.get_tip();
  if (!tip.has_value()) return std::nullopt;
  if (height == 0 || height > tip->height + 1) return std::nullopt;

  consensus::ValidatorRegistry vr;
  UtxoSet utxos;
  if (auto gj = db_.get("G:J"); gj.has_value()) {
    const std::string js(gj->begin(), gj->end());
    if (auto gd = genesis::parse_json(js); gd.has_value()) {
      for (const auto& pub : gd->initial_validators) {
        consensus::ValidatorInfo vi;
        vi.status = consensus::ValidatorStatus::ACTIVE;
        vi.has_bond = true;
        vi.joined_height = 0;
        vr.upsert(pub, vi);
      }
    }
  }

  auto apply_validator_changes = [&](const Block& block, std::uint64_t h) {
    for (size_t txi = 1; txi < block.txs.size(); ++txi) {
      for (const auto& in : block.txs[txi].inputs) {
        const OutPoint op{in.prev_txid, in.prev_index};
        auto it = utxos.find(op);
        if (it == utxos.end()) continue;
        PubKey32 pub{};
        if (!is_validator_register_script(it->second.out.script_pubkey, &pub)) continue;
        SlashEvidence ev;
        if (parse_slash_script_sig(in.script_sig, &ev)) vr.ban(pub);
        else vr.request_unbond(pub, h);
      }
    }
    for (const auto& tx : block.txs) {
      const Hash32 txid = tx.txid();
      for (std::uint32_t i = 0; i < tx.outputs.size(); ++i) {
        PubKey32 pub{};
        if (tx.outputs[i].value == BOND_AMOUNT && is_validator_register_script(tx.outputs[i].script_pubkey, &pub)) {
          vr.register_bond(pub, OutPoint{txid, i}, h);
        }
      }
    }
    vr.advance_height(h + 1);
  };

  for (std::uint64_t h = 1; h < height; ++h) {
    auto bh = db_.get_height_hash(h);
    if (!bh.has_value()) return std::nullopt;
    auto bb = db_.get_block(*bh);
    if (!bb.has_value()) return std::nullopt;
    auto blk = Block::parse(*bb);
    if (!blk.has_value()) return std::nullopt;
    apply_validator_changes(*blk, h);
    apply_block_to_utxo(*blk, utxos);
  }

  Hash32 prev = zero_hash();
  if (height > 1) {
    auto p = db_.get_height_hash(height - 1);
    if (!p.has_value()) return std::nullopt;
    prev = *p;
  }
  const auto active = vr.active_sorted(height);
  return consensus::select_committee(prev, height, active, cfg_.max_committee);
}

bool Server::relay_tx_to_peer(const Bytes& tx_bytes, std::string* err) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(cfg_.tx_relay_host.c_str(), std::to_string(cfg_.tx_relay_port).c_str(), &hints, &res) != 0) {
    if (err) *err = "getaddrinfo failed";
    return false;
  }
  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    if (err) *err = "connect relay peer failed";
    return false;
  }

  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg_.network.protocol_version);
  v.network_id = cfg_.network.network_id;
  v.feature_flags = cfg_.network.feature_flags;
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 424242;
  v.node_software_version = "selfcoin-lightserver/0.7";
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, cfg_.network.magic,
                          cfg_.network.protocol_version)) {
    ::close(fd);
    if (err) *err = "send VERSION failed";
    return false;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERACK, {}}, cfg_.network.magic, cfg_.network.protocol_version)) {
    ::close(fd);
    if (err) *err = "send VERACK failed";
    return false;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::TX, p2p::ser_tx(p2p::TxMsg{tx_bytes})}, cfg_.network.magic,
                          cfg_.network.protocol_version)) {
    ::close(fd);
    if (err) *err = "send TX failed";
    return false;
  }
  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);
  return true;
}

std::string Server::handle_rpc_body(const std::string& body) {
  const std::string id = find_id_token(body);
  auto method = find_string(body, "method");
  if (!method.has_value()) return make_error(id, -32600, "missing method");

  if (*method == "get_tip") {
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::ostringstream oss;
    oss << "{\"height\":" << tip->height << ",\"hash\":\"" << hex_encode32(tip->hash) << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_status") {
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    const std::uint64_t now = static_cast<std::uint64_t>(::time(nullptr));
    std::ostringstream oss;
    oss << "{\"network_name\":\"" << cfg_.network.name << "\",\"protocol_version\":"
        << cfg_.network.protocol_version << ",\"feature_flags\":" << cfg_.network.feature_flags
        << ",\"network_id\":\"" << chain_id_.network_id_hex << "\",\"magic\":" << chain_id_.magic
        << ",\"genesis_hash\":\"" << chain_id_.genesis_hash_hex << "\",\"genesis_source\":\""
        << chain_id_.genesis_source << "\",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false")
        << ",\"tip\":{\"height\":" << tip->height << ",\"hash\":\"" << hex_encode32(tip->hash)
        << "\"},\"peers\":null,\"mempool_size\":null,\"uptime_s\":" << (now - started_at_unix_)
        << ",\"version\":\"selfcoin-core/0.7\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_headers") {
    auto from = find_u64(body, "from_height");
    auto count = find_u64(body, "count");
    if (!from || !count) return make_error(id, -32602, "missing from_height/count");
    std::ostringstream arr;
    arr << "[";
    bool first = true;
    for (std::uint64_t h = *from; h < *from + *count; ++h) {
      auto bh = db_.get_height_hash(h);
      if (!bh.has_value()) break;
      auto bb = db_.get_block(*bh);
      if (!bb.has_value()) break;
      auto blk = Block::parse(*bb);
      if (!blk.has_value()) break;
      if (!first) arr << ",";
      first = false;
      auto ur = db_.get(root_index_key("UTXO", h));
      auto vr = db_.get(root_index_key("VAL", h));
      arr << "{\"height\":" << h << ",\"header_hex\":\"" << hex_encode(blk->header.serialize())
          << "\",\"block_hash\":\"" << hex_encode32(*bh) << "\"";
      if (ur.has_value() && ur->size() == 32) {
        Hash32 r{};
        std::copy(ur->begin(), ur->end(), r.begin());
        arr << ",\"utxo_root\":\"" << hex_encode32(r) << "\"";
      }
      if (vr.has_value() && vr->size() == 32) {
        Hash32 r{};
        std::copy(vr->begin(), vr->end(), r.begin());
        arr << ",\"validators_root\":\"" << hex_encode32(r) << "\"";
      }
      arr << ",\"finality_proof\":[";
      for (size_t i = 0; i < blk->finality_proof.sigs.size(); ++i) {
        if (i) arr << ",";
        const auto& s = blk->finality_proof.sigs[i];
        arr << "{\"pubkey_hex\":\"" << hex_encode(Bytes(s.validator_pubkey.begin(), s.validator_pubkey.end()))
            << "\",\"sig_hex\":\"" << hex_encode(Bytes(s.signature.begin(), s.signature.end())) << "\"}";
      }
      arr << "]}";
    }
    arr << "]";
    return make_result(id, arr.str());
  }

  if (*method == "get_header_range") {
    auto start = find_u64(body, "start_height");
    auto end = find_u64(body, "end_height");
    if (!start || !end || *end < *start) return make_error(id, -32602, "missing/invalid start_height,end_height");
    std::ostringstream arr;
    arr << "[";
    bool first = true;
    for (std::uint64_t h = *start; h <= *end; ++h) {
      auto bh = db_.get_height_hash(h);
      if (!bh.has_value()) break;
      auto bb = db_.get_block(*bh);
      if (!bb.has_value()) break;
      auto blk = Block::parse(*bb);
      if (!blk.has_value()) break;
      auto ur = db_.get(root_index_key("UTXO", h));
      auto vr = db_.get(root_index_key("VAL", h));
      if (!first) arr << ",";
      first = false;
      arr << "{\"height\":" << h << ",\"header_hex\":\"" << hex_encode(blk->header.serialize()) << "\",\"block_hash\":\""
          << hex_encode32(*bh) << "\"";
      if (ur.has_value() && ur->size() == 32) {
        Hash32 r{};
        std::copy(ur->begin(), ur->end(), r.begin());
        arr << ",\"utxo_root\":\"" << hex_encode32(r) << "\"";
      }
      if (vr.has_value() && vr->size() == 32) {
        Hash32 r{};
        std::copy(vr->begin(), vr->end(), r.begin());
        arr << ",\"validators_root\":\"" << hex_encode32(r) << "\"";
      }
      arr << ",\"finality_proof\":[";
      for (size_t i = 0; i < blk->finality_proof.sigs.size(); ++i) {
        if (i) arr << ",";
        const auto& s = blk->finality_proof.sigs[i];
        arr << "{\"pubkey_hex\":\"" << hex_encode(Bytes(s.validator_pubkey.begin(), s.validator_pubkey.end()))
            << "\",\"sig_hex\":\"" << hex_encode(Bytes(s.signature.begin(), s.signature.end())) << "\"}";
      }
      arr << "]}";
    }
    arr << "]";
    return make_result(id, arr.str());
  }

  if (*method == "get_block") {
    auto hash_hex = find_string(body, "hash");
    if (!hash_hex) return make_error(id, -32602, "missing hash");
    auto h = parse_hex32(*hash_hex);
    if (!h) return make_error(id, -32602, "bad hash");
    auto bb = db_.get_block(*h);
    if (!bb.has_value()) return make_error(id, -32001, "not found");
    return make_result(id, std::string("{\"block_hex\":\"") + hex_encode(*bb) + "\"}");
  }

  if (*method == "get_tx") {
    auto txid_hex = find_string(body, "txid");
    if (!txid_hex) return make_error(id, -32602, "missing txid");
    auto txid = parse_hex32(*txid_hex);
    if (!txid) return make_error(id, -32602, "bad txid");
    auto loc = db_.get_tx_index(*txid);
    if (!loc.has_value()) return make_error(id, -32001, "not found");
    std::ostringstream oss;
    oss << "{\"height\":" << loc->height << ",\"tx_hex\":\"" << hex_encode(loc->tx_bytes) << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_utxos") {
    auto sh_hex = find_string(body, "scripthash_hex");
    if (!sh_hex) return make_error(id, -32602, "missing scripthash_hex");
    auto sh = parse_hex32(*sh_hex);
    if (!sh) return make_error(id, -32602, "bad scripthash");
    auto utxos = db_.get_script_utxos(*sh);
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < utxos.size(); ++i) {
      if (i) oss << ",";
      const auto& u = utxos[i];
      oss << "{\"txid\":\"" << hex_encode32(u.outpoint.txid) << "\",\"vout\":" << u.outpoint.index
          << ",\"value\":" << u.value << ",\"height\":" << u.height
          << ",\"script_pubkey_hex\":\"" << hex_encode(u.script_pubkey) << "\"}";
    }
    oss << "]";
    return make_result(id, oss.str());
  }

  if (*method == "get_committee") {
    auto h = find_u64(body, "height");
    if (!h) return make_error(id, -32602, "missing height");
    auto committee = committee_for_height(*h);
    if (!committee.has_value()) return make_error(id, -32001, "height unavailable");
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < committee->size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode(Bytes((*committee)[i].begin(), (*committee)[i].end())) << "\"";
    }
    oss << "]";
    return make_result(id, oss.str());
  }

  if (*method == "get_roots") {
    auto h = find_u64(body, "height");
    if (!h) return make_error(id, -32602, "missing height");
    auto ur = db_.get(root_index_key("UTXO", *h));
    auto vr = db_.get(root_index_key("VAL", *h));
    if (!ur.has_value() || ur->size() != 32 || !vr.has_value() || vr->size() != 32) {
      return make_error(id, -32001, "roots unavailable");
    }
    Hash32 u{};
    Hash32 v{};
    std::copy(ur->begin(), ur->end(), u.begin());
    std::copy(vr->begin(), vr->end(), v.begin());
    std::ostringstream oss;
    oss << "{\"height\":" << *h << ",\"utxo_root\":\"" << hex_encode32(u) << "\",\"validators_root\":\"" << hex_encode32(v)
        << "\"}";
    return make_result(id, oss.str());
  }

  if (*method == "get_utxo_proof") {
    auto txid_hex = find_string(body, "txid");
    auto vout = find_u64(body, "vout");
    if (!txid_hex || !vout) return make_error(id, -32602, "missing txid/vout");
    auto txid = parse_hex32(*txid_hex);
    if (!txid) return make_error(id, -32602, "bad txid");
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::uint64_t h = tip->height;
    if (auto hopt = find_u64(body, "height"); hopt.has_value()) {
      h = *hopt;
      if (h != tip->height) return make_error(id, -32602, "historical proof not supported in v3.0");
    }

    const OutPoint op{*txid, static_cast<std::uint32_t>(*vout)};
    const Hash32 key = consensus::utxo_commitment_key(op);
    crypto::SparseMerkleTree tree(db_, "utxo");
    const auto value = tree.get_value(key);
    const auto proof = tree.get_proof(key);
    auto ur = db_.get(root_index_key("UTXO", h));
    if (!ur.has_value() || ur->size() != 32) return make_error(id, -32001, "utxo_root unavailable");
    Hash32 root{};
    std::copy(ur->begin(), ur->end(), root.begin());

    std::ostringstream oss;
    oss << "{\"proof_format\":\"smt_v0\",\"height\":" << h << ",\"key_hex\":\"" << hex_encode32(key)
        << "\",\"root_hex\":\"" << hex_encode32(root) << "\",\"utxo_root\":\"" << hex_encode32(root) << "\",";
    if (value.has_value()) oss << "\"value_hex\":\"" << hex_encode(*value) << "\",";
    else oss << "\"value_hex\":null,";
    oss << "\"siblings_hex\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "],\"siblings\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "]}";
    return make_result(id, oss.str());
  }

  if (*method == "get_validator_proof") {
    auto pub_hex = find_string(body, "pubkey_hex");
    if (!pub_hex) return make_error(id, -32602, "missing pubkey_hex");
    auto pub = parse_pubkey32(*pub_hex);
    if (!pub) return make_error(id, -32602, "bad pubkey");
    auto tip = db_.get_tip();
    if (!tip.has_value()) return make_error(id, -32000, "tip unavailable");
    std::uint64_t h = tip->height;
    if (auto hopt = find_u64(body, "height"); hopt.has_value()) {
      h = *hopt;
      if (h != tip->height) return make_error(id, -32602, "historical proof not supported in v3.0");
    }

    const Hash32 key = consensus::validator_commitment_key(*pub);
    crypto::SparseMerkleTree tree(db_, "validators");
    const auto value = tree.get_value(key);
    const auto proof = tree.get_proof(key);
    auto vr = db_.get(root_index_key("VAL", h));
    if (!vr.has_value() || vr->size() != 32) return make_error(id, -32001, "validators_root unavailable");
    Hash32 root{};
    std::copy(vr->begin(), vr->end(), root.begin());

    std::ostringstream oss;
    oss << "{\"proof_format\":\"smt_v0\",\"height\":" << h << ",\"key_hex\":\"" << hex_encode32(key)
        << "\",\"root_hex\":\"" << hex_encode32(root) << "\",\"validators_root\":\"" << hex_encode32(root) << "\",";
    if (value.has_value()) oss << "\"value_hex\":\"" << hex_encode(*value) << "\",";
    else oss << "\"value_hex\":null,";
    oss << "\"siblings_hex\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "],\"siblings\":[";
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
      if (i) oss << ",";
      oss << "\"" << hex_encode32(proof.siblings[i]) << "\"";
    }
    oss << "]}";
    return make_result(id, oss.str());
  }

  if (*method == "broadcast_tx") {
    auto tx_hex = find_string(body, "tx_hex");
    if (!tx_hex) return make_error(id, -32602, "missing tx_hex");
    auto tx_bytes = hex_decode(*tx_hex);
    if (!tx_bytes) return make_result(id, R"({"accepted":false,"error":"bad tx hex"})");
    auto tx = Tx::parse(*tx_bytes);
    if (!tx.has_value()) return make_result(id, R"({"accepted":false,"error":"tx parse failed"})");
    const Hash32 txid = tx->txid();
    const auto utxos = db_.load_utxos();
    const auto validators = db_.load_validators();
    consensus::ValidatorRegistry vr;
    for (const auto& [pub, info] : validators) vr.upsert(pub, info);
    auto tip = db_.get_tip();
    SpecialValidationContext ctx{
        .validators = &vr,
        .current_height = tip ? (tip->height + 1) : 1,
        .is_committee_member =
            [this](const PubKey32& pk, std::uint64_t h, std::uint32_t /*round*/) {
              auto committee = committee_for_height(h);
              if (!committee.has_value()) return false;
              return std::find(committee->begin(), committee->end(), pk) != committee->end();
            },
    };
    auto vrx = validate_tx(*tx, 1, utxos, &ctx);
    if (!vrx.ok) {
      return make_result(id, std::string("{\"accepted\":false,\"txid\":\"") + hex_encode32(txid) +
                                 "\",\"error\":\"" + json_escape(vrx.error) + "\"}");
    }
    std::string err;
    if (!relay_tx_to_peer(*tx_bytes, &err)) {
      return make_result(id, std::string("{\"accepted\":false,\"txid\":\"") + hex_encode32(txid) +
                                 "\",\"error\":\"" + json_escape(err) + "\"}");
    }
    return make_result(id, std::string("{\"accepted\":true,\"txid\":\"") + hex_encode32(txid) + "\"}");
  }

  return make_error(id, -32601, "method not found");
}

std::optional<Config> parse_args(int argc, char** argv) {
  Config cfg;
  cfg.network = mainnet_network();
  cfg.db_path = default_db_dir_for_network(cfg.network.name);
  cfg.port = cfg.network.lightserver_default_port;
  cfg.tx_relay_port = cfg.network.p2p_default_port;
  cfg.max_committee = cfg.network.max_committee;
  bool port_explicit = false;
  bool relay_port_explicit = false;
  bool committee_explicit = false;
  bool db_explicit = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() -> std::optional<std::string> {
      if (i + 1 >= argc) return std::nullopt;
      return std::string(argv[++i]);
    };
    if (a == "--db") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.db_path = *v;
      db_explicit = true;
    } else if (a == "--bind") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
    } else if (a == "--port") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.port = static_cast<std::uint16_t>(std::stoul(*v));
      port_explicit = true;
    } else if (a == "--relay-host") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.tx_relay_host = *v;
    } else if (a == "--relay-port") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.tx_relay_port = static_cast<std::uint16_t>(std::stoul(*v));
      relay_port_explicit = true;
    } else if (a == "--mainnet") {
      return std::nullopt;
    } else if (a == "--max-committee") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
      committee_explicit = true;
    } else {
      return std::nullopt;
    }
  }
  if (!db_explicit) cfg.db_path = default_db_dir_for_network(cfg.network.name);
  return cfg;
}

}  // namespace selfcoin::lightserver
