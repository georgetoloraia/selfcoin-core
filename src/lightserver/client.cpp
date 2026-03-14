#include "lightserver/client.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <regex>
#include <sstream>

#include "codec/bytes.hpp"

namespace selfcoin::lightserver {
namespace {

struct ParsedHttpUrl {
  std::string host;
  std::uint16_t port{0};
  std::string path;
};

std::optional<int> connect_tcp(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return std::nullopt;
  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(res);
  if (fd < 0) return std::nullopt;
  return fd;
}

std::optional<ParsedHttpUrl> parse_http_url(const std::string& url) {
  const std::string prefix = "http://";
  if (url.rfind(prefix, 0) != 0) return std::nullopt;
  const std::string rest = url.substr(prefix.size());
  const auto slash = rest.find('/');
  const std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
  const std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);
  const auto colon = hostport.rfind(':');
  if (colon == std::string::npos) return std::nullopt;
  ParsedHttpUrl parsed;
  parsed.host = hostport.substr(0, colon);
  parsed.port = static_cast<std::uint16_t>(std::stoi(hostport.substr(colon + 1)));
  parsed.path = path;
  return parsed;
}

bool write_all(int fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

std::optional<std::string> read_all(int fd) {
  std::string out;
  std::array<char, 4096> buf{};
  while (true) {
    ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) return std::nullopt;
    if (n == 0) break;
    out.append(buf.data(), static_cast<size_t>(n));
  }
  return out;
}

std::optional<std::string> http_post_json(const std::string& url, const std::string& body, std::string* err) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    if (err) *err = "invalid http url";
    return std::nullopt;
  }
  auto fd_opt = connect_tcp(parsed->host, parsed->port);
  if (!fd_opt) {
    if (err) *err = "connect failed";
    return std::nullopt;
  }
  const int fd = *fd_opt;
  std::ostringstream req;
  req << "POST " << parsed->path << " HTTP/1.1\r\n"
      << "Host: " << parsed->host << ":" << parsed->port << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  if (!write_all(fd, req.str())) {
    ::close(fd);
    if (err) *err = "send failed";
    return std::nullopt;
  }
  auto resp = read_all(fd);
  ::close(fd);
  if (!resp) {
    if (err) *err = "read failed";
    return std::nullopt;
  }
  const auto body_pos = resp->find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    if (err) *err = "invalid http response";
    return std::nullopt;
  }
  return resp->substr(body_pos + 4);
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

std::optional<Hash32> parse_hex32_field(const std::string& hex) {
  auto bytes = hex_decode(hex);
  if (!bytes || bytes->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

std::string extract_result_body(const std::string& body, std::string* err) {
  if (body.find("\"error\"") != std::string::npos) {
    if (err) *err = "rpc returned error";
    return {};
  }
  const auto pos = body.find("\"result\":");
  if (pos == std::string::npos) {
    if (err) *err = "missing rpc result";
    return {};
  }
  return body.substr(pos + 9);
}

std::vector<std::string> extract_object_blobs(const std::string& json) {
  std::vector<std::string> out;
  int depth = 0;
  std::size_t start = std::string::npos;
  for (std::size_t i = 0; i < json.size(); ++i) {
    if (json[i] == '{') {
      if (depth == 0) start = i;
      ++depth;
    } else if (json[i] == '}') {
      --depth;
      if (depth == 0 && start != std::string::npos) {
        out.push_back(json.substr(start, i - start + 1));
        start = std::string::npos;
      }
    }
  }
  return out;
}

}  // namespace

std::optional<RpcStatusView> rpc_get_status(const std::string& rpc_url, std::string* err) {
  auto body = http_post_json(rpc_url, R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})", err);
  if (!body) return std::nullopt;

  RpcStatusView out;
  auto network_name = find_json_string(*body, "network_name");
  auto network_id = find_json_string(*body, "network_id");
  auto genesis_hash = find_json_string(*body, "genesis_hash");
  auto genesis_source = find_json_string(*body, "genesis_source");
  auto proto = find_json_u64(*body, "protocol_version");
  auto magic = find_json_u64(*body, "magic");
  auto tip_height = find_json_u64(*body, "height");
  auto tip_hash = find_json_string(*body, "hash");
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

std::optional<std::vector<UtxoView>> rpc_get_utxos(const std::string& rpc_url, const Hash32& scripthash, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":2,"method":"get_utxos","params":{"scripthash_hex":")") +
                                hex_encode32(scripthash) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  const std::string result = extract_result_body(*body, err);
  if (result.empty() && body->find("\"result\":[]") == std::string::npos) return std::nullopt;

  std::vector<UtxoView> out;
  for (const auto& blob : extract_object_blobs(result)) {
    auto txid_hex = find_json_string(blob, "txid");
    auto vout = find_json_u64(blob, "vout");
    auto value = find_json_u64(blob, "value");
    auto height = find_json_u64(blob, "height");
    auto spk_hex = find_json_string(blob, "script_pubkey_hex");
    if (!txid_hex || !vout || !value || !height || !spk_hex) continue;
    auto txid = parse_hex32_field(*txid_hex);
    auto spk = hex_decode(*spk_hex);
    if (!txid || !spk) continue;
    out.push_back(UtxoView{*txid, static_cast<std::uint32_t>(*vout), *value, *height, *spk});
  }
  return out;
}

std::optional<std::vector<HistoryEntry>> rpc_get_history(const std::string& rpc_url, const Hash32& scripthash,
                                                         std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":3,"method":"get_history","params":{"scripthash_hex":")") +
                                hex_encode32(scripthash) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  const std::string result = extract_result_body(*body, err);
  if (result.empty() && body->find("\"result\":[]") == std::string::npos) return std::nullopt;

  std::vector<HistoryEntry> out;
  for (const auto& blob : extract_object_blobs(result)) {
    auto txid_hex = find_json_string(blob, "txid");
    auto height = find_json_u64(blob, "height");
    if (!txid_hex || !height) continue;
    auto txid = parse_hex32_field(*txid_hex);
    if (!txid) continue;
    out.push_back(HistoryEntry{*txid, *height});
  }
  return out;
}

std::optional<TxView> rpc_get_tx(const std::string& rpc_url, const Hash32& txid, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":4,"method":"get_tx","params":{"txid":")") +
                                hex_encode32(txid) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  if (body->find("\"error\"") != std::string::npos) {
    if (err) *err = "rpc returned error";
    return std::nullopt;
  }
  auto height = find_json_u64(*body, "height");
  auto tx_hex = find_json_string(*body, "tx_hex");
  if (!height || !tx_hex) {
    if (err) *err = "missing tx fields";
    return std::nullopt;
  }
  auto tx_bytes = hex_decode(*tx_hex);
  if (!tx_bytes) {
    if (err) *err = "invalid tx hex";
    return std::nullopt;
  }
  return TxView{*height, *tx_bytes};
}

std::optional<BroadcastResult> rpc_broadcast_tx(const std::string& rpc_url, const Bytes& tx_bytes, std::string* err) {
  const std::string body_json = std::string(R"({"jsonrpc":"2.0","id":5,"method":"broadcast_tx","params":{"tx_hex":")") +
                                hex_encode(tx_bytes) + R"("}})";
  auto body = http_post_json(rpc_url, body_json, err);
  if (!body) return std::nullopt;
  BroadcastResult out;
  out.accepted = body->find("\"accepted\":true") != std::string::npos;
  if (auto txid_hex = find_json_string(*body, "txid"); txid_hex) out.txid_hex = *txid_hex;
  if (auto error_str = find_json_string(*body, "error"); error_str) out.error = *error_str;
  return out;
}

}  // namespace selfcoin::lightserver
