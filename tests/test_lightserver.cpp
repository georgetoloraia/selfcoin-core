#include "test_framework.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <regex>
#include <thread>

#include "address/address.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/server.hpp"
#include "node/node.hpp"
#include "p2p/framing.hpp"
#include "storage/db.hpp"
#include "crypto/smt.hpp"
#include "utxo/signing.hpp"

using namespace selfcoin;

namespace {

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators = 1) {
  const auto keys = node::Node::deterministic_test_keypairs();
  if (keys.size() < n_validators) return false;

  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.min_committee = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = mainnet_network().default_seeds;
  d.note = "lightserver-tests";
  d.initial_validators.clear();
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

struct Cluster {
  std::vector<std::unique_ptr<node::Node>> nodes;
  Cluster() = default;
  Cluster(const Cluster&) = delete;
  Cluster& operator=(const Cluster&) = delete;
  Cluster(Cluster&&) = default;
  Cluster& operator=(Cluster&&) = default;
  ~Cluster() {
    for (auto& n : nodes) {
      if (n) n->stop();
    }
  }
};

Cluster make_cluster(const std::string& base, int node_count = 4) {
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(node_count))) {
    throw std::runtime_error("failed to write genesis");
  }

  Cluster c;
  c.nodes.reserve(static_cast<std::size_t>(node_count));
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.node_id = i;
    cfg.disable_p2p = true;
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.max_committee = static_cast<std::size_t>(node_count);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    keystore::ValidatorKey created_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &created_key, &kerr)) {
      throw std::runtime_error("failed to create validator keystore");
    }
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) throw std::runtime_error("cluster init failed");
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();
  return c;
}

std::optional<std::string> json_string_field(const std::string& s, const std::string& key) {
  const std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(s, m, re) || m.size() < 2) return std::nullopt;
  return m[1].str();
}

std::vector<std::string> json_string_array_field(const std::string& s, const std::string& key) {
  std::vector<std::string> out;
  const std::regex outer_re("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch outer;
  if (!std::regex_search(s, outer, outer_re) || outer.size() < 2) return out;
  const std::string body = outer[1].str();
  const std::regex item_re("\"([0-9a-fA-F]+)\"");
  for (std::sregex_iterator it(body.begin(), body.end(), item_re), end; it != end; ++it) {
    out.push_back((*it)[1].str());
  }
  return out;
}

bool wait_for(const std::function<bool()>& pred, std::chrono::milliseconds timeout) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < timeout) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  return pred();
}

std::optional<std::string> http_post_rpc(const std::string& host, std::uint16_t port, const std::string& body) {
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

  std::string req = "POST /rpc HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  if (!p2p::write_all(fd, reinterpret_cast<const std::uint8_t*>(req.data()), req.size())) {
    ::close(fd);
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 4096> buf{};
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<size_t>(n));
  }
  ::close(fd);
  const auto pos = resp.find("\r\n\r\n");
  if (pos == std::string::npos) return std::nullopt;
  return resp.substr(pos + 4);
}

}  // namespace

TEST(test_lightserver_parse_args_rejects_mainnet_flag) {
  std::vector<std::string> args = {"selfcoin-lightserver", "--mainnet"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& s : args) argv.push_back(s.data());
  ASSERT_TRUE(!lightserver::parse_args(static_cast<int>(argv.size()), argv.data()).has_value());
}

TEST(test_lightserver_indexing_after_finalization) {
  const std::string base = "/tmp/selfcoin_light_idx";
  auto cluster = make_cluster(base);
  auto& node = *cluster.nodes[0];

  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 2);
  ASSERT_TRUE(wait_for([&]() { return node.status().height >= 6; }, std::chrono::seconds(30)));

  const auto sender_pkh = crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end()));
  OutPoint spend_op{};
  auto spend_out = node.find_utxo_by_pubkey_hash_for_test(sender_pkh, &spend_op);
  ASSERT_TRUE(spend_out.has_value());

  const auto recipient_pkh = crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end()));
  const std::uint64_t fee = 1000;
  std::vector<TxOut> outs{TxOut{spend_out->value - fee, address::p2pkh_script_pubkey(recipient_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, *spend_out, keys[0].private_key, outs);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();
  ASSERT_TRUE(node.inject_tx_for_test(*tx, false));
  ASSERT_TRUE(wait_for([&]() { return !node.mempool_contains_for_test(txid); }, std::chrono::seconds(30)));

  storage::DB db;
  ASSERT_TRUE(db.open_readonly(base + "/node0"));
  auto loc = db.get_tx_index(txid);
  ASSERT_TRUE(loc.has_value());
  ASSERT_TRUE(loc->tx_bytes == tx->serialize());

  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh));
  auto utxos = db.get_script_utxos(sh);
  ASSERT_TRUE(!utxos.empty());
  bool found = false;
  for (const auto& u : utxos) {
    if (u.outpoint.txid == txid && u.outpoint.index == 0) found = true;
  }
  ASSERT_TRUE(found);

}

TEST(test_lightserver_rpc_endpoints_and_broadcast) {
  const std::string base = "/tmp/selfcoin_light_rpc";
  auto cluster = make_cluster(base);
  auto& node = cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 6; }, std::chrono::seconds(30)));

  const auto keys = node::Node::deterministic_test_keypairs();
  const auto sender_pkh = crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end()));
  OutPoint spend_op{};
  auto spend_out = node->find_utxo_by_pubkey_hash_for_test(sender_pkh, &spend_op);
  ASSERT_TRUE(spend_out.has_value());
  const auto recipient_pkh = crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end()));
  const std::uint64_t fee = 1000;
  std::vector<TxOut> outs{TxOut{spend_out->value - fee, address::p2pkh_script_pubkey(recipient_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, *spend_out, keys[0].private_key, outs);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();

  ASSERT_TRUE(node->inject_tx_for_test(*tx, false));
  ASSERT_TRUE(wait_for([&]() { return !node->mempool_contains_for_test(txid); }, std::chrono::seconds(45)));
  const auto blk_hash = node->status().tip_hash;

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  lcfg.bind_ip = "127.0.0.1";
  lcfg.max_committee = 1;
  lcfg.tx_relay_host = "127.0.0.1";
  lcfg.tx_relay_port = 29999;  // expected to be unavailable in test env
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  auto tip_resp = ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}})");
  ASSERT_TRUE(tip_resp.find("\"height\"") != std::string::npos);
  ASSERT_TRUE(tip_resp.find("\"hash\"") != std::string::npos);
  auto status_resp = ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":11,"method":"get_status","params":{}})");
  ASSERT_TRUE(status_resp.find("\"uptime_s\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"version\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"network_name\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"network_id\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"magic\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"protocol_version\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"feature_flags\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"genesis_hash\"") != std::string::npos);
  ASSERT_TRUE(status_resp.find("\"genesis_source\"") != std::string::npos);

  auto headers_resp = ls->handle_rpc_for_test(
      R"({"jsonrpc":"2.0","id":2,"method":"get_headers","params":{"from_height":1,"count":2}})");
  ASSERT_TRUE(headers_resp.find("header_hex") != std::string::npos);
  ASSERT_TRUE(headers_resp.find("finality_proof") != std::string::npos);

  auto committee_resp =
      ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":3,"method":"get_committee","params":{"height":1}})");
  ASSERT_TRUE(committee_resp.find("result") != std::string::npos);

  const std::string bcast_body = std::string(R"({"jsonrpc":"2.0","id":4,"method":"broadcast_tx","params":{"tx_hex":")") +
                                 hex_encode(tx->serialize()) + R"("}})";
  auto bcast_resp = ls->handle_rpc_for_test(bcast_body);
  ASSERT_TRUE(bcast_resp.find("\"accepted\":false") != std::string::npos);

  const std::string tx_q =
      std::string(R"({"jsonrpc":"2.0","id":5,"method":"get_tx","params":{"txid":")") + hex_encode32(txid) + R"("}})";
  ASSERT_TRUE(wait_for([&]() {
    auto r = ls->handle_rpc_for_test(tx_q);
    return r.find(hex_encode(tx->serialize())) != std::string::npos;
  }, std::chrono::seconds(30)));

  const Hash32 sh = crypto::sha256(address::p2pkh_script_pubkey(recipient_pkh));
  const std::string utxo_q = std::string(R"({"jsonrpc":"2.0","id":6,"method":"get_utxos","params":{"scripthash_hex":")") +
                             hex_encode32(sh) + R"("}})";
  auto uresp = ls->handle_rpc_for_test(utxo_q);
  ASSERT_TRUE(uresp.find(hex_encode32(txid)) != std::string::npos);

  const std::string blk_q = std::string(R"({"jsonrpc":"2.0","id":7,"method":"get_block","params":{"hash":")") +
                            hex_encode32(blk_hash) + R"("}})";
  auto bresp = ls->handle_rpc_for_test(blk_q);
  ASSERT_TRUE(bresp.find("block_hex") != std::string::npos);
}

TEST(test_lightserver_rejects_oversized_header_batches) {
  const std::string base = "/tmp/selfcoin_light_limits";
  auto cluster = make_cluster(base, 4);
  auto& node = *cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return node.status().height >= 2; }, std::chrono::seconds(20)));

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  const auto too_many_headers = ls->handle_rpc_for_test(
      R"({"jsonrpc":"2.0","id":1,"method":"get_headers","params":{"from_height":0,"count":3000}})");
  ASSERT_TRUE(too_many_headers.find("count too large") != std::string::npos);

  const auto too_large_range = ls->handle_rpc_for_test(
      R"({"jsonrpc":"2.0","id":2,"method":"get_header_range","params":{"start_height":0,"end_height":3000}})");
  ASSERT_TRUE(too_large_range.find("range too large") != std::string::npos);
}

TEST(test_lightserver_rejects_oversized_request_body_for_test_api) {
  lightserver::Config lcfg;
  lcfg.db_path = "/tmp/selfcoin_light_oversized_body";
  std::filesystem::create_directories(lcfg.db_path);
  lightserver::Server ls(lcfg);
  ASSERT_TRUE(ls.init());

  std::string body = R"({"jsonrpc":"2.0","id":1,"method":"get_status","pad":")";
  body.append(300 * 1024, 'x');
  body += "\"}";
  const auto resp = ls.handle_rpc_for_test(body);
  ASSERT_TRUE(resp.find("request too large") != std::string::npos);
}

TEST(test_lightserver_roots_endpoints_unavailable_in_fixed_runtime) {
  const std::string base = "/tmp/selfcoin_light_v3_proofs";
  auto cluster = make_cluster(base, 4);
  auto& node = *cluster.nodes[0];

  lightserver::Config lcfg;
  lcfg.db_path = base + "/node0";
  lcfg.bind_ip = "127.0.0.1";
  lcfg.max_committee = 4;
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  const auto tip = node.status();
  const std::uint64_t h = tip.height;

  const std::string roots_q =
      std::string(R"({"jsonrpc":"2.0","id":21,"method":"get_roots","params":{"height":)") + std::to_string(h) + "}}";
  const auto roots = ls->handle_rpc_for_test(roots_q);
  const bool roots_available = roots.find("utxo_root") != std::string::npos;
  const bool roots_unavailable = roots.find("roots unavailable") != std::string::npos;
  ASSERT_TRUE(roots_available || roots_unavailable);

  OutPoint op{};
  op.txid.fill(0x42);
  op.index = 0;

  const std::string up_q = std::string(R"({"jsonrpc":"2.0","id":22,"method":"get_utxo_proof","params":{"txid":")") +
                           hex_encode32(op.txid) + R"(","vout":)" + std::to_string(op.index) + R"(,"height":)" +
                           std::to_string(h) + "}}";
  const auto up = ls->handle_rpc_for_test(up_q);
  if (roots_available) {
    ASSERT_TRUE(up.find("proof_format") != std::string::npos);
  } else {
    const bool utxo_root_unavailable = up.find("utxo_root unavailable") != std::string::npos;
    const bool historical_height_rejected = up.find("historical proof not supported") != std::string::npos;
    ASSERT_TRUE(utxo_root_unavailable || historical_height_rejected);
  }

  const std::string vp_q =
      [&]() {
        const auto keys = node::Node::deterministic_test_keypairs();
        return std::string(R"({"jsonrpc":"2.0","id":23,"method":"get_validator_proof","params":{"pubkey_hex":")") +
               hex_encode(Bytes(keys[0].public_key.begin(), keys[0].public_key.end())) + R"(","height":)" +
               std::to_string(h) + "}}";
      }();
  const auto vp = ls->handle_rpc_for_test(vp_q);
  if (roots_available) {
    ASSERT_TRUE(vp.find("proof_format") != std::string::npos);
  } else {
    const bool validators_root_unavailable = vp.find("validators_root unavailable") != std::string::npos;
    const bool historical_height_rejected = vp.find("historical proof not supported") != std::string::npos;
    ASSERT_TRUE(validators_root_unavailable || historical_height_rejected);
  }
}

void register_lightserver_tests() {}
