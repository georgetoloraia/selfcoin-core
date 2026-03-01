#include "test_framework.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <thread>

#include "address/address.hpp"
#include "crypto/hash.hpp"
#include "lightserver/server.hpp"
#include "node/node.hpp"
#include "p2p/framing.hpp"
#include "storage/db.hpp"
#include "utxo/signing.hpp"

using namespace selfcoin;

namespace {

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

TEST(test_lightserver_indexing_after_finalization) {
  const std::string base = "/tmp/selfcoin_light_idx";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
  cfg.devnet = true;
  cfg.node_id = 0;
  cfg.disable_p2p = true;
  cfg.devnet_initial_active_validators = 1;
  cfg.db_path = base + "/node0";
  cfg.max_committee = 1;
  node::Node node(cfg);
  ASSERT_TRUE(node.init());
  node.start();

  const auto keys = node::Node::devnet_keypairs();
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
  ASSERT_TRUE(db.open_readonly(cfg.db_path));
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

  node.stop();
}

TEST(test_lightserver_rpc_endpoints_and_broadcast) {
  const std::string base = "/tmp/selfcoin_light_rpc";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig ncfg;
  ncfg.devnet = true;
  ncfg.node_id = 0;
  ncfg.disable_p2p = true;
  ncfg.devnet_initial_active_validators = 1;
  ncfg.max_committee = 1;
  ncfg.db_path = base + "/node0";
  ncfg.p2p_port = 19040;
  auto node = std::make_unique<node::Node>(ncfg);
  ASSERT_TRUE(node->init());
  node->start();
  ASSERT_TRUE(wait_for([&]() { return node->status().height >= 6; }, std::chrono::seconds(30)));

  const auto keys = node::Node::devnet_keypairs();
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
  node->stop();

  lightserver::Config lcfg;
  lcfg.db_path = ncfg.db_path;
  lcfg.bind_ip = "127.0.0.1";
  lcfg.devnet = true;
  lcfg.devnet_initial_active_validators = 1;
  lcfg.max_committee = 1;
  lcfg.tx_relay_host = "127.0.0.1";
  lcfg.tx_relay_port = 29999;  // expected to be unavailable in test env
  auto ls = std::make_unique<lightserver::Server>(lcfg);
  ASSERT_TRUE(ls->init());

  auto tip_resp = ls->handle_rpc_for_test(R"({"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}})");
  ASSERT_TRUE(tip_resp.find("\"height\"") != std::string::npos);
  ASSERT_TRUE(tip_resp.find("\"hash\"") != std::string::npos);

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

void register_lightserver_tests() {}
