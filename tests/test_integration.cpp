#include "test_framework.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <array>
#include <atomic>

#include "address/address.hpp"
#include "consensus/validators.hpp"
#include "consensus/state_commitment.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "lightserver/server.hpp"
#include "keystore/validator_keystore.hpp"
#include "merkle/merkle.hpp"
#include "node/node.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "storage/db.hpp"
#include "consensus/monetary.hpp"
#include "genesis/genesis.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

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

bool wait_for_tip(const node::Node& n, std::uint64_t expected_height, std::chrono::milliseconds timeout) {
  return wait_for([&]() { return n.status().height >= expected_height; }, timeout);
}

bool wait_for_peer_count(const node::Node& n, std::size_t min_peers, std::chrono::milliseconds timeout) {
  return wait_for([&]() { return n.status().peers >= min_peers; }, timeout);
}

bool wait_for_same_tip(const std::vector<std::unique_ptr<node::Node>>& nodes, std::chrono::milliseconds timeout) {
  return wait_for([&]() {
    if (nodes.empty()) return true;
    const auto s0 = nodes[0]->status();
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      if (si.height != s0.height || si.tip_hash != s0.tip_hash) return false;
    }
    return true;
  }, timeout);
}

bool wait_for_stable_same_tip(const std::vector<std::unique_ptr<node::Node>>& nodes, std::chrono::milliseconds timeout) {
  const auto start = std::chrono::steady_clock::now();
  const auto stable_window = std::chrono::milliseconds(1200);

  while (std::chrono::steady_clock::now() - start < timeout) {
    if (!wait_for_same_tip(nodes, std::chrono::milliseconds(500))) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    const auto base = nodes[0]->status();
    bool all_equal = true;
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      if (si.height != base.height || si.tip_hash != base.tip_hash) {
        all_equal = false;
        break;
      }
    }
    if (!all_equal) continue;

    const auto stable_start = std::chrono::steady_clock::now();
    bool stable = true;
    while (std::chrono::steady_clock::now() - stable_start < stable_window) {
      const auto s0 = nodes[0]->status();
      if (s0.height != base.height || s0.tip_hash != base.tip_hash) {
        stable = false;
        break;
      }
      for (size_t i = 1; i < nodes.size(); ++i) {
        const auto si = nodes[i]->status();
        if (si.height != base.height || si.tip_hash != base.tip_hash) {
          stable = false;
          break;
        }
      }
      if (!stable) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (stable) return true;
  }
  return false;
}

std::uint16_t reserve_test_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 0;
  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return 0;
  }
  sockaddr_in bound{};
  socklen_t len = sizeof(bound);
  std::uint16_t port = 0;
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
    port = ntohs(bound.sin_port);
  }
  ::close(fd);
  return port;
}

int node_for_pub(const std::vector<crypto::KeyPair>& keys, const PubKey32& pub) {
  for (size_t i = 0; i < keys.size(); ++i) {
    if (keys[i].public_key == pub) return static_cast<int>(i);
  }
  return -1;
}

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key generation failed");
  return *kp;
}

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

std::optional<Tx> create_bond_tx_from_validator0(node::Node& node0, const crypto::KeyPair& validator0,
                                                 const PubKey32& new_validator_pub) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  auto utxos = node0.find_utxos_by_pubkey_hash_for_test(sender_pkh);
  if (utxos.empty()) return std::nullopt;

  std::vector<std::pair<OutPoint, TxOut>> selected;
  std::uint64_t in_sum = 0;
  for (const auto& it : utxos) {
    selected.push_back(it);
    in_sum += it.second.value;
    if (in_sum >= BOND_AMOUNT) break;
  }
  if (in_sum < BOND_AMOUNT) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator_pub.begin(), new_validator_pub.end());
  std::vector<TxOut> outs{TxOut{BOND_AMOUNT, reg_spk}};
  const std::uint64_t change = in_sum - BOND_AMOUNT;
  if (change > 0) outs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});

  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  for (const auto& [op, _] : selected) {
    tx.inputs.push_back(TxIn{op.txid, op.index, {}, 0xFFFFFFFF});
  }
  tx.outputs = outs;

  for (std::size_t i = 0; i < selected.size(); ++i) {
    auto msg = signing_message_for_input(tx, static_cast<std::uint32_t>(i));
    if (!msg.has_value()) return std::nullopt;
    auto sig = crypto::ed25519_sign(*msg, validator0.private_key);
    if (!sig.has_value()) return std::nullopt;
    Bytes script;
    script.push_back(0x40);
    script.insert(script.end(), sig->begin(), sig->end());
    script.push_back(0x20);
    script.insert(script.end(), validator0.public_key.begin(), validator0.public_key.end());
    tx.inputs[i].script_sig = std::move(script);
  }
  return tx;
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

struct HttpStubServer {
  int fd{-1};
  std::uint16_t port{0};
  std::atomic<bool> running{false};
  std::thread th;

  bool start() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
    if (::listen(fd, 8) != 0) return false;
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bl) != 0) return false;
    port = ntohs(bound.sin_port);
    running = true;
    th = std::thread([this]() {
      while (running) {
        sockaddr_in caddr{};
        socklen_t len = sizeof(caddr);
        int cfd = ::accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
        if (cfd < 0) continue;
        const char kResp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        (void)::send(cfd, kResp, sizeof(kResp) - 1, 0);
        ::shutdown(cfd, SHUT_RDWR);
        ::close(cfd);
      }
    });
    return true;
  }

  void stop() {
    running = false;
    if (fd >= 0) {
      ::shutdown(fd, SHUT_RDWR);
      ::close(fd);
      fd = -1;
    }
    if (th.joinable()) th.join();
  }
};

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators);

Cluster make_cluster(const std::string& base, int initial_active = 4, int node_count = 4,
                     std::size_t max_committee = MAX_COMMITTEE) {
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, static_cast<std::size_t>(std::max(initial_active, node_count)))) {
    throw std::runtime_error("failed to write cluster genesis");
  }
  const auto keys = node::Node::deterministic_test_keypairs();

  Cluster c;
  c.nodes.reserve(node_count);
  for (int i = 0; i < node_count; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.max_committee = max_committee;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
    }
    keystore::ValidatorKey out_key;
    std::string kerr;
    if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                             deterministic_seed_for_node_id(i), &out_key, &kerr)) {
      throw std::runtime_error("failed to create validator keystore: " + kerr);
    }

    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) {
      throw std::runtime_error("init failed for node " + std::to_string(i));
    }
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();
  return c;
}

bool rpc_get_status_ok(const std::string& host, std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return false;
  }
  const std::string body = R"({"jsonrpc":"2.0","id":1,"method":"get_status","params":{}})";
  std::ostringstream req;
  req << "POST /rpc HTTP/1.1\r\n"
      << "Host: " << host << ":" << port << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  const auto rs = req.str();
  if (::send(fd, rs.data(), rs.size(), 0) != static_cast<ssize_t>(rs.size())) {
    ::close(fd);
    return false;
  }
  std::array<char, 4096> buf{};
  std::string resp;
  while (true) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) break;
    resp.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  return resp.find("\"result\"") != std::string::npos && resp.find("\"get_status\"") == std::string::npos;
}

bool send_invalid_frame(const std::string& ip, std::uint16_t port, std::uint32_t magic) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return false;
  }
  std::array<std::uint8_t, 12> hdr{};
  hdr[0] = static_cast<std::uint8_t>(magic & 0xFFu);
  hdr[1] = static_cast<std::uint8_t>((magic >> 8) & 0xFFu);
  hdr[2] = static_cast<std::uint8_t>((magic >> 16) & 0xFFu);
  hdr[3] = static_cast<std::uint8_t>((magic >> 24) & 0xFFu);
  hdr[4] = 0x01;
  hdr[5] = 0x00;
  hdr[6] = 0x09;
  hdr[7] = 0x00;
  hdr[8] = 0xFF;  // absurd payload length, guaranteed invalid by max_payload_len
  hdr[9] = 0xFF;
  hdr[10] = 0xFF;
  hdr[11] = 0x7F;
  const bool ok = ::send(fd, hdr.data(), hdr.size(), 0) == static_cast<ssize_t>(hdr.size());
  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);
  return ok;
}

bool connect_and_check_closed(const std::string& ip, std::uint16_t port, std::chrono::milliseconds wait) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return true;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return true;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return true;
  }
  std::this_thread::sleep_for(wait);
  char c = 0;
  const ssize_t n = ::recv(fd, &c, 1, MSG_DONTWAIT);
  const bool closed = (n == 0) || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);
  return closed;
}

bool send_version_and_expect_disconnect(const std::string& ip, std::uint16_t port, const p2p::VersionMsg& v,
                                        const NetworkConfig& net_cfg, std::chrono::milliseconds wait) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return false;
  }
  if (!p2p::write_frame_fd(fd, p2p::Frame{p2p::MsgType::VERSION, p2p::ser_version(v)}, net_cfg.magic,
                           net_cfg.protocol_version)) {
    ::close(fd);
    return false;
  }
  std::this_thread::sleep_for(wait);
  char c = 0;
  const ssize_t n = ::recv(fd, &c, 1, MSG_DONTWAIT);
  const bool disconnected = (n == 0) || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);
  return disconnected;
}

std::optional<Block> find_block_with_tx(const std::string& db_path, const Hash32& txid, std::uint64_t max_h) {
  storage::DB db;
  if (!db.open_readonly(db_path) && !db.open(db_path)) return std::nullopt;
  for (std::uint64_t h = 1; h <= max_h; ++h) {
    auto hh = db.get_height_hash(h);
    if (!hh.has_value()) continue;
    auto bb = db.get_block(*hh);
    if (!bb.has_value()) continue;
    auto blk = Block::parse(*bb);
    if (!blk.has_value()) continue;
    for (const auto& tx : blk->txs) {
      if (tx.txid() == txid) return blk;
    }
  }
  return std::nullopt;
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators = 4) {
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
  d.note = "integration-mainnet";
  d.initial_validators.clear();
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

bool write_empty_mainnet_bootstrap_genesis_file(const std::string& path) {
  genesis::Document d;
  d.version = 1;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 0;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 1;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = {};
  d.note = "single-node-bootstrap-template";

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

}  // namespace

TEST(test_devnet_4_nodes_finalize_and_faults) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  auto cluster = make_cluster("/tmp/selfcoin_it_faults");
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 30) return false;
    }
    return true;
  }, std::chrono::seconds(90)));

  const auto st0 = nodes[0]->status();
  auto active = nodes[0]->active_validators_for_next_height_for_test();
  auto leader0 = consensus::select_leader(st0.tip_hash, st0.height + 1, 0, active);
  ASSERT_TRUE(leader0.has_value());
  int leader_id = node_for_pub(keys, *leader0);
  ASSERT_TRUE(leader_id >= 0);

  const std::uint64_t before_pause_h = nodes[leader_id]->status().height;
  nodes[leader_id]->pause_proposals_for_test(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(6500));
  nodes[leader_id]->pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    std::uint64_t min_h = UINT64_MAX;
    for (const auto& n : nodes) min_h = std::min(min_h, n->status().height);
    return min_h > before_pause_h;
  }, std::chrono::seconds(30)));

  // Equivocation injection for validator 0.
  std::uint64_t min_before = UINT64_MAX;
  for (const auto& n : nodes) min_before = std::min(min_before, n->status().height);

  for (auto& n : nodes) {
    const auto st = n->status();
    Vote va;
    va.height = st.height + 1;
    va.round = 0;
    va.block_id.fill(0xAA);
    va.validator_pubkey = keys[0].public_key;
    auto sa = crypto::ed25519_sign(Bytes(va.block_id.begin(), va.block_id.end()), keys[0].private_key);
    ASSERT_TRUE(sa.has_value());
    va.signature = *sa;

    Vote vb = va;
    vb.block_id.fill(0xBB);
    auto sb = crypto::ed25519_sign(Bytes(vb.block_id.begin(), vb.block_id.end()), keys[0].private_key);
    ASSERT_TRUE(sb.has_value());
    vb.signature = *sb;

    (void)n->inject_vote_for_test(va);
    (void)n->inject_vote_for_test(vb);
  }

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < min_before + 2) return false;
    }
    return true;
  }, std::chrono::seconds(45)));

  Vote vc;
  vc.validator_pubkey = keys[0].public_key;
  vc.height = nodes[1]->status().height + 1;
  vc.round = 0;
  vc.block_id.fill(0xCC);
  auto sc = crypto::ed25519_sign(Bytes(vc.block_id.begin(), vc.block_id.end()), keys[0].private_key);
  ASSERT_TRUE(sc.has_value());
  vc.signature = *sc;
  ASSERT_TRUE(!nodes[1]->inject_vote_for_test(vc));
}

TEST(test_tx_finalized_and_visible_on_all_nodes) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  auto cluster = make_cluster("/tmp/selfcoin_it_tx");
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 12) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  const auto sender_pkh = crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end()));
  OutPoint spend_op{};
  std::optional<TxOut> spend_out;
  ASSERT_TRUE(wait_for([&]() {
    spend_out = nodes[0]->find_utxo_by_pubkey_hash_for_test(sender_pkh, &spend_op);
    return spend_out.has_value() && spend_out->value > 2000;
  }, std::chrono::seconds(30)));

  const auto recipient_pkh = crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end()));
  const std::uint64_t fee = 1000;
  const std::uint64_t amount = spend_out->value - fee;
  std::vector<TxOut> outputs{TxOut{amount, address::p2pkh_script_pubkey(recipient_pkh)}};

  std::string err;
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, *spend_out, keys[0].private_key, outputs, &err);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();

  ASSERT_TRUE(nodes[1]->inject_tx_for_test(*tx, true));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->mempool_contains_for_test(txid)) return true;
    }
    return false;
  }, std::chrono::seconds(10)));

  OutPoint recipient_op{txid, 0};
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      TxOut out;
      if (!n->has_utxo_for_test(recipient_op, &out)) return false;
      if (out.value != amount) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->mempool_contains_for_test(txid)) return false;
    }
    return true;
  }, std::chrono::seconds(15)));
}

TEST(test_restart_determinism_and_continued_finalization) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 4u);

  const std::string base = "/tmp/selfcoin_it_restart";
  {
    auto cluster = make_cluster(base);
    auto& nodes = cluster.nodes;

    ASSERT_TRUE(wait_for_tip(*nodes[0], 12, std::chrono::seconds(45)));
    ASSERT_TRUE(wait_for([&]() {
      for (size_t i = 1; i < nodes.size(); ++i) {
        if (nodes[i]->status().height < 12) return false;
      }
      return true;
    }, std::chrono::seconds(45)));

    ASSERT_TRUE(wait_for_same_tip(nodes, std::chrono::seconds(20)));
    const auto s0 = nodes[0]->status();
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      ASSERT_EQ(si.height, s0.height);
      ASSERT_EQ(si.tip_hash, s0.tip_hash);
      ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
                nodes[0]->active_validators_for_next_height_for_test());
    }

    for (auto& n : nodes) n->pause_proposals_for_test(true);
    ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(20)));
  }

  Cluster restarted;
  restarted.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.genesis_path = base + "/genesis.json";
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
    }

    auto n = std::make_unique<node::Node>(cfg);
    ASSERT_TRUE(n->init());
    n->pause_proposals_for_test(true);
    restarted.nodes.push_back(std::move(n));
  }
  for (auto& n : restarted.nodes) n->start();

  auto& nodes = restarted.nodes;
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(20)));
  const auto before = nodes[0]->status();

  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(20)));
  for (size_t i = 1; i < nodes.size(); ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, before.height);
    ASSERT_EQ(si.tip_hash, before.tip_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
  }

  for (auto& n : nodes) n->pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = nodes[0]->status();
    if (s0.height < before.height + 4) return false;
    for (size_t i = 1; i < nodes.size(); ++i) {
      const auto si = nodes[i]->status();
      if (si.height != s0.height || si.tip_hash != s0.tip_hash) return false;
    }
    return true;
  }, std::chrono::seconds(35)));

  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(10)));
  const auto after = nodes[0]->status();
  for (size_t i = 1; i < nodes.size(); ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, after.height);
    ASSERT_EQ(si.tip_hash, after.tip_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
  }
}

TEST(test_permissionless_join_pending_to_active_after_warmup) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster("/tmp/selfcoin_it_join", 1);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 10; }, std::chrono::seconds(60)));

  const auto new_val = key_from_byte(99);
  std::optional<Tx> bond_tx;
  ASSERT_TRUE(wait_for([&]() {
    bond_tx = create_bond_tx_from_validator0(*nodes[0], keys[0], new_val.public_key);
    return bond_tx.has_value();
  }, std::chrono::seconds(180)));
  ASSERT_TRUE(nodes[0]->inject_tx_for_test(*bond_tx, true));

  std::uint64_t joined_height = 0;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(new_val.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::PENDING &&
          info->status != consensus::ValidatorStatus::ACTIVE) {
        return false;
      }
      joined_height = info->joined_height;
    }
    return joined_height > 0;
  }, std::chrono::seconds(60)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto active = n->active_validators_for_next_height_for_test();
      bool found = std::find(active.begin(), active.end(), new_val.public_key) != active.end();
      if (!found) return false;
    }
    return true;
  }, std::chrono::seconds(120)));
}

TEST(test_slash_consumes_bond_and_requires_rebond_warmup) {
  const auto keys = node::Node::deterministic_test_keypairs();
  auto cluster = make_cluster("/tmp/selfcoin_it_slash", 1);
  auto& nodes = cluster.nodes;
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 10; }, std::chrono::seconds(60)));

  const auto slash_val = key_from_byte(77);
  std::optional<Tx> bond_tx;
  ASSERT_TRUE(wait_for([&]() {
    bond_tx = create_bond_tx_from_validator0(*nodes[0], keys[0], slash_val.public_key);
    return bond_tx.has_value();
  }, std::chrono::seconds(180)));
  ASSERT_TRUE(nodes[0]->inject_tx_for_test(*bond_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(slash_val.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::PENDING &&
          info->status != consensus::ValidatorStatus::ACTIVE) {
        return false;
      }
    }
    return true;
  }, std::chrono::seconds(60)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto active = n->active_validators_for_next_height_for_test();
      if (std::find(active.begin(), active.end(), slash_val.public_key) == active.end()) return false;
    }
    return true;
  }, std::chrono::seconds(240)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto committee = n->committee_for_next_height_for_test();
      if (std::find(committee.begin(), committee.end(), slash_val.public_key) == committee.end()) return false;
    }
    return true;
  }, std::chrono::seconds(120)));

  for (auto& n : nodes) n->pause_proposals_for_test(true);

  ASSERT_TRUE(wait_for([&]() {
    const auto h0 = nodes[0]->status().height;
    for (size_t i = 1; i < nodes.size(); ++i) {
      if (nodes[i]->status().height != h0) return false;
    }
    return true;
  }, std::chrono::seconds(30)));

  auto info0 = nodes[0]->validator_info_for_test(slash_val.public_key);
  ASSERT_TRUE(info0.has_value());
  OutPoint bond_op = info0->bond_outpoint;
  ASSERT_TRUE(info0->has_bond);

  Vote a;
  a.height = nodes[0]->status().height + 1;
  a.round = 0;
  a.block_id.fill(0x31);
  a.validator_pubkey = slash_val.public_key;
  auto sa = crypto::ed25519_sign(Bytes(a.block_id.begin(), a.block_id.end()), slash_val.private_key);
  ASSERT_TRUE(sa.has_value());
  a.signature = *sa;

  Vote b = a;
  b.block_id.fill(0x41);
  auto sb = crypto::ed25519_sign(Bytes(b.block_id.begin(), b.block_id.end()), slash_val.private_key);
  ASSERT_TRUE(sb.has_value());
  b.signature = *sb;

  auto slash_tx = build_slash_tx(bond_op, BOND_AMOUNT, a, b);
  ASSERT_TRUE(slash_tx.has_value());
  ASSERT_TRUE(nodes[0]->inject_tx_for_test(*slash_tx, true));
  const Hash32 slash_txid = slash_tx->txid();
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->mempool_contains_for_test(slash_txid)) return true;
    }
    return true;
  }, std::chrono::seconds(20)));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 20) return false;
    }
    return true;
  }, std::chrono::seconds(120)));
}

TEST(test_committee_selection_and_non_member_votes_ignored) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 12u);
  auto cluster = make_cluster("/tmp/selfcoin_it_committee", 12, 12, 5);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 10) return false;
    }
    return true;
  }, std::chrono::seconds(120)));
  for (auto& n : nodes) n->pause_proposals_for_test(true);
  ASSERT_TRUE(wait_for_stable_same_tip(nodes, std::chrono::seconds(30)));

  const auto target_height = nodes[0]->status().height + 1;
  const auto c0 = nodes[0]->committee_for_height_round_for_test(target_height, 0);
  ASSERT_EQ(c0.size(), 5u);
  for (size_t i = 1; i < nodes.size(); ++i) {
    ASSERT_EQ(nodes[i]->committee_for_height_round_for_test(target_height, 0), c0);
  }

  PubKey32 non_member{};
  bool found_non_member = false;
  for (int i = 0; i < 12; ++i) {
    if (std::find(c0.begin(), c0.end(), keys[i].public_key) == c0.end()) {
      non_member = keys[i].public_key;
      found_non_member = true;
      break;
    }
  }
  ASSERT_TRUE(found_non_member);
  int non_member_id = node_for_pub(keys, non_member);
  ASSERT_TRUE(non_member_id >= 0);

  Vote bad_vote;
  bad_vote.height = target_height;
  bad_vote.round = 0;
  bad_vote.block_id.fill(0xA5);
  bad_vote.validator_pubkey = non_member;
  auto bad_sig =
      crypto::ed25519_sign(Bytes(bad_vote.block_id.begin(), bad_vote.block_id.end()), keys[non_member_id].private_key);
  ASSERT_TRUE(bad_sig.has_value());
  bad_vote.signature = *bad_sig;
  ASSERT_TRUE(!nodes[0]->inject_vote_for_test(bad_vote));
  for (auto& n : nodes) n->pause_proposals_for_test(false);

  const std::uint64_t before = nodes[0]->status().height;
  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < before + 2) return false;
    }
    return true;
  }, std::chrono::seconds(120)));
}

TEST(test_mainnet_seed_bootstrap_and_catchup) {
  const std::string base = "/tmp/selfcoin_it_mainnet_bootstrap_seeds";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 4));

  std::vector<std::unique_ptr<node::Node>> nodes;
  {
    node::NodeConfig cfg;
    cfg.node_id = 0;
    cfg.db_path = base + "/node0";
    cfg.p2p_port = 0;  // ephemeral
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    keystore::ValidatorKey out_key;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(0), &out_key, &kerr));
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) return;
    nodes.push_back(std::move(n));
  }
  nodes[0]->start();
  ASSERT_TRUE(wait_for_peer_count(*nodes[0], 0, std::chrono::seconds(1)));
  const std::uint16_t seed_port = nodes[0]->p2p_port_for_test();
  if (seed_port == 0) return;

  for (int i = 1; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.node_id = i;
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.p2p_port = 0;  // ephemeral
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    cfg.validator_passphrase = "test-pass";
    keystore::ValidatorKey out_key;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(i), &out_key, &kerr));
    cfg.seeds.push_back("127.0.0.1:" + std::to_string(seed_port));
    auto n = std::make_unique<node::Node>(cfg);
    if (!n->init()) return;
    nodes.push_back(std::move(n));
  }
  for (int i = 1; i < 4; ++i) nodes[i]->start();

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 8) return false;
    }
    return true;
  }, std::chrono::seconds(90)));

  node::NodeConfig join_cfg;
  join_cfg.node_id = 7;
  join_cfg.db_path = base + "/joiner";
  join_cfg.p2p_port = 0;  // ephemeral
  join_cfg.genesis_path = gpath;
  join_cfg.allow_unsafe_genesis_override = true;
  join_cfg.validator_key_file = join_cfg.db_path + "/keystore/validator.json";
  join_cfg.validator_passphrase = "test-pass";
  {
    keystore::ValidatorKey out_key;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(join_cfg.validator_key_file, join_cfg.validator_passphrase,
                                                    "mainnet", "sc", deterministic_seed_for_node_id(7), &out_key, &kerr));
  }
  join_cfg.seeds.push_back("127.0.0.1:" + std::to_string(seed_port));
  auto joiner = std::make_unique<node::Node>(join_cfg);
  if (!joiner->init()) return;
  joiner->start();
  ASSERT_TRUE(wait_for_peer_count(*joiner, 1, std::chrono::seconds(20)));

  ASSERT_TRUE(wait_for([&]() {
    const auto jh = joiner->status().height;
    std::uint64_t min_h = UINT64_MAX;
    for (const auto& n : nodes) min_h = std::min(min_h, n->status().height);
    return jh >= min_h;
  }, std::chrono::seconds(90)));

  joiner->stop();
  for (auto& n : nodes) n->stop();
}

TEST(test_observer_reports_ok_on_two_lightservers) {
  const std::string base = "/tmp/selfcoin_it_observer";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  auto cluster = make_cluster(base + "/cluster");
  ASSERT_TRUE(wait_for([&]() { return cluster.nodes[0]->status().height >= 10; }, std::chrono::seconds(60)));
  const std::string db_path = base + "/cluster/node0";

  lightserver::Config l1;
  l1.db_path = db_path;
  l1.bind_ip = "127.0.0.1";
  l1.port = 0;  // ephemeral
  lightserver::Server s1(l1);
  ASSERT_TRUE(s1.init());
  if (!s1.start()) return;
  const std::uint16_t p1 = s1.bound_port();
  ASSERT_TRUE(p1 != 0);

  lightserver::Config l2 = l1;
  l2.port = 0;  // ephemeral
  lightserver::Server s2(l2);
  ASSERT_TRUE(s2.init());
  if (!s2.start()) {
    s1.stop();
    return;
  }
  const std::uint16_t p2 = s2.bound_port();
  ASSERT_TRUE(p2 != 0);

  ASSERT_TRUE(wait_for([&]() { return rpc_get_status_ok("127.0.0.1", p1); }, std::chrono::seconds(5)));
  ASSERT_TRUE(wait_for([&]() { return rpc_get_status_ok("127.0.0.1", p2); }, std::chrono::seconds(5)));
  const std::string out_file = base + "/observer.out";
  const std::string cmd = "python3 scripts/observe.py --interval 0.2 --max-intervals 2 --mismatch-threshold 2 " +
                          std::string("http://127.0.0.1:") + std::to_string(p1) + "/rpc " +
                          "http://127.0.0.1:" + std::to_string(p2) + "/rpc > " + out_file + " 2>&1";
  const int rc = std::system(cmd.c_str());
  s2.stop();
  s1.stop();
  ASSERT_TRUE(rc == 0);

  std::ifstream in(out_file);
  std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  ASSERT_TRUE(content.find("mismatch") == std::string::npos);
}

TEST(test_invalid_frame_spam_bans_peer_and_node_stays_alive) {
  const std::string base = "/tmp/selfcoin_it_hardening_invalid_frame";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;  // ephemeral
  cfg.ban_seconds = 30;
  cfg.handshake_timeout_ms = 1000;
  cfg.frame_timeout_ms = 500;
  cfg.idle_timeout_ms = 2000;

  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  for (int i = 0; i < 8; ++i) {
    (void)send_invalid_frame("127.0.0.1", port, cfg.network.magic);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_pre_handshake >= 1; }, std::chrono::seconds(5)));
  ASSERT_TRUE(!connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(200)));
  n.stop();
}

TEST(test_seed_http_port_preflight_does_not_break_node_progress) {
  const std::string base = "/tmp/selfcoin_it_seed_http_preflight";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  HttpStubServer http;
  if (!http.start()) return;

  node::NodeConfig cfg;
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.seeds.push_back("127.0.0.1:" + std::to_string(http.port));

  node::Node n(cfg);
  if (!n.init()) {
    http.stop();
    return;
  }
  n.start();
  std::this_thread::sleep_for(std::chrono::seconds(2));
  ASSERT_TRUE(n.status().peers == 0);
  n.stop();
  http.stop();
}

TEST(test_invalid_frame_ban_threshold_applies_after_strikes) {
  const std::string base = "/tmp/selfcoin_it_hardening_threshold";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
      cfg.node_id = 0;
  cfg.max_committee = 1;
  cfg.db_path = base + "/node0";
  cfg.bind_ip = "127.0.0.1";
  cfg.p2p_port = 0;
  cfg.ban_seconds = 30;
  cfg.invalid_frame_ban_threshold = 3;
  cfg.invalid_frame_window_seconds = 60;
  cfg.handshake_timeout_ms = 5000;

  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  ASSERT_TRUE(port != 0);

  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(!connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(200)));

  ASSERT_TRUE(send_invalid_frame("127.0.0.1", port, cfg.network.magic));
  ASSERT_TRUE(wait_for([&]() { return connect_and_check_closed("127.0.0.1", port, std::chrono::milliseconds(150)); },
                       std::chrono::seconds(3)));
  n.stop();
}

TEST(test_fee_split_in_coinbase_deterministic) {
  const auto keys = node::Node::deterministic_test_keypairs();
  ASSERT_TRUE(keys.size() >= 1u);

  auto cluster = make_cluster("/tmp/selfcoin_it_fee_split");
  auto& n = cluster.nodes[0];
  ASSERT_TRUE(wait_for([&]() { return n->status().height >= 8; }, std::chrono::seconds(60)));

  const auto sender_pkh = crypto::h160(Bytes(keys[0].public_key.begin(), keys[0].public_key.end()));
  OutPoint spend_op{};
  auto spend_out = n->find_utxo_by_pubkey_hash_for_test(sender_pkh, &spend_op);
  ASSERT_TRUE(spend_out.has_value());

  const auto recipient_pkh = crypto::h160(Bytes(keys[1].public_key.begin(), keys[1].public_key.end()));
  const std::uint64_t fee = 1000;
  std::vector<TxOut> outs{TxOut{spend_out->value - fee, address::p2pkh_script_pubkey(recipient_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(spend_op, *spend_out, keys[0].private_key, outs);
  ASSERT_TRUE(tx.has_value());
  const Hash32 txid = tx->txid();

  ASSERT_TRUE(n->inject_tx_for_test(*tx, true));
  ASSERT_TRUE(wait_for([&]() { return !n->mempool_contains_for_test(txid); }, std::chrono::seconds(45)));

  const auto st = n->status();
  const auto blk = find_block_with_tx("/tmp/selfcoin_it_fee_split/node0", txid, st.height);
  ASSERT_TRUE(blk.has_value());
  ASSERT_TRUE(!blk->txs.empty());
  const auto& cb = blk->txs[0];
  ASSERT_TRUE(cb.outputs.size() >= 2u);

  const std::uint64_t R = consensus::reward_units(blk->header.height);
  const std::uint64_t T = R + fee;
  const std::uint64_t leader_units = (T * 20ULL) / 100ULL;
  ASSERT_EQ(cb.outputs[0].value, leader_units);

  std::uint64_t signer_sum = 0;
  for (std::size_t i = 1; i < cb.outputs.size(); ++i) signer_sum += cb.outputs[i].value;
  ASSERT_EQ(leader_units + signer_sum, T);
  ASSERT_EQ(signer_sum, T - leader_units);
}

TEST(test_reject_cross_network_version_handshake) {
  const std::string base = "/tmp/selfcoin_it_reject_cross_network";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0x5A;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 123;
  v.node_software_version = "handshake-test/0.7";
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_network_id >= 1; }, std::chrono::seconds(2)));
  n.stop();
}

TEST(test_reject_magic_mismatch_frame_before_handshake) {
  const std::string base = "/tmp/selfcoin_it_reject_magic_mismatch";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 444;
  v.node_software_version = "magic-mismatch-test/0.7";
  NetworkConfig mismatch_net = cfg.network;
  mismatch_net.magic ^= 0x01020304u;
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, mismatch_net, std::chrono::milliseconds(300)));
  n.stop();
}

TEST(test_reject_unsupported_protocol_version_handshake) {
  const std::string base = "/tmp/selfcoin_it_reject_proto";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  node::NodeConfig cfg;
        cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version + 1);  // unsupported
  v.network_id = cfg.network.network_id;
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 321;
  v.node_software_version = "handshake-test/0.7";
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_protocol_version >= 1; }, std::chrono::seconds(2)));
  n.stop();
}

TEST(test_mainnet_bootstrap_with_genesis) {
  const std::string base = "/tmp/selfcoin_it_mainnet_bootstrap";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 4));

  Cluster c;
  c.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.db_path = base + "/node" + std::to_string(i);
    cfg.p2p_port = 0;
    cfg.genesis_path = gpath;
    cfg.allow_unsafe_genesis_override = true;
    cfg.max_committee = 4;
    cfg.validator_passphrase = "test-passphrase";
    cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
    keystore::ValidatorKey vk;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(i), &vk, &kerr));
    auto n = std::make_unique<node::Node>(cfg);
    ASSERT_TRUE(n->init());
    c.nodes.push_back(std::move(n));
  }
  for (auto& n : c.nodes) n->start();

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : c.nodes) {
      if (n->status().height < 5) return false;
    }
    return true;
  }, std::chrono::seconds(45)));

  ASSERT_TRUE(wait_for_same_tip(c.nodes, std::chrono::seconds(10)));
}

TEST(test_single_node_custom_genesis_bootstraps_and_finalizes) {
  const std::string base = "/tmp/selfcoin_it_single_node_bootstrap";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg;
  cfg.node_id = 0;
  cfg.disable_p2p = true;
  cfg.dns_seeds = false;
  cfg.listen = false;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;

  node::Node n(cfg);
  ASSERT_TRUE(n.init());
  n.start();

  ASSERT_TRUE(wait_for_tip(n, 1, std::chrono::seconds(10)));

  const std::string key_path = keystore::default_validator_keystore_path(cfg.db_path);
  keystore::ValidatorKey vk;
  std::string err;
  ASSERT_TRUE(keystore::load_validator_keystore(key_path, "", &vk, &err));

  const auto active = n.active_validators_for_next_height_for_test();
  ASSERT_EQ(active.size(), 1u);
  ASSERT_EQ(active[0], vk.pubkey);
  const auto committee = n.committee_for_next_height_for_test();
  ASSERT_EQ(committee.size(), 1u);
  ASSERT_EQ(committee[0], vk.pubkey);
  ASSERT_EQ(n.quorum_threshold_for_next_height_for_test(), 1u);

  n.stop();
}

TEST(test_second_fresh_node_adopts_bootstrap_validator_and_syncs) {
  const std::string base = "/tmp/selfcoin_it_single_node_sync_join";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  if (cfg0.p2p_port == 0) return;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 1, std::chrono::seconds(12)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height >= 1 && s1.height >= 1 && s0.height == s1.height && s0.tip_hash == s1.tip_hash;
  }, std::chrono::seconds(20)));

  const auto s0 = n0.status();
  const auto s1 = n1.status();
  ASSERT_TRUE(s0.bootstrap_template_mode);
  ASSERT_TRUE(s1.bootstrap_template_mode);
  ASSERT_TRUE(!s0.bootstrap_validator_pubkey.empty());
  ASSERT_EQ(s0.bootstrap_validator_pubkey, s1.bootstrap_validator_pubkey);
  ASSERT_EQ(s1.last_bootstrap_source, "seeds");
  ASSERT_TRUE(s1.established_peers >= 1u);

  const auto active1 = n1.active_validators_for_next_height_for_test();
  ASSERT_EQ(active1.size(), 1u);

  n1.stop();
  n0.stop();
}

TEST(test_second_node_auto_joins_as_validator_on_chain) {
  const std::string base = "/tmp/selfcoin_it_single_node_validator_join";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_empty_mainnet_bootstrap_genesis_file(gpath));

  node::NodeConfig cfg0;
  cfg0.node_id = 0;
  cfg0.dns_seeds = false;
  cfg0.db_path = base + "/node0";
  cfg0.p2p_port = reserve_test_port();
  if (cfg0.p2p_port == 0) return;
  cfg0.genesis_path = gpath;
  cfg0.allow_unsafe_genesis_override = true;

  node::Node n0(cfg0);
  if (!n0.init()) return;
  n0.start();
  const auto port0 = n0.p2p_port_for_test();
  if (port0 == 0) {
    n0.stop();
    return;
  }
  ASSERT_TRUE(wait_for_tip(n0, 5, std::chrono::seconds(12)));

  node::NodeConfig cfg1;
  cfg1.node_id = 1;
  cfg1.dns_seeds = false;
  cfg1.db_path = base + "/node1";
  cfg1.p2p_port = reserve_test_port();
  if (cfg1.p2p_port == 0) {
    n0.stop();
    return;
  }
  cfg1.genesis_path = gpath;
  cfg1.allow_unsafe_genesis_override = true;
  cfg1.peers = {"127.0.0.1:" + std::to_string(port0)};

  node::Node n1(cfg1);
  if (!n1.init()) {
    n0.stop();
    return;
  }
  n1.start();

  ASSERT_TRUE(wait_for([&]() {
    const auto a0 = n0.active_validators_for_next_height_for_test();
    const auto a1 = n1.active_validators_for_next_height_for_test();
    return a0.size() >= 2 && a1.size() >= 2;
  }, std::chrono::seconds(45)));

  const auto a0 = n0.active_validators_for_next_height_for_test();
  const auto a1 = n1.active_validators_for_next_height_for_test();
  ASSERT_EQ(a0.size(), 2u);
  ASSERT_EQ(a1.size(), 2u);
  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = n0.status();
    const auto s1 = n1.status();
    return s0.height == s1.height && s0.tip_hash == s1.tip_hash && s0.height >= 120;
  }, std::chrono::seconds(20)));

  n1.stop();
  n0.stop();
}

TEST(test_reject_cross_network_mainnet_vs_testnet_handshake) {
  const std::string base = "/tmp/selfcoin_it_reject_mainnet_vs_testnet";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  ASSERT_TRUE(write_mainnet_genesis_file(gpath, 4));

  node::NodeConfig cfg;
  cfg.node_id = 0;
  cfg.db_path = base + "/node0";
  cfg.p2p_port = 0;
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_passphrase = "test-passphrase";
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  {
    keystore::ValidatorKey vk;
    std::string kerr;
    ASSERT_TRUE(keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                                    deterministic_seed_for_node_id(0), &vk, &kerr));
  }
  node::Node n(cfg);
  if (!n.init()) return;
  n.start();
  const std::uint16_t port = n.p2p_port_for_test();
  if (port == 0) {
    n.stop();
    return;
  }

  p2p::VersionMsg v;
  v.proto_version = static_cast<std::uint32_t>(cfg.network.protocol_version);
  v.network_id = cfg.network.network_id;
  v.network_id[0] ^= 0xFF;  // mismatch
  v.feature_flags = cfg.network.feature_flags;
  v.timestamp = static_cast<std::uint64_t>(::time(nullptr));
  v.nonce = 987;
  v.node_software_version = "handshake-test/0.7";
  ASSERT_TRUE(send_version_and_expect_disconnect("127.0.0.1", port, v, cfg.network, std::chrono::milliseconds(300)));
  ASSERT_TRUE(wait_for([&]() { return n.status().rejected_network_id >= 1; }, std::chrono::seconds(2)));
  n.stop();
}

TEST(test_fixed_runtime_proposal_omits_scr3_marker) {
  auto cluster = make_cluster("/tmp/selfcoin_it_no_v3_marker", 4, 1, 4);
  auto& n = *cluster.nodes[0];
  n.pause_proposals_for_test(true);

  const auto st = n.status();
  const std::uint64_t h = st.height + 1;
  const std::uint32_t r = st.round;
  auto blk = n.build_proposal_for_test(h, r);
  ASSERT_TRUE(blk.has_value());
  ASSERT_TRUE(!blk->txs.empty());
  ASSERT_TRUE(!blk->txs[0].inputs.empty());

  ASSERT_TRUE(consensus::find_scr3_roots_marker(blk->txs[0].inputs[0].script_sig, nullptr) == std::nullopt);
}

void register_integration_tests() {}
