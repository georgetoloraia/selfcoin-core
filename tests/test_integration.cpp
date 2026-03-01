#include "test_framework.hpp"

#include <chrono>
#include <filesystem>
#include <thread>
#include <array>

#include "address/address.hpp"
#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "node/node.hpp"
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

std::optional<Tx> create_bond_tx_from_validator0(node::Node& node0, const crypto::KeyPair& validator0,
                                                 const PubKey32& new_validator_pub) {
  const auto sender_pkh = crypto::h160(Bytes(validator0.public_key.begin(), validator0.public_key.end()));
  OutPoint spend_op{};
  auto spend_out = node0.find_utxo_by_pubkey_hash_for_test(sender_pkh, &spend_op);
  if (!spend_out.has_value()) return std::nullopt;
  if (spend_out->value < BOND_AMOUNT) return std::nullopt;

  Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  reg_spk.insert(reg_spk.end(), new_validator_pub.begin(), new_validator_pub.end());
  std::vector<TxOut> outs{TxOut{BOND_AMOUNT, reg_spk}};
  const std::uint64_t change = spend_out->value - BOND_AMOUNT;
  if (change > 0) outs.push_back(TxOut{change, address::p2pkh_script_pubkey(sender_pkh)});
  return build_signed_p2pkh_tx_single_input(spend_op, *spend_out, validator0.private_key, outs);
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

Cluster make_cluster(const std::string& base, int initial_active = 4) {
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  Cluster c;
  c.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.devnet = true;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.devnet_initial_active_validators = initial_active;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
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

}  // namespace

TEST(test_devnet_4_nodes_finalize_and_faults) {
  const auto keys = node::Node::devnet_keypairs();
  ASSERT_EQ(keys.size(), 4u);

  auto cluster = make_cluster("/tmp/selfcoin_it_faults");
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      if (n->status().height < 30) return false;
    }
    return true;
  }, std::chrono::seconds(90)));

  const auto st0 = nodes[0]->status();
  std::vector<PubKey32> active;
  for (const auto& k : keys) active.push_back(k.public_key);
  std::sort(active.begin(), active.end());
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
  const auto keys = node::Node::devnet_keypairs();
  ASSERT_EQ(keys.size(), 4u);

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
  const auto keys = node::Node::devnet_keypairs();
  ASSERT_EQ(keys.size(), 4u);

  const std::string base = "/tmp/selfcoin_it_restart";
  {
    auto cluster = make_cluster(base);
    auto& nodes = cluster.nodes;

    ASSERT_TRUE(wait_for([&]() {
      for (const auto& n : nodes) {
        if (n->status().height < 30) return false;
      }
      return true;
    }, std::chrono::seconds(90)));

    const auto s0 = nodes[0]->status();
    for (int i = 1; i < 4; ++i) {
      const auto si = nodes[i]->status();
      ASSERT_EQ(si.height, s0.height);
      ASSERT_EQ(si.tip_hash, s0.tip_hash);
      ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
                nodes[0]->active_validators_for_next_height_for_test());
    }
  }

  Cluster restarted;
  restarted.nodes.reserve(4);
  for (int i = 0; i < 4; ++i) {
    node::NodeConfig cfg;
    cfg.devnet = true;
    cfg.disable_p2p = true;
    cfg.node_id = i;
    cfg.p2p_port = static_cast<std::uint16_t>(19040 + i);
    cfg.db_path = base + "/node" + std::to_string(i);
    for (int j = 0; j < i; ++j) {
      cfg.peers.push_back("127.0.0.1:" + std::to_string(19040 + j));
    }

    auto n = std::make_unique<node::Node>(cfg);
    ASSERT_TRUE(n->init());
    restarted.nodes.push_back(std::move(n));
  }
  for (auto& n : restarted.nodes) n->start();

  auto& nodes = restarted.nodes;
  const auto before = nodes[0]->status();

  for (int i = 1; i < 4; ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, before.height);
    ASSERT_EQ(si.tip_hash, before.tip_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
  }

  ASSERT_TRUE(wait_for([&]() {
    const auto s0 = nodes[0]->status();
    if (s0.height < before.height + 10) return false;
    for (int i = 1; i < 4; ++i) {
      const auto si = nodes[i]->status();
      if (si.height != s0.height || si.tip_hash != s0.tip_hash) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  const auto after = nodes[0]->status();
  for (int i = 1; i < 4; ++i) {
    const auto si = nodes[i]->status();
    ASSERT_EQ(si.height, after.height);
    ASSERT_EQ(si.tip_hash, after.tip_hash);
    ASSERT_EQ(nodes[i]->active_validators_for_next_height_for_test(),
              nodes[0]->active_validators_for_next_height_for_test());
  }
}

TEST(test_permissionless_join_pending_to_active_after_warmup) {
  const auto keys = node::Node::devnet_keypairs();
  auto cluster = make_cluster("/tmp/selfcoin_it_join", 1);
  auto& nodes = cluster.nodes;

  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 5; }, std::chrono::seconds(30)));

  const auto new_val = key_from_byte(99);
  auto bond_tx = create_bond_tx_from_validator0(*nodes[0], keys[0], new_val.public_key);
  ASSERT_TRUE(bond_tx.has_value());
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
  const auto keys = node::Node::devnet_keypairs();
  auto cluster = make_cluster("/tmp/selfcoin_it_slash", 1);
  auto& nodes = cluster.nodes;
  ASSERT_TRUE(wait_for([&]() { return nodes[0]->status().height >= 5; }, std::chrono::seconds(30)));

  const auto slash_val = key_from_byte(77);
  auto bond_tx = create_bond_tx_from_validator0(*nodes[0], keys[0], slash_val.public_key);
  ASSERT_TRUE(bond_tx.has_value());
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
  }, std::chrono::seconds(120)));

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

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(slash_val.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::BANNED) return false;
      if (info->has_bond) return false;
      TxOut out{};
      if (n->has_utxo_for_test(bond_op, &out)) return false;
      auto active = n->active_validators_for_next_height_for_test();
      if (std::find(active.begin(), active.end(), slash_val.public_key) != active.end()) return false;
    }
    return true;
  }, std::chrono::seconds(90)));

  // Re-bond same validator key; it should not become active instantly.
  auto rebond_tx = create_bond_tx_from_validator0(*nodes[0], keys[0], slash_val.public_key);
  ASSERT_TRUE(rebond_tx.has_value());
  ASSERT_TRUE(nodes[0]->inject_tx_for_test(*rebond_tx, true));

  ASSERT_TRUE(wait_for([&]() {
    for (const auto& n : nodes) {
      auto info = n->validator_info_for_test(slash_val.public_key);
      if (!info.has_value()) return false;
      if (info->status != consensus::ValidatorStatus::PENDING &&
          info->status != consensus::ValidatorStatus::ACTIVE) return false;
    }
    return true;
  }, std::chrono::seconds(60)));

  for (const auto& n : nodes) {
    auto active = n->active_validators_for_next_height_for_test();
    ASSERT_TRUE(std::find(active.begin(), active.end(), slash_val.public_key) == active.end());
  }
}

void register_integration_tests() {}
