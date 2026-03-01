#include "test_framework.hpp"

#include <chrono>
#include <filesystem>
#include <thread>

#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"
#include "node/node.hpp"

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

}  // namespace

TEST(test_devnet_4_nodes_finalize_and_faults) {
  const auto keys = node::Node::devnet_keypairs();
  ASSERT_EQ(keys.size(), 4u);

  const std::string base = "/tmp/selfcoin_it";
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);

  std::vector<std::unique_ptr<node::Node>> nodes;
  nodes.reserve(4);

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
    if (!n->init()) {
      throw std::runtime_error("init failed for node " + std::to_string(i));
    }
    nodes.push_back(std::move(n));
  }
  for (auto& n : nodes) n->start();

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

  // Equivocation injection: validator 0 sends two votes for same (h, r) with different block_id.
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

  for (auto& n : nodes) n->stop();
}

void register_integration_tests() {}
