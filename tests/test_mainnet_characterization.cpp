#include "test_framework.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>

#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "node/node.hpp"
#include "utxo/validate.hpp"

using namespace selfcoin;

namespace {

std::array<std::uint8_t, 32> deterministic_seed_for_node_id(int node_id) {
  std::array<std::uint8_t, 32> seed{};
  const int i = node_id + 1;
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + static_cast<int>(j));
  return seed;
}

Bytes valreg_script(const PubKey32& pub) {
  Bytes out{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  out.insert(out.end(), pub.begin(), pub.end());
  return out;
}

bool write_mainnet_genesis_file(const std::string& path, std::size_t n_validators) {
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
  d.note = "mainnet-characterization";
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  if (!out.good()) return false;
  out << genesis::to_json(d);
  return out.good();
}

std::unique_ptr<node::Node> make_node(const std::string& base, int node_id, std::size_t n_validators, std::size_t max_committee) {
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const std::string gpath = base + "/genesis.json";
  if (!write_mainnet_genesis_file(gpath, n_validators)) throw std::runtime_error("failed to write genesis");

  node::NodeConfig cfg;
  cfg.disable_p2p = true;
  cfg.node_id = node_id;
  cfg.max_committee = max_committee;
  cfg.db_path = base + "/node";
  cfg.genesis_path = gpath;
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "test-pass";

  keystore::ValidatorKey out_key;
  std::string kerr;
  if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc",
                                           deterministic_seed_for_node_id(node_id), &out_key, &kerr)) {
    throw std::runtime_error("failed to create validator keystore: " + kerr);
  }

  auto n = std::make_unique<node::Node>(cfg);
  if (!n->init()) throw std::runtime_error("node init failed");
  return n;
}

}  // namespace

TEST(test_characterize_mainnet_defaults_fixed_deterministic_runtime) {
  const auto& net = mainnet_network();
  ASSERT_EQ(net.validator_bond_min_amount, BOND_AMOUNT);
  ASSERT_EQ(net.validator_bond_max_amount, BOND_AMOUNT * 100);
}

TEST(test_characterize_mainnet_default_node_routes_legacy_consensus_paths) {
  auto n = make_node("/tmp/selfcoin_characterize_routes", 0, 4, 3);

  ASSERT_EQ(n->proposer_path_for_next_height_for_test(), std::string("deterministic-leader"));
  ASSERT_EQ(n->committee_path_for_next_height_for_test(), std::string("deterministic-committee"));
  ASSERT_EQ(n->vote_path_for_next_height_for_test(), std::string("committee-membership"));

  const auto active = n->active_validators_for_next_height_for_test();
  const auto status = n->status();
  const auto committee = n->committee_for_next_height_for_test();
  const auto expected = consensus::select_committee(status.tip_hash, status.height + 1, active, 3);
  ASSERT_EQ(committee, expected);
  ASSERT_EQ(n->quorum_threshold_for_next_height_for_test(), consensus::quorum_threshold(committee.size()));
}

TEST(test_characterize_mainnet_default_node_builds_deterministic_leader_proposal) {
  auto probe = make_node("/tmp/selfcoin_characterize_propose_probe", 0, 4, 4);
  const auto active = probe->active_validators_for_next_height_for_test();
  const auto status = probe->status();
  const auto expected_leader = consensus::select_leader(status.tip_hash, status.height + 1, 0, active);
  ASSERT_TRUE(expected_leader.has_value());

  const auto keys = node::Node::deterministic_test_keypairs();
  int leader_node_id = -1;
  for (std::size_t i = 0; i < 4; ++i) {
    if (keys[i].public_key == *expected_leader) {
      leader_node_id = static_cast<int>(i);
      break;
    }
  }
  ASSERT_TRUE(leader_node_id >= 0);

  auto n = make_node("/tmp/selfcoin_characterize_propose", leader_node_id, 4, 4);
  auto block = n->build_proposal_for_test(1, 0);
  ASSERT_TRUE(block.has_value());
  ASSERT_EQ(block->header.leader_pubkey, *expected_leader);
}

TEST(test_characterize_mainnet_runtime_is_deterministic_routing_with_current_validation_semantics) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  PubKey32 pub{};
  pub[0] = 42;
  tx.outputs.push_back(TxOut{BOND_AMOUNT - 1, valreg_script(pub)});

  SpecialValidationContext ctx;
  ctx.enforce_variable_bond_range = true;
  ctx.min_bond_amount = BOND_AMOUNT;
  ctx.max_bond_amount = BOND_AMOUNT * 100;
  const auto r = validate_tx(tx, 1, UtxoSet{}, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, std::string("SCVALREG output out of v7 bond range"));
}

void register_mainnet_characterization_tests() {}
