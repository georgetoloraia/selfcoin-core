#include "test_framework.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

std::vector<std::pair<std::string, TestFn>>& tests() {
  static std::vector<std::pair<std::string, TestFn>> t;
  return t;
}

Reg::Reg(const std::string& n, TestFn fn) { tests().push_back({n, std::move(fn)}); }

void register_codec_tests();
void register_chain_id_tests();
void register_crypto_tests();
void register_vrf_tests();
void register_address_tests();
void register_consensus_tests();
void register_sortition_v2_tests();
void register_sortition_v5_tests();
void register_sortition_v6_tests();
void register_bond_weight_v7_tests();
void register_p2p_tests();
void register_addrman_tests();
void register_monetary_tests();
void register_state_commitment_tests();
void register_smt_tests();
void register_activation_tests();
void register_bonding_tests();
void register_mempool_tests();
void register_hardening_tests();
void register_genesis_tests();
void register_paths_tests();
void register_keystore_tests();
void register_integration_tests();
void register_lightserver_tests();

int main() {
  register_codec_tests();
  register_chain_id_tests();
  register_crypto_tests();
  register_vrf_tests();
  register_address_tests();
  register_consensus_tests();
  register_sortition_v2_tests();
  register_sortition_v5_tests();
  register_sortition_v6_tests();
  register_bond_weight_v7_tests();
  register_p2p_tests();
  register_addrman_tests();
  register_monetary_tests();
  register_state_commitment_tests();
  register_smt_tests();
  register_activation_tests();
  register_bonding_tests();
  register_mempool_tests();
  register_hardening_tests();
  register_genesis_tests();
  register_paths_tests();
  register_keystore_tests();
  register_integration_tests();
  register_lightserver_tests();

  int failed = 0;
  const char* filter = std::getenv("SELFCOIN_TEST_FILTER");
  for (const auto& [name, fn] : tests()) {
    if (filter && std::string(name).find(filter) == std::string::npos) continue;
    try {
      fn();
      std::cout << "[ok] " << name << "\n";
    } catch (const std::exception& e) {
      ++failed;
      std::cout << "[fail] " << name << ": " << e.what() << "\n";
    }
  }
  if (failed) {
    std::cerr << failed << " tests failed\n";
    return 1;
  }
  std::cout << "all tests passed\n";
  return 0;
}
