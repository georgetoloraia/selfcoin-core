#include "test_framework.hpp"

#include <exception>
#include <iostream>

std::vector<std::pair<std::string, TestFn>>& tests() {
  static std::vector<std::pair<std::string, TestFn>> t;
  return t;
}

Reg::Reg(const std::string& n, TestFn fn) { tests().push_back({n, std::move(fn)}); }

void register_codec_tests();
void register_crypto_tests();
void register_address_tests();
void register_consensus_tests();
void register_monetary_tests();
void register_bonding_tests();
void register_mempool_tests();
void register_hardening_tests();
void register_integration_tests();
void register_lightserver_tests();

int main() {
  register_codec_tests();
  register_crypto_tests();
  register_address_tests();
  register_consensus_tests();
  register_monetary_tests();
  register_bonding_tests();
  register_mempool_tests();
  register_hardening_tests();
  register_integration_tests();
  register_lightserver_tests();

  int failed = 0;
  for (const auto& [name, fn] : tests()) {
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
