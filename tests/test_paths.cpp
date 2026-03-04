#include "test_framework.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "common/paths.hpp"
#include "node/node.hpp"

using namespace selfcoin;

namespace {

std::vector<char*> make_argv(std::vector<std::string>& args) {
  std::vector<char*> out;
  out.reserve(args.size());
  for (auto& a : args) out.push_back(a.data());
  return out;
}

}  // namespace

TEST(test_paths_default_db_dir_and_expand_home) {
  ASSERT_EQ(default_db_dir_for_network("mainnet"), "~/.selfcoin/mainnet");
  ASSERT_EQ(default_db_dir_for_network("testnet"), "~/.selfcoin/testnet");
  ASSERT_EQ(default_db_dir_for_network("devnet"), "~/.selfcoin/devnet");

  const std::string fake_home = "/tmp/selfcoin_test_home_paths";
  ::setenv("HOME", fake_home.c_str(), 1);
  ASSERT_EQ(expand_user_home("~/.selfcoin/mainnet"), fake_home + "/.selfcoin/mainnet");
}

TEST(test_node_default_db_path_uses_home_by_network) {
  const std::string home = "/tmp/selfcoin_test_home_default_db";
  std::filesystem::remove_all(home);
  std::filesystem::create_directories(home);
  ::setenv("HOME", home.c_str(), 1);

  struct Case {
    std::string net_flag;
    std::string net_name;
  };
  const std::vector<Case> cases{{"--devnet", "devnet"}, {"--testnet", "testnet"}, {"--mainnet", "mainnet"}};

  for (const auto& c : cases) {
    std::vector<std::string> args = {"selfcoin-node", c.net_flag, "--node-id", "0", "--disable-p2p"};
    if (c.net_name == "mainnet") {
      args.push_back("--validator-passphrase");
      args.push_back("test-passphrase");
    }
    auto argv = make_argv(args);
    auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
    ASSERT_TRUE(cfg.has_value());

    node::Node n(*cfg);
    ASSERT_TRUE(n.init());
    const auto st = n.status();
    const std::string expected = home + "/.selfcoin/" + c.net_name;
    ASSERT_EQ(st.db_dir, expected);
    ASSERT_TRUE(std::filesystem::exists(expected));
    n.stop();
  }
}

void register_paths_tests() {}
