#include "test_framework.hpp"

#include <filesystem>

#include "p2p/addrman.hpp"
#include "p2p/messages.hpp"

using namespace selfcoin;

TEST(test_addrman_add_select_and_limit) {
  p2p::AddrMan am(3);
  am.add_or_update({"10.0.0.1", 1001}, 100);
  am.add_or_update({"10.0.0.2", 1002}, 101);
  am.add_or_update({"10.0.0.3", 1003}, 102);
  am.mark_success({"10.0.0.2", 1002}, 110);
  am.mark_success({"10.0.0.3", 1003}, 111);
  am.add_or_update({"10.0.0.4", 1004}, 50);  // triggers deterministic eviction

  ASSERT_TRUE(am.size() <= 3);
  auto picks = am.select_candidates(3, 200);
  ASSERT_TRUE(!picks.empty());
}

TEST(test_addrman_save_load_roundtrip) {
  p2p::AddrMan am(10);
  am.add_or_update({"127.0.0.1", 18444}, 100);
  am.mark_attempt({"127.0.0.1", 18444}, 110);
  am.mark_success({"127.0.0.1", 18444}, 120);

  const std::string path = "/tmp/selfcoin-addrman-test.dat";
  ASSERT_TRUE(am.save(path));

  p2p::AddrMan loaded(10);
  ASSERT_TRUE(loaded.load(path));
  ASSERT_TRUE(loaded.size() == 1);
  std::filesystem::remove(path);
}

TEST(test_addr_message_roundtrip_ipv4_ipv6) {
  p2p::AddrMsg m;
  p2p::AddrEntryMsg a4;
  a4.ip_version = 4;
  a4.ip = {};
  a4.ip[0] = 1;
  a4.ip[1] = 2;
  a4.ip[2] = 3;
  a4.ip[3] = 4;
  a4.port = 19440;
  a4.last_seen_unix = 123;
  m.entries.push_back(a4);

  p2p::AddrEntryMsg a6;
  a6.ip_version = 6;
  a6.ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  a6.port = 19441;
  a6.last_seen_unix = 124;
  m.entries.push_back(a6);

  const Bytes b = p2p::ser_addr(m);
  auto d = p2p::de_addr(b);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->entries.size(), 2);
  ASSERT_EQ(d->entries[0].ip_version, 4);
  ASSERT_EQ(d->entries[0].port, 19440);
  ASSERT_EQ(d->entries[1].ip_version, 6);
  ASSERT_EQ(d->entries[1].port, 19441);
}

void register_addrman_tests() {}
