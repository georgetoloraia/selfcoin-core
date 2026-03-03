#include "test_framework.hpp"

#include "p2p/hardening.hpp"

using namespace selfcoin;

TEST(test_token_bucket_refill_and_consume) {
  p2p::TokenBucket b(10.0, 5.0);
  ASSERT_TRUE(b.consume(8.0, 1000));
  ASSERT_TRUE(!b.consume(3.0, 1000));
  ASSERT_TRUE(b.consume(2.0, 1400));  // +2 tokens after 400ms
  ASSERT_TRUE(!b.consume(5.0, 1400));
  ASSERT_TRUE(b.consume(4.0, 2000));  // enough refill by now
}

TEST(test_peer_discipline_soft_mute_and_ban) {
  p2p::PeerDiscipline d(30, 100, 60);
  const std::string ip = "203.0.113.5";
  auto s1 = d.add_score(ip, p2p::MisbehaviorReason::INVALID_PAYLOAD, 100);
  ASSERT_TRUE(!s1.soft_muted);
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 101);
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 102);
  auto s2 = d.status(ip, 103);
  ASSERT_TRUE(!s2.soft_muted);  // first two invalid frames are strikes only
  d.add_score(ip, p2p::MisbehaviorReason::INVALID_FRAME, 103);  // threshold reached, accumulated score applied
  auto s3 = d.status(ip, 104);
  ASSERT_TRUE(s3.soft_muted);
  ASSERT_TRUE(s3.banned);
  ASSERT_TRUE(d.is_banned(ip, 120));
  ASSERT_TRUE(!d.is_banned(ip, 1000));
}

void register_hardening_tests() {}
