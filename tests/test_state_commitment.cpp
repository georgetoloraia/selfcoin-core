#include "test_framework.hpp"

#include "consensus/state_commitment.hpp"

using namespace selfcoin;

namespace {

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

}  // namespace

TEST(test_scr3_marker_parses_single_marker) {
  const Hash32 u = filled(0x11);
  const Hash32 v = filled(0x22);
  Bytes script{'c', 'b', ':', '1'};
  script = consensus::append_v3_roots_to_coinbase_script(script, u, v);

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kNone);
  ASSERT_TRUE(parsed->utxo_root == u);
  ASSERT_TRUE(parsed->validators_root == v);
}

TEST(test_scr3_marker_multiple_markers_fails) {
  const Hash32 u = filled(0x33);
  const Hash32 v = filled(0x44);
  Bytes script = consensus::append_v3_roots_to_coinbase_script(Bytes{'x'}, u, v);
  const auto second = consensus::append_v3_roots_to_coinbase_script({}, u, v);
  script.insert(script.end(), second.begin(), second.end());

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kMultipleMarkers);
}

TEST(test_scr3_marker_wrong_length_fails) {
  Bytes script{'c', 'b'};
  script.insert(script.end(), consensus::kSCR3Prefix.begin(), consensus::kSCR3Prefix.end());
  script.push_back(0x01);  // truncated marker payload

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kWrongLength);
}

TEST(test_scr3_marker_missing_and_legacy_ascii_is_not_marker) {
  const Bytes script{'c', 'b', ':', '0', ':', 'r', '3', '=', 'x', 'x'};
  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kMissing);
}

void register_state_commitment_tests() {}
