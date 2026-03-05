#include "test_framework.hpp"

#include "consensus/activation.hpp"
#include "node/node.hpp"

using namespace selfcoin;

TEST(test_activation_signal_roundtrip) {
  const Bytes script = consensus::make_coinbase_script_sig(12, 3, 2);
  Tx coinbase;
  coinbase.inputs.push_back(TxIn{zero_hash(), 0xFFFFFFFF, script, 0xFFFFFFFF});
  const auto sv = consensus::parse_coinbase_signal_version(coinbase);
  ASSERT_TRUE(sv.has_value());
  ASSERT_EQ(*sv, 2u);
}

TEST(test_activation_window_threshold_sets_pending) {
  consensus::ActivationParams p;
  p.enabled = true;
  p.initial_version = 1;
  p.max_version = 2;
  p.window_blocks = 10;
  p.threshold_percent = 90;
  p.activation_delay_blocks = 5;

  consensus::ActivationState s;
  s.current_version = 1;

  for (std::uint64_t h = 1; h <= 10; ++h) {
    const std::optional<std::uint32_t> signal = (h == 10) ? std::nullopt : std::optional<std::uint32_t>(2);
    consensus::apply_signal(&s, p, h, signal);
  }
  ASSERT_EQ(s.pending_version, 2u);
  ASSERT_EQ(s.pending_activation_height, 15u);
}

TEST(test_activation_below_threshold_stays_signaling) {
  consensus::ActivationParams p;
  p.enabled = true;
  p.initial_version = 1;
  p.max_version = 2;
  p.window_blocks = 10;
  p.threshold_percent = 90;
  p.activation_delay_blocks = 5;

  consensus::ActivationState s;
  s.current_version = 1;

  // 8/10 signals < 90% threshold, so we must not lock-in.
  for (std::uint64_t h = 1; h <= 10; ++h) {
    const bool signaled = (h <= 8);
    const std::optional<std::uint32_t> signal = signaled ? std::optional<std::uint32_t>(2) : std::nullopt;
    consensus::apply_signal(&s, p, h, signal);
  }
  ASSERT_EQ(s.current_version, 1u);
  ASSERT_EQ(s.pending_version, 0u);
  ASSERT_EQ(s.pending_activation_height, 0u);
}

TEST(test_activation_applies_after_delay_height) {
  consensus::ActivationParams p;
  p.enabled = true;
  p.initial_version = 1;
  p.max_version = 2;
  p.window_blocks = 4;
  p.threshold_percent = 75;
  p.activation_delay_blocks = 2;

  consensus::ActivationState s;
  s.current_version = 1;
  consensus::apply_signal(&s, p, 1, 2);
  consensus::apply_signal(&s, p, 2, 2);
  consensus::apply_signal(&s, p, 3, std::nullopt);
  consensus::apply_signal(&s, p, 4, 2);
  ASSERT_EQ(s.pending_version, 2u);
  ASSERT_EQ(s.current_version, 1u);

  consensus::apply_signal(&s, p, 5, 2);
  ASSERT_EQ(s.current_version, 1u);
  consensus::apply_signal(&s, p, 6, 2);
  ASSERT_EQ(s.current_version, 2u);
  ASSERT_EQ(s.pending_version, 0u);
}

TEST(test_activation_replay_same_sequence_same_state) {
  consensus::ActivationParams p;
  p.enabled = true;
  p.initial_version = 1;
  p.max_version = 2;
  p.window_blocks = 8;
  p.threshold_percent = 75;
  p.activation_delay_blocks = 3;

  const std::vector<std::optional<std::uint32_t>> sequence = {
      2, 2, std::nullopt, 2, 2, std::nullopt, 2, 2, 2, std::nullopt, 2, 2,
  };

  auto run_once = [&](consensus::ActivationState* st) {
    st->current_version = 1;
    for (std::uint64_t h = 1; h <= sequence.size(); ++h) {
      consensus::apply_signal(st, p, h, sequence[static_cast<std::size_t>(h - 1)]);
    }
  };

  consensus::ActivationState a;
  consensus::ActivationState b;
  run_once(&a);
  run_once(&b);

  ASSERT_EQ(a.current_version, b.current_version);
  ASSERT_EQ(a.pending_version, b.pending_version);
  ASSERT_EQ(a.pending_activation_height, b.pending_activation_height);
  ASSERT_EQ(a.last_height, b.last_height);
  ASSERT_EQ(a.window_start_height, b.window_start_height);
  ASSERT_EQ(a.window_signal_count, b.window_signal_count);
  ASSERT_EQ(a.window_total_count, b.window_total_count);
}

TEST(test_activation_malformed_coinbase_signal_is_ignored) {
  consensus::ActivationParams p;
  p.enabled = true;
  p.initial_version = 1;
  p.max_version = 2;
  p.window_blocks = 4;
  p.threshold_percent = 75;
  p.activation_delay_blocks = 2;

  consensus::ActivationState s;
  s.current_version = 1;

  Tx bad_coinbase;
  bad_coinbase.inputs.push_back(TxIn{zero_hash(), 0xFFFFFFFF, Bytes{'c', 'b', ':', '1', ':', '0', ':', 'c', 'v', '=', 'x'}, 0xFFFFFFFF});
  const auto malformed = consensus::parse_coinbase_signal_version(bad_coinbase);
  ASSERT_TRUE(!malformed.has_value());

  // 3/4 valid + 1 malformed(ignored) => still exactly 75%, should lock-in deterministically.
  consensus::apply_signal(&s, p, 1, 2);
  consensus::apply_signal(&s, p, 2, 2);
  consensus::apply_signal(&s, p, 3, malformed);
  consensus::apply_signal(&s, p, 4, 2);
  ASSERT_EQ(s.pending_version, 2u);
  ASSERT_EQ(s.pending_activation_height, 6u);
}

TEST(test_node_parse_args_nextnet) {
  std::vector<std::string> args = {"selfcoin-node", "--nextnet", "--node-id", "3", "--disable-p2p"};
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& s : args) argv.push_back(s.data());
  auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());
  ASSERT_TRUE(cfg->nextnet);
  ASSERT_EQ(cfg->network.name, std::string("nextnet"));
  ASSERT_EQ(cfg->network.activation_enabled, true);
  ASSERT_EQ(cfg->network.initial_consensus_version, 1u);
}

void register_activation_tests() {}
