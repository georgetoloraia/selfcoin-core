#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "consensus/validators.hpp"
#include "consensus/votes.hpp"
#include "crypto/ed25519.hpp"
#include "mempool/mempool.hpp"
#include "p2p/messages.hpp"
#include "p2p/peer_manager.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"

namespace selfcoin::node {

struct NodeConfig {
  bool devnet{true};
  int node_id{0};
  std::string bind_ip{"127.0.0.1"};
  std::uint16_t p2p_port{18444};
  std::vector<std::string> peers;
  std::string db_path{"./data/node"};
  bool disable_p2p{false};
};

struct NodeStatus {
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 tip_hash{};
  PubKey32 leader{};
  std::size_t votes_for_current{0};
};

class Node {
 public:
  explicit Node(NodeConfig cfg);
  ~Node();

  bool init();
  void start();
  void stop();

  NodeStatus status() const;

  // Test hooks.
  bool inject_vote_for_test(const Vote& vote);
  bool inject_tx_for_test(const Tx& tx, bool relay);
  bool pause_proposals_for_test(bool pause);
  std::size_t mempool_size_for_test() const;
  bool mempool_contains_for_test(const Hash32& txid) const;
  std::optional<TxOut> find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                         OutPoint* outpoint = nullptr) const;
  bool has_utxo_for_test(const OutPoint& op, TxOut* out = nullptr) const;
  std::vector<PubKey32> active_validators_for_next_height_for_test() const;

  static std::vector<crypto::KeyPair> devnet_keypairs();

 private:
  void event_loop();
  void handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload);

  void send_version(int peer_id);
  void maybe_send_verack(int peer_id);

  bool handle_propose(const p2p::ProposeMsg& msg, bool from_network);
  bool handle_vote(const Vote& vote, bool from_network);
  bool handle_tx(const Tx& tx, bool from_network, int from_peer_id = 0);
  bool finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round);

  std::optional<Block> build_proposal_block(std::uint64_t height, std::uint32_t round);
  void broadcast_propose(const Block& block);
  void broadcast_vote(const Vote& vote);
  void broadcast_finalized_block(const Block& block);
  void broadcast_tx(const Tx& tx, int skip_peer_id = 0);

  bool persist_finalized_block(const Block& block);
  bool load_state();
  void apply_validator_registrations(const Block& block, std::uint64_t height);

  std::uint64_t now_unix() const;
  void log_line(const std::string& s) const;

  NodeConfig cfg_;
  storage::DB db_;
  mutable std::mutex mu_;

  std::uint64_t finalized_height_{0};
  Hash32 finalized_hash_{};
  std::uint32_t current_round_{0};
  std::uint64_t round_started_ms_{0};

  consensus::ValidatorRegistry validators_;
  UtxoSet utxos_;
  mempool::Mempool mempool_;
  consensus::VoteTracker votes_;
  std::map<int, std::pair<std::uint64_t, std::uint32_t>> tx_rate_state_;

  std::map<Hash32, Block> candidate_blocks_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, bool> proposed_in_round_;

  crypto::KeyPair local_key_;
  bool is_validator_{false};

  std::atomic<bool> running_{false};
  std::thread loop_thread_;
  p2p::PeerManager p2p_;

  bool pause_proposals_{false};
};

std::optional<NodeConfig> parse_args(int argc, char** argv);

}  // namespace selfcoin::node
