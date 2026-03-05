#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>

#include "consensus/activation.hpp"
#include "consensus/validators.hpp"
#include "consensus/votes.hpp"
#include "crypto/ed25519.hpp"
#include "mempool/mempool.hpp"
#include "p2p/messages.hpp"
#include "p2p/addrman.hpp"
#include "p2p/peer_manager.hpp"
#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "p2p/hardening.hpp"
#include "storage/db.hpp"
#include "utxo/validate.hpp"

namespace selfcoin::node {

struct NodeConfig {
  NetworkConfig network{mainnet_network()};
  bool allow_unsafe_genesis_override{false};
  std::string validator_key_file;
  std::string validator_passphrase;
  int node_id{0};
  std::string bind_ip{"127.0.0.1"};
  bool listen{true};
  bool public_mode{false};
  bool dns_seeds{true};
  std::size_t outbound_target{8};
  std::size_t max_inbound{64};
  std::uint16_t p2p_port{18444};
  std::vector<std::string> peers;
  std::vector<std::string> seeds;
  std::string db_path{"./data/node"};
  std::string genesis_path;
  bool disable_p2p{false};
  bool log_json{false};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint32_t handshake_timeout_ms{10'000};
  std::uint32_t frame_timeout_ms{3'000};
  std::uint32_t idle_timeout_ms{120'000};
  std::size_t peer_queue_max_bytes{2 * 1024 * 1024};
  std::size_t peer_queue_max_msgs{2'000};
  std::uint64_t ban_seconds{600};
  int invalid_frame_ban_threshold{3};
  std::uint64_t invalid_frame_window_seconds{60};
  std::uint64_t min_relay_fee{0};
  std::optional<bool> activation_enabled_override;
  std::optional<std::uint32_t> activation_max_version_override;
  std::optional<std::uint64_t> activation_window_blocks_override;
  std::optional<std::uint32_t> activation_threshold_percent_override;
  std::optional<std::uint64_t> activation_delay_blocks_override;
  double tx_rate_capacity{200.0};
  double tx_rate_refill{100.0};
  double propose_rate_capacity{20.0};
  double propose_rate_refill{10.0};
  double vote_rate_capacity{120.0};
  double vote_rate_refill{60.0};
  double block_rate_capacity{40.0};
  double block_rate_refill{20.0};
  double vote_verify_capacity{60.0};
  double vote_verify_refill{30.0};
  double tx_verify_capacity{200.0};
  double tx_verify_refill{100.0};
};

struct NodeStatus {
  std::string network_name;
  std::uint32_t protocol_version{0};
  std::string network_id_short;
  std::uint32_t magic{0};
  std::string genesis_hash;
  std::string genesis_source;
  bool chain_id_ok{true};
  std::string db_dir;
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 tip_hash{};
  std::string tip_hash_short;
  PubKey32 leader{};
  std::size_t votes_for_current{0};
  std::size_t peers{0};
  std::size_t mempool_size{0};
  std::size_t committee_size{0};
  std::size_t quorum_threshold{0};
  std::size_t addrman_size{0};
  std::size_t inbound_connected{0};
  std::size_t outbound_connected{0};
  std::size_t observed_signers{0};
  std::string consensus_state;
  std::string last_bootstrap_source;
  std::uint64_t rejected_network_id{0};
  std::uint64_t rejected_protocol_version{0};
  std::uint64_t rejected_pre_handshake{0};
  std::uint32_t consensus_version{1};
  std::uint32_t pending_consensus_version{0};
  std::uint64_t pending_activation_height{0};
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
  std::vector<std::pair<OutPoint, TxOut>> find_utxos_by_pubkey_hash_for_test(
      const std::array<std::uint8_t, 20>& pkh) const;
  bool has_utxo_for_test(const OutPoint& op, TxOut* out = nullptr) const;
  std::vector<PubKey32> active_validators_for_next_height_for_test() const;
  std::vector<PubKey32> committee_for_next_height_for_test() const;
  std::optional<consensus::ValidatorInfo> validator_info_for_test(const PubKey32& pub) const;
  std::uint16_t p2p_port_for_test() const;

  static std::vector<crypto::KeyPair> deterministic_test_keypairs();

 private:
  void event_loop();
  void handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload);

  void send_version(int peer_id);
  void maybe_send_verack(int peer_id);

  bool handle_propose(const p2p::ProposeMsg& msg, bool from_network);
  bool handle_vote(const Vote& vote, bool from_network, int from_peer_id = 0);
  bool handle_tx(const Tx& tx, bool from_network, int from_peer_id = 0);
  bool finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round);

  std::optional<Block> build_proposal_block(std::uint64_t height, std::uint32_t round);
  void broadcast_propose(const Block& block);
  void broadcast_vote(const Vote& vote);
  void broadcast_finalized_block(const Block& block);
  void broadcast_tx(const Tx& tx, int skip_peer_id = 0);

  bool persist_finalized_block(const Block& block);
  bool init_mainnet_genesis();
  bool load_state();
  void apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height);
  bool is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const;
  std::vector<PubKey32> committee_for_height(std::uint64_t height) const;
  std::vector<PubKey32> committee_for_height_round(std::uint64_t height, std::uint32_t round) const;
  std::optional<PubKey32> leader_for_height_round(std::uint64_t height, std::uint32_t round) const;
  void load_persisted_peers();
  void persist_peers() const;
  void load_addrman();
  void persist_addrman() const;
  bool seed_preflight_ok(const std::string& host, std::uint16_t port);
  void try_connect_bootstrap_peers();
  std::vector<std::string> resolve_dns_seeds_once() const;
  void maybe_request_getaddr(int peer_id);
  std::size_t peer_count() const;
  std::string peer_ip_for(int peer_id) const;
  std::optional<p2p::NetAddress> addrman_address_for_peer(const p2p::PeerInfo& info) const;
  void score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note);
  bool should_mute_peer(int peer_id) const;
  void prune_caches_locked(std::uint64_t height, std::uint32_t round);
  bool check_rate_limit_locked(int peer_id, std::uint16_t msg_type);
  std::string consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers = nullptr,
                                     std::size_t* quorum_threshold = nullptr) const;
  void apply_activation_signal(const Block& block, std::uint64_t height);

  std::uint64_t now_unix() const;
  std::uint64_t now_ms() const;
  void log_line(const std::string& s) const;
  void spawn_local_bus_task(std::function<void()> fn);
  void join_local_bus_tasks();

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
  p2p::PeerDiscipline discipline_{30, 100, 600};
  p2p::VoteVerifyCache vote_verify_cache_{20'000};
  std::map<int, std::map<std::uint16_t, p2p::TokenBucket>> msg_rate_buckets_;
  std::map<int, p2p::TokenBucket> vote_verify_buckets_;
  std::map<int, p2p::TokenBucket> tx_verify_buckets_;
  std::map<Hash32, std::size_t> candidate_block_sizes_;
  std::map<int, std::string> peer_ip_cache_;
  std::map<std::string, std::uint64_t> invalid_frame_log_ms_;
  std::map<std::string, std::uint64_t> addr_drop_log_ms_;
  std::uint64_t rejected_network_id_{0};
  std::uint64_t rejected_protocol_version_{0};
  std::uint64_t rejected_pre_handshake_{0};
  consensus::ActivationState activation_state_{};
  consensus::ActivationParams activation_params_{};

  std::map<Hash32, Block> candidate_blocks_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, bool> proposed_in_round_;
  std::set<std::pair<std::uint64_t, std::uint32_t>> logged_committee_rounds_;

  crypto::KeyPair local_key_;
  bool is_validator_{false};

  std::atomic<bool> running_{false};
  std::thread loop_thread_;
  mutable std::mutex local_bus_tasks_mu_;
  std::vector<std::thread> local_bus_tasks_;
  p2p::PeerManager p2p_;

  std::atomic<bool> pause_proposals_{false};
  std::uint64_t last_seed_attempt_ms_{0};
  std::uint64_t last_addrman_save_ms_{0};
  std::uint64_t last_summary_log_ms_{0};
  std::uint64_t last_finalized_progress_ms_{0};
  std::vector<std::string> bootstrap_peers_;
  std::vector<std::string> dns_seed_peers_;
  std::set<std::string> preflight_checked_seeds_;
  p2p::AddrMan addrman_{10'000};
  ChainId chain_id_{};
  std::optional<Hash32> expected_genesis_hash_;
  std::string genesis_source_hint_{"embedded"};
  std::set<int> getaddr_requested_peers_;
  std::string last_bootstrap_source_{"none"};
  bool restart_debug_{false};
};

std::optional<NodeConfig> parse_args(int argc, char** argv);

}  // namespace selfcoin::node
