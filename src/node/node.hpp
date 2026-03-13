#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>

#include "consensus/validators.hpp"
#include "consensus/randomness.hpp"
#include "consensus/vrf_sortition.hpp"
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
  std::uint16_t p2p_port{19440};
  std::vector<std::string> peers;
  std::vector<std::string> seeds;
  std::string db_path{"./data/node"};
  std::string genesis_path;
  bool disable_p2p{false};
  bool log_json{false};
  std::size_t max_committee{MAX_COMMITTEE};
  std::uint32_t handshake_timeout_ms{10'000};
  std::uint32_t frame_timeout_ms{3'000};
  std::uint32_t idle_timeout_ms{600'000};
  std::size_t peer_queue_max_bytes{2 * 1024 * 1024};
  std::size_t peer_queue_max_msgs{2'000};
  std::uint64_t ban_seconds{600};
  int invalid_frame_ban_threshold{3};
  std::uint64_t invalid_frame_window_seconds{60};
  std::uint64_t min_relay_fee{0};
  bool hashcash_enabled{false};
  std::uint32_t hashcash_base_bits{18};
  std::uint32_t hashcash_max_bits{30};
  std::uint64_t hashcash_epoch_seconds{60};
  std::uint64_t hashcash_fee_exempt_min{1'000};
  std::size_t hashcash_pressure_tx_threshold{1'000};
  std::size_t hashcash_pressure_step_txs{500};
  std::uint32_t hashcash_pressure_bits_per_step{1};
  std::size_t hashcash_large_tx_bytes{2'048};
  std::uint32_t hashcash_large_tx_extra_bits{1};
  std::optional<std::uint64_t> validator_min_bond_override;
  std::optional<std::uint64_t> validator_bond_min_amount_override;
  std::optional<std::uint64_t> validator_bond_max_amount_override;
  std::optional<std::uint64_t> validator_warmup_blocks_override;
  std::optional<std::uint64_t> validator_cooldown_blocks_override;
  std::optional<std::uint64_t> validator_join_limit_window_blocks_override;
  std::optional<std::uint32_t> validator_join_limit_max_new_override;
  std::optional<std::uint64_t> liveness_window_blocks_override;
  std::optional<std::uint32_t> miss_rate_suspend_threshold_percent_override;
  std::optional<std::uint32_t> miss_rate_exit_threshold_percent_override;
  std::optional<std::uint64_t> suspend_duration_blocks_override;
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
  std::size_t established_peers{0};
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
  std::uint64_t participation_eligible_signers{0};
  bool bootstrap_template_mode{false};
  std::string bootstrap_validator_pubkey;
  std::size_t pending_bootstrap_joiners{0};
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
  bool inject_propose_for_test(const Block& block);
  bool observe_propose_for_test(const Block& block);
  bool inject_tx_for_test(const Tx& tx, bool relay);
  bool pause_proposals_for_test(bool pause);
  std::size_t mempool_size_for_test() const;
  bool mempool_contains_for_test(const Hash32& txid) const;
  std::optional<TxOut> find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                         OutPoint* outpoint = nullptr) const;
  std::vector<std::pair<OutPoint, TxOut>> find_utxos_by_pubkey_hash_for_test(
      const std::array<std::uint8_t, 20>& pkh) const;
  bool has_utxo_for_test(const OutPoint& op, TxOut* out = nullptr) const;
  std::string proposer_path_for_next_height_for_test() const;
  std::string committee_path_for_next_height_for_test() const;
  std::string vote_path_for_next_height_for_test() const;
  std::size_t quorum_threshold_for_next_height_for_test() const;
  std::vector<PubKey32> active_validators_for_next_height_for_test() const;
  std::vector<PubKey32> committee_for_next_height_for_test() const;
  std::vector<PubKey32> committee_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const;
  std::optional<consensus::ValidatorInfo> validator_info_for_test(const PubKey32& pub) const;
  std::uint16_t p2p_port_for_test() const;
  std::optional<Block> build_proposal_for_test(std::uint64_t height, std::uint32_t round);
  std::pair<std::uint64_t, std::uint32_t> v4_join_window_state_for_test() const;
  std::uint64_t v4_liveness_epoch_start_for_test() const;

  static std::vector<crypto::KeyPair> deterministic_test_keypairs();

 private:
  void event_loop();
  void handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload);

  void send_version(int peer_id);
  void maybe_send_verack(int peer_id);
  void send_ping(int peer_id);

  bool handle_propose(const p2p::ProposeMsg& msg, bool from_network);
  bool handle_vote(const Vote& vote, bool from_network, int from_peer_id = 0, const Bytes& vrf_proof = {},
                   const Hash32* vrf_output = nullptr);
  bool handle_tx(const Tx& tx, bool from_network, int from_peer_id = 0);
  bool finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round);

  std::optional<Block> build_proposal_block(std::uint64_t height, std::uint32_t round);
  void broadcast_propose(const Block& block, const Bytes& vrf_proof = {}, const Hash32* vrf_output = nullptr);
  void broadcast_vote(const Vote& vote, const Bytes& vrf_proof = {}, const Hash32* vrf_output = nullptr);
  void broadcast_finalized_block(const Block& block);
  void broadcast_tx(const Tx& tx, int skip_peer_id = 0);

  bool persist_finalized_block(const Block& block, const FinalityCertificate& certificate);
  bool init_local_validator_key();
  bool bootstrap_template_bind_validator(const PubKey32& pub, bool local_validator);
  bool maybe_adopt_bootstrap_validator_from_peer(int peer_id, const PubKey32& pub, std::uint64_t peer_height,
                                                 const char* source);
  void maybe_self_bootstrap_template(std::uint64_t now_ms);
  bool bootstrap_joiner_ready_locked(const PubKey32& pub) const;
  bool bootstrap_sync_incomplete_locked(int peer_id) const;
  std::optional<crypto::VrfProof> local_proposer_vrf_locked(std::uint64_t height, std::uint32_t round) const;
  bool verify_block_proposer_locked(const Block& block) const;
  bool check_and_record_proposer_equivocation_locked(const Block& block);
  Hash32 committee_epoch_randomness_for_height_locked(std::uint64_t height) const;
  std::optional<storage::CommitteeEpochSnapshot> committee_epoch_snapshot_for_height_locked(std::uint64_t height) const;
  storage::CommitteeEpochSnapshot build_committee_epoch_snapshot_locked(std::uint64_t epoch_start_height,
                                                                        const std::vector<PubKey32>& active,
                                                                        const Hash32& epoch_randomness) const;
  void persist_committee_epoch_snapshot_locked(std::uint64_t epoch_start_height, const std::vector<PubKey32>& active,
                                               const Hash32& epoch_randomness);
  std::optional<Hash32> pending_join_request_for_validator_locked(const PubKey32& pub) const;
  std::size_t pending_join_request_count_locked() const;
  bool init_mainnet_genesis();
  bool load_state();
  void apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height);
  bool is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const;
  std::vector<PubKey32> committee_for_height(std::uint64_t height) const;
  std::vector<PubKey32> committee_for_height_round(std::uint64_t height, std::uint32_t round) const;
  std::vector<PubKey32> reward_signers_for_height_round(std::uint64_t height, std::uint32_t round) const;
  std::optional<PubKey32> leader_for_height_round(std::uint64_t height, std::uint32_t round) const;
  void load_persisted_peers();
  void persist_peers() const;
  void load_addrman();
  void persist_addrman() const;
  bool seed_preflight_ok(const std::string& host, std::uint16_t port);
  void try_connect_bootstrap_peers();
  std::vector<std::string> resolve_dns_seeds_once() const;
  void maybe_request_getaddr(int peer_id);
  void request_finalized_tip(int peer_id);
  void send_finalized_tip(int peer_id);
  void broadcast_finalized_tip();
  void maybe_request_sync_parent_locked(int peer_id, const Block& blk);
  void maybe_apply_buffered_sync_blocks_locked();
  bool has_peer_endpoint(const std::string& host, std::uint16_t port) const;
  std::size_t peer_count() const;
  std::size_t established_peer_count() const;
  std::size_t outbound_peer_count() const;
  std::string peer_ip_for(int peer_id) const;
  bool is_bootstrap_peer_ip(const std::string& ip) const;
  std::optional<p2p::NetAddress> addrman_address_for_peer(const p2p::PeerInfo& info) const;
  void score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note);
  bool should_mute_peer(int peer_id) const;
  void prune_caches_locked(std::uint64_t height, std::uint32_t round);
  bool check_rate_limit_locked(int peer_id, std::uint16_t msg_type);
  std::string consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers = nullptr,
                                     std::size_t* quorum_threshold = nullptr) const;
  bool validate_v4_registration_rules(const Block& block, std::uint64_t height) const;
  void update_v4_liveness_from_finality(std::uint64_t height, std::uint32_t round,
                                        const std::vector<FinalitySig>& finality_sigs);
  bool v4_active_for_height(std::uint64_t height) const;

  std::uint64_t now_unix() const;
  std::uint64_t now_ms() const;
  void log_line(const std::string& s) const;
  void append_mining_log(const Block& block, std::uint32_t round, std::size_t votes, std::size_t quorum);
  void spawn_local_bus_task(std::function<void()> fn);
  void join_local_bus_tasks();

  NodeConfig cfg_;
  storage::DB db_;
  mutable std::mutex mu_;

  std::uint64_t finalized_height_{0};
  Hash32 finalized_hash_{};
  Hash32 finalized_randomness_{};
  std::map<std::uint64_t, Hash32> committee_epoch_randomness_cache_;
  mutable std::map<std::uint64_t, storage::CommitteeEpochSnapshot> committee_epoch_snapshots_;
  std::uint32_t current_round_{0};
  std::uint64_t round_started_ms_{0};

  consensus::ValidatorRegistry validators_;
  UtxoSet utxos_;
  mempool::Mempool mempool_;
  consensus::VoteTracker votes_;
  p2p::PeerDiscipline discipline_{30, 100, 600};
  p2p::VoteVerifyCache vote_verify_cache_{20'000};
  p2p::VoteVerifyCache invalid_vote_verify_cache_{20'000};
  p2p::RecentHashCache invalid_message_payloads_{16'384};
  p2p::RecentHashCache accepted_propose_payloads_{4'096};
  p2p::RecentHashCache accepted_block_payloads_{4'096};
  p2p::RecentHashCache accepted_tx_payloads_{16'384};
  std::map<int, std::map<std::uint16_t, p2p::TokenBucket>> msg_rate_buckets_;
  std::map<int, p2p::TokenBucket> vote_verify_buckets_;
  std::map<int, p2p::TokenBucket> tx_verify_buckets_;
  std::map<Hash32, std::size_t> candidate_block_sizes_;
  std::map<Hash32, Block> buffered_sync_blocks_;
  std::map<Hash32, ValidatorJoinRequest> validator_join_requests_;
  std::set<Hash32> requested_sync_blocks_;
  std::map<int, std::string> peer_ip_cache_;
  std::map<int, std::uint64_t> peer_keepalive_ms_;
  std::map<std::string, std::uint64_t> invalid_frame_log_ms_;
  std::map<std::string, std::uint64_t> addr_drop_log_ms_;
  std::uint64_t rejected_network_id_{0};
  std::uint64_t rejected_protocol_version_{0};
  std::uint64_t rejected_pre_handshake_{0};
  std::uint64_t v4_min_bond_{BOND_AMOUNT};
  std::uint64_t validator_bond_min_amount_{BOND_AMOUNT};
  std::uint64_t validator_bond_max_amount_{BOND_AMOUNT};
  std::uint64_t v4_warmup_blocks_{WARMUP_BLOCKS};
  std::uint64_t v4_cooldown_blocks_{0};
  std::uint64_t v4_join_limit_window_blocks_{0};
  std::uint32_t v4_join_limit_max_new_{0};
  std::uint64_t v4_join_window_start_height_{0};
  std::uint32_t v4_join_count_in_window_{0};
  std::uint64_t v4_liveness_window_blocks_{10'000};
  std::uint64_t v4_liveness_epoch_start_height_{0};
  std::uint32_t v4_miss_rate_suspend_threshold_percent_{30};
  std::uint32_t v4_miss_rate_exit_threshold_percent_{60};
  std::uint64_t v4_suspend_duration_blocks_{1'000};
  std::size_t last_participation_eligible_signers_{0};
  std::map<Hash32, Block> candidate_blocks_;
  std::map<std::tuple<std::uint64_t, std::uint32_t, PubKey32>, BlockHeader> observed_proposals_;
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
  std::string mining_log_path_;
  bool bootstrap_template_mode_{false};
  std::optional<PubKey32> bootstrap_validator_pubkey_;
  std::uint64_t startup_ms_{0};
  std::map<int, PubKey32> peer_validator_pubkeys_;
  std::map<int, p2p::FinalizedTipMsg> peer_finalized_tips_;
  bool restart_debug_{false};
};

std::optional<NodeConfig> parse_args(int argc, char** argv);

}  // namespace selfcoin::node
