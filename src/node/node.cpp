#include "node/node.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <netdb.h>
#include <poll.h>
#include <cstdlib>
#include <set>
#include <sstream>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "consensus/validators.hpp"
#include "consensus/monetary.hpp"
#include "consensus/vrf_sortition.hpp"
#include "common/paths.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "genesis/embedded_mainnet.hpp"
#include "genesis/genesis.hpp"
#include "keystore/validator_keystore.hpp"
#include "merkle/merkle.hpp"
#include "utxo/signing.hpp"

namespace selfcoin::node {
namespace {
constexpr std::uint32_t kFixedValidationRulesVersion = 7;

constexpr std::size_t kMaxBlockTxs = 1000;
constexpr std::size_t kMaxBlockBytes = 1 * 1024 * 1024;
constexpr std::size_t kMaxCandidateBlocks = 512;
constexpr std::size_t kMaxCandidateBlockBytes = 32 * 1024 * 1024;
constexpr std::uint32_t kProposalRoundWindow = 32;

std::string short_pub_hex(const PubKey32& pub) {
  Bytes b(pub.begin(), pub.begin() + 4);
  return hex_encode(b);
}

std::string short_hash_hex(const Hash32& h) {
  Bytes b(h.begin(), h.begin() + 4);
  return hex_encode(b);
}

const char* msg_type_name(std::uint16_t msg_type) {
  switch (msg_type) {
    case p2p::MsgType::VERSION:
      return "VERSION";
    case p2p::MsgType::VERACK:
      return "VERACK";
    case p2p::MsgType::GET_FINALIZED_TIP:
      return "GET_FINALIZED_TIP";
    case p2p::MsgType::FINALIZED_TIP:
      return "FINALIZED_TIP";
    case p2p::MsgType::PROPOSE:
      return "PROPOSE";
    case p2p::MsgType::VOTE:
      return "VOTE";
    case p2p::MsgType::GET_BLOCK:
      return "GET_BLOCK";
    case p2p::MsgType::BLOCK:
      return "BLOCK";
    case p2p::MsgType::TX:
      return "TX";
    case p2p::MsgType::GETADDR:
      return "GETADDR";
    case p2p::MsgType::ADDR:
      return "ADDR";
    case p2p::MsgType::PING:
      return "PING";
    case p2p::MsgType::PONG:
      return "PONG";
    default:
      return "UNKNOWN";
  }
}

bool restart_debug_enabled() {
  const char* v = std::getenv("SELFCOIN_RESTART_DEBUG");
  if (!v) return false;
  return std::string(v) == "1" || std::string(v) == "true" || std::string(v) == "yes";
}

bool is_loopback_seed_host(const std::string& host) {
  if (host == "localhost") return true;
  if (host == "::1") return true;
  return host == "127.0.0.1" || host.rfind("127.", 0) == 0;
}

std::string endpoint_to_ip(std::string endpoint) {
  const auto pos = endpoint.find(':');
  if (pos == std::string::npos) return endpoint;
  return endpoint.substr(0, pos);
}

std::string token_value(const std::string& s, const std::string& key) {
  const std::string needle = key + "=";
  const auto pos = s.find(needle);
  if (pos == std::string::npos) return "";
  auto end = s.find(' ', pos + needle.size());
  if (end == std::string::npos) end = s.size();
  return s.substr(pos + needle.size(), end - (pos + needle.size()));
}

std::string ascii_lower(std::string s) {
  for (auto& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return s;
}

std::string network_id_hex(const NetworkConfig& cfg) {
  return hex_encode(Bytes(cfg.network_id.begin(), cfg.network_id.end()));
}

std::string local_software_version_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv) {
  std::ostringstream oss;
  oss << "selfcoin-node/0.7"
      << ";genesis=" << chain_id.genesis_hash_hex << ";network_id=" << network_id_hex(cfg) << ";cv=" << cv;
  return oss.str();
}

std::optional<std::string> software_fingerprint_value(const std::string& ua, const std::string& key) {
  const std::string needle = key + "=";
  std::size_t start = 0;
  while (start <= ua.size()) {
    std::size_t end = ua.find(';', start);
    if (end == std::string::npos) end = ua.size();
    const std::string part = ua.substr(start, end - start);
    if (part.rfind(needle, 0) == 0) return part.substr(needle.size());
    if (end == ua.size()) break;
    start = end + 1;
  }
  return std::nullopt;
}

std::mutex g_local_bus_mu;
std::vector<Node*> g_local_bus_nodes;

constexpr const char* kSmtTreeUtxo = "utxo";
constexpr const char* kSmtTreeValidators = "validators";

bool v4_active_for_height(std::uint64_t height) {
  (void)height;
  return false;
}

struct StateRoots {
  Hash32 utxo_root{};
  Hash32 validators_root{};
};

FinalityCertificate make_finality_certificate(std::uint64_t height, std::uint32_t round, const Hash32& block_id,
                                              std::size_t quorum_threshold, const std::vector<PubKey32>& committee,
                                              const std::vector<FinalitySig>& signatures) {
  FinalityCertificate cert;
  cert.height = height;
  cert.round = round;
  cert.block_id = block_id;
  cert.quorum_threshold = static_cast<std::uint32_t>(quorum_threshold);
  cert.committee_members = committee;
  cert.signatures = signatures;
  return cert;
}

StateRoots compute_roots_for_state(const UtxoSet& utxos, const consensus::ValidatorRegistry& validators,
                                   std::uint32_t validation_rules_version) {
  std::vector<std::pair<Hash32, Bytes>> utxo_leaves;
  utxo_leaves.reserve(utxos.size());
  for (const auto& [op, ue] : utxos) {
    utxo_leaves.push_back({consensus::utxo_commitment_key(op), consensus::utxo_commitment_value(ue.out)});
  }

  std::vector<std::pair<Hash32, Bytes>> validator_leaves;
  validator_leaves.reserve(validators.all().size());
  for (const auto& [pub, info] : validators.all()) {
    validator_leaves.push_back(
        {consensus::validator_commitment_key(pub), consensus::validator_commitment_value(info, validation_rules_version)});
  }

  StateRoots roots;
  roots.utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  roots.validators_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);
  return roots;
}

std::string smt_leaf_prefix(const std::string& tree_id) { return "SMTL:" + tree_id + ":"; }
std::string smt_leaf_key(const std::string& tree_id, const Hash32& key) {
  return smt_leaf_prefix(tree_id) + hex_encode(Bytes(key.begin(), key.end()));
}
std::string root_index_key(const std::string& kind, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "ROOT:" + kind + ":" + hex_encode(w.data());
}

constexpr const char* kV4JoinWindowStartKey = "PV4:JOIN_WINDOW_START";
constexpr const char* kV4JoinWindowCountKey = "PV4:JOIN_WINDOW_COUNT";
constexpr const char* kV4LivenessEpochStartKey = "PV4:LIVENESS_EPOCH_START";
constexpr const char* kFinalizedRandomnessKey = "PRAND:FINALIZED";

Bytes make_coinbase_script_sig(std::uint64_t height, std::uint32_t round) {
  std::ostringstream oss;
  oss << "cb:" << height << ":" << round;
  const auto s = oss.str();
  return Bytes(s.begin(), s.end());
}

Bytes block_proposal_signing_message(const BlockHeader& header) {
  const Hash32 bid = header.block_id();
  return Bytes(bid.begin(), bid.end());
}

Hash32 message_payload_id(const Bytes& payload) { return crypto::sha256(payload); }

Hash32 vote_equivocation_record_id(const EquivocationEvidence& ev) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'L', 'V', 'O', 'T', 'E'});
  w.u64le(ev.a.height);
  w.u32le(ev.a.round);
  w.bytes_fixed(ev.a.validator_pubkey);
  w.bytes_fixed(ev.a.block_id);
  w.bytes_fixed(ev.a.signature);
  w.bytes_fixed(ev.b.block_id);
  w.bytes_fixed(ev.b.signature);
  return crypto::sha256d(w.data());
}

Hash32 proposer_equivocation_record_id(const BlockHeader& a, const BlockHeader& b) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'L', 'P', 'R', 'O', 'P'});
  w.u64le(a.height);
  w.u32le(a.round);
  w.bytes_fixed(a.leader_pubkey);
  w.bytes_fixed(a.block_id());
  w.bytes_fixed(b.block_id());
  return crypto::sha256d(w.data());
}

storage::SlashingRecord make_vote_equivocation_record(const EquivocationEvidence& ev, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  rec.record_id = vote_equivocation_record_id(ev);
  rec.kind = storage::SlashingRecordKind::VOTE_EQUIVOCATION;
  rec.validator_pubkey = ev.a.validator_pubkey;
  rec.height = ev.a.height;
  rec.round = ev.a.round;
  rec.observed_height = observed_height;
  rec.object_a = ev.a.block_id;
  rec.object_b = ev.b.block_id;
  return rec;
}

storage::SlashingRecord make_proposer_equivocation_record(const BlockHeader& a, const BlockHeader& b,
                                                          std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  rec.record_id = proposer_equivocation_record_id(a, b);
  rec.kind = storage::SlashingRecordKind::PROPOSER_EQUIVOCATION;
  rec.validator_pubkey = a.leader_pubkey;
  rec.height = a.height;
  rec.round = a.round;
  rec.observed_height = observed_height;
  rec.object_a = a.block_id();
  rec.object_b = b.block_id();
  return rec;
}

storage::SlashingRecord make_onchain_slash_record(const SlashEvidence& ev, const Hash32& txid, std::uint64_t observed_height) {
  storage::SlashingRecord rec;
  const Hash32 evidence_hash = crypto::sha256d(ev.raw_blob);
  rec.record_id = evidence_hash;
  rec.kind = storage::SlashingRecordKind::ONCHAIN_SLASH;
  rec.validator_pubkey = ev.a.validator_pubkey;
  rec.height = ev.a.height;
  rec.round = ev.a.round;
  rec.observed_height = observed_height;
  rec.object_a = ev.a.block_id;
  rec.object_b = ev.b.block_id;
  rec.txid = txid;
  return rec;
}

void sync_smt_tree(storage::DB& db, const std::string& tree_id, const std::vector<std::pair<Hash32, Bytes>>& leaves) {
  const std::string prefix = smt_leaf_prefix(tree_id);
  std::set<std::string> desired;
  desired.clear();
  for (const auto& [k, _] : leaves) desired.insert(smt_leaf_key(tree_id, k));
  for (const auto& [k, _] : db.scan_prefix(prefix)) {
    if (desired.find(k) == desired.end()) (void)db.put(k, {});
  }
  for (const auto& [k, v] : leaves) (void)db.put(smt_leaf_key(tree_id, k), v);
}

StateRoots persist_state_roots(storage::DB& db, std::uint64_t height, const UtxoSet& utxos,
                               const consensus::ValidatorRegistry& validators, std::uint32_t validation_rules_version) {
  std::vector<std::pair<Hash32, Bytes>> utxo_leaves;
  utxo_leaves.reserve(utxos.size());
  for (const auto& [op, ue] : utxos) {
    utxo_leaves.push_back({consensus::utxo_commitment_key(op), consensus::utxo_commitment_value(ue.out)});
  }
  std::vector<std::pair<Hash32, Bytes>> validator_leaves;
  validator_leaves.reserve(validators.all().size());
  for (const auto& [pub, info] : validators.all()) {
    validator_leaves.push_back(
        {consensus::validator_commitment_key(pub), consensus::validator_commitment_value(info, validation_rules_version)});
  }

  sync_smt_tree(db, kSmtTreeUtxo, utxo_leaves);
  sync_smt_tree(db, kSmtTreeValidators, validator_leaves);

  StateRoots roots{};
  roots.utxo_root = crypto::SparseMerkleTree::compute_root_from_leaves(utxo_leaves);
  roots.validators_root = crypto::SparseMerkleTree::compute_root_from_leaves(validator_leaves);
  crypto::SparseMerkleTree utxo_tree(db, kSmtTreeUtxo);
  crypto::SparseMerkleTree validators_tree(db, kSmtTreeValidators);
  (void)utxo_tree.set_root_for_height(height, roots.utxo_root);
  (void)validators_tree.set_root_for_height(height, roots.validators_root);
  (void)db.put(root_index_key("UTXO", height), Bytes(roots.utxo_root.begin(), roots.utxo_root.end()));
  (void)db.put(root_index_key("VAL", height), Bytes(roots.validators_root.begin(), roots.validators_root.end()));
  return roots;
}

}  // namespace

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {
  finalized_hash_ = zero_hash();
  finalized_randomness_ = zero_hash();
  restart_debug_ = restart_debug_enabled();
}

Node::~Node() { stop(); }

std::vector<crypto::KeyPair> Node::deterministic_test_keypairs() {
  std::vector<crypto::KeyPair> out;
  for (int i = 1; i <= 16; ++i) {
    std::array<std::uint8_t, 32> seed{};
    for (size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + j);
    auto kp = crypto::keypair_from_seed32(seed);
    if (kp.has_value()) out.push_back(*kp);
  }
  return out;
}

bool Node::init() {
  // systemd/journald captures stdout via a pipe, which is block-buffered by
  // default. Force line flushing so quiet followers still emit live handshake
  // and sync diagnostics instead of holding them until process exit.
  std::cout.setf(std::ios::unitbuf);
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  genesis_source_hint_ = cfg_.genesis_path.empty() ? "embedded" : "file";
  cfg_.db_path = expand_user_home(cfg_.db_path);
  const std::filesystem::path dbp(cfg_.db_path);
  const auto parent = dbp.parent_path();
  if (!parent.empty()) (void)ensure_private_dir(parent.string());
  (void)ensure_private_dir(cfg_.db_path);
  mining_log_path_ = (dbp / "MiningLOG").string();
  startup_ms_ = now_unix() * 1000;
  std::cout << "[node " << cfg_.node_id << "] db-dir=" << cfg_.db_path << "\n";
  std::cout << "[node " << cfg_.node_id << "] mining-log=" << mining_log_path_ << "\n";
  if (cfg_.public_mode) {
    std::cout << "[node " << cfg_.node_id
              << "] warning: public mode enabled (listening for inbound peers on " << cfg_.bind_ip << ":"
              << cfg_.p2p_port << ")\n";
  }
  discipline_ = p2p::PeerDiscipline(30, 100, cfg_.ban_seconds, cfg_.invalid_frame_ban_threshold,
                                    cfg_.invalid_frame_window_seconds);
  v4_min_bond_ = cfg_.network.validator_min_bond;
  validator_bond_min_amount_ = cfg_.network.validator_bond_min_amount;
  validator_bond_max_amount_ = cfg_.network.validator_bond_max_amount;
  v4_warmup_blocks_ = cfg_.network.validator_warmup_blocks;
  v4_cooldown_blocks_ = cfg_.network.validator_cooldown_blocks;
  v4_join_limit_window_blocks_ = cfg_.network.validator_join_limit_window_blocks;
  v4_join_limit_max_new_ = cfg_.network.validator_join_limit_max_new;
  v4_liveness_window_blocks_ = cfg_.network.liveness_window_blocks;
  v4_miss_rate_suspend_threshold_percent_ = cfg_.network.miss_rate_suspend_threshold_percent;
  v4_miss_rate_exit_threshold_percent_ = cfg_.network.miss_rate_exit_threshold_percent;
  v4_suspend_duration_blocks_ = cfg_.network.suspend_duration_blocks;
  if (cfg_.validator_min_bond_override.has_value()) v4_min_bond_ = *cfg_.validator_min_bond_override;
  if (cfg_.validator_bond_min_amount_override.has_value())
    validator_bond_min_amount_ = *cfg_.validator_bond_min_amount_override;
  if (cfg_.validator_bond_max_amount_override.has_value())
    validator_bond_max_amount_ = *cfg_.validator_bond_max_amount_override;
  if (validator_bond_max_amount_ < validator_bond_min_amount_) validator_bond_max_amount_ = validator_bond_min_amount_;
  if (cfg_.validator_warmup_blocks_override.has_value()) v4_warmup_blocks_ = *cfg_.validator_warmup_blocks_override;
  if (cfg_.validator_cooldown_blocks_override.has_value()) v4_cooldown_blocks_ = *cfg_.validator_cooldown_blocks_override;
  if (cfg_.validator_join_limit_window_blocks_override.has_value())
    v4_join_limit_window_blocks_ = *cfg_.validator_join_limit_window_blocks_override;
  if (cfg_.validator_join_limit_max_new_override.has_value()) v4_join_limit_max_new_ = *cfg_.validator_join_limit_max_new_override;
  if (cfg_.liveness_window_blocks_override.has_value()) v4_liveness_window_blocks_ = *cfg_.liveness_window_blocks_override;
  if (cfg_.miss_rate_suspend_threshold_percent_override.has_value())
    v4_miss_rate_suspend_threshold_percent_ = *cfg_.miss_rate_suspend_threshold_percent_override;
  if (cfg_.miss_rate_exit_threshold_percent_override.has_value())
    v4_miss_rate_exit_threshold_percent_ = *cfg_.miss_rate_exit_threshold_percent_override;
  if (cfg_.suspend_duration_blocks_override.has_value()) v4_suspend_duration_blocks_ = *cfg_.suspend_duration_blocks_override;
  mempool_.set_network(cfg_.network);
  mempool_.set_hashcash_config(policy::HashcashConfig{
      .enabled = cfg_.hashcash_enabled,
      .base_bits = cfg_.hashcash_base_bits,
      .max_bits = cfg_.hashcash_max_bits,
      .epoch_seconds = cfg_.hashcash_epoch_seconds,
      .fee_exempt_min = cfg_.hashcash_fee_exempt_min,
      .pressure_tx_threshold = cfg_.hashcash_pressure_tx_threshold,
      .pressure_step_txs = cfg_.hashcash_pressure_step_txs,
      .pressure_bits_per_step = cfg_.hashcash_pressure_bits_per_step,
      .large_tx_bytes = cfg_.hashcash_large_tx_bytes,
      .large_tx_extra_bits = cfg_.hashcash_large_tx_extra_bits,
  });

  validators_.set_rules(consensus::ValidatorRules{
      .min_bond = v4_min_bond_,
      .warmup_blocks = v4_warmup_blocks_,
      .cooldown_blocks = v4_cooldown_blocks_,
  });
  if (!init_local_validator_key()) return false;
  p2p::AddrPolicy addr_policy;
  addr_policy.required_port = cfg_.network.p2p_default_port;
  addr_policy.reject_unroutable = true;
  addrman_.set_policy(addr_policy);
  if (!db_.open(cfg_.db_path)) {
    std::cerr << "db open failed: " << cfg_.db_path << "\n";
    return false;
  }
  if (!init_mainnet_genesis()) {
    std::cerr << "mainnet genesis init failed\n";
    return false;
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  if (!load_state()) {
    std::cerr << "load_state failed\n";
    return false;
  }
  {
    std::ostringstream oss;
    oss << "chain-id network=" << chain_id_.network_name << " proto=" << chain_id_.protocol_version
        << " network_id=" << chain_id_.network_id_hex << " magic=" << chain_id_.magic
        << " genesis_hash=" << chain_id_.genesis_hash_hex << " genesis_source=" << chain_id_.genesis_source
        << " chain_id_ok=" << (chain_id_.chain_id_ok ? 1 : 0) << " db_dir=" << cfg_.db_path;
    log_line(oss.str());
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    // Ensure no stale in-memory state survives re-init.
    current_round_ = 0;
    round_started_ms_ = now_unix() * 1000;
    candidate_blocks_.clear();
    candidate_block_sizes_.clear();
    proposed_in_round_.clear();
    logged_committee_rounds_.clear();
    votes_.clear_height(finalized_height_ + 1);
  }
  if (restart_debug_) {
    log_line("restart-debug startup-state height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " tip=" + hex_encode32(finalized_hash_));
  }

  is_validator_ = validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1);

  round_started_ms_ = now_unix() * 1000;
  last_finalized_progress_ms_ = now_unix() * 1000;
  last_finalized_tip_poll_ms_ = 0;

  load_persisted_peers();
  load_addrman();
  for (const auto& p : cfg_.peers) bootstrap_peers_.push_back(p);
  for (const auto& s : cfg_.seeds) bootstrap_peers_.push_back(s);
  const bool allow_default_seed_fallback = !bootstrap_template_mode_;
  if (cfg_.seeds.empty() && allow_default_seed_fallback) {
    for (const auto& s : cfg_.network.default_seeds) bootstrap_peers_.push_back(s);
  }
  if (cfg_.dns_seeds) {
    dns_seed_peers_ = resolve_dns_seeds_once();
    for (const auto& d : dns_seed_peers_) bootstrap_peers_.push_back(d);
  }

  if (!cfg_.disable_p2p) {
    p2p_.configure_network(cfg_.network.magic, cfg_.network.protocol_version, cfg_.network.max_payload_len);
    p2p_.configure_limits(
        p2p::PeerManager::Limits{cfg_.handshake_timeout_ms, cfg_.frame_timeout_ms, cfg_.idle_timeout_ms,
                                 cfg_.peer_queue_max_bytes, cfg_.peer_queue_max_msgs, cfg_.max_inbound});
    p2p_.set_on_message([this](int peer_id, std::uint16_t msg_type, const Bytes& payload) {
      handle_message(peer_id, msg_type, payload);
    });
    p2p_.set_read_timeout_override([this](int peer_id, const p2p::PeerInfo& info) -> std::optional<std::uint32_t> {
      if (!info.established()) return std::nullopt;
      std::lock_guard<std::mutex> lk(mu_);
      bool sync_incomplete = bootstrap_sync_incomplete_locked(peer_id);
      bool local_sync_backlog = !buffered_sync_blocks_.empty() || !requested_sync_blocks_.empty();
      bool peer_tip_diverged = false;
      if (auto it = peer_finalized_tips_.find(peer_id); it != peer_finalized_tips_.end()) {
        peer_tip_diverged = it->second.height != finalized_height_ || it->second.hash != finalized_hash_;
      }
      if (!sync_incomplete && !local_sync_backlog && !peer_tip_diverged) return std::nullopt;
      return std::max<std::uint32_t>(cfg_.idle_timeout_ms, 600'000u);
    });
    p2p_.set_on_event([this](int peer_id, p2p::PeerManager::PeerEventType type, const std::string& detail) {
      if (type == p2p::PeerManager::PeerEventType::CONNECTED) {
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_ip_cache_[peer_id] = endpoint_to_ip(detail);
          peer_keepalive_ms_[peer_id] = now_ms();
        }
        const auto info = p2p_.get_peer_info(peer_id);
        log_line("peer-connected peer_id=" + std::to_string(peer_id) + " dir=" + (info.inbound ? "inbound" : "outbound") +
                 " endpoint=" + detail);
        if (discipline_.is_banned(endpoint_to_ip(detail), now_unix())) {
          p2p_.disconnect_peer(peer_id);
          return;
        }
        if (!info.version_tx) send_version(peer_id);
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::DISCONNECTED) {
        const auto info = p2p_.get_peer_info(peer_id);
        log_line("peer-disconnected peer_id=" + std::to_string(peer_id) + " dir=" + (info.inbound ? "inbound" : "outbound") +
                 " detail=" + detail);
        std::lock_guard<std::mutex> lk(mu_);
        peer_ip_cache_.erase(peer_id);
        peer_keepalive_ms_.erase(peer_id);
        peer_validator_pubkeys_.erase(peer_id);
        peer_finalized_tips_.erase(peer_id);
        getaddr_requested_peers_.erase(peer_id);
        msg_rate_buckets_.erase(peer_id);
        vote_verify_buckets_.erase(peer_id);
        tx_verify_buckets_.erase(peer_id);
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::FRAME_INVALID) {
        const auto pi = p2p_.get_peer_info(peer_id);
        const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
        const std::uint64_t tms = now_ms();
        bool should_log = false;
        {
          std::lock_guard<std::mutex> lk(mu_);
          auto& last = invalid_frame_log_ms_[ip];
          if (tms > last + 10'000) {
            should_log = true;
            last = tms;
          }
        }
        const std::string klass = token_value(detail, "class");
        if (should_log) {
          std::ostringstream oss;
          oss << "frame-parse-fail peer_id=" << peer_id << " dir=" << (pi.inbound ? "inbound" : "outbound")
              << " endpoint=" << pi.endpoint << " " << detail;
          log_line(oss.str());
          if (klass == "HTTP" || klass == "JSON") {
            log_line("peer sent HTTP/JSON bytes; likely dialing lightserver port (19444) instead of P2P");
          } else if (klass == "TLS") {
            log_line("peer sent TLS handshake bytes; do not place TLS/proxy in front of P2P port");
          } else if (token_value(detail, "reason") == "MAGIC_MISMATCH") {
            log_line("magic mismatch: peer is likely on a different network");
          }
        }
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "invalid-frame");
      } else if (type == p2p::PeerManager::PeerEventType::FRAME_TIMEOUT ||
                 type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT) {
        const auto pi = p2p_.get_peer_info(peer_id);
        const std::string ip = pi.ip.empty() ? endpoint_to_ip(pi.endpoint) : pi.ip;
        log_line("peer-timeout peer_id=" + std::to_string(peer_id) + " dir=" + (pi.inbound ? "inbound" : "outbound") +
                 " endpoint=" + pi.endpoint + " detail=" + detail + " stage=" +
                 (type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT ? "handshake" : "frame"));
        if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value() && is_bootstrap_peer_ip(ip)) {
          log_line("bootstrap-timeout peer_id=" + std::to_string(peer_id) + " ip=" + ip + " note=timeout");
          return;
        }
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "timeout");
      } else if (type == p2p::PeerManager::PeerEventType::QUEUE_OVERFLOW) {
        score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "queue-overflow");
      }
    });
    if (cfg_.listen) {
      if (!p2p_.start_listener(cfg_.bind_ip, cfg_.p2p_port)) {
        std::cerr << "listener start failed " << cfg_.bind_ip << ":" << cfg_.p2p_port << "\n";
        return false;
      }
      cfg_.p2p_port = p2p_.listener_port();
    }
    try_connect_bootstrap_peers();
  }

  return true;
}

bool Node::init_local_validator_key() {
  const std::string key_path = expand_user_home(cfg_.validator_key_file.empty()
                                                    ? keystore::default_validator_keystore_path(cfg_.db_path)
                                                    : cfg_.validator_key_file);
  keystore::ValidatorKey vk;
  std::string kerr;
  if (keystore::keystore_exists(key_path)) {
    if (!keystore::load_validator_keystore(key_path, cfg_.validator_passphrase, &vk, &kerr)) {
      std::cerr << "failed to load validator keystore: " << kerr << "\n";
      return false;
    }
  } else {
    if (!keystore::create_validator_keystore(key_path, cfg_.validator_passphrase, cfg_.network.name,
                                             keystore::hrp_for_network(cfg_.network.name), std::nullopt, &vk, &kerr)) {
      std::cerr << "failed to create validator keystore: " << kerr << "\n";
      return false;
    }
    log_line("created validator keystore path=" + key_path);
  }
  local_key_.private_key.assign(vk.privkey.begin(), vk.privkey.end());
  local_key_.public_key = vk.pubkey;
  log_line("validator pubkey=" + hex_encode(Bytes(vk.pubkey.begin(), vk.pubkey.end())) + " address=" + vk.address);
  return true;
}

bool Node::bootstrap_template_bind_validator(const PubKey32& pub, bool local_validator) {
  consensus::ValidatorInfo vi;
  vi.status = consensus::ValidatorStatus::ACTIVE;
  vi.joined_height = 0;
  vi.has_bond = true;
  vi.bonded_amount = BOND_AMOUNT;
  vi.bond_outpoint = OutPoint{zero_hash(), 0};
  vi.unbond_height = 0;

  validators_.upsert(pub, vi);
  if (!db_.put_validator(pub, vi)) return false;

  genesis::Document effective;
  effective.version = 1;
  effective.network_name = cfg_.network.name;
  effective.protocol_version = cfg_.network.protocol_version;
  effective.network_id = cfg_.network.network_id;
  effective.magic = cfg_.network.magic;
  effective.genesis_time_unix = 1735689600ULL;
  effective.initial_height = 0;
  effective.initial_validators = {pub};
  effective.initial_active_set_size = 1;
  effective.initial_committee_params.min_committee = 1;
  effective.initial_committee_params.max_committee = static_cast<std::uint32_t>(cfg_.network.max_committee);
  effective.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  effective.initial_committee_params.c = 1;
  effective.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  effective.note = local_validator ? "single-node bootstrap bound to local validator"
                                   : "bootstrap validator adopted from network";
  const auto json = genesis::to_json(effective);
  if (!db_.put("G:J", Bytes(json.begin(), json.end()))) return false;

  if (finalized_randomness_ == zero_hash()) {
    finalized_randomness_ = consensus::initial_finalized_randomness(cfg_.network, chain_id_);
  }
  committee_epoch_randomness_cache_[1] = finalized_randomness_;
  persist_committee_epoch_snapshot_locked(1, std::vector<PubKey32>{pub}, finalized_randomness_);

  const UtxoSet empty_utxos;
  (void)persist_state_roots(db_, 0, empty_utxos, validators_, kFixedValidationRulesVersion);
  (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  if (!db_.flush()) return false;

  bootstrap_validator_pubkey_ = pub;
  is_validator_ = local_validator;
  return true;
}

bool Node::maybe_adopt_bootstrap_validator_from_peer(int peer_id, const PubKey32& pub, std::uint64_t peer_height,
                                                     const char* source) {
  const auto info = p2p_.get_peer_info(peer_id);
  const std::string ip = info.ip.empty() ? endpoint_to_ip(info.endpoint) : info.ip;
  // Trust boundary: height-0 bootstrap adoption is only allowed from an explicitly
  // configured bootstrap peer that advertises bootstrap_validator in VERSION.
  const bool explicit_bootstrap_advertisement = std::string(source) == "version-bootstrap";
  if (!bootstrap_template_mode_) return false;
  if (bootstrap_validator_pubkey_.has_value()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-bound");
    return false;
  }
  if (finalized_height_ != 0) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=already-synced height=" + std::to_string(finalized_height_));
    return false;
  }
  if (!validators_.active_sorted(1).empty()) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=validators-present");
    return false;
  }
  if (!is_bootstrap_peer_ip(ip)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-not-bootstrap ip=" + ip);
    return false;
  }
  if (peer_height == 0 && !explicit_bootstrap_advertisement) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=peer-height-zero");
    return false;
  }
  if (!bootstrap_template_bind_validator(pub, pub == local_key_.public_key)) {
    log_line("bootstrap-adopt-skip peer_id=" + std::to_string(peer_id) + " source=" + source +
             " reason=bind-failed");
    return false;
  }
  log_line(std::string("adopted bootstrap validator from peer pubkey=") +
           hex_encode(Bytes(pub.begin(), pub.end())) + " source=" + source + " peer_id=" + std::to_string(peer_id) +
           " peer_height=" + std::to_string(peer_height));
  return true;
}

void Node::maybe_self_bootstrap_template(std::uint64_t now_ms) {
  if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) return;
  if (finalized_height_ != 0) return;
  if (!validators_.active_sorted(1).empty()) return;
  const bool has_bootstrap_sources = !cfg_.disable_p2p && (!bootstrap_peers_.empty() || !dns_seed_peers_.empty());
  if (has_bootstrap_sources) return;
  const std::uint64_t wait_ms = 5000ULL;
  if (now_ms < startup_ms_ + wait_ms) return;
  if (bootstrap_template_bind_validator(local_key_.public_key, true)) {
    log_line("bootstrap single-node genesis from local validator pubkey=" +
             hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end())));
    if (!cfg_.disable_p2p) {
      // Safe: duplicate VERSION handling is idempotent and is used here to refresh
      // already-connected peers with the newly-bound bootstrap validator identity.
      for (int peer_id : p2p_.peer_ids()) send_version(peer_id);
    }
  }
}

std::optional<Hash32> Node::pending_join_request_for_validator_locked(const PubKey32& pub) const {
  for (const auto& [request_txid, req] : validator_join_requests_) {
    if (req.validator_pubkey != pub) continue;
    if (req.status != ValidatorJoinRequestStatus::REQUESTED) continue;
    return request_txid;
  }
  return std::nullopt;
}

std::size_t Node::pending_join_request_count_locked() const {
  std::size_t count = 0;
  for (const auto& [_, req] : validator_join_requests_) {
    if (req.status == ValidatorJoinRequestStatus::REQUESTED) ++count;
  }
  return count;
}

bool Node::bootstrap_joiner_ready_locked(const PubKey32& pub) const {
  for (const auto& [peer_id, peer_pub] : peer_validator_pubkeys_) {
    if (peer_pub != pub) continue;
    const auto tip_it = peer_finalized_tips_.find(peer_id);
    if (tip_it == peer_finalized_tips_.end()) continue;
    if (tip_it->second.height != finalized_height_ || tip_it->second.hash != finalized_hash_) continue;
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    return true;
  }
  return false;
}

bool Node::bootstrap_sync_incomplete_locked(int peer_id) const {
  if (!bootstrap_template_mode_) return false;
  if (is_validator_) return false;
  if (finalized_height_ == 0) return true;
  const auto it = peer_finalized_tips_.find(peer_id);
  if (it == peer_finalized_tips_.end()) return false;
  return it->second.height > finalized_height_ || it->second.hash != finalized_hash_;
}

void Node::start() {
  if (running_.exchange(true)) return;
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.push_back(this);
  }
  loop_thread_ = std::thread([this]() { event_loop(); });
}

void Node::stop() {
  if (restart_debug_) {
    std::lock_guard<std::mutex> lk(mu_);
    log_line("restart-debug shutdown-begin height=" + std::to_string(finalized_height_) + " round=" +
             std::to_string(current_round_) + " tip=" + hex_encode32(finalized_hash_));
  }
  if (!running_.exchange(false)) {
    db_.close();
    return;
  }
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.erase(std::remove(g_local_bus_nodes.begin(), g_local_bus_nodes.end(), this), g_local_bus_nodes.end());
  }
  if (loop_thread_.joinable()) loop_thread_.join();
  if (restart_debug_) log_line("restart-debug event-loop-joined");
  if (restart_debug_) log_line("restart-debug round-timer-cancelled");
  join_local_bus_tasks();
  if (restart_debug_) log_line("restart-debug local-bus-tasks-joined");
  persist_peers();
  persist_addrman();
  if (restart_debug_) log_line("restart-debug peers-persisted");
  p2p_.stop();
  if (restart_debug_) log_line("restart-debug p2p-stopped");
  {
    std::lock_guard<std::mutex> lk(mu_);
    (void)db_.flush();
    if (restart_debug_) log_line("restart-debug db-flushed");
    db_.close();
    if (restart_debug_) log_line("restart-debug db-closed");
  }
}

NodeStatus Node::status() const {
  std::lock_guard<std::mutex> lk(mu_);
  NodeStatus s;
  s.network_name = cfg_.network.name;
  s.protocol_version = cfg_.network.protocol_version;
  s.magic = cfg_.network.magic;
  s.genesis_hash = chain_id_.genesis_hash_hex;
  s.genesis_source = chain_id_.genesis_source;
  s.chain_id_ok = chain_id_.chain_id_ok;
  s.db_dir = cfg_.db_path;
  s.network_id_short = hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4));
  s.height = finalized_height_;
  s.round = current_round_;
  s.tip_hash = finalized_hash_;
  s.tip_hash_short = short_hash_hex(finalized_hash_);
  auto leader = leader_for_height_round(finalized_height_ + 1, current_round_);
  if (leader.has_value()) s.leader = *leader;
  s.votes_for_current = 0;
  s.peers = peer_count();
  s.established_peers = established_peer_count();
  s.mempool_size = mempool_.size();
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  s.committee_size = committee.size();
  s.quorum_threshold = consensus::quorum_threshold(committee.size());
  s.addrman_size = addrman_.size();
  s.inbound_connected = cfg_.disable_p2p ? 0 : p2p_.inbound_count();
  s.outbound_connected = cfg_.disable_p2p ? peer_count() : p2p_.outbound_count();
  s.consensus_state = consensus_state_locked(now_unix() * 1000, &s.observed_signers, &s.quorum_threshold);
  s.last_bootstrap_source = last_bootstrap_source_;
  s.rejected_network_id = rejected_network_id_;
  s.rejected_protocol_version = rejected_protocol_version_;
  s.rejected_pre_handshake = rejected_pre_handshake_;
  s.consensus_version = kFixedValidationRulesVersion;
  s.participation_eligible_signers = static_cast<std::uint64_t>(last_participation_eligible_signers_);
  s.bootstrap_template_mode = bootstrap_template_mode_;
  if (bootstrap_validator_pubkey_.has_value()) {
    s.bootstrap_validator_pubkey =
        hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  s.pending_bootstrap_joiners = pending_join_request_count_locked();
  return s;
}

std::string Node::consensus_state_locked(std::uint64_t now_ms, std::size_t* observed_signers,
                                         std::size_t* quorum_threshold) const {
  const std::uint64_t h = finalized_height_ + 1;
  const auto committee = committee_for_height_round(h, current_round_);
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  if (quorum_threshold) *quorum_threshold = quorum;

  std::size_t observed = 0;
  if (!committee.empty()) {
    const auto participants = votes_.participants_for(h, current_round_);
    for (const auto& pub : committee) {
      if (participants.find(pub) != participants.end()) ++observed;
    }
    if (is_committee_member_for(local_key_.public_key, h, current_round_)) observed = std::max<std::size_t>(observed, 1);
  }
  if (observed_signers) *observed_signers = observed;

  const std::size_t peers = peer_count();
  if (peers == 0 || (finalized_height_ == 0 && observed == 0)) return "SYNCING";

  const std::uint64_t stale_ms = cfg_.network.round_timeout_ms * 2ULL;
  if (now_ms > last_finalized_progress_ms_ + stale_ms) {
    if (observed < quorum) return "WAITING_FOR_QUORUM";
    return "SYNCING";
  }
  return "FINALIZING";
}

bool Node::inject_vote_for_test(const Vote& vote) { return handle_vote(vote, false, 0, {}, nullptr); }
bool Node::inject_propose_for_test(const Block& block) {
  p2p::ProposeMsg p;
  p.height = block.header.height;
  p.round = block.header.round;
  p.prev_finalized_hash = block.header.prev_finalized_hash;
  p.block_bytes = block.serialize();
  return handle_propose(p, false);
}
bool Node::observe_propose_for_test(const Block& block) {
  std::lock_guard<std::mutex> lk(mu_);
  return check_and_record_proposer_equivocation_locked(block);
}
Hash32 Node::committee_epoch_randomness_for_height_locked(std::uint64_t height) const {
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.vrf_committee_epoch_blocks);
  auto it = committee_epoch_randomness_cache_.find(epoch_start);
  if (it != committee_epoch_randomness_cache_.end()) return it->second;
  return consensus::initial_finalized_randomness(cfg_.network, chain_id_);
}

std::optional<storage::CommitteeEpochSnapshot> Node::committee_epoch_snapshot_for_height_locked(
    std::uint64_t height) const {
  if (!cfg_.network.vrf_committee_enabled || height == 0) return std::nullopt;
  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.vrf_committee_epoch_blocks);
  auto it = committee_epoch_snapshots_.find(epoch_start);
  if (it != committee_epoch_snapshots_.end()) return it->second;
  return db_.get_committee_epoch_snapshot(epoch_start);
}

storage::CommitteeEpochSnapshot Node::build_committee_epoch_snapshot_locked(std::uint64_t epoch_start_height,
                                                                            const std::vector<PubKey32>& active,
                                                                            const Hash32& epoch_randomness) const {
  storage::CommitteeEpochSnapshot snapshot;
  snapshot.epoch_start_height = epoch_start_height;
  snapshot.epoch_seed = consensus::committee_epoch_seed(epoch_randomness, epoch_start_height);
  const auto take = std::min<std::size_t>(cfg_.max_committee, active.size());
  snapshot.ordered_members = consensus::select_committee_v2(active, snapshot.epoch_seed, take);
  return snapshot;
}

void Node::persist_committee_epoch_snapshot_locked(std::uint64_t epoch_start_height,
                                                   const std::vector<PubKey32>& active,
                                                   const Hash32& epoch_randomness) {
  auto snapshot = build_committee_epoch_snapshot_locked(epoch_start_height, active, epoch_randomness);
  committee_epoch_snapshots_[epoch_start_height] = snapshot;
  (void)db_.put_committee_epoch_snapshot(snapshot);
}
bool Node::inject_tx_for_test(const Tx& tx, bool relay) {
  if (relay) return handle_tx(tx, true);
  std::lock_guard<std::mutex> lk(mu_);
  mempool_.set_validation_context(
      SpecialValidationContext{
          .validators = &validators_,
          .current_height = finalized_height_ + 1,
          .enforce_variable_bond_range = true,
          .min_bond_amount = validator_bond_min_amount_,
          .max_bond_amount = validator_bond_max_amount_,
          .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
          .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
            return is_committee_member_for(pub, h, round);
          }});
  std::string err;
  return mempool_.accept_tx(tx, utxos_, &err);
}
bool Node::pause_proposals_for_test(bool pause) {
  pause_proposals_.store(pause);
  return true;
}
std::size_t Node::mempool_size_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return mempool_.size();
}
bool Node::mempool_contains_for_test(const Hash32& txid) const {
  std::lock_guard<std::mutex> lk(mu_);
  return mempool_.contains(txid);
}
std::optional<TxOut> Node::find_utxo_by_pubkey_hash_for_test(const std::array<std::uint8_t, 20>& pkh,
                                                              OutPoint* outpoint) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(e.out.script_pubkey, &got)) continue;
    if (got != pkh) continue;
    if (outpoint) *outpoint = op;
    return e.out;
  }
  return std::nullopt;
}
std::vector<std::pair<OutPoint, TxOut>> Node::find_utxos_by_pubkey_hash_for_test(
    const std::array<std::uint8_t, 20>& pkh) const {
  std::vector<std::pair<OutPoint, TxOut>> out;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [op, e] : utxos_) {
    std::array<std::uint8_t, 20> got{};
    if (!is_p2pkh_script_pubkey(e.out.script_pubkey, &got)) continue;
    if (got != pkh) continue;
    out.push_back({op, e.out});
  }
  return out;
}
bool Node::has_utxo_for_test(const OutPoint& op, TxOut* out) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = utxos_.find(op);
  if (it == utxos_.end()) return false;
  if (out) *out = it->second.out;
  return true;
}
std::string Node::proposer_path_for_next_height_for_test() const {
  return cfg_.network.vrf_proposer_enabled ? "vrf-threshold-proposer" : "deterministic-leader";
}
std::string Node::committee_path_for_next_height_for_test() const {
  return cfg_.network.vrf_committee_enabled ? "vrf-epoch-committee" : "deterministic-committee";
}
std::string Node::vote_path_for_next_height_for_test() const {
  return "committee-membership";
}
std::size_t Node::quorum_threshold_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  const auto committee = committee_for_height_round(finalized_height_ + 1, current_round_);
  return consensus::quorum_threshold(committee.size());
}
std::vector<PubKey32> Node::active_validators_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.active_sorted(finalized_height_ + 1);
}
std::vector<PubKey32> Node::committee_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(finalized_height_ + 1, current_round_);
}
std::vector<PubKey32> Node::committee_for_height_round_for_test(std::uint64_t height, std::uint32_t round) const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height_round(height, round);
}
std::optional<consensus::ValidatorInfo> Node::validator_info_for_test(const PubKey32& pub) const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.get(pub);
}
std::uint16_t Node::p2p_port_for_test() const { return cfg_.p2p_port; }

std::optional<Block> Node::build_proposal_for_test(std::uint64_t height, std::uint32_t round) {
  std::lock_guard<std::mutex> lk(mu_);
  auto block = build_proposal_block(height, round);
  if (!block.has_value()) return std::nullopt;
  if (!cfg_.network.vrf_proposer_enabled) return block;
  auto proof = local_proposer_vrf_locked(height, round);
  if (!proof.has_value()) return std::nullopt;
  block->header.vrf_proof = proof->proof;
  block->header.vrf_output = proof->output;
  return block;
}

std::pair<std::uint64_t, std::uint32_t> Node::v4_join_window_state_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return {v4_join_window_start_height_, v4_join_count_in_window_};
}

std::uint64_t Node::v4_liveness_epoch_start_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return v4_liveness_epoch_start_height_;
}

void Node::event_loop() {
  while (running_) {
    std::optional<Block> to_propose;
    std::vector<int> keepalive_peers;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::uint64_t h = finalized_height_ + 1;
      validators_.advance_height(h);
      const std::uint32_t cv = kFixedValidationRulesVersion;
      mempool_.set_validation_context(
          SpecialValidationContext{
              .validators = &validators_,
              .current_height = h,
              .enforce_variable_bond_range = true,
              .min_bond_amount = validator_bond_min_amount_,
              .max_bond_amount = validator_bond_max_amount_,
              .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
              .is_committee_member = [this](const PubKey32& pub, std::uint64_t ch, std::uint32_t round) {
                return is_committee_member_for(pub, ch, round);
              }});
      const auto committee = committee_for_height_round(h, current_round_);
      const std::size_t quorum = consensus::quorum_threshold(committee.size());

      const std::uint64_t now_ms = now_unix() * 1000;
      if (now_ms > round_started_ms_ + cfg_.network.round_timeout_ms) {
        ++current_round_;
        round_started_ms_ = now_ms;
        log_line("round-timeout height=" + std::to_string(h) + " new_round=" + std::to_string(current_round_));
        if (restart_debug_) {
          log_line("restart-debug round-timer-reset height=" + std::to_string(h) + " round=" +
                   std::to_string(current_round_));
        }
      }

      const auto hr = std::make_pair(h, current_round_);
      prune_caches_locked(h, current_round_);
      if (logged_committee_rounds_.insert(hr).second) {
        std::ostringstream coss;
        coss << "committee height=" << h << " round=" << current_round_ << " size=" << committee.size()
             << " quorum=" << quorum << " members=";
        for (std::size_t i = 0; i < committee.size(); ++i) {
          if (i) coss << ",";
          coss << short_pub_hex(committee[i]);
        }
        log_line(coss.str());
        if (cfg_.log_json) {
          std::ostringstream j;
          j << "{\"type\":\"status\",\"network\":\"" << cfg_.network.name << "\",\"height\":" << finalized_height_
            << ",\"hash\":\"" << hex_encode32(finalized_hash_) << "\",\"round\":" << current_round_
            << ",\"peers\":" << peer_count() << ",\"established_peers\":" << established_peer_count()
            << ",\"mempool_size\":" << mempool_.size()
            << ",\"committee_size\":" << committee.size() << ",\"addrman_size\":" << addrman_.size()
            << ",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"genesis_hash\":\"" << chain_id_.genesis_hash_hex << "\""
            << ",\"genesis_source\":\"" << chain_id_.genesis_source << "\""
            << ",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false")
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"last_bootstrap_source\":\"" << last_bootstrap_source_ << "\""
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j
            << ",\"rejected_network_id\":" << rejected_network_id_
            << ",\"rejected_protocol_version\":" << rejected_protocol_version_
            << ",\"rejected_pre_handshake\":" << rejected_pre_handshake_ << "}";
          std::cout << j.str() << "\n";
        }
      }

      if (now_ms > last_summary_log_ms_ + 30'000) {
        std::size_t observed = 0;
        std::size_t q = quorum;
        const auto state = consensus_state_locked(now_ms, &observed, &q);
        if (cfg_.log_json) {
          std::ostringstream j;
          j << "{\"type\":\"summary\",\"network\":\"" << cfg_.network.name << "\",\"protocol_version\":"
            << cfg_.network.protocol_version << ",\"network_id\":\""
            << hex_encode(Bytes(cfg_.network.network_id.begin(), cfg_.network.network_id.begin() + 4)) << "\",\"magic\":"
            << cfg_.network.magic << ",\"db_dir\":\"" << cfg_.db_path << "\",\"height\":" << finalized_height_
            << ",\"tip\":\"" << short_hash_hex(finalized_hash_) << "\",\"genesis_hash\":\""
            << chain_id_.genesis_hash_hex << "\",\"genesis_source\":\"" << chain_id_.genesis_source
            << "\",\"chain_id_ok\":" << (chain_id_.chain_id_ok ? "true" : "false") << ",\"peers\":" << peer_count()
            << ",\"established_peers\":" << established_peer_count()
            << ",\"outbound_connected\":" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count())
            << ",\"inbound_connected\":" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
            << ",\"outbound_target\":" << cfg_.outbound_target << ",\"addrman_size\":" << addrman_.size()
            << ",\"bootstrap_source_last\":\"" << last_bootstrap_source_ << "\",\"committee_size\":" << committee.size()
            << ",\"quorum_threshold\":" << q << ",\"observed_signers\":" << observed
            << ",\"consensus_state\":\"" << state << "\",\"consensus_version\":" << kFixedValidationRulesVersion
            << ",\"bootstrap_template_mode\":" << (bootstrap_template_mode_ ? "true" : "false")
            << ",\"pending_bootstrap_joiners\":" << pending_join_request_count_locked();
          if (bootstrap_validator_pubkey_.has_value()) {
            j << ",\"bootstrap_validator_pubkey\":\""
              << hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end())) << "\"";
          }
          j << "}";
          std::cout << j.str() << "\n";
        } else {
          std::cout << cfg_.network.name << " h=" << finalized_height_ << " tip=" << short_hash_hex(finalized_hash_)
                    << " gen=" << chain_id_.genesis_hash_hex.substr(0, 8) << " peers=" << peer_count()
                    << " outbound=" << (cfg_.disable_p2p ? peer_count() : p2p_.outbound_count()) << "/"
                    << cfg_.outbound_target << " inbound=" << (cfg_.disable_p2p ? 0 : p2p_.inbound_count())
                    << " established=" << established_peer_count() << " addrman=" << addrman_.size()
                    << " cv=" << kFixedValidationRulesVersion << " state=" << state;
          if (bootstrap_template_mode_) {
            std::cout << " bootstrap=template";
            if (bootstrap_validator_pubkey_.has_value()) {
              std::cout << " validator=" << short_pub_hex(*bootstrap_validator_pubkey_);
            }
            if (!last_bootstrap_source_.empty()) {
              std::cout << " source=" << last_bootstrap_source_;
            }
            const auto pending_joiners = pending_join_request_count_locked();
            if (pending_joiners != 0) {
              std::cout << " pending_joiners=" << pending_joiners;
            }
          }
          std::cout << "\n";
        }
        last_summary_log_ms_ = now_ms;
      }

      maybe_self_bootstrap_template(now_ms);

      const std::uint64_t keepalive_interval_ms =
          std::max<std::uint64_t>(200, static_cast<std::uint64_t>(cfg_.idle_timeout_ms) / 3);
      const std::uint64_t sync_poll_interval_ms =
          std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
      for (int peer_id : p2p_.peer_ids()) {
        const auto info = p2p_.get_peer_info(peer_id);
        if (!info.established()) continue;
        auto& last = peer_keepalive_ms_[peer_id];
        if (now_ms >= last + keepalive_interval_ms) {
          keepalive_peers.push_back(peer_id);
          last = now_ms;
        }
      }

      if (!cfg_.disable_p2p && established_peer_count() > 0 &&
          now_ms >= last_finalized_progress_ms_ + sync_poll_interval_ms &&
          now_ms >= last_finalized_tip_poll_ms_ + sync_poll_interval_ms) {
        for (int peer_id : p2p_.peer_ids()) {
          const auto info = p2p_.get_peer_info(peer_id);
          if (!info.established()) continue;
          keepalive_peers.push_back(peer_id);
        }
        last_finalized_tip_poll_ms_ = now_ms;
      }

      std::optional<crypto::VrfProof> local_vrf;
      bool can_propose = false;
      if (cfg_.network.vrf_proposer_enabled) {
        local_vrf = local_proposer_vrf_locked(h, current_round_);
        can_propose = local_vrf.has_value();
      } else {
        const auto leader = leader_for_height_round(h, current_round_);
        can_propose = leader.has_value() && *leader == local_key_.public_key;
      }

      const bool block_interval_elapsed =
          now_ms >= last_finalized_progress_ms_ + static_cast<std::uint64_t>(cfg_.network.min_block_interval_ms);
      if (!pause_proposals_.load() && can_propose && block_interval_elapsed) {
        auto key = std::make_pair(h, current_round_);
        if (proposed_in_round_.find(key) == proposed_in_round_.end()) {
          auto b = build_proposal_block(h, current_round_);
          if (b.has_value()) {
            if (cfg_.network.vrf_proposer_enabled && local_vrf.has_value()) {
              b->header.vrf_proof = local_vrf->proof;
              b->header.vrf_output = local_vrf->output;
              auto leader_sig = crypto::ed25519_sign(block_proposal_signing_message(b->header), local_key_.private_key);
              if (!leader_sig.has_value()) {
                b.reset();
              } else {
                b->header.leader_signature = *leader_sig;
              }
            }
            if (b.has_value()) {
              proposed_in_round_[key] = true;
              candidate_blocks_[b->header.block_id()] = *b;
              to_propose = *b;
            }
          }
        }
      }
    }

    if (to_propose.has_value()) {
      p2p::ProposeMsg local_msg{to_propose->header.height, to_propose->header.round,
                                to_propose->header.prev_finalized_hash, to_propose->serialize()};
      broadcast_propose(*to_propose);
      handle_propose(local_msg, false);
    }

    {
      std::sort(keepalive_peers.begin(), keepalive_peers.end());
      keepalive_peers.erase(std::unique(keepalive_peers.begin(), keepalive_peers.end()), keepalive_peers.end());
    }
    for (int peer_id : keepalive_peers) {
      send_ping(peer_id);
      const std::uint64_t now_ms = now_unix() * 1000;
      const std::uint64_t sync_poll_interval_ms =
          std::max<std::uint64_t>(3000, static_cast<std::uint64_t>(cfg_.network.round_timeout_ms));
      if (!cfg_.disable_p2p && now_ms >= last_finalized_progress_ms_ + sync_poll_interval_ms) {
        request_finalized_tip(peer_id);
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!cfg_.disable_p2p) {
      const std::uint64_t now_ms = now_unix() * 1000;
      if (outbound_peer_count() < cfg_.outbound_target && now_ms > last_seed_attempt_ms_ + 3000) {
        try_connect_bootstrap_peers();
        last_seed_attempt_ms_ = now_ms;
      }
      if (now_ms > last_addrman_save_ms_ + 10'000) {
        persist_addrman();
        last_addrman_save_ms_ = now_ms;
      }
    }
  }
}

void Node::send_version(int peer_id) {
  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.timestamp = now_unix();
  v.proto_version = static_cast<std::uint32_t>(cfg_.network.protocol_version);
  v.network_id = cfg_.network.network_id;
  v.feature_flags = cfg_.network.feature_flags;
  v.nonce = static_cast<std::uint32_t>(cfg_.node_id + 1000);
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();
  v.node_software_version = local_software_version_fingerprint(cfg_.network, chain_id_, kFixedValidationRulesVersion);
  if (bootstrap_validator_pubkey_.has_value()) {
    v.node_software_version +=
        ";bootstrap_validator=" + hex_encode(Bytes(bootstrap_validator_pubkey_->begin(), bootstrap_validator_pubkey_->end()));
  }
  v.node_software_version +=
      ";validator_pubkey=" + hex_encode(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));

  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v));
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERSION) + " peer_id=" + std::to_string(peer_id) +
           " start_height=" + std::to_string(v.start_height) + " start_hash=" + short_hash_hex(v.start_hash) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, true, false);
}

void Node::maybe_send_verack(int peer_id) {
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::VERACK, {});
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::VERACK) + " peer_id=" + std::to_string(peer_id) +
           " status=" + (ok ? "ok" : "failed"));
  if (ok) p2p_.mark_handshake_tx(peer_id, false, true);
}

void Node::send_ping(int peer_id) {
  const p2p::PingMsg ping{now_ms()};
  const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PING, p2p::ser_ping(ping), true);
  log_line(std::string("send ") + msg_type_name(p2p::MsgType::PING) + " peer_id=" + std::to_string(peer_id) +
           " nonce=" + std::to_string(ping.nonce) + " status=" + (ok ? "ok" : "failed"));
}

void Node::handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  if (!p2p::is_known_message_type(msg_type)) {
    score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "unknown-msg-type");
    return;
  }

  const Hash32 payload_id = message_payload_id(payload);
  bool known_invalid = false;
  bool rate_limited = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (invalid_message_payloads_.contains(payload_id)) {
      known_invalid = true;
    } else {
      rate_limited = !check_rate_limit_locked(peer_id, msg_type);
    }
  }
  if (known_invalid) {
    score_peer(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "known-invalid-payload");
    return;
  }
  if (rate_limited) {
    score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "msg-rate");
    return;
  }

  if (msg_type == p2p::MsgType::VERSION) {
    auto v = p2p::de_version(payload);
    if (!v.has_value()) {
      score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-version");
      return;
    }
    // Duplicate VERSION on an established connection is intentional in bootstrap-template
    // mode: after self-bootstrap, the node refreshes peer metadata with the bound
    // bootstrap validator identity. This handler keeps VERSION processing idempotent.
    log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
             " start_height=" + std::to_string(v->start_height) + " start_hash=" + short_hash_hex(v->start_hash));
    if (v->network_id != cfg_.network.network_id) {
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_network_id_;
      }
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-mismatch");
      score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "network-id-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (v->proto_version != static_cast<std::uint32_t>(cfg_.network.protocol_version)) {
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_protocol_version_;
      }
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=unsupported-protocol peer_proto=" +
               std::to_string(v->proto_version) + " local_proto=" + std::to_string(cfg_.network.protocol_version));
      p2p_.disconnect_peer(peer_id);
      return;
    }
    const std::string local_genesis = ascii_lower(chain_id_.genesis_hash_hex);
    const std::string local_nid = ascii_lower(network_id_hex(cfg_.network));
    const auto peer_genesis = software_fingerprint_value(v->node_software_version, "genesis");
    const auto peer_nid = software_fingerprint_value(v->node_software_version, "network_id");
    const auto peer_bootstrap = software_fingerprint_value(v->node_software_version, "bootstrap_validator");
    const auto peer_validator = software_fingerprint_value(v->node_software_version, "validator_pubkey");
    if (peer_genesis.has_value() && ascii_lower(*peer_genesis) != local_genesis) {
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=genesis-fingerprint-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (peer_nid.has_value() && ascii_lower(*peer_nid) != local_nid) {
      log_line("reject-version peer_id=" + std::to_string(peer_id) + " reason=network-id-fingerprint-mismatch");
      p2p_.disconnect_peer(peer_id);
      return;
    }
    if (peer_bootstrap.has_value()) {
      auto b = hex_decode(*peer_bootstrap);
      if (b && b->size() == 32) {
        PubKey32 pub{};
        std::copy(b->begin(), b->end(), pub.begin());
        (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-bootstrap");
      }
    }
    if (peer_validator.has_value()) {
      auto b = hex_decode(*peer_validator);
      if (b && b->size() == 32) {
        PubKey32 pub{};
        std::copy(b->begin(), b->end(), pub.begin());
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_validator_pubkeys_[peer_id] = pub;
        }
        if (!peer_bootstrap.has_value()) {
          (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, pub, v->start_height, "version-validator-fallback");
        }
      }
    }
    p2p_.set_peer_handshake_meta(peer_id, v->proto_version, v->network_id, v->feature_flags);
    p2p_.mark_handshake_rx(peer_id, true, false);

    auto info = p2p_.get_peer_info(peer_id);
    if (!info.version_tx) send_version(peer_id);

    {
      auto i = p2p_.get_peer_info(peer_id);
      (void)i;
    }

    maybe_send_verack(peer_id);
    return;
  }

  if (msg_type == p2p::MsgType::VERACK) {
    log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
    p2p_.mark_handshake_rx(peer_id, false, true);
    maybe_request_getaddr(peer_id);
    send_finalized_tip(peer_id);
    request_finalized_tip(peer_id);
    auto pi = p2p_.get_peer_info(peer_id);
    auto na = addrman_address_for_peer(pi);
    if (na.has_value()) {
      std::lock_guard<std::mutex> lk(mu_);
      addrman_.mark_success(*na, now_unix());
    }
    return;
  }

  const auto info = p2p_.get_peer_info(peer_id);
  if (!info.established()) {
    const bool bootstrap_sync_msg =
        msg_type == p2p::MsgType::GET_FINALIZED_TIP || msg_type == p2p::MsgType::FINALIZED_TIP ||
        msg_type == p2p::MsgType::GET_BLOCK || msg_type == p2p::MsgType::BLOCK;
    // After VERSION exchange and our VERACK transmit, the peer may already start
    // sync bootstrap traffic before we have observed its VERACK locally. Allow
    // these messages through instead of misclassifying them as pre-handshake
    // consensus traffic and dropping the first finalized-tip/block sync step.
    if (bootstrap_sync_msg && info.version_rx && info.version_tx && info.verack_tx) {
      // fall through
    } else {
      if (msg_type == p2p::MsgType::ADDR || msg_type == p2p::MsgType::GETADDR) {
        log_line("drop-addr peer_id=" + std::to_string(peer_id) + " reason=pre-handshake");
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        ++rejected_pre_handshake_;
      }
      score_peer(peer_id, p2p::MisbehaviorReason::PRE_HANDSHAKE_CONSENSUS, "pre-handshake-msg");
      return;
    }
  }

  switch (msg_type) {
    case p2p::MsgType::GET_FINALIZED_TIP: {
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id));
      send_finalized_tip(peer_id);
      break;
    }
    case p2p::MsgType::FINALIZED_TIP: {
      auto tip = p2p::de_finalized_tip(payload);
      if (!tip.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-finalized-tip");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(tip->height) + " hash=" + short_hash_hex(tip->hash));
      {
        std::lock_guard<std::mutex> lk(mu_);
        peer_finalized_tips_[peer_id] = *tip;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_validator_pubkeys_.find(peer_id);
        if (it != peer_validator_pubkeys_.end()) {
          (void)maybe_adopt_bootstrap_validator_from_peer(peer_id, it->second, tip->height, "finalized-tip-fallback");
        }
      }
      if (tip->height > finalized_height_) {
        log_line("request-sync-tip-block peer_id=" + std::to_string(peer_id) + " remote_height=" +
                 std::to_string(tip->height) + " remote_hash=" + short_hash_hex(tip->hash));
        auto req = p2p::GetBlockMsg{tip->hash};
        (void)p2p_.send_to(peer_id, p2p::MsgType::GET_BLOCK, p2p::ser_get_block(req));
      }
      break;
    }
    case p2p::MsgType::GET_BLOCK: {
      auto gb = p2p::de_get_block(payload);
      if (!gb.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-get-block");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " hash=" + short_hash_hex(gb->hash));
      auto blk = db_.get_block(gb->hash);
      if (!blk.has_value()) return;
      (void)p2p_.send_to(peer_id, p2p::MsgType::BLOCK, p2p::ser_block(p2p::BlockMsg{*blk}), true);
      break;
    }
    case p2p::MsgType::BLOCK: {
      auto b = p2p::de_block(payload);
      if (!b.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-msg");
        return;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_block_payloads_.contains(payload_id)) return;
      }
      auto blk = Block::parse(b->block_bytes);
      if (!blk.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-parse");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(blk->header.height) + " hash=" + short_hash_hex(blk->header.block_id()) +
               " prev=" + short_hash_hex(blk->header.prev_finalized_hash));
      std::lock_guard<std::mutex> lk(mu_);
      if (blk->header.height > finalized_height_ + 1 || blk->header.prev_finalized_hash != finalized_hash_) {
        buffered_sync_blocks_[blk->header.block_id()] = *blk;
        accepted_block_payloads_.insert(payload_id);
        log_line("buffer-sync-block peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(blk->header.height) +
                 " hash=" + short_hash_hex(blk->header.block_id()) + " local_height=" +
                 std::to_string(finalized_height_) + " local_tip=" + short_hash_hex(finalized_hash_));
        maybe_request_sync_parent_locked(peer_id, *blk);
        maybe_apply_buffered_sync_blocks_locked();
        return;
      }
      if (blk->header.height == finalized_height_ + 1 && blk->header.prev_finalized_hash == finalized_hash_) {
        if (!verify_block_proposer_locked(*blk)) return;
        if (candidate_blocks_.size() >= kMaxCandidateBlocks ||
            (candidate_block_sizes_.size() >= kMaxCandidateBlocks &&
             candidate_block_sizes_.find(blk->header.block_id()) == candidate_block_sizes_.end())) {
          return;
        }
        const auto bid = blk->header.block_id();
        if (candidate_blocks_.find(bid) == candidate_blocks_.end()) {
          const std::size_t sz = blk->serialize().size();
          std::size_t total = 0;
          for (const auto& [_, s] : candidate_block_sizes_) total += s;
          if (total + sz > kMaxCandidateBlockBytes) return;
          candidate_block_sizes_[bid] = sz;
        }
        std::set<PubKey32> committee_set;
        const auto committee = committee_for_height_round(blk->header.height, blk->header.round);
        if (committee.empty()) return;
        const std::size_t quorum = consensus::quorum_threshold(committee.size());
        committee_set.insert(committee.begin(), committee.end());
        std::set<PubKey32> seen;
        std::size_t valid_sigs = 0;
        std::vector<FinalitySig> filtered_sigs;
        filtered_sigs.reserve(blk->finality_proof.sigs.size());
        for (const auto& s : blk->finality_proof.sigs) {
          if (!committee_set.empty() && committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
          if (!seen.insert(s.validator_pubkey).second) continue;
          Bytes bid_bytes(bid.begin(), bid.end());
          if (!crypto::ed25519_verify(bid_bytes, s.signature, s.validator_pubkey)) continue;
          ++valid_sigs;
          filtered_sigs.push_back(s);
        }
        if (valid_sigs >= quorum) {
          if (!validate_v4_registration_rules(*blk, blk->header.height)) return;
          const FinalityCertificate certificate =
              make_finality_certificate(blk->header.height, blk->header.round, bid, quorum, committee, filtered_sigs);
          if (persist_finalized_block(*blk, certificate)) {
            accepted_block_payloads_.insert(payload_id);
            std::vector<Hash32> confirmed_txids;
            confirmed_txids.reserve(blk->txs.size());
            for (const auto& tx : blk->txs) confirmed_txids.push_back(tx.txid());
            mempool_.remove_confirmed(confirmed_txids);
            UtxoSet pre_utxos = utxos_;
            update_v4_liveness_from_finality(blk->header.height, blk->header.round, filtered_sigs);
            apply_validator_state_changes(*blk, pre_utxos, blk->header.height);
            apply_block_to_utxo(*blk, utxos_);
            mempool_.prune_against_utxo(utxos_);
            finalized_height_ = blk->header.height;
            finalized_hash_ = bid;
            finalized_randomness_ = consensus::advance_finalized_randomness(finalized_randomness_, blk->header);
            if (consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.vrf_committee_epoch_blocks) ==
                finalized_height_ + 1) {
              committee_epoch_randomness_cache_[finalized_height_ + 1] = finalized_randomness_;
              persist_committee_epoch_snapshot_locked(finalized_height_ + 1, validators_.active_sorted(finalized_height_ + 1),
                                                      finalized_randomness_);
            }
            (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
            (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
            last_finalized_progress_ms_ = now_unix() * 1000;
            current_round_ = 0;
            round_started_ms_ = now_unix() * 1000;
            if (restart_debug_) {
              log_line("restart-debug round-timer-reset height=" + std::to_string(finalized_height_) + " round=0");
            }
            votes_.clear_height(blk->header.height);
            candidate_blocks_.clear();
            candidate_block_sizes_.clear();
            requested_sync_blocks_.erase(bid);
            broadcast_finalized_tip();
            maybe_apply_buffered_sync_blocks_locked();
          }
        } else {
          candidate_blocks_[bid] = *blk;
          accepted_block_payloads_.insert(payload_id);
          finalize_if_quorum(bid, blk->header.height, blk->header.round);
        }
      }
      break;
    }
    case p2p::MsgType::PROPOSE: {
      auto p = p2p::de_propose(payload);
      if (!p.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-propose-msg");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(p->height) + " round=" + std::to_string(p->round));
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (bootstrap_sync_incomplete_locked(peer_id)) {
          log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=PROPOSE reason=bootstrap-sync-incomplete" +
                   " local_height=" + std::to_string(finalized_height_));
          return;
        }
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_propose_payloads_.contains(payload_id)) return;
      }
      if (!handle_propose(*p, true)) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PROPOSE, "invalid-propose");
      } else {
        std::lock_guard<std::mutex> lk(mu_);
        accepted_propose_payloads_.insert(payload_id);
      }
      break;
    }
    case p2p::MsgType::VOTE: {
      auto v = p2p::de_vote(payload);
      if (!v.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-vote-msg");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " height=" + std::to_string(v->vote.height) + " round=" + std::to_string(v->vote.round) +
               " block=" + short_hash_hex(v->vote.block_id));
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (bootstrap_sync_incomplete_locked(peer_id)) {
          log_line("defer-consensus peer_id=" + std::to_string(peer_id) + " type=VOTE reason=bootstrap-sync-incomplete" +
                   " local_height=" + std::to_string(finalized_height_));
          return;
        }
      }
      if (!handle_vote(v->vote, true, peer_id, v->vrf_proof, v->vrf_proof.empty() ? nullptr : &v->vrf_output)) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-vote");
      }
      break;
    }
    case p2p::MsgType::TX: {
      auto m = p2p::de_tx(payload);
      if (!m.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-msg");
        return;
      }
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (accepted_tx_payloads_.contains(payload_id)) return;
      }
      auto tx = Tx::parse(m->tx_bytes);
      if (!tx.has_value()) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-parse");
        return;
      }
      if (!handle_tx(*tx, true, peer_id)) {
        std::lock_guard<std::mutex> lk(mu_);
        invalid_message_payloads_.insert(payload_id);
        score_peer(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "tx-rejected");
      } else {
        std::lock_guard<std::mutex> lk(mu_);
        accepted_tx_payloads_.insert(payload_id);
      }
      break;
    }
    case p2p::MsgType::GETADDR: {
      auto req = p2p::de_getaddr(payload);
      if (!req.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-getaddr");
        return;
      }
      p2p::AddrMsg msg;
      {
        std::lock_guard<std::mutex> lk(mu_);
        const auto addrs = addrman_.select_candidates(256, now_unix());
        msg.entries.reserve(addrs.size());
        for (const auto& a : addrs) {
          p2p::AddrEntryMsg e;
          std::array<std::uint8_t, 16> bin{};
          if (inet_pton(AF_INET, a.ip.c_str(), bin.data()) == 1) {
            e.ip_version = 4;
          } else if (inet_pton(AF_INET6, a.ip.c_str(), bin.data()) == 1) {
            e.ip_version = 6;
          } else {
            continue;
          }
          e.ip = bin;
          e.port = a.port;
          e.last_seen_unix = now_unix();
          msg.entries.push_back(e);
        }
      }
      (void)p2p_.send_to(peer_id, p2p::MsgType::ADDR, p2p::ser_addr(msg), true);
      break;
    }
    case p2p::MsgType::ADDR: {
      auto msg = p2p::de_addr(payload);
      if (!msg.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-addr");
        return;
      }
      std::lock_guard<std::mutex> lk(mu_);
      for (const auto& e : msg->entries) {
        char ipbuf[INET6_ADDRSTRLEN]{};
        const char* s = nullptr;
        if (e.ip_version == 4) {
          s = inet_ntop(AF_INET, e.ip.data(), ipbuf, sizeof(ipbuf));
        } else if (e.ip_version == 6) {
          s = inet_ntop(AF_INET6, e.ip.data(), ipbuf, sizeof(ipbuf));
        }
        if (!s || e.port == 0) continue;
        const p2p::NetAddress na{std::string(ipbuf), e.port};
        const auto reject = addrman_.validate(na);
        if (reject != p2p::AddrRejectReason::NONE) {
          const std::string reason = (reject == p2p::AddrRejectReason::PORT_MISMATCH)   ? "port"
                                     : (reject == p2p::AddrRejectReason::UNROUTABLE_IP) ? "unroutable"
                                                                                         : "invalid";
          const std::string log_key = reason + ":" + na.ip;
          auto& last = addr_drop_log_ms_[log_key];
          const std::uint64_t now = now_ms();
          if (now > last + 10'000) {
            last = now;
            log_line("drop-addr peer_id=" + std::to_string(peer_id) + " ip=" + na.ip + ":" + std::to_string(na.port) +
                     " reason=" + reason);
          }
          continue;
        }
        addrman_.add_or_update(na, e.last_seen_unix);
      }
      break;
    }
    case p2p::MsgType::PING: {
      auto ping = p2p::de_ping(payload);
      if (!ping.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-ping");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(ping->nonce));
      const bool ok = p2p_.send_to(peer_id, p2p::MsgType::PONG, p2p::ser_ping(*ping), true);
      log_line(std::string("send ") + msg_type_name(p2p::MsgType::PONG) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(ping->nonce) + " status=" + (ok ? "ok" : "failed"));
      break;
    }
    case p2p::MsgType::PONG: {
      auto pong = p2p::de_ping(payload);
      if (!pong.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-pong");
        return;
      }
      log_line("recv " + std::string(msg_type_name(msg_type)) + " peer_id=" + std::to_string(peer_id) +
               " nonce=" + std::to_string(pong->nonce));
      break;
    }
    default:
      break;
  }
}

bool Node::handle_propose(const p2p::ProposeMsg& msg, bool from_network) {
  if (from_network && !running_) return false;
  std::optional<Vote> maybe_vote;
  Bytes maybe_vote_proof;
  Hash32 maybe_vote_output{};
  bool maybe_vote_has_output = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (from_network && !running_) return false;
    if (msg.height != finalized_height_ + 1) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=unexpected-height local_next=" + std::to_string(finalized_height_ + 1));
      return false;
    }
    if (msg.prev_finalized_hash != finalized_hash_) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=prev-hash-mismatch local_tip=" + short_hash_hex(finalized_hash_) +
               " remote_prev=" + short_hash_hex(msg.prev_finalized_hash));
      return false;
    }

    auto blk = Block::parse(msg.block_bytes);
    if (!blk.has_value()) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=block-parse-failed");
      return false;
    }
    if (blk->header.height != msg.height || blk->header.round != msg.round) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=header-mismatch block_height=" + std::to_string(blk->header.height) +
               " block_round=" + std::to_string(blk->header.round));
      return false;
    }
    if (!verify_block_proposer_locked(*blk)) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=invalid-proposer leader=" + short_pub_hex(blk->header.leader_pubkey));
      return false;
    }
    if (check_and_record_proposer_equivocation_locked(*blk)) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=proposer-equivocation");
      return false;
    }

    std::vector<Bytes> tx_bytes;
    tx_bytes.reserve(blk->txs.size());
    for (const auto& tx : blk->txs) tx_bytes.push_back(tx.serialize());
    auto merkle_root = merkle::compute_merkle_root_from_txs(tx_bytes);
    if (!merkle_root.has_value() || blk->header.merkle_root != *merkle_root) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=merkle-root-mismatch");
      return false;
    }

    SpecialValidationContext vctx{
        .validators = &validators_,
        .current_height = msg.height,
        .enforce_variable_bond_range = true,
        .min_bond_amount = validator_bond_min_amount_,
        .max_bond_amount = validator_bond_max_amount_,
        .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
        .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
          return is_committee_member_for(pub, h, round);
        }};
    const auto reward_signers = reward_signers_for_height_round(msg.height, msg.round);
    auto valid = validate_block_txs(*blk, utxos_, BLOCK_REWARD, &vctx, &reward_signers);
    if (!valid.ok) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=invalid-block-txs detail=" + valid.error);
      return false;
    }
    if (!validate_v4_registration_rules(*blk, msg.height)) {
      log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
               " reason=v4-registration-rules");
      return false;
    }

    Hash32 bid = blk->header.block_id();
    if (candidate_blocks_.find(bid) == candidate_blocks_.end()) {
      const std::size_t sz = msg.block_bytes.size();
      std::size_t total = 0;
      for (const auto& [_, s] : candidate_block_sizes_) total += s;
      if (candidate_blocks_.size() >= kMaxCandidateBlocks || total + sz > kMaxCandidateBlockBytes) {
        log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
                 " reason=candidate-cache-full");
        return false;
      }
      candidate_block_sizes_[bid] = sz;
    }
    candidate_blocks_[bid] = *blk;
    prune_caches_locked(msg.height, msg.round);
    // Votes can arrive before proposal in local-bus mode; try finalizing immediately
    // once candidate block is available.
    (void)finalize_if_quorum(bid, msg.height, msg.round);

    const auto voters = votes_.participants_for(msg.height, msg.round);
    if (is_committee_member_for(local_key_.public_key, msg.height, msg.round) &&
        voters.find(local_key_.public_key) == voters.end()) {
      Bytes b_id(bid.begin(), bid.end());
      auto sig = crypto::ed25519_sign(b_id, local_key_.private_key);
      if (!sig.has_value()) {
        log_line("propose-reject height=" + std::to_string(msg.height) + " round=" + std::to_string(msg.round) +
                 " reason=local-vote-sign-failed");
        return false;
      }
      maybe_vote = Vote{msg.height, msg.round, bid, local_key_.public_key, *sig};
    }
  }

  if (maybe_vote.has_value()) {
    broadcast_vote(*maybe_vote, maybe_vote_proof, maybe_vote_has_output ? &maybe_vote_output : nullptr);
    return handle_vote(*maybe_vote, false, 0, maybe_vote_proof, maybe_vote_has_output ? &maybe_vote_output : nullptr);
  }
  return true;
}

bool Node::handle_vote(const Vote& vote, bool from_network, int from_peer_id, const Bytes& vrf_proof,
                       const Hash32* vrf_output) {
  if (from_network && !running_) return false;
  bool relay_vote = false;
  bool finalize_ok = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (from_network && !running_) return false;
    if (vote.height != finalized_height_ + 1) return false;
    if (cfg_.network.vrf_committee_enabled) {
      auto snapshot = committee_epoch_snapshot_for_height_locked(vote.height);
      if (!snapshot.has_value()) return false;
      const auto committee_size =
          consensus::committee_size_for_round_v2(snapshot->ordered_members.size(), cfg_.max_committee, vote.round);
      const auto end = std::min<std::size_t>(committee_size, snapshot->ordered_members.size());
      const auto member_it =
          std::find(snapshot->ordered_members.begin(), snapshot->ordered_members.begin() + end, vote.validator_pubkey);
      if (member_it == snapshot->ordered_members.begin() + end) {
        log_line("vote-reject-snapshot-nonmember validator=" +
                 hex_encode(Bytes(vote.validator_pubkey.begin(), vote.validator_pubkey.end())) +
                 " height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round) +
                 " epoch_start=" +
                 std::to_string(consensus::committee_epoch_start(vote.height, cfg_.network.vrf_committee_epoch_blocks)));
        return false;
      }
    } else if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
      return false;
    }

    const auto nowm = now_ms();
    auto& verify_bucket = vote_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.vote_verify_capacity, cfg_.vote_verify_refill);
    if (from_network && !verify_bucket.consume(1.0, nowm)) return false;

    const p2p::VoteVerifyCache::Key vkey{vote.height, vote.round, vote.block_id, vote.validator_pubkey};
    if (invalid_vote_verify_cache_.contains(vkey)) return false;
    if (!vote_verify_cache_.contains(vkey)) {
      Bytes bid(vote.block_id.begin(), vote.block_id.end());
      if (!crypto::ed25519_verify(bid, vote.signature, vote.validator_pubkey)) {
        invalid_vote_verify_cache_.insert(vkey);
        return false;
      }
      vote_verify_cache_.insert(vkey);
    }

    auto tr = votes_.add_vote(vote);
    if (tr.equivocation && tr.evidence.has_value()) {
      if (is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
        validators_.ban(vote.validator_pubkey);
        auto vi = validators_.get(vote.validator_pubkey);
        if (vi.has_value()) db_.put_validator(vote.validator_pubkey, *vi);
        (void)db_.put_slashing_record(make_vote_equivocation_record(*tr.evidence, finalized_height_));
        log_line("equivocation-banned validator=" +
                 hex_encode(Bytes(vote.validator_pubkey.begin(), vote.validator_pubkey.end())) +
                 " height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round));
      }
    }

    if (!tr.accepted) {
      return tr.duplicate;
    }

    relay_vote = from_network && !should_mute_peer(from_peer_id);
    finalize_ok = finalize_if_quorum(vote.block_id, vote.height, vote.round);
  }

  if (relay_vote) broadcast_vote(vote, vrf_proof, vrf_output);
  return finalize_ok;
}

std::optional<crypto::VrfProof> Node::local_proposer_vrf_locked(std::uint64_t height, std::uint32_t round) const {
  if (!cfg_.network.vrf_proposer_enabled) return std::nullopt;
  const auto active = validators_.active_sorted(height);
  if (active.empty()) return std::nullopt;
  if (std::find(active.begin(), active.end(), local_key_.public_key) == active.end()) return std::nullopt;

  const auto transcript = consensus::proposer_vrf_transcript(cfg_.network, finalized_randomness_, height, round);
  auto proof = crypto::vrf_prove(local_key_.private_key, local_key_.public_key, transcript);
  if (!proof.has_value()) return std::nullopt;
  if (!consensus::proposer_vrf_output_is_eligible(proof->output, active.size(), round,
                                                  cfg_.network.vrf_proposer_expected_num,
                                                  cfg_.network.vrf_proposer_expected_den)) {
    return std::nullopt;
  }
  return proof;
}

bool Node::verify_block_proposer_locked(const Block& block) const {
  const Bytes bid = block_proposal_signing_message(block.header);
  if (!crypto::ed25519_verify(bid, block.header.leader_signature, block.header.leader_pubkey)) return false;

  if (!cfg_.network.vrf_proposer_enabled) {
    auto expected = leader_for_height_round(block.header.height, block.header.round);
    return expected.has_value() && block.header.leader_pubkey == *expected;
  }

  const auto active = validators_.active_sorted(block.header.height);
  if (active.empty()) return false;
  if (std::find(active.begin(), active.end(), block.header.leader_pubkey) == active.end()) return false;
  if (block.header.vrf_proof.empty()) return false;

  crypto::VrfProof proof;
  proof.proof = block.header.vrf_proof;
  proof.output = block.header.vrf_output;
  return consensus::verify_proposer_vrf(cfg_.network, block.header.leader_pubkey, finalized_randomness_,
                                        block.header.height, block.header.round, proof, active.size(),
                                        cfg_.network.vrf_proposer_expected_num,
                                        cfg_.network.vrf_proposer_expected_den);
}

bool Node::check_and_record_proposer_equivocation_locked(const Block& block) {
  const auto key = std::make_tuple(block.header.height, block.header.round, block.header.leader_pubkey);
  auto it = observed_proposals_.find(key);
  if (it == observed_proposals_.end()) {
    observed_proposals_[key] = block.header;
    return false;
  }
  const auto old_block_id = it->second.block_id();
  const auto new_block_id = block.header.block_id();
  if (old_block_id == new_block_id) return false;

  validators_.ban(block.header.leader_pubkey, block.header.height);
  if (auto vi = validators_.get(block.header.leader_pubkey); vi.has_value()) {
    (void)db_.put_validator(block.header.leader_pubkey, *vi);
  }
  (void)db_.put_slashing_record(make_proposer_equivocation_record(it->second, block.header, finalized_height_));
  log_line("proposer-equivocation-banned validator=" +
           hex_encode(Bytes(block.header.leader_pubkey.begin(), block.header.leader_pubkey.end())) +
           " height=" + std::to_string(block.header.height) + " round=" + std::to_string(block.header.round) +
           " block_a=" + hex_encode32(old_block_id) + " block_b=" + hex_encode32(new_block_id));
  return true;
}

bool Node::handle_tx(const Tx& tx, bool from_network, int from_peer_id) {
  if (from_network && !running_) return false;
  Hash32 txid{};
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (from_network && !running_) return false;
    auto& verify_bucket = tx_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.tx_verify_capacity, cfg_.tx_verify_refill);
    if (from_network && !verify_bucket.consume(static_cast<double>(std::max<std::size_t>(1, tx.inputs.size())), now_ms())) {
      return false;
    }
    mempool_.set_validation_context(
        SpecialValidationContext{
            .validators = &validators_,
            .current_height = finalized_height_ + 1,
            .enforce_variable_bond_range = true,
            .min_bond_amount = validator_bond_min_amount_,
            .max_bond_amount = validator_bond_max_amount_,
            .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
            .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
              return is_committee_member_for(pub, h, round);
            }});
    std::string err;
    std::uint64_t fee = 0;
    if (!mempool_.accept_tx(tx, utxos_, &err, cfg_.min_relay_fee, &fee)) {
      return false;
    }
    if (fee < cfg_.min_relay_fee) return false;
    txid = tx.txid();
    log_line("mempool-accept txid=" + hex_encode32(txid) + " mempool_size=" + std::to_string(mempool_.size()));
  }

  if (from_network && !should_mute_peer(from_peer_id)) broadcast_tx(tx, from_peer_id);
  return true;
}

bool Node::finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round) {
  auto blk_it = candidate_blocks_.find(block_id);
  if (blk_it == candidate_blocks_.end()) return false;

  auto sigs = votes_.signatures_for(height, round, block_id);
  std::set<PubKey32> committee_set;
  const auto committee = committee_for_height_round(height, round);
  if (committee.empty()) return false;
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  committee_set.insert(committee.begin(), committee.end());
  if (sigs.size() < quorum) return false;

  std::set<PubKey32> seen;
  std::vector<FinalitySig> filtered;
  for (const auto& s : sigs) {
    if (!committee_set.empty() && committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(s.validator_pubkey).second) continue;
    Bytes bid(block_id.begin(), block_id.end());
    if (!crypto::ed25519_verify(bid, s.signature, s.validator_pubkey)) continue;
    filtered.push_back(s);
  }
  if (filtered.size() < quorum) return false;

  Block b = blk_it->second;
  b.finality_proof.sigs = filtered;
  if (!validate_v4_registration_rules(b, height)) return false;

  const FinalityCertificate certificate = make_finality_certificate(height, round, block_id, quorum, committee, filtered);
  if (!persist_finalized_block(b, certificate)) return false;

  std::vector<Hash32> confirmed_txids;
  confirmed_txids.reserve(b.txs.size());
  for (const auto& tx : b.txs) confirmed_txids.push_back(tx.txid());
  mempool_.remove_confirmed(confirmed_txids);
  UtxoSet pre_utxos = utxos_;
  update_v4_liveness_from_finality(height, round, filtered);
  apply_validator_state_changes(b, pre_utxos, height);
  apply_block_to_utxo(b, utxos_);
  mempool_.prune_against_utxo(utxos_);

  finalized_height_ = b.header.height;
  finalized_hash_ = block_id;
  finalized_randomness_ = consensus::advance_finalized_randomness(finalized_randomness_, b.header);
  if (consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.vrf_committee_epoch_blocks) ==
      finalized_height_ + 1) {
    committee_epoch_randomness_cache_[finalized_height_ + 1] = finalized_randomness_;
    persist_committee_epoch_snapshot_locked(finalized_height_ + 1, validators_.active_sorted(finalized_height_ + 1),
                                            finalized_randomness_);
  }
  (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
  last_finalized_progress_ms_ = now_unix() * 1000;
  current_round_ = 0;
  round_started_ms_ = now_unix() * 1000;
  if (restart_debug_) {
    log_line("restart-debug round-timer-reset height=" + std::to_string(finalized_height_) + " round=0");
  }

  votes_.clear_height(height);
  vote_verify_cache_.clear_height(height);
  invalid_vote_verify_cache_.clear_height(height);
  candidate_blocks_.clear();
  candidate_block_sizes_.clear();

  broadcast_finalized_block(b);
  broadcast_finalized_tip();

  std::ostringstream oss;
  oss << "finalized height=" << finalized_height_ << " round=" << round << " leader="
      << hex_encode(Bytes(b.header.leader_pubkey.begin(), b.header.leader_pubkey.end()))
      << " votes=" << filtered.size() << "/" << quorum << " txs=" << b.txs.size()
      << " hash=" << hex_encode32(block_id);
  if (b.txs.size() > 1) {
    oss << " included_txid=" << hex_encode32(b.txs[1].txid());
  }
  log_line(oss.str());
  append_mining_log(b, round, filtered.size(), quorum);

  return true;
}

std::optional<Block> Node::build_proposal_block(std::uint64_t height, std::uint32_t round) {
  Block b;
  b.header.prev_finalized_hash = finalized_hash_;
  b.header.height = height;
  b.header.timestamp = now_unix();
  b.header.round = round;
  b.header.leader_pubkey = local_key_.public_key;

  Tx coinbase;
  coinbase.version = 1;
  coinbase.lock_time = 0;
  TxIn in;
  in.prev_txid = zero_hash();
  in.prev_index = 0xFFFFFFFF;
  in.sequence = 0xFFFFFFFF;
  in.script_sig = make_coinbase_script_sig(height, round);
  coinbase.inputs.push_back(in);

  std::vector<Tx> picked;
  {
    picked = mempool_.select_for_block(kMaxBlockTxs, kMaxBlockBytes, utxos_);
  }

  std::uint64_t total_fees = 0;
  SpecialValidationContext vctx{
      .validators = &validators_,
      .current_height = height,
      .enforce_variable_bond_range = true,
      .min_bond_amount = validator_bond_min_amount_,
      .max_bond_amount = validator_bond_max_amount_,
      .unbond_delay_blocks = cfg_.network.unbond_delay_blocks,
      .is_committee_member = [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
        return is_committee_member_for(pub, h, round);
      }};
  for (const auto& tx : picked) {
    auto vr = validate_tx(tx, 1, utxos_, &vctx);
    if (vr.ok) total_fees += vr.fee;
  }

  const auto reward_signers = reward_signers_for_height_round(height, round);
  const auto payout = consensus::compute_payout(height, total_fees, local_key_.public_key, reward_signers);

  {
    const auto pkh = crypto::h160(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));
    TxOut leader_out;
    leader_out.value = payout.leader;
    leader_out.script_pubkey = address::p2pkh_script_pubkey(pkh);
    coinbase.outputs.push_back(leader_out);
  }
  for (const auto& [pub, units] : payout.signers) {
    const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
    TxOut so;
    so.value = units;
    so.script_pubkey = address::p2pkh_script_pubkey(pkh);
    coinbase.outputs.push_back(std::move(so));
  }

  b.txs.push_back(coinbase);
  for (auto tx : picked) {
    tx.hashcash.reset();
    b.txs.push_back(std::move(tx));
  }

  std::vector<Bytes> tx_bytes;
  tx_bytes.reserve(b.txs.size());
  for (const auto& tx : b.txs) tx_bytes.push_back(tx.serialize());
  auto m = merkle::compute_merkle_root_from_txs(tx_bytes);
  if (!m.has_value()) return std::nullopt;
  b.header.merkle_root = *m;
  auto leader_sig = crypto::ed25519_sign(block_proposal_signing_message(b.header), local_key_.private_key);
  if (!leader_sig.has_value()) return std::nullopt;
  b.header.leader_signature = *leader_sig;
  if (!picked.empty()) {
    log_line("propose-assembled height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " txs=" + std::to_string(picked.size()) + " fees=" + std::to_string(total_fees));
  }
  return b;
}

void Node::broadcast_propose(const Block& block, const Bytes& vrf_proof, const Hash32* vrf_output) {
  p2p::ProposeMsg p;
  p.height = block.header.height;
  p.round = block.header.round;
  p.prev_finalized_hash = block.header.prev_finalized_hash;
  p.block_bytes = block.serialize();
  p.vrf_proof = !vrf_proof.empty() ? vrf_proof : block.header.vrf_proof;
  if (vrf_output) {
    p.vrf_output = *vrf_output;
  } else if (!block.header.vrf_proof.empty()) {
    p.vrf_output = block.header.vrf_output;
  }
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, p]() { peer->handle_propose(p, true); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::PROPOSE, p2p::ser_propose(p));
  }
}

void Node::broadcast_vote(const Vote& vote, const Bytes& vrf_proof, const Hash32* vrf_output) {
  p2p::VoteMsg vm;
  vm.vote = vote;
  vm.vrf_proof = vrf_proof;
  if (vrf_output) vm.vrf_output = *vrf_output;
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, vm]() {
        (void)peer->handle_vote(vm.vote, true, 0, vm.vrf_proof, vm.vrf_proof.empty() ? nullptr : &vm.vrf_output);
      });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::VOTE, p2p::ser_vote(vm));
  }
}

void Node::broadcast_finalized_block(const Block& block) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, block]() {
        p2p::ProposeMsg pm{block.header.height, block.header.round, block.header.prev_finalized_hash, block.serialize()};
        peer->handle_propose(pm, true);
      });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::BLOCK, p2p::ser_block(p2p::BlockMsg{block.serialize()}));
  }
}

void Node::broadcast_tx(const Tx& tx, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, tx]() { peer->handle_tx(tx, true); });
    }
  } else {
    const auto payload = p2p::ser_tx(p2p::TxMsg{tx.serialize()});
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      (void)p2p_.send_to(id, p2p::MsgType::TX, payload, true);
    }
  }
}

bool Node::persist_finalized_block(const Block& block, const FinalityCertificate& certificate) {
  const Hash32 h = block.header.block_id();
  if (!db_.put_block(h, block.serialize())) return false;
  if (!db_.put_finality_certificate(certificate)) return false;
  if (!db_.set_height_hash(block.header.height, h)) return false;
  if (!db_.set_tip(storage::TipState{block.header.height, h})) return false;

  // Persist tx index + UTXOs + lightserver indexes for finalized state.
  for (std::uint32_t tx_i = 0; tx_i < block.txs.size(); ++tx_i) {
    const auto& tx = block.txs[tx_i];
    if (!db_.put_tx_index(tx.txid(), block.header.height, tx_i, tx.serialize())) return false;
  }

  if (block.txs.size() > 1) {
    for (size_t i = 1; i < block.txs.size(); ++i) {
      const auto spending_txid = block.txs[i].txid();
      for (const auto& in : block.txs[i].inputs) {
        const OutPoint op{in.prev_txid, in.prev_index};
        auto prev = utxos_.find(op);
        if (prev != utxos_.end()) {
          const Hash32 sh = crypto::sha256(prev->second.out.script_pubkey);
          if (!db_.erase_script_utxo(sh, op)) return false;
          if (!db_.add_script_history(sh, block.header.height, spending_txid)) return false;
        }
        if (!db_.erase_utxo(op)) return false;
      }
    }
  }
  for (const auto& tx : block.txs) {
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const OutPoint op{txid, out_i};
      const auto& out = tx.outputs[out_i];
      const Hash32 sh = crypto::sha256(out.script_pubkey);
      if (!db_.put_utxo(op, out)) return false;
      if (!db_.put_script_utxo(sh, op, out, block.header.height)) return false;
      if (!db_.add_script_history(sh, block.header.height, txid)) return false;
    }
  }
  if (!db_.flush()) return false;
  if (restart_debug_) {
    log_line("restart-debug db-commit-flush height=" + std::to_string(block.header.height) + " hash=" +
             hex_encode32(h));
  }
  return true;
}

bool Node::init_mainnet_genesis() {
  const bool use_embedded = cfg_.genesis_path.empty();
  std::string err;
  std::optional<genesis::Document> doc;
  Hash32 ghash{};
  if (use_embedded) {
    const Bytes bin(genesis::MAINNET_GENESIS_BIN, genesis::MAINNET_GENESIS_BIN + genesis::MAINNET_GENESIS_BIN_LEN);
    doc = genesis::decode_bin(bin, &err);
    if (doc.has_value()) ghash = genesis::hash_bin(bin);
  } else {
    doc = genesis::load_from_path(cfg_.genesis_path, &err);
    if (doc.has_value()) ghash = genesis::hash_doc(*doc);
  }
  if (!doc.has_value()) {
    std::cerr << "genesis load failed: " << err << "\n";
    return false;
  }
  bootstrap_template_mode_ = (!use_embedded && doc->initial_validators.empty());
  if (!genesis::validate_document(*doc, cfg_.network, &err, bootstrap_template_mode_ ? 0 : 1)) {
    std::cerr << "genesis validation failed: " << err << "\n";
    return false;
  }
  if (use_embedded && ghash != genesis::MAINNET_GENESIS_HASH) {
    std::cerr << "embedded genesis hash mismatch; binary may be corrupted\n";
    return false;
  }
  expected_genesis_hash_ = ghash;

  const Bytes ghash_b(ghash.begin(), ghash.end());
  const Hash32 gblock = genesis::block_id(*doc);
  const Bytes gblock_b(gblock.begin(), gblock.end());
  const auto stored = db_.get("G:");
  if (stored.has_value()) {
    if (stored->size() != 32 || !std::equal(stored->begin(), stored->end(), ghash_b.begin())) {
      std::cerr << "genesis mismatch against existing database\n";
      return false;
    }
    if (!db_.get("G:J").has_value()) {
      const auto json = genesis::to_json(*doc);
      (void)db_.put("G:J", Bytes(json.begin(), json.end()));
    }
    if (bootstrap_template_mode_) {
      const auto all = db_.scan_prefix("V:");
      if (all.size() == 1) {
        const auto& key = all.begin()->first;
        if (key.size() > 2) {
          auto b = hex_decode(key.substr(2));
          if (b && b->size() == 32) {
            PubKey32 pub{};
            std::copy(b->begin(), b->end(), pub.begin());
            bootstrap_validator_pubkey_ = pub;
          }
        }
      }
    }
    const auto tip = db_.get_tip();
    if (tip.has_value() && tip->height == 0 && tip->hash != gblock) {
      std::cerr << "genesis block id mismatch against existing database tip\n";
      return false;
    }
    return true;
  }

  if (!db_.put("G:", ghash_b)) return false;
  if (!db_.put("GB:", gblock_b)) return false;
  {
    const auto json = genesis::to_json(*doc);
    if (!db_.put("G:J", Bytes(json.begin(), json.end()))) return false;
  }
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (!(tip->height == 0 && tip->hash == zero_hash()) && tip->height != 0) {
    std::cerr << "existing non-empty database is missing genesis marker\n";
    return false;
  } else if (tip->height == 0 && tip->hash == zero_hash()) {
    if (!db_.set_tip(storage::TipState{0, gblock})) return false;
  } else if (tip->height == 0 && tip->hash != gblock) {
    std::cerr << "height-0 tip does not match provided genesis\n";
    return false;
  }

  for (const auto& pub : doc->initial_validators) {
    consensus::ValidatorInfo vi;
    vi.status = consensus::ValidatorStatus::ACTIVE;
    vi.joined_height = 0;
    vi.has_bond = true;
    vi.bond_outpoint = OutPoint{zero_hash(), 0};
    vi.unbond_height = 0;
    if (!db_.put_validator(pub, vi)) return false;
  }
  {
    consensus::ValidatorRegistry vr;
    for (const auto& pub : doc->initial_validators) {
      consensus::ValidatorInfo vi;
      vi.status = consensus::ValidatorStatus::ACTIVE;
      vi.joined_height = 0;
      vi.has_bond = true;
      vi.bond_outpoint = OutPoint{zero_hash(), 0};
      vi.unbond_height = 0;
      vr.upsert(pub, vi);
    }
    const UtxoSet empty_utxos;
    (void)persist_state_roots(db_, 0, empty_utxos, vr, kFixedValidationRulesVersion);
  }
  {
    codec::ByteWriter w0;
    w0.u64le(0);
    (void)db_.put(kV4JoinWindowStartKey, w0.take());
    codec::ByteWriter w1;
    w1.u32le(0);
    (void)db_.put(kV4JoinWindowCountKey, w1.take());
    codec::ByteWriter w2;
    w2.u64le(0);
    (void)db_.put(kV4LivenessEpochStartKey, w2.take());
  }
  chain_id_ =
      ChainId::from_config_and_db(cfg_.network, db_, std::nullopt, genesis_source_hint_, expected_genesis_hash_);
  finalized_randomness_ = consensus::initial_finalized_randomness(cfg_.network, chain_id_);
  committee_epoch_randomness_cache_.clear();
  committee_epoch_snapshots_.clear();
  committee_epoch_randomness_cache_[1] = finalized_randomness_;
  std::vector<PubKey32> genesis_active = doc->initial_validators;
  std::sort(genesis_active.begin(), genesis_active.end());
  persist_committee_epoch_snapshot_locked(1, genesis_active, finalized_randomness_);
  (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  return db_.flush();
}

bool Node::load_state() {
  auto tip = db_.get_tip();
  if (!tip.has_value()) {
    finalized_height_ = 0;
    finalized_hash_ = zero_hash();
    db_.set_tip(storage::TipState{0, finalized_hash_});
  } else {
    finalized_height_ = tip->height;
    finalized_hash_ = tip->hash;
  }

  utxos_ = db_.load_utxos();

  const auto vals = db_.load_validators();
  for (const auto& [pub, info] : vals) validators_.upsert(pub, info);
  validator_join_requests_ = db_.load_validator_join_requests();
  committee_epoch_randomness_cache_.clear();
  committee_epoch_snapshots_ = db_.load_committee_epoch_snapshots();
  Hash32 replay_randomness = consensus::initial_finalized_randomness(cfg_.network, chain_id_);
  committee_epoch_randomness_cache_[1] = replay_randomness;
  for (std::uint64_t h = 1; h <= finalized_height_; ++h) {
    auto bh = db_.get_height_hash(h);
    if (!bh.has_value()) continue;
    auto bb = db_.get_block(*bh);
    if (!bb.has_value()) continue;
    auto blk = Block::parse(*bb);
    if (!blk.has_value()) continue;
    replay_randomness = consensus::advance_finalized_randomness(replay_randomness, blk->header);
    const auto next_epoch_start = consensus::committee_epoch_start(h + 1, cfg_.network.vrf_committee_epoch_blocks);
    if (next_epoch_start == h + 1) committee_epoch_randomness_cache_[next_epoch_start] = replay_randomness;
  }
  if (auto b = db_.get(kFinalizedRandomnessKey); b.has_value() && b->size() == 32) {
    std::copy(b->begin(), b->end(), finalized_randomness_.begin());
  } else {
    finalized_randomness_ = replay_randomness;
    (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
  }

  if (cfg_.network.vrf_committee_enabled && committee_epoch_snapshots_.empty()) {
    consensus::ValidatorRegistry replay_validators;
    std::map<Hash32, ValidatorJoinRequest> replay_join_requests;
    replay_validators.set_rules(validators_.rules());
    UtxoSet replay_utxos;
    if (auto gj = db_.get("G:J"); gj.has_value()) {
      const std::string js(gj->begin(), gj->end());
      if (auto gd = genesis::parse_json(js); gd.has_value()) {
        for (const auto& pub : gd->initial_validators) {
          consensus::ValidatorInfo vi;
          vi.status = consensus::ValidatorStatus::ACTIVE;
          vi.joined_height = 0;
          vi.has_bond = true;
          vi.bond_outpoint = OutPoint{zero_hash(), 0};
          replay_validators.upsert(pub, vi);
        }
      }
    }

    committee_epoch_snapshots_.clear();
    persist_committee_epoch_snapshot_locked(1, replay_validators.active_sorted(1), replay_randomness);

    auto apply_changes = [&](const Block& block, std::uint64_t h) {
      for (size_t txi = 1; txi < block.txs.size(); ++txi) {
        const auto& tx = block.txs[txi];
        for (const auto& in : tx.inputs) {
          OutPoint op{in.prev_txid, in.prev_index};
          auto it = replay_utxos.find(op);
          if (it == replay_utxos.end()) continue;
          PubKey32 pub{};
          SlashEvidence evidence;
          if (is_validator_register_script(it->second.out.script_pubkey, &pub)) {
            if (parse_slash_script_sig(in.script_sig, &evidence)) {
              replay_validators.ban(pub, h);
              (void)replay_validators.finalize_withdrawal(pub);
            } else {
              replay_validators.request_unbond(pub, h);
            }
            continue;
          }
          if (is_validator_unbond_script(it->second.out.script_pubkey, &pub)) {
            if (parse_slash_script_sig(in.script_sig, &evidence)) {
              replay_validators.ban(pub, h);
            }
            (void)replay_validators.finalize_withdrawal(pub);
          }
        }
      }

      for (const auto& tx : block.txs) {
        const Hash32 txid = tx.txid();
        std::set<PubKey32> requested_in_tx;
        for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
          const auto& out = tx.outputs[out_i];
          PubKey32 pub{};
          PubKey32 payout{};
          Sig64 pop{};
          if (!is_validator_join_request_script(out.script_pubkey, &pub, &payout, &pop)) continue;
          for (std::uint32_t bond_i = 0; bond_i < tx.outputs.size(); ++bond_i) {
            PubKey32 bond_pub{};
            if (!is_validator_register_script(tx.outputs[bond_i].script_pubkey, &bond_pub) || bond_pub != pub) continue;
            ValidatorJoinRequest req;
            req.request_txid = txid;
            req.validator_pubkey = pub;
            req.payout_pubkey = payout;
            req.bond_outpoint = OutPoint{txid, bond_i};
            req.bond_amount = tx.outputs[bond_i].value;
            req.requested_height = h;
            req.status = ValidatorJoinRequestStatus::APPROVED;
            req.approved_height = h;
            replay_join_requests[txid] = req;
            replay_validators.register_bond(req.validator_pubkey, req.bond_outpoint, h, req.bond_amount);
            requested_in_tx.insert(pub);
            break;
          }
        }
        for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
          const auto& out = tx.outputs[out_i];
          PubKey32 pub{};
          if (is_validator_register_script(out.script_pubkey, &pub) && out.value == BOND_AMOUNT) {
            if (requested_in_tx.find(pub) != requested_in_tx.end()) continue;
            replay_validators.register_bond(pub, OutPoint{txid, out_i}, h);
            continue;
          }
        }
      }
      replay_validators.advance_height(h + 1);
    };

    Hash32 snapshot_randomness = consensus::initial_finalized_randomness(cfg_.network, chain_id_);
    for (std::uint64_t h = 1; h <= finalized_height_; ++h) {
      auto bh = db_.get_height_hash(h);
      if (!bh.has_value()) continue;
      auto bb = db_.get_block(*bh);
      if (!bb.has_value()) continue;
      auto blk = Block::parse(*bb);
      if (!blk.has_value()) continue;
      apply_changes(*blk, h);
      apply_block_to_utxo(*blk, replay_utxos);
      snapshot_randomness = consensus::advance_finalized_randomness(snapshot_randomness, blk->header);
      const auto next_epoch_start = consensus::committee_epoch_start(h + 1, cfg_.network.vrf_committee_epoch_blocks);
      if (next_epoch_start == h + 1) {
        persist_committee_epoch_snapshot_locked(next_epoch_start, replay_validators.active_sorted(h + 1), snapshot_randomness);
      }
    }
  }

  if (auto b = db_.get(kV4JoinWindowStartKey); b.has_value()) {
    (void)codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto s = r.u64le();
      if (!s) return false;
      v4_join_window_start_height_ = *s;
      return true;
    });
  }
  if (auto b = db_.get(kV4JoinWindowCountKey); b.has_value()) {
    (void)codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto c = r.u32le();
      if (!c) return false;
      v4_join_count_in_window_ = *c;
      return true;
    });
  }
  bool loaded_liveness_epoch = false;
  if (auto b = db_.get(kV4LivenessEpochStartKey); b.has_value()) {
    loaded_liveness_epoch = codec::parse_exact(*b, [&](codec::ByteReader& r) {
      auto s = r.u64le();
      if (!s) return false;
      v4_liveness_epoch_start_height_ = *s;
      return true;
    });
  }
  if (!loaded_liveness_epoch) {
    if (v4_liveness_window_blocks_ > 0) {
      v4_liveness_epoch_start_height_ = (finalized_height_ / v4_liveness_window_blocks_) * v4_liveness_window_blocks_;
    } else {
      v4_liveness_epoch_start_height_ = 0;
    }
  }

  if (validators_.all().empty() && finalized_height_ > 0) {
    UtxoSet replay_utxos;
    for (std::uint64_t h = 1; h <= finalized_height_; ++h) {
      auto bh = db_.get_height_hash(h);
      if (!bh.has_value()) continue;
      auto bb = db_.get_block(*bh);
      if (!bb.has_value()) continue;
      auto blk = Block::parse(*bb);
      if (!blk.has_value()) continue;
      apply_validator_state_changes(*blk, replay_utxos, h);
      apply_block_to_utxo(*blk, replay_utxos);
    }
  }

  const auto existing = db_.get(root_index_key("UTXO", finalized_height_));
  if (!existing.has_value() || existing->size() != 32) {
    (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
  }

  return true;
}

std::vector<PubKey32> Node::committee_for_height(std::uint64_t height) const {
  return committee_for_height_round(height, 0);
}

std::vector<PubKey32> Node::reward_signers_for_height_round(std::uint64_t height, std::uint32_t round) const {
  auto committee = committee_for_height_round(height, round);
  if (!v4_active_for_height(height)) return committee;

  std::vector<PubKey32> out;
  out.reserve(committee.size());
  for (const auto& pub : committee) {
    auto it = validators_.all().find(pub);
    if (it == validators_.all().end()) continue;
    const auto& vi = it->second;
    if (vi.status == consensus::ValidatorStatus::SUSPENDED) continue;
    if (vi.eligible_count_window == 0 || vi.participated_count_window > 0) {
      out.push_back(pub);
    }
  }
  if (out.empty()) return committee;
  return out;
}

std::vector<PubKey32> Node::committee_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == 0) return {};
  if (height > finalized_height_ + 1) return {};

  std::vector<PubKey32> active;
  Hash32 prev_hash = zero_hash();
  FinalityProof prev_fp{};

  if (height == finalized_height_ + 1) {
    active = validators_.active_sorted(height);
    prev_hash = finalized_hash_;
    if (auto bb = db_.get_block(prev_hash); bb.has_value()) {
      if (auto blk = Block::parse(*bb); blk.has_value()) prev_fp = blk->finality_proof;
    }
  } else {
    consensus::ValidatorRegistry replay_validators;
    std::map<Hash32, ValidatorJoinRequest> replay_join_requests;
    replay_validators.set_rules(validators_.rules());
    UtxoSet replay_utxos;
    if (auto gj = db_.get("G:J"); gj.has_value()) {
      const std::string js(gj->begin(), gj->end());
      if (auto gd = genesis::parse_json(js); gd.has_value()) {
        for (const auto& pub : gd->initial_validators) {
          consensus::ValidatorInfo vi;
          vi.status = consensus::ValidatorStatus::ACTIVE;
          vi.joined_height = 0;
          vi.has_bond = true;
          vi.bond_outpoint = OutPoint{zero_hash(), 0};
          vi.unbond_height = 0;
          replay_validators.upsert(pub, vi);
        }
      }
    }

    auto apply_changes = [&](const Block& block, std::uint64_t h) {
      for (size_t txi = 1; txi < block.txs.size(); ++txi) {
        const auto& tx = block.txs[txi];
        for (const auto& in : tx.inputs) {
          OutPoint op{in.prev_txid, in.prev_index};
          auto it = replay_utxos.find(op);
          if (it == replay_utxos.end()) continue;
          PubKey32 pub{};
          SlashEvidence evidence;
          if (is_validator_register_script(it->second.out.script_pubkey, &pub)) {
            if (parse_slash_script_sig(in.script_sig, &evidence)) {
              replay_validators.ban(pub, h);
              (void)replay_validators.finalize_withdrawal(pub);
            } else {
              replay_validators.request_unbond(pub, h);
            }
            continue;
          }
          if (is_validator_unbond_script(it->second.out.script_pubkey, &pub)) {
            if (parse_slash_script_sig(in.script_sig, &evidence)) {
              replay_validators.ban(pub, h);
            }
            (void)replay_validators.finalize_withdrawal(pub);
          }
        }
      }

      for (const auto& tx : block.txs) {
        const Hash32 txid = tx.txid();
        std::set<PubKey32> requested_in_tx;
        for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
          const auto& out = tx.outputs[out_i];
          PubKey32 pub{};
          PubKey32 payout{};
          Sig64 pop{};
          if (!is_validator_join_request_script(out.script_pubkey, &pub, &payout, &pop)) continue;
          for (std::uint32_t bond_i = 0; bond_i < tx.outputs.size(); ++bond_i) {
            PubKey32 bond_pub{};
            if (!is_validator_register_script(tx.outputs[bond_i].script_pubkey, &bond_pub) || bond_pub != pub) continue;
            ValidatorJoinRequest req;
            req.request_txid = txid;
            req.validator_pubkey = pub;
            req.payout_pubkey = payout;
            req.bond_outpoint = OutPoint{txid, bond_i};
            req.bond_amount = tx.outputs[bond_i].value;
            req.requested_height = h;
            req.status = ValidatorJoinRequestStatus::APPROVED;
            req.approved_height = h;
            replay_join_requests[txid] = req;
            replay_validators.register_bond(req.validator_pubkey, req.bond_outpoint, h, req.bond_amount);
            requested_in_tx.insert(pub);
            break;
          }
        }
        for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
          const auto& out = tx.outputs[out_i];
          PubKey32 pub{};
          if (is_validator_register_script(out.script_pubkey, &pub) && out.value == BOND_AMOUNT) {
            if (requested_in_tx.find(pub) != requested_in_tx.end()) continue;
            replay_validators.register_bond(pub, OutPoint{txid, out_i}, h);
            continue;
          }
        }
      }
      replay_validators.advance_height(h + 1);
    };

    for (std::uint64_t h = 1; h <= height - 1; ++h) {
      auto bh = db_.get_height_hash(h);
      if (!bh.has_value()) return {};
      auto bb = db_.get_block(*bh);
      if (!bb.has_value()) return {};
      auto blk = Block::parse(*bb);
      if (!blk.has_value()) return {};
      apply_changes(*blk, h);
      apply_block_to_utxo(*blk, replay_utxos);
    }

    if (height > 1) {
      auto prev = db_.get_height_hash(height - 1);
      if (!prev.has_value()) return {};
      prev_hash = *prev;
      if (auto bb = db_.get_block(prev_hash); bb.has_value()) {
        if (auto blk = Block::parse(*bb); blk.has_value()) prev_fp = blk->finality_proof;
      }
    }
    active = replay_validators.active_sorted(height);
  }

  if (!cfg_.network.vrf_committee_enabled) {
    return consensus::select_committee(prev_hash, height, active, cfg_.max_committee);
  }

  const auto epoch_start = consensus::committee_epoch_start(height, cfg_.network.vrf_committee_epoch_blocks);
  auto it = committee_epoch_snapshots_.find(epoch_start);
  if (it == committee_epoch_snapshots_.end()) {
    const auto epoch_randomness = committee_epoch_randomness_for_height_locked(height);
    auto snapshot = build_committee_epoch_snapshot_locked(epoch_start, active, epoch_randomness);
    it = committee_epoch_snapshots_.emplace(epoch_start, std::move(snapshot)).first;
  }
  const auto& ordered = it->second.ordered_members;
  const auto committee_size = consensus::committee_size_for_round_v2(ordered.size(), cfg_.max_committee, round);
  return std::vector<PubKey32>(ordered.begin(), ordered.begin() + std::min<std::size_t>(committee_size, ordered.size()));
}

std::optional<PubKey32> Node::leader_for_height_round(std::uint64_t height, std::uint32_t round) const {
  if (height == 0 || height > finalized_height_ + 1) return std::nullopt;
  if (cfg_.network.vrf_proposer_enabled) return std::nullopt;
  const auto active = (height == finalized_height_ + 1) ? validators_.active_sorted(height) : std::vector<PubKey32>{};
  if (!active.empty()) return consensus::select_leader(finalized_hash_, height, round, active);

  // Historical heights are only used in verification/test paths; derive via round-aware committee fallback.
  const auto committee = committee_for_height_round(height, round);
  if (committee.empty()) return std::nullopt;
  return committee.front();
}

bool Node::is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const {
  const auto committee = committee_for_height_round(height, round);
  return std::find(committee.begin(), committee.end(), pub) != committee.end();
}

bool Node::v4_active_for_height(std::uint64_t height) const {
  return ::selfcoin::node::v4_active_for_height(height);
}

bool Node::validate_v4_registration_rules(const Block& block, std::uint64_t height) const {
  if (!v4_active_for_height(height)) return true;

  std::uint64_t window_start = v4_join_window_start_height_;
  std::uint32_t window_count = v4_join_count_in_window_;
  consensus::v4_advance_join_window(height, v4_join_limit_window_blocks_, &window_start, &window_count);

  auto registry = validators_;
  std::size_t new_regs = 0;
  for (std::size_t txi = 0; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 pub{};
      if (!is_validator_register_script(out.script_pubkey, &pub)) continue;
      if (out.value < validator_bond_min_amount_ || out.value > validator_bond_max_amount_) return false;

      std::string err;
      if (!registry.can_register_bond(pub, height, out.value, &err)) return false;
      if (v4_join_limit_window_blocks_ > 0 && v4_join_limit_max_new_ > 0 &&
          window_count + static_cast<std::uint32_t>(new_regs + 1) > v4_join_limit_max_new_) {
        return false;
      }
      if (!registry.register_bond(pub, OutPoint{txid, out_i}, height, out.value, &err)) return false;
      ++new_regs;
    }
  }
  return true;
}

void Node::update_v4_liveness_from_finality(std::uint64_t height, std::uint32_t round,
                                            const std::vector<FinalitySig>& finality_sigs) {
  if (!v4_active_for_height(height)) return;

  std::vector<PubKey32> committee = committee_for_height_round(height, round);
  if (committee.empty()) return;
  const auto participants = consensus::committee_participants_from_finality(committee, finality_sigs);
  std::set<PubKey32> participant_set(participants.begin(), participants.end());
  last_participation_eligible_signers_ = participant_set.size();

  auto& all = validators_.mutable_all();
  for (const auto& pub : committee) {
    auto it = all.find(pub);
    if (it == all.end()) continue;
    auto& info = it->second;
    if (info.status != consensus::ValidatorStatus::ACTIVE && info.status != consensus::ValidatorStatus::SUSPENDED) continue;
    info.liveness_window_start = v4_liveness_epoch_start_height_;
    ++info.eligible_count_window;
    if (participant_set.find(pub) != participant_set.end()) ++info.participated_count_window;
  }

  const bool evaluate =
      consensus::v4_liveness_should_rollover(height, v4_liveness_epoch_start_height_, v4_liveness_window_blocks_);
  if (!evaluate) return;

  for (auto& [pub, info] : all) {
    const std::uint64_t eligible = info.eligible_count_window;
    const std::uint64_t participated = info.participated_count_window;
    if (eligible >= 10) {
      const std::uint64_t miss = (eligible >= participated) ? (eligible - participated) : 0;
      const std::uint32_t miss_rate = static_cast<std::uint32_t>((miss * 100) / eligible);
      if (miss_rate >= v4_miss_rate_exit_threshold_percent_) {
        info.status = consensus::ValidatorStatus::EXITING;
        info.last_exit_height = height;
        info.unbond_height = height;
        info.penalty_strikes += 1;
      } else if (miss_rate >= v4_miss_rate_suspend_threshold_percent_) {
        info.status = consensus::ValidatorStatus::SUSPENDED;
        info.suspended_until_height = height + v4_suspend_duration_blocks_;
        info.penalty_strikes += 1;
      }
    }
    info.eligible_count_window = 0;
    info.participated_count_window = 0;
    info.liveness_window_start = height + 1;
    (void)db_.put_validator(pub, info);
  }
  v4_liveness_epoch_start_height_ =
      consensus::v4_liveness_next_epoch_start(height, v4_liveness_epoch_start_height_, v4_liveness_window_blocks_);
}

void Node::apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height) {
  if (v4_active_for_height(height)) {
    consensus::v4_advance_join_window(height, v4_join_limit_window_blocks_, &v4_join_window_start_height_,
                                      &v4_join_count_in_window_);
  }

  for (size_t txi = 1; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    for (const auto& in : tx.inputs) {
      OutPoint op{in.prev_txid, in.prev_index};
      auto it = pre_utxos.find(op);
      if (it == pre_utxos.end()) continue;
      PubKey32 pub{};
      SlashEvidence evidence;
      if (is_validator_register_script(it->second.out.script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          (void)db_.put_slashing_record(make_onchain_slash_record(evidence, tx.txid(), height));
          validators_.ban(pub, height);
          (void)validators_.finalize_withdrawal(pub);
        } else {
          validators_.request_unbond(pub, height);
        }
        continue;
      }
      if (is_validator_unbond_script(it->second.out.script_pubkey, &pub)) {
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          (void)db_.put_slashing_record(make_onchain_slash_record(evidence, tx.txid(), height));
          validators_.ban(pub, height);
        }
        (void)validators_.finalize_withdrawal(pub);
      }
    }
  }

  for (size_t txi = 0; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    const Hash32 txid = tx.txid();
    std::set<PubKey32> requested_in_tx;
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 validator_pub{};
      PubKey32 payout_pub{};
      Sig64 pop{};
      if (!is_validator_join_request_script(out.script_pubkey, &validator_pub, &payout_pub, &pop)) continue;

      for (std::uint32_t bond_i = 0; bond_i < tx.outputs.size(); ++bond_i) {
        PubKey32 bond_pub{};
        if (!is_validator_register_script(tx.outputs[bond_i].script_pubkey, &bond_pub) || bond_pub != validator_pub) continue;
        ValidatorJoinRequest req;
        req.request_txid = txid;
        req.validator_pubkey = validator_pub;
        req.payout_pubkey = payout_pub;
        req.bond_outpoint = OutPoint{txid, bond_i};
        req.bond_amount = tx.outputs[bond_i].value;
        req.requested_height = height;
        req.status = ValidatorJoinRequestStatus::APPROVED;
        req.approved_height = height;
        validator_join_requests_[txid] = req;
        (void)db_.put_validator_join_request(txid, req);
        std::string err;
        if (validators_.register_bond(req.validator_pubkey, req.bond_outpoint, height, req.bond_amount, &err)) {
          if (v4_active_for_height(height) && v4_join_limit_window_blocks_ > 0) {
            ++v4_join_count_in_window_;
          }
        }
        requested_in_tx.insert(validator_pub);
        break;
      }
    }

    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 pub{};
      if (is_validator_register_script(out.script_pubkey, &pub)) {
        if (requested_in_tx.find(pub) != requested_in_tx.end()) continue;
        std::string err;
        if (validators_.register_bond(pub, OutPoint{txid, out_i}, height, out.value, &err)) {
          if (v4_active_for_height(height) && v4_join_limit_window_blocks_ > 0) {
            ++v4_join_count_in_window_;
          }
        } else if (!v4_active_for_height(height) && out.value == BOND_AMOUNT) {
          // Preserve pre-v4 behavior.
          validators_.register_bond_legacy(pub, OutPoint{txid, out_i}, height);
        }
        continue;
      }

    }
  }

  validators_.advance_height(height + 1);
  codec::ByteWriter w_start;
  w_start.u64le(v4_join_window_start_height_);
  (void)db_.put(kV4JoinWindowStartKey, w_start.take());
  codec::ByteWriter w_count;
  w_count.u32le(v4_join_count_in_window_);
  (void)db_.put(kV4JoinWindowCountKey, w_count.take());
  codec::ByteWriter w_epoch;
  w_epoch.u64le(v4_liveness_epoch_start_height_);
  (void)db_.put(kV4LivenessEpochStartKey, w_epoch.take());
  for (const auto& [pub, info] : validators_.all()) {
    db_.put_validator(pub, info);
  }
}

std::uint64_t Node::now_unix() const {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::uint64_t Node::now_ms() const {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void Node::log_line(const std::string& s) const {
  if (cfg_.log_json) {
    std::cout << "{\"type\":\"log\",\"node_id\":" << cfg_.node_id << ",\"network\":\"" << cfg_.network.name
              << "\",\"msg\":\"" << s << "\"}\n";
    return;
  }
  std::cout << "[node " << cfg_.node_id << "] " << s << "\n";
}

void Node::append_mining_log(const Block& block, std::uint32_t round, std::size_t votes, std::size_t quorum) {
  if (mining_log_path_.empty()) return;
  if (block.txs.empty()) return;

  const std::size_t committee_size = committee_for_height_round(block.header.height, round).size();

  std::uint64_t coinbase_total = 0;
  for (const auto& out : block.txs[0].outputs) coinbase_total += out.value;
  const std::uint64_t generated_coin = consensus::reward_units(block.header.height);
  const std::uint64_t fees = (coinbase_total > generated_coin) ? (coinbase_total - generated_coin) : 0;
  const std::size_t active_validators = validators_.active_sorted(block.header.height + 1).size();

  std::time_t ts = static_cast<std::time_t>(block.header.timestamp);
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &ts);
#else
  gmtime_r(&ts, &tm_utc);
#endif
  std::ostringstream iso;
  iso << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");

  std::ofstream out(mining_log_path_, std::ios::app);
  if (!out.good()) return;
  out << block.header.timestamp << " | " << iso.str() << " | h=" << block.header.height << " | round=" << round
      << " | generated_coin=" << generated_coin << " | fees=" << fees << " | coinbase_total=" << coinbase_total
      << " | active_validators=" << active_validators << " | committee=" << committee_size << " | votes=" << votes
      << "/" << quorum << " | block_hash=" << hex_encode32(block.header.block_id()) << "\n";
}

void Node::spawn_local_bus_task(std::function<void()> fn) {
  std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
  local_bus_tasks_.emplace_back([f = std::move(fn)]() { f(); });
}

void Node::join_local_bus_tasks() {
  std::vector<std::thread> tasks;
  {
    std::lock_guard<std::mutex> lk(local_bus_tasks_mu_);
    tasks.swap(local_bus_tasks_);
  }
  for (auto& t : tasks) {
    if (t.joinable()) t.join();
  }
}

void Node::load_persisted_peers() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ifstream in(p);
  if (!in.good()) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    cfg_.peers.push_back(line);
  }
}

void Node::persist_peers() const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "peers.dat";
  std::ofstream out(p, std::ios::trunc);
  if (!out.good()) return;

  std::set<std::string> seen;
  for (const auto& ep : cfg_.peers) seen.insert(ep);
  for (const auto& ep : cfg_.seeds) seen.insert(ep);
  for (int id : p2p_.peer_ids()) {
    auto pi = p2p_.get_peer_info(id);
    if (!pi.endpoint.empty()) seen.insert(pi.endpoint);
  }
  for (const auto& ep : seen) out << ep << "\n";
}

void Node::load_addrman() {
  if (bootstrap_template_mode_ && !bootstrap_validator_pubkey_.has_value()) return;
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.load(p.string());
}

void Node::persist_addrman() const {
  const std::filesystem::path p = std::filesystem::path(cfg_.db_path) / "addrman.dat";
  (void)addrman_.save(p.string());
}

std::vector<std::string> Node::resolve_dns_seeds_once() const {
  std::vector<std::string> out;
  std::set<std::string> dedup;
  for (const auto& ep : cfg_.network.default_seeds) {
    const auto pos = ep.rfind(':');
    if (pos == std::string::npos) continue;
    const std::string host = ep.substr(0, pos);
    const std::string port = ep.substr(pos + 1);
    if (host.empty() || port.empty()) continue;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) continue;
    for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
      char ipbuf[INET6_ADDRSTRLEN]{};
      if (it->ai_family == AF_INET) {
        auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
        if (!inet_ntop(AF_INET, &sa->sin_addr, ipbuf, sizeof(ipbuf))) continue;
      } else if (it->ai_family == AF_INET6) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, ipbuf, sizeof(ipbuf))) continue;
      } else {
        continue;
      }
      dedup.insert(std::string(ipbuf) + ":" + port);
    }
    freeaddrinfo(res);
  }
  out.assign(dedup.begin(), dedup.end());
  return out;
}

void Node::maybe_request_getaddr(int peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!getaddr_requested_peers_.insert(peer_id).second) return;
  (void)p2p_.send_to(peer_id, p2p::MsgType::GETADDR, p2p::ser_getaddr(p2p::GetAddrMsg{}), true);
}

void Node::request_finalized_tip(int peer_id) {
  log_line("request-finalized-tip peer_id=" + std::to_string(peer_id) + " local_height=" + std::to_string(finalized_height_) +
           " local_tip=" + short_hash_hex(finalized_hash_));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_FINALIZED_TIP,
                     p2p::ser_finalized_tip(p2p::FinalizedTipMsg{}), true);
}

void Node::send_finalized_tip(int peer_id) {
  p2p::FinalizedTipMsg tip{finalized_height_, finalized_hash_};
  log_line("send-finalized-tip peer_id=" + std::to_string(peer_id) + " height=" + std::to_string(tip.height) +
           " hash=" + short_hash_hex(tip.hash));
  (void)p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip), true);
}

void Node::broadcast_finalized_tip() {
  if (cfg_.disable_p2p) return;
  p2p::FinalizedTipMsg tip{finalized_height_, finalized_hash_};
  const Bytes payload = p2p::ser_finalized_tip(tip);
  for (int peer_id : p2p_.peer_ids()) {
    if (!p2p_.get_peer_info(peer_id).established()) continue;
    (void)p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, payload, true);
  }
}

void Node::maybe_request_sync_parent_locked(int peer_id, const Block& blk) {
  if (blk.header.height <= finalized_height_ + 1) return;
  if (blk.header.prev_finalized_hash == finalized_hash_) return;
  if (db_.get_block(blk.header.prev_finalized_hash).has_value()) {
    log_line("sync-parent-skip peer_id=" + std::to_string(peer_id) + " child_height=" +
             std::to_string(blk.header.height) + " reason=parent-already-present parent=" +
             short_hash_hex(blk.header.prev_finalized_hash));
    return;
  }
  if (!requested_sync_blocks_.insert(blk.header.prev_finalized_hash).second) {
    log_line("sync-parent-skip peer_id=" + std::to_string(peer_id) + " child_height=" +
             std::to_string(blk.header.height) + " reason=already-requested parent=" +
             short_hash_hex(blk.header.prev_finalized_hash));
    return;
  }
  log_line("request-sync-parent peer_id=" + std::to_string(peer_id) + " child_height=" +
           std::to_string(blk.header.height) + " parent=" + short_hash_hex(blk.header.prev_finalized_hash));
  (void)p2p_.send_to(peer_id, p2p::MsgType::GET_BLOCK,
                     p2p::ser_get_block(p2p::GetBlockMsg{blk.header.prev_finalized_hash}), true);
}

void Node::maybe_apply_buffered_sync_blocks_locked() {
  for (;;) {
    bool advanced = false;
    for (auto it = buffered_sync_blocks_.begin(); it != buffered_sync_blocks_.end(); ++it) {
      const auto& blk = it->second;
      if (blk.header.height != finalized_height_ + 1 || blk.header.prev_finalized_hash != finalized_hash_) continue;

      const auto bid = blk.header.block_id();
      std::set<PubKey32> committee_set;
      const auto committee = committee_for_height_round(blk.header.height, blk.header.round);
      if (committee.empty()) {
        log_line("buffered-sync-skip height=" + std::to_string(blk.header.height) + " hash=" + short_hash_hex(bid) +
                 " reason=empty-committee");
        continue;
      }
      const std::size_t quorum = consensus::quorum_threshold(committee.size());
      committee_set.insert(committee.begin(), committee.end());
      std::set<PubKey32> seen;
      std::size_t valid_sigs = 0;
      std::vector<FinalitySig> filtered_sigs;
      filtered_sigs.reserve(blk.finality_proof.sigs.size());
      for (const auto& s : blk.finality_proof.sigs) {
        if (committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
        if (!seen.insert(s.validator_pubkey).second) continue;
        Bytes bid_bytes(bid.begin(), bid.end());
        if (!crypto::ed25519_verify(bid_bytes, s.signature, s.validator_pubkey)) continue;
        ++valid_sigs;
        filtered_sigs.push_back(s);
      }
      if (valid_sigs < quorum) {
        log_line("buffered-sync-skip height=" + std::to_string(blk.header.height) + " hash=" + short_hash_hex(bid) +
                 " reason=insufficient-finality valid=" + std::to_string(valid_sigs) +
                 " quorum=" + std::to_string(quorum));
        continue;
      }
      if (!validate_v4_registration_rules(blk, blk.header.height)) {
        log_line("buffered-sync-skip height=" + std::to_string(blk.header.height) + " hash=" + short_hash_hex(bid) +
                 " reason=v4-registration-rules");
        continue;
      }

      const FinalityCertificate certificate =
          make_finality_certificate(blk.header.height, blk.header.round, bid, quorum, committee, filtered_sigs);
      if (!persist_finalized_block(blk, certificate)) {
        log_line("buffered-sync-skip height=" + std::to_string(blk.header.height) + " hash=" + short_hash_hex(bid) +
                 " reason=persist-failed");
        continue;
      }

      std::vector<Hash32> confirmed_txids;
      confirmed_txids.reserve(blk.txs.size());
      for (const auto& tx : blk.txs) confirmed_txids.push_back(tx.txid());
      mempool_.remove_confirmed(confirmed_txids);
      UtxoSet pre_utxos = utxos_;
      update_v4_liveness_from_finality(blk.header.height, blk.header.round, filtered_sigs);
      apply_validator_state_changes(blk, pre_utxos, blk.header.height);
      apply_block_to_utxo(blk, utxos_);
      mempool_.prune_against_utxo(utxos_);
      finalized_height_ = blk.header.height;
      finalized_hash_ = bid;
      finalized_randomness_ = consensus::advance_finalized_randomness(finalized_randomness_, blk.header);
      if (consensus::committee_epoch_start(finalized_height_ + 1, cfg_.network.vrf_committee_epoch_blocks) ==
          finalized_height_ + 1) {
        committee_epoch_randomness_cache_[finalized_height_ + 1] = finalized_randomness_;
        persist_committee_epoch_snapshot_locked(finalized_height_ + 1, validators_.active_sorted(finalized_height_ + 1),
                                                finalized_randomness_);
      }
      (void)db_.put(kFinalizedRandomnessKey, Bytes(finalized_randomness_.begin(), finalized_randomness_.end()));
      (void)persist_state_roots(db_, finalized_height_, utxos_, validators_, kFixedValidationRulesVersion);
      last_finalized_progress_ms_ = now_unix() * 1000;
      current_round_ = 0;
      round_started_ms_ = now_unix() * 1000;
      votes_.clear_height(blk.header.height);
      candidate_blocks_.clear();
      candidate_block_sizes_.clear();
      requested_sync_blocks_.erase(bid);
      buffered_sync_blocks_.erase(it);
      log_line("buffered-sync-applied height=" + std::to_string(finalized_height_) + " hash=" + short_hash_hex(bid));
      broadcast_finalized_tip();
      advanced = true;
      break;
    }
    if (!advanced) break;
  }
}

bool Node::seed_preflight_ok(const std::string& host, std::uint16_t port) {
  const std::string key = host + ":" + std::to_string(port);
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (preflight_checked_seeds_.find(key) != preflight_checked_seeds_.end()) return true;
    preflight_checked_seeds_.insert(key);
  }

  // Avoid sacrificial TCP probes against public seeds. They look like real
  // inbound peers to a bootstrap node, trigger VERSION sends, and then close
  // before the actual handshake connection is attempted.
  if (!is_loopback_seed_host(host)) return true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return true;
  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return true;

  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  Bytes prefix;
  if (::poll(&pfd, 1, 200) > 0 && (pfd.revents & POLLIN)) {
    std::array<std::uint8_t, 16> tmp{};
    const ssize_t n = ::recv(fd, tmp.data(), tmp.size(), MSG_DONTWAIT);
    if (n > 0) prefix.assign(tmp.begin(), tmp.begin() + n);
  }
  ::shutdown(fd, SHUT_RDWR);
  ::close(fd);

  if (prefix.empty()) return true;
  const auto kind = p2p::classify_prefix(prefix);
  if (kind == p2p::PrefixKind::HTTP || kind == p2p::PrefixKind::JSON) {
    log_line("seed preflight warning " + key + " appears HTTP/JSON; likely lightserver port");
    return false;
  }
  if (kind == p2p::PrefixKind::TLS) {
    log_line("seed preflight warning " + key + " appears TLS; do not put TLS/proxy in front of P2P");
    return false;
  }
  return true;
}

void Node::try_connect_bootstrap_peers() {
  struct Candidate {
    std::string peer;
    const char* source;
  };
  std::vector<Candidate> candidates;
  std::set<std::string> seen;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& p : bootstrap_peers_) {
      if (seen.insert(p).second) candidates.push_back({p, "seeds"});
    }
    for (const auto& p : dns_seed_peers_) {
      if (seen.insert(p).second) candidates.push_back({p, "dns"});
    }
    if (!bootstrap_template_mode_ || bootstrap_validator_pubkey_.has_value()) {
      for (const auto& a : addrman_.select_candidates(cfg_.outbound_target * 2, now_unix())) {
        if (seen.insert(a.key()).second) candidates.push_back({a.key(), "addrman"});
      }
    }
  }

  for (const auto& candidate : candidates) {
    const auto& peer = candidate.peer;
    const auto pos = peer.find(':');
    if (pos == std::string::npos) continue;
    const std::string host = peer.substr(0, pos);
    std::uint16_t port = 0;
    try {
      port = static_cast<std::uint16_t>(std::stoi(peer.substr(pos + 1)));
    } catch (...) {
      continue;
    }
    if (has_peer_endpoint(host, port)) continue;
    if (discipline_.is_banned(host, now_unix())) continue;
    if (!seed_preflight_ok(host, port)) continue;
    {
      std::lock_guard<std::mutex> lk(mu_);
      addrman_.mark_attempt(p2p::NetAddress{host, port}, now_unix());
    }
    if (!p2p_.connect_to(host, port)) continue;
    {
      std::lock_guard<std::mutex> lk(mu_);
      last_bootstrap_source_ = candidate.source;
      addrman_.mark_success(p2p::NetAddress{host, port}, now_unix());
    }
  }
}

bool Node::has_peer_endpoint(const std::string& host, std::uint16_t port) const {
  const std::string endpoint = host + ":" + std::to_string(port);
  for (int pid : p2p_.peer_ids()) {
    const auto info = p2p_.get_peer_info(pid);
    if (info.endpoint == endpoint) return true;
    if (info.ip == host && !info.inbound) return true;
  }
  return false;
}

std::size_t Node::peer_count() const { return static_cast<std::size_t>(p2p_.peer_ids().size()); }

std::size_t Node::established_peer_count() const {
  std::size_t n = 0;
  for (int id : p2p_.peer_ids()) {
    if (p2p_.get_peer_info(id).established()) ++n;
  }
  return n;
}

std::size_t Node::outbound_peer_count() const {
  if (cfg_.disable_p2p) return peer_count();
  return p2p_.outbound_count();
}

std::string Node::peer_ip_for(int peer_id) const {
  auto it = peer_ip_cache_.find(peer_id);
  if (it != peer_ip_cache_.end()) return it->second;
  const auto pi = p2p_.get_peer_info(peer_id);
  if (!pi.ip.empty()) return pi.ip;
  return endpoint_to_ip(pi.endpoint);
}

bool Node::is_bootstrap_peer_ip(const std::string& ip) const {
  if (ip.empty()) return false;
  auto matches_host = [&](const std::string& peer) {
    const auto pos = peer.find(':');
    const std::string host = (pos == std::string::npos) ? peer : peer.substr(0, pos);
    return host == ip;
  };
  for (const auto& peer : cfg_.peers) {
    if (matches_host(peer)) return true;
  }
  for (const auto& seed : cfg_.seeds) {
    if (matches_host(seed)) return true;
  }
  for (const auto& peer : bootstrap_peers_) {
    if (matches_host(peer)) return true;
  }
  return false;
}

std::optional<p2p::NetAddress> Node::addrman_address_for_peer(const p2p::PeerInfo& info) const {
  if (info.ip.empty()) return std::nullopt;
  if (!info.inbound) {
    auto parsed = p2p::parse_endpoint(info.endpoint);
    if (parsed.has_value()) return *parsed;
  }
  return p2p::NetAddress{info.ip, cfg_.network.p2p_default_port};
}

void Node::score_peer(int peer_id, p2p::MisbehaviorReason reason, const std::string& note) {
  std::string ip;
  p2p::PeerScoreStatus st;
  {
    std::lock_guard<std::mutex> lk(mu_);
    ip = peer_ip_for(peer_id);
    if (ip.empty()) return;
    st = discipline_.add_score(ip, reason, now_unix());
  }
  if (st.banned) {
    log_line("peer-banned ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
    p2p_.disconnect_peer(peer_id);
  } else if (st.soft_muted) {
    log_line("peer-soft-muted ip=" + ip + " score=" + std::to_string(st.score) + " note=" + note);
  }
}

bool Node::should_mute_peer(int peer_id) const {
  if (peer_id <= 0) return false;
  std::lock_guard<std::mutex> lk(mu_);
  const std::string ip = peer_ip_for(peer_id);
  if (ip.empty()) return false;
  return discipline_.status(ip, now_unix()).soft_muted;
}

void Node::prune_caches_locked(std::uint64_t height, std::uint32_t round) {
  const std::uint64_t min_h = (height > 2) ? (height - 2) : 0;
  for (auto it = candidate_blocks_.begin(); it != candidate_blocks_.end();) {
    if (it->second.header.height < min_h) {
      candidate_block_sizes_.erase(it->first);
      it = candidate_blocks_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = proposed_in_round_.begin(); it != proposed_in_round_.end();) {
    if (it->first.first < height || (it->first.first == height && it->first.second + kProposalRoundWindow < round)) {
      it = proposed_in_round_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = logged_committee_rounds_.begin(); it != logged_committee_rounds_.end();) {
    if (it->first < height || (it->first == height && it->second + kProposalRoundWindow < round)) {
      it = logged_committee_rounds_.erase(it);
    } else {
      ++it;
    }
  }
}

bool Node::check_rate_limit_locked(int peer_id, std::uint16_t msg_type) {
  if (peer_id <= 0) return true;
  auto& buckets = msg_rate_buckets_[peer_id];
  auto get = [&](std::uint16_t type, double cap, double refill) -> p2p::TokenBucket& {
    auto it = buckets.find(type);
    if (it == buckets.end()) {
      it = buckets.emplace(type, p2p::TokenBucket(cap, refill)).first;
    }
    return it->second;
  };

  const auto nms = now_ms();
  switch (msg_type) {
    case p2p::MsgType::TX:
      return get(msg_type, cfg_.tx_rate_capacity, cfg_.tx_rate_refill).consume(1.0, nms);
    case p2p::MsgType::PROPOSE:
      return get(msg_type, cfg_.propose_rate_capacity, cfg_.propose_rate_refill).consume(1.0, nms);
    case p2p::MsgType::VOTE:
      return get(msg_type, cfg_.vote_rate_capacity, cfg_.vote_rate_refill).consume(1.0, nms);
    case p2p::MsgType::BLOCK:
      return get(msg_type, cfg_.block_rate_capacity, cfg_.block_rate_refill).consume(1.0, nms);
    case p2p::MsgType::GET_BLOCK:
      return get(msg_type, 30.0, 15.0).consume(1.0, nms);
    case p2p::MsgType::GET_FINALIZED_TIP:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::GETADDR:
      return get(msg_type, 4.0, 1.0).consume(1.0, nms);
    case p2p::MsgType::ADDR:
      return get(msg_type, 8.0, 2.0).consume(1.0, nms);
    case p2p::MsgType::PING:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    case p2p::MsgType::PONG:
      return get(msg_type, 20.0, 10.0).consume(1.0, nms);
    default:
      return true;
  }
}

std::optional<NodeConfig> parse_args(int argc, char** argv) {
  NodeConfig cfg;
  cfg.listen = false;  // safe CLI default: outbound-only unless --listen is set
  cfg.network = mainnet_network();
  cfg.p2p_port = cfg.network.p2p_default_port;
  cfg.max_committee = cfg.network.max_committee;
  cfg.db_path = default_db_dir_for_network(cfg.network.name);
  bool port_explicit = false;
  bool committee_explicit = false;
  bool bind_explicit = false;
  bool db_explicit = false;
  std::string validator_passphrase_env;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](const std::string& name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << name << "\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (a == "--mainnet") {
      std::cerr << "--mainnet is not needed in mainnet-only build; remove this flag\n";
      return std::nullopt;
      cfg.dns_seeds = true;
    } else if (a == "--node-id") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.node_id = std::stoi(*v);
    } else if (a == "--port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.p2p_port = static_cast<std::uint16_t>(std::stoi(*v));
      port_explicit = true;
    } else if (a == "--listen") {
      cfg.listen = true;
    } else if (a == "--bind") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
      bind_explicit = true;
    } else if (a == "--db") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.db_path = *v;
      db_explicit = true;
    } else if (a == "--validator-key-file") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_key_file = *v;
    } else if (a == "--validator-passphrase") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_passphrase = *v;
    } else if (a == "--validator-passphrase-env") {
      auto v = next(a);
      if (!v) return std::nullopt;
      validator_passphrase_env = *v;
    } else if (a == "--genesis") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.genesis_path = *v;
    } else if (a == "--peers") {
      auto v = next(a);
      if (!v) return std::nullopt;
      std::stringstream ss(*v);
      std::string item;
      while (std::getline(ss, item, ',')) {
        if (!item.empty()) cfg.peers.push_back(item);
      }
    } else if (a == "--disable-p2p") {
      cfg.disable_p2p = true;
    } else if (a == "--seeds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      std::stringstream ss(*v);
      std::string item;
      while (std::getline(ss, item, ',')) {
        if (!item.empty()) cfg.seeds.push_back(item);
      }
    } else if (a == "--allow-unsafe-genesis-override") {
      cfg.allow_unsafe_genesis_override = true;
    } else if (a == "--outbound-target") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.outbound_target = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--dns-seeds") {
      cfg.dns_seeds = true;
    } else if (a == "--no-dns-seeds") {
      cfg.dns_seeds = false;
    } else if (a == "--public") {
      cfg.public_mode = true;
      cfg.listen = true;
    } else if (a == "--max-committee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
      committee_explicit = true;
    } else if (a == "--log-json") {
      cfg.log_json = true;
    } else if (a == "--handshake-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.handshake_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--frame-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.frame_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--idle-timeout-ms") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.idle_timeout_ms = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--peer-queue-max-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--peer-queue-max-msgs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.peer_queue_max_msgs = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--max-inbound") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_inbound = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--ban-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.ban_seconds = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--invalid-frame-ban-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_ban_threshold = std::max(1, std::stoi(*v));
    } else if (a == "--invalid-frame-window-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.invalid_frame_window_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--min-relay-fee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.min_relay_fee = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--hashcash-enabled") {
      cfg.hashcash_enabled = true;
    } else if (a == "--hashcash-base-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_base_bits = static_cast<std::uint32_t>(std::stoul(*v));
      cfg.hashcash_enabled = (cfg.hashcash_base_bits != 0);
    } else if (a == "--hashcash-max-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_max_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-epoch-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_epoch_seconds = std::max<std::uint64_t>(1, std::stoull(*v));
    } else if (a == "--hashcash-fee-exempt-min") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_fee_exempt_min = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-tx-threshold") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_tx_threshold = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-pressure-step-txs") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_step_txs = std::max<std::size_t>(1, static_cast<std::size_t>(std::stoull(*v)));
    } else if (a == "--hashcash-pressure-bits-per-step") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_pressure_bits_per_step = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--hashcash-large-tx-bytes") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_bytes = static_cast<std::size_t>(std::stoull(*v));
    } else if (a == "--hashcash-large-tx-extra-bits") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.hashcash_large_tx_extra_bits = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--activation-enabled" || a == "--activation-max-version" || a == "--activation-window-blocks" ||
               a == "--activation-threshold-percent" || a == "--activation-delay-blocks") {
      std::cerr << "activation flags are not supported in fixed-cv7 mode\n";
      return std::nullopt;
    } else if (a == "--validator-min-bond") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_min_bond_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-warmup-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_warmup_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-cooldown-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_cooldown_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--validator-join-limit-max-new") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.validator_join_limit_max_new_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--liveness-window-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.liveness_window_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--miss-rate-suspend-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_suspend_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--miss-rate-exit-threshold-percent") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.miss_rate_exit_threshold_percent_override = static_cast<std::uint32_t>(std::stoul(*v));
    } else if (a == "--suspend-duration-blocks") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.suspend_duration_blocks_override = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--v5-proposer-expected-num" || a == "--v5-proposer-expected-den" || a == "--v5-voter-target-k" ||
               a == "--v5-round-expand-cap" || a == "--v5-round-expand-factor" || a == "--v6-bond-unit" ||
               a == "--v6-units-max" || a == "--v6-proposer-expected-num" || a == "--v6-proposer-expected-den" ||
               a == "--v6-voter-target-k" || a == "--v6-round-expand-cap" || a == "--v6-round-expand-factor" ||
               a == "--v7-min-bond-amount" || a == "--v7-max-bond-amount" || a == "--v7-effective-units-cap") {
      std::cerr << "legacy consensus tuning flags are not supported in fixed runtime mode\n";
      return std::nullopt;
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }

  if (!cfg.genesis_path.empty() && !cfg.allow_unsafe_genesis_override) {
    std::cerr << "--genesis override on mainnet requires --allow-unsafe-genesis-override\n";
    return std::nullopt;
  }
  if (cfg.validator_passphrase.empty() && !validator_passphrase_env.empty()) {
    const char* pv = std::getenv(validator_passphrase_env.c_str());
    if (pv) cfg.validator_passphrase = pv;
  }
  if (!db_explicit) cfg.db_path = default_db_dir_for_network(cfg.network.name);
  if (cfg.public_mode && !bind_explicit) cfg.bind_ip = "0.0.0.0";
  return cfg;
}

}  // namespace selfcoin::node
