#include "node/node.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <cstdlib>
#include <set>
#include <sstream>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/validators.hpp"
#include "consensus/monetary.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "merkle/merkle.hpp"

namespace selfcoin::node {
namespace {

constexpr std::size_t kMaxBlockTxs = 1000;
constexpr std::size_t kMaxBlockBytes = 1 * 1024 * 1024;
constexpr std::size_t kMaxCandidateBlocks = 512;
constexpr std::size_t kMaxCandidateBlockBytes = 32 * 1024 * 1024;
constexpr std::uint32_t kProposalRoundWindow = 32;

std::string short_pub_hex(const PubKey32& pub) {
  Bytes b(pub.begin(), pub.begin() + 4);
  return hex_encode(b);
}

Bytes make_coinbase_script_sig(std::uint64_t h, std::uint32_t r) {
  std::string msg = "cb:" + std::to_string(h) + ":" + std::to_string(r);
  return Bytes(msg.begin(), msg.end());
}

bool restart_debug_enabled() {
  const char* v = std::getenv("SELFCOIN_RESTART_DEBUG");
  if (!v) return false;
  return std::string(v) == "1" || std::string(v) == "true" || std::string(v) == "yes";
}

std::string endpoint_to_ip(std::string endpoint) {
  const auto pos = endpoint.find(':');
  if (pos == std::string::npos) return endpoint;
  return endpoint.substr(0, pos);
}

std::mutex g_local_bus_mu;
std::vector<Node*> g_local_bus_nodes;

}  // namespace

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {
  finalized_hash_ = zero_hash();
  restart_debug_ = restart_debug_enabled();
}

Node::~Node() { stop(); }

std::vector<crypto::KeyPair> Node::devnet_keypairs() {
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
  if (cfg_.max_committee == 0) cfg_.max_committee = cfg_.network.max_committee;
  if (cfg_.testnet && cfg_.min_relay_fee == 0) cfg_.min_relay_fee = 1000;
  discipline_ = p2p::PeerDiscipline(30, 100, cfg_.ban_seconds);
  if (!db_.open(cfg_.db_path)) {
    std::cerr << "db open failed: " << cfg_.db_path << "\n";
    return false;
  }
  if (cfg_.mainnet && !init_mainnet_genesis()) {
    std::cerr << "mainnet genesis init failed\n";
    return false;
  }
  if (!load_state()) {
    std::cerr << "load_state failed\n";
    return false;
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

  {
    const auto keys = devnet_keypairs();
    if (keys.empty()) {
      std::cerr << "no key material available\n";
      return false;
    }
    const int safe_node_id = std::max(0, cfg_.node_id);
    local_key_ = keys[static_cast<std::size_t>(safe_node_id) % keys.size()];

    if (validators_.all().empty() && (cfg_.devnet || cfg_.testnet)) {
      const int n_active = std::max(1, std::min(static_cast<int>(keys.size()), cfg_.devnet_initial_active_validators));
      for (int idx = 0; idx < static_cast<int>(keys.size()); ++idx) {
        const auto& kp = keys[idx];
        consensus::ValidatorInfo vi;
        vi.status = (idx < n_active) ? consensus::ValidatorStatus::ACTIVE : consensus::ValidatorStatus::BANNED;
        vi.joined_height = 0;
        vi.has_bond = (idx < n_active);
        vi.bond_outpoint = OutPoint{zero_hash(), 0};
        vi.unbond_height = 0;
        validators_.upsert(kp.public_key, vi);
        db_.put_validator(kp.public_key, vi);
      }
    }
    is_validator_ = validators_.is_active_for_height(local_key_.public_key, finalized_height_ + 1);
  }

  round_started_ms_ = now_unix() * 1000;

  load_persisted_peers();
  for (const auto& p : cfg_.peers) bootstrap_peers_.push_back(p);
  for (const auto& s : cfg_.seeds) bootstrap_peers_.push_back(s);
  if ((cfg_.testnet || cfg_.mainnet) && cfg_.seeds.empty()) {
    for (const auto& s : cfg_.network.default_seeds) bootstrap_peers_.push_back(s);
  }

  if (!cfg_.disable_p2p) {
    p2p_.configure_network(cfg_.network.magic, cfg_.network.protocol_version, cfg_.network.max_payload_len);
    p2p_.configure_limits(p2p::PeerManager::Limits{cfg_.handshake_timeout_ms, cfg_.frame_timeout_ms, cfg_.idle_timeout_ms,
                                                    cfg_.peer_queue_max_bytes, cfg_.peer_queue_max_msgs});
    p2p_.set_on_message([this](int peer_id, std::uint16_t msg_type, const Bytes& payload) {
      handle_message(peer_id, msg_type, payload);
    });
    p2p_.set_on_event([this](int peer_id, p2p::PeerManager::PeerEventType type, const std::string& detail) {
      if (type == p2p::PeerManager::PeerEventType::CONNECTED) {
        {
          std::lock_guard<std::mutex> lk(mu_);
          peer_ip_cache_[peer_id] = endpoint_to_ip(detail);
        }
        if (discipline_.is_banned(endpoint_to_ip(detail), now_unix())) {
          p2p_.disconnect_peer(peer_id);
        }
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::DISCONNECTED) {
        std::lock_guard<std::mutex> lk(mu_);
        peer_ip_cache_.erase(peer_id);
        msg_rate_buckets_.erase(peer_id);
        vote_verify_buckets_.erase(peer_id);
        tx_verify_buckets_.erase(peer_id);
        return;
      }
      if (type == p2p::PeerManager::PeerEventType::FRAME_INVALID) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "invalid-frame");
      } else if (type == p2p::PeerManager::PeerEventType::FRAME_TIMEOUT ||
                 type == p2p::PeerManager::PeerEventType::HANDSHAKE_TIMEOUT) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_FRAME, "timeout");
      } else if (type == p2p::PeerManager::PeerEventType::QUEUE_OVERFLOW) {
        score_peer(peer_id, p2p::MisbehaviorReason::RATE_LIMIT, "queue-overflow");
      }
    });
    if (!p2p_.start_listener(cfg_.bind_ip, cfg_.p2p_port)) {
      std::cerr << "listener start failed " << cfg_.bind_ip << ":" << cfg_.p2p_port << "\n";
      return false;
    }
    cfg_.p2p_port = p2p_.listener_port();
    try_connect_bootstrap_peers();
  }

  return true;
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
  if (loop_thread_.joinable()) loop_thread_.join();
  if (restart_debug_) log_line("restart-debug event-loop-joined");
  if (restart_debug_) log_line("restart-debug round-timer-cancelled");
  join_local_bus_tasks();
  if (restart_debug_) log_line("restart-debug local-bus-tasks-joined");
  persist_peers();
  if (restart_debug_) log_line("restart-debug peers-persisted");
  p2p_.stop();
  if (restart_debug_) log_line("restart-debug p2p-stopped");
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.erase(std::remove(g_local_bus_nodes.begin(), g_local_bus_nodes.end(), this), g_local_bus_nodes.end());
  }
  (void)db_.flush();
  if (restart_debug_) log_line("restart-debug db-flushed");
  db_.close();
  if (restart_debug_) log_line("restart-debug db-closed");
}

NodeStatus Node::status() const {
  std::lock_guard<std::mutex> lk(mu_);
  NodeStatus s;
  s.height = finalized_height_;
  s.round = current_round_;
  s.tip_hash = finalized_hash_;
  const auto active = validators_.active_sorted(finalized_height_ + 1);
  auto leader = consensus::select_leader(finalized_hash_, finalized_height_ + 1, current_round_, active);
  if (leader.has_value()) s.leader = *leader;
  s.votes_for_current = 0;
  s.peers = peer_count();
  s.mempool_size = mempool_.size();
  s.committee_size = committee_for_height(finalized_height_ + 1).size();
  s.rejected_network_id = rejected_network_id_;
  s.rejected_protocol_version = rejected_protocol_version_;
  s.rejected_pre_handshake = rejected_pre_handshake_;
  return s;
}

bool Node::inject_vote_for_test(const Vote& vote) { return handle_vote(vote, false, 0); }
bool Node::inject_tx_for_test(const Tx& tx, bool relay) {
  if (relay) return handle_tx(tx, true);
  std::lock_guard<std::mutex> lk(mu_);
  mempool_.set_validation_context(
      SpecialValidationContext{&validators_, finalized_height_ + 1,
                               [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
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
std::vector<PubKey32> Node::active_validators_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.active_sorted(finalized_height_ + 1);
}
std::vector<PubKey32> Node::committee_for_next_height_for_test() const {
  std::lock_guard<std::mutex> lk(mu_);
  return committee_for_height(finalized_height_ + 1);
}
std::optional<consensus::ValidatorInfo> Node::validator_info_for_test(const PubKey32& pub) const {
  std::lock_guard<std::mutex> lk(mu_);
  return validators_.get(pub);
}
std::uint16_t Node::p2p_port_for_test() const { return cfg_.p2p_port; }

void Node::event_loop() {
  while (running_) {
    std::optional<Block> to_propose;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::uint64_t h = finalized_height_ + 1;
      validators_.advance_height(h);
      mempool_.set_validation_context(
          SpecialValidationContext{&validators_, h, [this](const PubKey32& pub, std::uint64_t ch, std::uint32_t round) {
                                     return is_committee_member_for(pub, ch, round);
                                   }});
      const auto active = validators_.active_sorted(h);
      const auto committee = consensus::select_committee(finalized_hash_, h, active, cfg_.max_committee);
      const auto leader = consensus::select_leader(finalized_hash_, h, current_round_, active);
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
            << ",\"peers\":" << peer_count() << ",\"mempool_size\":" << mempool_.size()
            << ",\"committee_size\":" << committee.size()
            << ",\"rejected_network_id\":" << rejected_network_id_
            << ",\"rejected_protocol_version\":" << rejected_protocol_version_
            << ",\"rejected_pre_handshake\":" << rejected_pre_handshake_ << "}";
          std::cout << j.str() << "\n";
        }
      }

      if (!pause_proposals_.load() && leader.has_value() && *leader == local_key_.public_key) {
        auto key = std::make_pair(h, current_round_);
        if (proposed_in_round_.find(key) == proposed_in_round_.end()) {
          auto b = build_proposal_block(h, current_round_);
          if (b.has_value()) {
            proposed_in_round_[key] = true;
            candidate_blocks_[b->header.block_id()] = *b;
            to_propose = *b;
          }
        }
      }
    }

    if (to_propose.has_value()) {
      broadcast_propose(*to_propose);
      handle_propose(p2p::ProposeMsg{to_propose->header.height, to_propose->header.round,
                                     to_propose->header.prev_finalized_hash, to_propose->serialize()},
                     false);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!cfg_.disable_p2p && cfg_.testnet) {
      const std::uint64_t now_ms = now_unix() * 1000;
      if (peer_count() == 0 && now_ms > last_seed_attempt_ms_ + 3000) {
        try_connect_bootstrap_peers();
        last_seed_attempt_ms_ = now_ms;
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
  v.node_software_version = "selfcoin-node/0.7";

  (void)p2p_.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v));
  p2p_.mark_handshake_tx(peer_id, true, false);
}

void Node::maybe_send_verack(int peer_id) {
  (void)p2p_.send_to(peer_id, p2p::MsgType::VERACK, {});
  p2p_.mark_handshake_tx(peer_id, false, true);
}

void Node::handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  bool rate_limited = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    rate_limited = !check_rate_limit_locked(peer_id, msg_type);
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
    p2p_.mark_handshake_rx(peer_id, false, true);
    return;
  }

  const auto info = p2p_.get_peer_info(peer_id);
  if (!info.established()) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      ++rejected_pre_handshake_;
    }
    score_peer(peer_id, p2p::MisbehaviorReason::PRE_HANDSHAKE_CONSENSUS, "pre-handshake-msg");
    return;
  }

  switch (msg_type) {
    case p2p::MsgType::GET_FINALIZED_TIP: {
      p2p::FinalizedTipMsg tip{finalized_height_, finalized_hash_};
      (void)p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip));
      break;
    }
    case p2p::MsgType::FINALIZED_TIP: {
      auto tip = p2p::de_finalized_tip(payload);
      if (!tip.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-finalized-tip");
        return;
      }
      if (tip->height > finalized_height_) {
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
      auto blk = db_.get_block(gb->hash);
      if (!blk.has_value()) return;
      (void)p2p_.send_to(peer_id, p2p::MsgType::BLOCK, p2p::ser_block(p2p::BlockMsg{*blk}), true);
      break;
    }
    case p2p::MsgType::BLOCK: {
      auto b = p2p::de_block(payload);
      if (!b.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-msg");
        return;
      }
      auto blk = Block::parse(b->block_bytes);
      if (!blk.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-block-parse");
        return;
      }
      std::lock_guard<std::mutex> lk(mu_);
      if (blk->header.height == finalized_height_ + 1 && blk->header.prev_finalized_hash == finalized_hash_) {
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
        const auto committee = committee_for_height(blk->header.height);
        if (committee.empty()) return;
        const std::size_t quorum = consensus::quorum_threshold(committee.size());
        std::set<PubKey32> committee_set(committee.begin(), committee.end());
        std::set<PubKey32> seen;
        std::size_t valid_sigs = 0;
        for (const auto& s : blk->finality_proof.sigs) {
          if (committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
          if (!seen.insert(s.validator_pubkey).second) continue;
          Bytes bid_bytes(bid.begin(), bid.end());
          if (!crypto::ed25519_verify(bid_bytes, s.signature, s.validator_pubkey)) continue;
          ++valid_sigs;
        }
        if (valid_sigs >= quorum) {
          if (persist_finalized_block(*blk)) {
            std::vector<Hash32> confirmed_txids;
            confirmed_txids.reserve(blk->txs.size());
            for (const auto& tx : blk->txs) confirmed_txids.push_back(tx.txid());
            mempool_.remove_confirmed(confirmed_txids);
            UtxoSet pre_utxos = utxos_;
            apply_validator_state_changes(*blk, pre_utxos, blk->header.height);
            apply_block_to_utxo(*blk, utxos_);
            mempool_.prune_against_utxo(utxos_);
            finalized_height_ = blk->header.height;
            finalized_hash_ = bid;
            current_round_ = 0;
            round_started_ms_ = now_unix() * 1000;
            if (restart_debug_) {
              log_line("restart-debug round-timer-reset height=" + std::to_string(finalized_height_) + " round=0");
            }
            votes_.clear_height(blk->header.height);
            candidate_blocks_.clear();
            candidate_block_sizes_.clear();
          }
        } else {
          candidate_blocks_[bid] = *blk;
          finalize_if_quorum(bid, blk->header.height, blk->header.round);
        }
      }
      break;
    }
    case p2p::MsgType::PROPOSE: {
      auto p = p2p::de_propose(payload);
      if (!p.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-propose-msg");
        return;
      }
      if (!handle_propose(*p, true)) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PROPOSE, "invalid-propose");
      }
      break;
    }
    case p2p::MsgType::VOTE: {
      auto v = p2p::de_vote(payload);
      if (!v.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-vote-msg");
        return;
      }
      if (!handle_vote(v->vote, true, peer_id)) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_VOTE_SIGNATURE, "invalid-vote");
      }
      break;
    }
    case p2p::MsgType::TX: {
      auto m = p2p::de_tx(payload);
      if (!m.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-msg");
        return;
      }
      auto tx = Tx::parse(m->tx_bytes);
      if (!tx.has_value()) {
        score_peer(peer_id, p2p::MisbehaviorReason::INVALID_PAYLOAD, "bad-tx-parse");
        return;
      }
      if (!handle_tx(*tx, true, peer_id)) {
        score_peer(peer_id, p2p::MisbehaviorReason::DUPLICATE_SPAM, "tx-rejected");
      }
      break;
    }
    default:
      break;
  }
}

bool Node::handle_propose(const p2p::ProposeMsg& msg, bool from_network) {
  if (from_network && !running_) return false;
  std::optional<Vote> maybe_vote;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (msg.height != finalized_height_ + 1) return false;
    if (msg.prev_finalized_hash != finalized_hash_) return false;

    auto blk = Block::parse(msg.block_bytes);
    if (!blk.has_value()) return false;
    if (blk->header.height != msg.height || blk->header.round != msg.round) return false;

    const auto active = validators_.active_sorted(msg.height);
    auto expected = consensus::select_leader(finalized_hash_, msg.height, msg.round, active);
    if (!expected.has_value() || blk->header.leader_pubkey != *expected) return false;

    std::vector<Bytes> tx_bytes;
    tx_bytes.reserve(blk->txs.size());
    for (const auto& tx : blk->txs) tx_bytes.push_back(tx.serialize());
    auto merkle_root = merkle::compute_merkle_root_from_txs(tx_bytes);
    if (!merkle_root.has_value() || blk->header.merkle_root != *merkle_root) return false;

    SpecialValidationContext vctx{&validators_, msg.height,
                                  [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
                                    return is_committee_member_for(pub, h, round);
                                  }};
    const auto reward_signers = committee_for_height(msg.height);
    auto valid = validate_block_txs(*blk, utxos_, BLOCK_REWARD, &vctx, &reward_signers);
    if (!valid.ok) return false;

    Hash32 bid = blk->header.block_id();
    if (candidate_blocks_.find(bid) == candidate_blocks_.end()) {
      const std::size_t sz = msg.block_bytes.size();
      std::size_t total = 0;
      for (const auto& [_, s] : candidate_block_sizes_) total += s;
      if (candidate_blocks_.size() >= kMaxCandidateBlocks || total + sz > kMaxCandidateBlockBytes) return false;
      candidate_block_sizes_[bid] = sz;
    }
    candidate_blocks_[bid] = *blk;
    prune_caches_locked(msg.height, msg.round);

    if (is_committee_member_for(local_key_.public_key, msg.height, msg.round)) {
      Bytes b_id(bid.begin(), bid.end());
      auto sig = crypto::ed25519_sign(b_id, local_key_.private_key);
      if (!sig.has_value()) return false;
      maybe_vote = Vote{msg.height, msg.round, bid, local_key_.public_key, *sig};
    }
  }

  if (maybe_vote.has_value()) {
    if (from_network) {
      broadcast_vote(*maybe_vote);
    } else {
      broadcast_vote(*maybe_vote);
    }
    return handle_vote(*maybe_vote, false);
  }
  return true;
}

bool Node::handle_vote(const Vote& vote, bool from_network, int from_peer_id) {
  if (from_network && !running_) return false;
  bool relay_vote = false;
  bool finalize_ok = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (vote.height != finalized_height_ + 1) return false;
    if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) return false;

    const auto nowm = now_ms();
    auto& verify_bucket = vote_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.vote_verify_capacity, cfg_.vote_verify_refill);
    if (from_network && !verify_bucket.consume(1.0, nowm)) return false;

    const p2p::VoteVerifyCache::Key vkey{vote.height, vote.round, vote.block_id, vote.validator_pubkey};
    if (!vote_verify_cache_.contains(vkey)) {
      Bytes bid(vote.block_id.begin(), vote.block_id.end());
      if (!crypto::ed25519_verify(bid, vote.signature, vote.validator_pubkey)) return false;
      vote_verify_cache_.insert(vkey);
    }

    auto tr = votes_.add_vote(vote);
    if (tr.equivocation && tr.evidence.has_value()) {
      if (is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) {
        validators_.ban(vote.validator_pubkey);
        auto vi = validators_.get(vote.validator_pubkey);
        if (vi.has_value()) db_.put_validator(vote.validator_pubkey, *vi);
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

  if (relay_vote) {
    broadcast_vote(vote);
  }
  return finalize_ok;
}

bool Node::handle_tx(const Tx& tx, bool from_network, int from_peer_id) {
  if (from_network && !running_) return false;
  Hash32 txid{};
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto& verify_bucket = tx_verify_buckets_[from_peer_id];
    verify_bucket.configure(cfg_.tx_verify_capacity, cfg_.tx_verify_refill);
    if (from_network && !verify_bucket.consume(static_cast<double>(std::max<std::size_t>(1, tx.inputs.size())), now_ms())) {
      return false;
    }
    mempool_.set_validation_context(
        SpecialValidationContext{&validators_, finalized_height_ + 1,
                                 [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
                                   return is_committee_member_for(pub, h, round);
                                 }});
    std::string err;
    std::uint64_t fee = 0;
    if (!mempool_.accept_tx(tx, utxos_, &err, cfg_.min_relay_fee, &fee)) {
      return false;
    }
    if (cfg_.testnet && fee < cfg_.min_relay_fee) return false;
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
  const auto committee = committee_for_height(height);
  if (committee.empty()) return false;
  const std::size_t quorum = consensus::quorum_threshold(committee.size());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  if (sigs.size() < quorum) return false;

  std::set<PubKey32> seen;
  std::vector<FinalitySig> filtered;
  for (const auto& s : sigs) {
    if (committee_set.find(s.validator_pubkey) == committee_set.end()) continue;
    if (!seen.insert(s.validator_pubkey).second) continue;
    Bytes bid(block_id.begin(), block_id.end());
    if (!crypto::ed25519_verify(bid, s.signature, s.validator_pubkey)) continue;
    filtered.push_back(s);
  }
  if (filtered.size() < quorum) return false;

  Block b = blk_it->second;
  b.finality_proof.sigs = filtered;

  if (!persist_finalized_block(b)) return false;

  std::vector<Hash32> confirmed_txids;
  confirmed_txids.reserve(b.txs.size());
  for (const auto& tx : b.txs) confirmed_txids.push_back(tx.txid());
  mempool_.remove_confirmed(confirmed_txids);
  UtxoSet pre_utxos = utxos_;
  apply_validator_state_changes(b, pre_utxos, height);
  apply_block_to_utxo(b, utxos_);
  mempool_.prune_against_utxo(utxos_);

  finalized_height_ = b.header.height;
  finalized_hash_ = block_id;
  current_round_ = 0;
  round_started_ms_ = now_unix() * 1000;
  if (restart_debug_) {
    log_line("restart-debug round-timer-reset height=" + std::to_string(finalized_height_) + " round=0");
  }

  votes_.clear_height(height);
  vote_verify_cache_.clear_height(height);
  candidate_blocks_.clear();
  candidate_block_sizes_.clear();

  broadcast_finalized_block(b);

  std::ostringstream oss;
  oss << "finalized height=" << finalized_height_ << " round=" << round << " leader="
      << hex_encode(Bytes(b.header.leader_pubkey.begin(), b.header.leader_pubkey.end()))
      << " votes=" << filtered.size() << "/" << quorum << " txs=" << b.txs.size()
      << " hash=" << hex_encode32(block_id);
  if (b.txs.size() > 1) {
    oss << " included_txid=" << hex_encode32(b.txs[1].txid());
  }
  log_line(oss.str());

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
  SpecialValidationContext vctx{&validators_, height, [this](const PubKey32& pub, std::uint64_t h,
                                                             std::uint32_t round) {
                                  return is_committee_member_for(pub, h, round);
                                }};
  for (const auto& tx : picked) {
    auto vr = validate_tx(tx, 1, utxos_, &vctx);
    if (vr.ok) total_fees += vr.fee;
  }

  const auto committee = committee_for_height(height);
  const auto payout = consensus::compute_payout(height, total_fees, local_key_.public_key, committee);

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
  b.txs.insert(b.txs.end(), picked.begin(), picked.end());

  std::vector<Bytes> tx_bytes;
  tx_bytes.reserve(b.txs.size());
  for (const auto& tx : b.txs) tx_bytes.push_back(tx.serialize());
  auto m = merkle::compute_merkle_root_from_txs(tx_bytes);
  if (!m.has_value()) return std::nullopt;
  b.header.merkle_root = *m;
  if (!picked.empty()) {
    log_line("propose-assembled height=" + std::to_string(height) + " round=" + std::to_string(round) +
             " txs=" + std::to_string(picked.size()) + " fees=" + std::to_string(total_fees));
  }
  return b;
}

void Node::broadcast_propose(const Block& block) {
  p2p::ProposeMsg p;
  p.height = block.header.height;
  p.round = block.header.round;
  p.prev_finalized_hash = block.header.prev_finalized_hash;
  p.block_bytes = block.serialize();
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

void Node::broadcast_vote(const Vote& vote) {
  if (cfg_.disable_p2p) {
    if (!running_) return;
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      spawn_local_bus_task([peer, vote]() { peer->handle_vote(vote, true, 0); });
    }
  } else {
    p2p_.broadcast(p2p::MsgType::VOTE, p2p::ser_vote(p2p::VoteMsg{vote}));
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

bool Node::persist_finalized_block(const Block& block) {
  const Hash32 h = block.header.block_id();
  if (!db_.put_block(h, block.serialize())) return false;
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
  std::string path = cfg_.genesis_path.empty() ? "mainnet/genesis.json" : cfg_.genesis_path;
  std::string err;
  auto doc = genesis::load_from_path(path, &err);
  if (!doc.has_value()) {
    std::cerr << "genesis load failed: " << err << "\n";
    return false;
  }
  if (!genesis::validate_document(*doc, cfg_.network, &err, 4)) {
    std::cerr << "genesis validation failed: " << err << "\n";
    return false;
  }

  const Hash32 ghash = genesis::hash_doc(*doc);
  const Bytes ghash_b(ghash.begin(), ghash.end());
  const Hash32 gblock = genesis::block_id(*doc);
  const Bytes gblock_b(gblock.begin(), gblock.end());
  const auto stored = db_.get("G:");
  if (stored.has_value()) {
    if (stored->size() != 32 || !std::equal(stored->begin(), stored->end(), ghash_b.begin())) {
      std::cerr << "genesis mismatch against existing database\n";
      return false;
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

  return true;
}

std::vector<PubKey32> Node::committee_for_height(std::uint64_t height) const {
  if (height == 0) return {};
  if (height == finalized_height_ + 1) {
    const auto active = validators_.active_sorted(height);
    return consensus::select_committee(finalized_hash_, height, active, cfg_.max_committee);
  }
  if (height > finalized_height_) return {};

  consensus::ValidatorRegistry replay_validators;
  UtxoSet replay_utxos;

  if (cfg_.devnet || cfg_.testnet) {
    const auto keys = devnet_keypairs();
    const int n_active = std::max(1, std::min(static_cast<int>(keys.size()), cfg_.devnet_initial_active_validators));
    for (int idx = 0; idx < static_cast<int>(keys.size()); ++idx) {
      consensus::ValidatorInfo vi;
      vi.status = (idx < n_active) ? consensus::ValidatorStatus::ACTIVE : consensus::ValidatorStatus::BANNED;
      vi.joined_height = 0;
      vi.has_bond = (idx < n_active);
      vi.bond_outpoint = OutPoint{zero_hash(), 0};
      vi.unbond_height = 0;
      replay_validators.upsert(keys[idx].public_key, vi);
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
        if (!is_validator_register_script(it->second.out.script_pubkey, &pub)) continue;

        SlashEvidence evidence;
        if (parse_slash_script_sig(in.script_sig, &evidence)) {
          replay_validators.ban(pub);
        } else {
          replay_validators.request_unbond(pub, h);
        }
      }
    }

    for (const auto& tx : block.txs) {
      const Hash32 txid = tx.txid();
      for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
        const auto& out = tx.outputs[out_i];
        PubKey32 pub{};
        if (out.value == BOND_AMOUNT && is_validator_register_script(out.script_pubkey, &pub)) {
          replay_validators.register_bond(pub, OutPoint{txid, out_i}, h);
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

  Hash32 prev_hash = zero_hash();
  if (height > 1) {
    auto prev = db_.get_height_hash(height - 1);
    if (!prev.has_value()) return {};
    prev_hash = *prev;
  }
  const auto active = replay_validators.active_sorted(height);
  return consensus::select_committee(prev_hash, height, active, cfg_.max_committee);
}

bool Node::is_committee_member_for(const PubKey32& pub, std::uint64_t height, std::uint32_t round) const {
  (void)round;
  const auto committee = committee_for_height(height);
  return std::find(committee.begin(), committee.end(), pub) != committee.end();
}

void Node::apply_validator_state_changes(const Block& block, const UtxoSet& pre_utxos, std::uint64_t height) {
  for (size_t txi = 1; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    for (const auto& in : tx.inputs) {
      OutPoint op{in.prev_txid, in.prev_index};
      auto it = pre_utxos.find(op);
      if (it == pre_utxos.end()) continue;
      PubKey32 pub{};
      if (!is_validator_register_script(it->second.out.script_pubkey, &pub)) continue;

      SlashEvidence evidence;
      if (parse_slash_script_sig(in.script_sig, &evidence)) {
        validators_.ban(pub);
      } else {
        validators_.request_unbond(pub, height);
      }
    }
  }

  for (size_t txi = 0; txi < block.txs.size(); ++txi) {
    const auto& tx = block.txs[txi];
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      const auto& out = tx.outputs[out_i];
      PubKey32 pub{};
      if (out.value == BOND_AMOUNT && is_validator_register_script(out.script_pubkey, &pub)) {
        validators_.register_bond(pub, OutPoint{txid, out_i}, height);
      }
    }
  }

  validators_.advance_height(height + 1);
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

void Node::try_connect_bootstrap_peers() {
  std::set<std::string> uniq(bootstrap_peers_.begin(), bootstrap_peers_.end());
  for (const auto& peer : uniq) {
    const auto pos = peer.find(':');
    if (pos == std::string::npos) continue;
    const std::string host = peer.substr(0, pos);
    const std::uint16_t port = static_cast<std::uint16_t>(std::stoi(peer.substr(pos + 1)));
    if (discipline_.is_banned(host, now_unix())) continue;
    if (!p2p_.connect_to(host, port)) continue;
    for (int pid : p2p_.peer_ids()) send_version(pid);
  }
}

std::size_t Node::peer_count() const { return static_cast<std::size_t>(p2p_.peer_ids().size()); }

std::string Node::peer_ip_for(int peer_id) const {
  auto it = peer_ip_cache_.find(peer_id);
  if (it != peer_ip_cache_.end()) return it->second;
  const auto pi = p2p_.get_peer_info(peer_id);
  if (!pi.ip.empty()) return pi.ip;
  return endpoint_to_ip(pi.endpoint);
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
    default:
      return true;
  }
}

std::optional<NodeConfig> parse_args(int argc, char** argv) {
  NodeConfig cfg;
  cfg.network = devnet_network();
  cfg.p2p_port = cfg.network.p2p_default_port;
  cfg.max_committee = cfg.network.max_committee;
  bool port_explicit = false;
  bool committee_explicit = false;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](const std::string& name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << name << "\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (a == "--devnet") {
      cfg.devnet = true;
      cfg.testnet = false;
      cfg.mainnet = false;
      cfg.network = devnet_network();
      if (!port_explicit) cfg.p2p_port = cfg.network.p2p_default_port;
      if (!committee_explicit) cfg.max_committee = cfg.network.max_committee;
    } else if (a == "--testnet") {
      cfg.testnet = true;
      cfg.devnet = false;
      cfg.mainnet = false;
      cfg.network = testnet_network();
      if (!port_explicit) cfg.p2p_port = cfg.network.p2p_default_port;
      if (!committee_explicit) cfg.max_committee = cfg.network.max_committee;
    } else if (a == "--mainnet") {
      cfg.mainnet = true;
      cfg.devnet = false;
      cfg.testnet = false;
      cfg.network = mainnet_network();
      if (!port_explicit) cfg.p2p_port = cfg.network.p2p_default_port;
      if (!committee_explicit) cfg.max_committee = cfg.network.max_committee;
    } else if (a == "--node-id") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.node_id = std::stoi(*v);
    } else if (a == "--port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.p2p_port = static_cast<std::uint16_t>(std::stoi(*v));
      port_explicit = true;
    } else if (a == "--db") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.db_path = *v;
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
    } else if (a == "--devnet-initial-active") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.devnet_initial_active_validators = std::stoi(*v);
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
    } else if (a == "--ban-seconds") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.ban_seconds = static_cast<std::uint64_t>(std::stoull(*v));
    } else if (a == "--min-relay-fee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.min_relay_fee = static_cast<std::uint64_t>(std::stoull(*v));
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }
  return cfg;
}

}  // namespace selfcoin::node
